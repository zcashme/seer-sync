pub mod chain;
pub mod decrypt;
pub mod scan;

use std::error::Error;

use tokio_stream::StreamExt;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use self::chain::{LwdClient, RpcError};
use self::decrypt::ScanningKeys;
use self::scan::{scan, scan_compact, Nullifiers, ScanError, WalletTx};

// How many shielded outputs (sapling + orchard + ironwood) to accumulate before
// flushing a batch to apply_blocks.  Keeps memory bounded during long syncs.
const OUTPUTS_PER_BATCH: usize = 100_000;
// Hard cap on block count per batch.  Prevents a single apply_blocks call from
// holding too many compact blocks in memory at once.
const BLOCKS_PER_BATCH: usize = 1_000;

/// A position in the Zcash chain that has been fully scanned and persisted.
///
/// The `hash` is the block hash at `height` — it is always present (never `None`)
/// because a checkpoint without a hash is useless for reorg detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

/// The full state needed to resume syncing an account.
///
/// Returned by `Account::resume()` at the start of each sync pass.  The engine
/// uses this to know where to start streaming and which nullifiers to watch.
pub struct Resume {
    /// The earliest block height this account cares about.  Syncing never
    /// rewinds below this height.
    pub birthday: BlockHeight,
    /// The last fully synced position, or `None` if never synced.
    /// When `None`, syncing starts from `birthday`.
    pub checkpoint: Option<Cursor>,
    /// The set of nullifiers for all unspent notes this account has received.
    /// Used to detect when our notes are spent.  Only available with full
    /// viewing keys (UFVK); incoming-only keys (UIVK) cannot compute nullifiers.
    pub nullifiers: Nullifiers,
}

/// Storage contract: the account implements this to persist and rewind state.
///
/// The sync engine calls these three methods.  The account is responsible for
/// maintaining a consistent nullifier set across reorgs (see `rewind`).
pub trait Account {
    /// Load the current sync state: birthday, checkpoint, and nullifier set.
    /// Called at the start of every sync pass and after every reorg rewind.
    fn resume(&self) -> Result<Resume, Box<dyn Error + Send + Sync>>;

    /// Discard all persisted state at or above the given height.  This is called
    /// when a reorg is detected — the chain forked and some persisted blocks
    /// are no longer on the best chain.
    ///
    /// The account must:
    ///   1. Delete transactions received at height >= `to`.
    ///   2. Remove nullifiers from notes received at height >= `to`.
    ///   3. Delete spends recorded at height >= `to`.
    ///   4. Re-add nullifiers for notes received before `to` that were spent
    ///      after `to` (those notes are unspent again on the new chain).
    fn rewind(&self, to: BlockHeight) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Persist a batch of scanned transactions at the given cursor position.
    /// The cursor is the last block in the batch.  The account should update
    /// its checkpoint to this cursor and store the transactions (including
    /// their note nullifiers and spend nullifiers for future reorg recovery).
    fn apply(&self, at: Cursor, transactions: &[WalletTx]) -> Result<(), Box<dyn Error + Send + Sync>>;
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Chain(#[from] RpcError),
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error("failed to parse transaction {txid}: {source}")]
    Transaction {
        txid: TxId,
        #[source]
        source: std::io::Error,
    },
    #[error("account storage error")]
    Account {
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
}

/// Syncs the account from its persisted checkpoint to the current chain tip.
///
/// ## High-level flow
///
/// 1. Load state from the account (checkpoint, nullifiers, birthday).
/// 2. Stream compact blocks from `checkpoint + 1` to the chain tip.
/// 3. For each block, verify chain continuity (reorg detection).
/// 4. Accumulate blocks into batches (bounded by block count and output count).
/// 5. When a batch is full, call `apply_blocks`:
///    a. `scan_compact` — trial-decrypt shielded notes, detect spent nullifiers.
///    b. `update_with` — prune spent nullifiers, add new ones.
///    c. `fetch_raw_transactions` — fetch full transactions for memo enrichment.
///    d. `scan` — decrypt memos and recover outgoing notes from full transactions.
///    e. `account.apply` — persist the batch.
/// 6. If a reorg is detected, rewind the account and restart from step 1.
/// 7. Return the final cursor (or `None` if already at tip).
///
/// ## Reorg handling
///
/// When a block's `prev_hash` doesn't match the block we expected it to connect
/// to, the chain has forked.  We rewind the account by `rewind_by` blocks and
/// restart.  `rewind_by` starts at 1 and doubles on each consecutive reorg
/// (exponential backoff) until we rewind past the fork point.  It resets to 1
/// after a successful batch is applied.
///
/// The stream and any unflushed blocks are dropped on reorg — they may be from
/// the dead chain.  The account's persisted state (via `rewind`) is the source
/// of truth.
pub(crate) async fn run<A: Account>(
    mut client: LwdClient,
    keys: &ScanningKeys,
    network: Network,
    account: &A,
) -> Result<Option<Cursor>, SyncError> {
    // How many blocks to rewind on a reorg.  Doubles on each consecutive
    // reorg without progress.  Resets to 1 after a successful batch apply.
    let mut rewind_by = 1;

    'outer: loop {
        // Step 1: Load state and fetch the current chain tip.
        let (tip, _) = client.latest_block().await?;
        let Resume {
            birthday,
            checkpoint,
            mut nullifiers,
        } = account.resume().map_err(|source| SyncError::Account { source })?;

        // Where to start streaming.  If we have a checkpoint, resume from the
        // next block.  Otherwise, start from the account's birthday.
        let start = checkpoint
            .map(|cursor| cursor.height + 1)
            .unwrap_or(birthday);
        if start > tip {
            // Already synced past the tip.  Nothing to do.
            return Ok(checkpoint);
        }

        // Clone the client for parallel use: `stream` owns the original,
        // `fetch_client` is used by apply_blocks for full-tx fetches.
        let mut fetch_client = client.clone();
        let mut stream = client.blocks(start, tip).await?;

        // `prior` tracks the block we expect the next block to connect to.
        // Seeded from the checkpoint.  Updated per-block (not per-batch) so
        // reorg detection works on every block, not just the first in a batch.
        let mut prior = checkpoint.map(|cursor| (cursor.height, cursor.hash));

        // The last successfully applied cursor.  Returned at the end.
        // Starts as the checkpoint (in case no blocks are processed).
        let mut last = checkpoint;
        let mut blocks = Vec::with_capacity(BLOCKS_PER_BATCH);
        let mut output_count = 0;

        // Step 2-3: Stream and verify blocks.
        while let Some(block) = stream.next().await {
            let block = block?;
            let height = BlockHeight::from_u32(
                u32::try_from(block.height)
                    .expect("lightwalletd block heights fit Zcash's block-height type"),
            );
            let prev_hash = BlockHash(
                block
                    .prev_hash
                    .as_slice()
                    .try_into()
                    .expect("lightwalletd block hashes are 32 bytes"),
            );

            // Reorg detection: does this block connect to the block we expect?
            // `detect_reorg` returns the height of the mismatched `prior` block.
            // If it returns `Some`, the chain has forked at or before that height.
            if let Some(at) = client.detect_reorg(prior, prev_hash) {
                // Rewind the account past the suspected fork point.
                // Clamp to birthday — we never go below it.
                let rewind_to = at.saturating_sub(rewind_by);
                account
                    .rewind(if rewind_to < birthday { birthday } else { rewind_to })
                    .map_err(|source| SyncError::Account { source })?;
                // Exponential backoff: if the fork is deeper, we'll detect
                // another reorg on restart and double again.
                rewind_by = rewind_by.saturating_mul(2);
                // Drop the stream and unflushed blocks, restart from step 1.
                // The account's rewound state becomes the new starting point.
                continue 'outer;
            }

            // This block connects.  Update `prior` to this block so the next
            // block is checked against THIS block's hash (not the checkpoint's).
            let block_hash = BlockHash(
                block
                    .hash
                    .as_slice()
                    .try_into()
                    .expect("lightwalletd block hashes are 32 bytes"),
            );
            prior = Some((height, block_hash));

            // Step 4: Accumulate into a batch.
            // Count shielded outputs in this block to track batch size.
            let block_output_count = block
                .vtx
                .iter()
                .map(|tx| tx.outputs.len() + tx.actions.len() + tx.ironwood_actions.len())
                .sum::<usize>();

            // Flush the current batch BEFORE adding this block if the batch
            // is full (by block count or output count).  This block starts
            // the next batch.
            if !blocks.is_empty()
                && (blocks.len() == BLOCKS_PER_BATCH
                    || output_count + block_output_count > OUTPUTS_PER_BATCH)
            {
                last = Some(
                    apply_blocks(
                        &mut fetch_client,
                        keys,
                        network,
                        account,
                        &mut nullifiers,
                        &blocks,
                    )
                    .await?,
                );
                // After a successful apply, the cursor is the last block in
                // the flushed batch.  Update `prior` to it.
                prior = last.map(|cursor| (cursor.height, cursor.hash));
                // Reset backoff — we made progress, so this is a new reorg
                // episode if we hit another fork later.
                rewind_by = 1;
                blocks.clear();
                output_count = 0;
            }

            output_count += block_output_count;
            blocks.push(block);
        }

        // Step 5: Flush any remaining blocks after the stream ends.
        if !blocks.is_empty() {
            last = Some(
                apply_blocks(
                    &mut fetch_client,
                    keys,
                    network,
                    account,
                    &mut nullifiers,
                    &blocks,
                )
                .await?,
            );
        }

        // Step 7: Done.  Return the last applied cursor (or the checkpoint
        // if no blocks were processed).
        return Ok(last);
    }
}

/// Process a batch of compact blocks: scan, enrich, and persist.
///
/// This is the core per-batch pipeline:
///
/// 1. **`scan_compact`** — For each compact block, trial-decrypt every shielded
///    output against our viewing keys.  If a note decrypts, we record it as an
///    incoming note.  We also check every nullifier in the block against our
///    tracked set — if a match is found, one of our notes was spent.
///
/// 2. **`nullifiers.update_with`** — Remove nullifiers for detected spends
///    (those notes are spent, stop watching).  Add nullifiers for new incoming
///    notes (start watching for their future spend).
///
/// 3. **`fetch_raw_transactions`** — Fetch the full serialized transaction for
///    every detected txid.  Compact blocks only have a 52-byte ciphertext prefix;
///    the full transaction contains the complete memo and enough data for OVK
///    (outgoing viewing key) recovery.
///
/// 4. **`scan`** — For each full transaction, decrypt the full memo and attempt
///    outgoing note recovery (detects notes we sent to others, including change).
///
/// 5. **`account.apply`** — Persist the enriched transactions and update the
///    checkpoint to the last block in the batch.
async fn apply_blocks<A: Account>(
    client: &mut LwdClient,
    keys: &ScanningKeys,
    network: Network,
    account: &A,
    nullifiers: &mut Nullifiers,
    blocks: &[crate::proto::CompactBlock],
) -> Result<Cursor, SyncError> {
    // Step 1: Scan compact blocks for incoming notes and spent nullifiers.
    let mut transactions = scan_compact(blocks, keys, network, nullifiers)?;

    // Step 2: Update the nullifier set with detected spends and new notes.
    nullifiers.update_with(&transactions);

    // Step 3: Fetch full transactions for every detected txid.
    // Only transactions that had shielded activity relevant to us are fetched
    // (transactions with no detected notes or spends are skipped).
    let txids: Vec<(TxId, BlockHeight)> = transactions
        .iter()
        .map(|t| (t.txid, t.height))
        .collect();
    let raw_transactions = client.fetch_raw_transactions(&txids).await?;

    // Step 3b: Parse each raw transaction.  The branch ID (consensus rule set)
    // varies by height, so we need the correct one for each transaction.
    let mut full_transactions = Vec::with_capacity(raw_transactions.len());
    for (txid, height, raw) in raw_transactions {
        let branch_id = BranchId::for_height(&network, height);
        let parsed = Transaction::read(raw.data.as_slice(), branch_id).map_err(|source| {
            SyncError::Transaction {
                txid,
                source,
            }
        })?;
        full_transactions.push((txid, height, parsed));
    }

    // Step 4: Enrich transactions with memos and outgoing notes from full data.
    scan(&mut transactions, &full_transactions, keys, network)?;

    // Step 5: Build the cursor (last block in the batch) and persist.
    let block = blocks.last().expect("apply_blocks is called with blocks");
    let height = BlockHeight::try_from(block.height).map_err(|_| {
        ScanError::InvalidCompactBlock(BlockHeight::from(0))
    })?;
    let hash: [u8; 32] = block.hash.as_slice().try_into().map_err(|_| {
        ScanError::InvalidCompactBlock(height)
    })?;
    let cursor = Cursor { height, hash: BlockHash(hash) };
    account
        .apply(cursor, &transactions)
        .map_err(|source| SyncError::Account { source })?;

    Ok(cursor)
}