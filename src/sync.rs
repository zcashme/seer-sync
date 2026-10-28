pub mod chain;
pub mod decrypt;
pub mod scan;

use std::error::Error;
use std::time::Duration;

use self::chain::{LwdClient, NoServer, RpcError};
use self::decrypt::ScanningKeys;
use self::scan::{scan, scan_compact, Nullifiers, ScanError, WalletTx};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

const OUTPUTS_PER_BATCH: usize = 100_000;
const BLOCKS_PER_BATCH: usize = 1_000;
const MAX_REORG_DEPTH: u32 = 100;

/// Provides account state, atomic transaction persistence, and an optional raw-block hook.
pub trait Account {
    /// Returns the last applied block, if any.
    fn checkpoint(&self) -> Result<Option<Cursor>, Box<dyn Error + Send + Sync>>;
    /// Returns the first block height to scan.
    fn birthday(&self) -> Result<BlockHeight, Box<dyn Error + Send + Sync>>;
    /// Returns the nullifiers to watch for spends.
    fn nullifiers(&self) -> Result<Nullifiers, Box<dyn Error + Send + Sync>>;

    /// Atomically removes data above the earlier cursor `to` and makes it the checkpoint.
    fn rewind(&self, to: Cursor) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Atomically persists the detected transactions and advances the checkpoint to `at`.
    fn apply_transactions(
        &self,
        at: Cursor,
        transactions: &[WalletTx],
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Receives raw blocks and full transactions after [`Self::apply_transactions`] at the same cursor, doing nothing by default.
    fn apply_blocks(
        &self,
        _at: Cursor,
        _blocks: &[crate::proto::CompactBlock],
        _full_txs: &[(TxId, BlockHeight, Transaction)],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
}

/// Identifies the last applied block by height and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

/// Extracts a cursor from a block validated by the chain client.
fn cursor(block: &crate::proto::CompactBlock) -> Cursor {
    Cursor {
        height: BlockHeight::try_from(block.height)
            .expect("LwdClient validates streamed block heights"),
        hash: BlockHash::from_slice(&block.hash),
    }
}

/// Counts shielded outputs across all pools for the batch limit.
fn block_output_count(block: &crate::proto::CompactBlock) -> usize {
    block
        .vtx
        .iter()
        .map(|tx| tx.outputs.len() + tx.actions.len() + tx.ironwood_actions.len())
        .sum()
}

/// Scans and applies a nonempty batch in segments, reloading nullifiers before each scan to detect subsequent spends.
async fn process_batch<P: Parameters + Sync, A: Account>(
    client: &mut LwdClient,
    keys: &ScanningKeys,
    params: &P,
    account: &A,
    mut remaining_blocks: &[crate::proto::CompactBlock],
) -> Result<(), SyncError> {
    loop {
        let nullifiers = account
            .nullifiers()
            .map_err(|source| SyncError::Account { source })?;
        let (mut transactions, scanned) =
            scan_compact(remaining_blocks, keys, params, &nullifiers)?;
        let (scanned_blocks, remaining) = remaining_blocks.split_at(scanned);

        let txids: Vec<(TxId, BlockHeight)> =
            transactions.iter().map(|t| (t.txid, t.height)).collect();
        let raw_transactions = client.fetch_raw_transactions(&txids).await?;

        let mut full_transactions = Vec::with_capacity(raw_transactions.len());
        for (txid, height, raw) in raw_transactions {
            let branch_id = BranchId::for_height(params, height);
            let parsed = Transaction::read(raw.data.as_slice(), branch_id)
                .map_err(|source| SyncError::Transaction { txid, source })?;
            full_transactions.push((txid, height, parsed));
        }

        scan(&mut transactions, &full_transactions, keys, params);

        let block = scanned_blocks
            .last()
            .expect("process_batch is called with blocks");
        let cursor = cursor(block);
        account
            .apply_transactions(cursor, &transactions)
            .map_err(|source| SyncError::Account { source })?;

        account
            .apply_blocks(cursor, scanned_blocks, &full_transactions)
            .map_err(|source| SyncError::Account { source })?;

        if remaining.is_empty() {
            return Ok(());
        }
        remaining_blocks = remaining;
    }
}

/// Syncs the account to the chain tip and polls for new blocks, rewinding on reorgs.
pub(crate) async fn run<P: Parameters + Sync, A: Account>(
    mut client: LwdClient,
    keys: &ScanningKeys,
    params: &P,
    account: &A,
) -> Result<(), SyncError> {
    'outer: loop {
        let (tip, _) = client.latest_block().await?;
        let checkpoint = account
            .checkpoint()
            .map_err(|source| SyncError::Account { source })?;
        let birthday = account
            .birthday()
            .map_err(|source| SyncError::Account { source })?;

        let start = checkpoint
            .map(|cursor| cursor.height + 1)
            .unwrap_or(birthday);
        if start > tip {
            sleep(Duration::from_secs(30)).await;
            continue 'outer;
        }

        let mut fetch_client = client.clone();
        let mut stream = client.blocks(start, tip).await?;

        // The last block read; `checkpoint` until the first one arrives.
        let mut prior = checkpoint;

        let mut blocks = Vec::with_capacity(BLOCKS_PER_BATCH);
        let mut output_count = 0;

        while let Some(block) = stream.next().await {
            let block = block?;
            let prev_hash = BlockHash::from_slice(&block.prev_hash);

            if prior.is_some_and(|prior| prior.hash != prev_hash) {
                // Drop buffered blocks on a broken link and rewind if the checkpoint itself no longer connects.
                if let Some(seam) = checkpoint.filter(|&seam| prior == Some(seam)) {
                    let height = seam
                        .height
                        .saturating_sub(MAX_REORG_DEPTH)
                        .max(birthday.saturating_sub(1));
                    let hash = client.block_hash(height).await?;
                    account
                        .rewind(Cursor { height, hash })
                        .map_err(|source| SyncError::Account { source })?;
                }
                continue 'outer;
            }

            prior = Some(cursor(&block));

            let block_output_count = block_output_count(&block);

            if !blocks.is_empty()
                && (blocks.len() == BLOCKS_PER_BATCH
                    || output_count + block_output_count > OUTPUTS_PER_BATCH)
            {
                process_batch(&mut fetch_client, keys, params, account, &blocks).await?;
                blocks.clear();
                output_count = 0;
            }

            output_count += block_output_count;
            blocks.push(block);
        }

        if !blocks.is_empty() {
            process_batch(&mut fetch_client, keys, params, account, &blocks).await?;
        }
    }
}

/// Reports connection, chain, viewing-key, scanning, transaction parsing, or account failures.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Chain(#[from] RpcError),
    #[error(transparent)]
    Connect(#[from] NoServer),
    #[error("view key is neither a UFVK nor a UIVK for this network")]
    ViewKey,
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
