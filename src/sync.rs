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
/// Neither zcashd nor zebrad reorgs more than 99 blocks, so a block this far
/// below the checkpoint is final.
const MAX_REORG_DEPTH: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

pub struct Resume {
    pub birthday: BlockHeight,
    pub checkpoint: Option<Cursor>,
    pub nullifiers: Nullifiers,
}

pub trait Account {
    fn resume(&self) -> Result<Resume, Box<dyn Error + Send + Sync>>;

    /// Drop everything above `to`, which becomes the checkpoint, atomically.
    ///
    /// `to` is below the current checkpoint.
    fn rewind(&self, to: Cursor) -> Result<(), Box<dyn Error + Send + Sync>>;

    fn apply_transactions(
        &self,
        at: Cursor,
        transactions: &[WalletTx],
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Receive raw compact blocks and full transactions for custom decryption.
    ///
    /// Called after [`apply_transactions`](Self::apply_transactions) with the same
    /// cursor. The default implementation does nothing — consumers that don't
    /// need raw data (e.g. the reference [`Db`](crate::db::Db)) are unaffected.
    fn apply_blocks(
        &self,
        _at: Cursor,
        _blocks: &[crate::proto::CompactBlock],
        _full_txs: &[(TxId, BlockHeight, Transaction)],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
}

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

pub(crate) async fn run<P: Parameters + Sync, A: Account>(
    mut client: LwdClient,
    keys: &ScanningKeys,
    params: &P,
    account: &A,
) -> Result<(), SyncError> {
    'outer: loop {
        let (tip, _) = client.latest_block().await?;
        let Resume {
            birthday,
            mut checkpoint,
            mut nullifiers,
        } = account
            .resume()
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
            let prev_hash = BlockHash(
                block
                    .prev_hash
                    .as_slice()
                    .try_into()
                    .expect("lightwalletd block hashes are 32 bytes"),
            );

            if prior.is_some_and(|prior| prior.hash != prev_hash) {
                // Unapplied blocks are only a download cache, so a reorg drops
                // them and starts over from the checkpoint. If the checkpoint
                // itself no longer connects, rewind below any possible fork,
                // where the server's hash is safe to trust.
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
                checkpoint = Some(
                    process_batch(
                        &mut fetch_client,
                        keys,
                        params,
                        account,
                        &mut nullifiers,
                        &blocks,
                    )
                    .await?,
                );
                blocks.clear();
                output_count = 0;
            }

            output_count += block_output_count;
            blocks.push(block);
        }

        if !blocks.is_empty() {
            process_batch(
                &mut fetch_client,
                keys,
                params,
                account,
                &mut nullifiers,
                &blocks,
            )
            .await?;
        }

        continue 'outer;
    }
}

fn cursor(block: &crate::proto::CompactBlock) -> Cursor {
    Cursor {
        height: BlockHeight::from_u32(
            u32::try_from(block.height)
                .expect("lightwalletd block heights fit Zcash's block-height type"),
        ),
        hash: BlockHash(
            block
                .hash
                .as_slice()
                .try_into()
                .expect("lightwalletd block hashes are 32 bytes"),
        ),
    }
}

fn block_output_count(block: &crate::proto::CompactBlock) -> usize {
    block
        .vtx
        .iter()
        .map(|tx| tx.outputs.len() + tx.actions.len() + tx.ironwood_actions.len())
        .sum()
}

async fn process_batch<P: Parameters + Sync, A: Account>(
    client: &mut LwdClient,
    keys: &ScanningKeys,
    params: &P,
    account: &A,
    nullifiers: &mut Nullifiers,
    blocks: &[crate::proto::CompactBlock],
) -> Result<Cursor, SyncError> {
    let mut transactions = scan_compact(blocks, keys, params, nullifiers)?;

    nullifiers.update_with(&transactions);

    let txids: Vec<(TxId, BlockHeight)> = transactions.iter().map(|t| (t.txid, t.height)).collect();
    let raw_transactions = client.fetch_raw_transactions(&txids).await?;

    let mut full_transactions = Vec::with_capacity(raw_transactions.len());
    for (txid, height, raw) in raw_transactions {
        let branch_id = BranchId::for_height(params, height);
        let parsed = Transaction::read(raw.data.as_slice(), branch_id)
            .map_err(|source| SyncError::Transaction { txid, source })?;
        full_transactions.push((txid, height, parsed));
    }

    scan(&mut transactions, &full_transactions, keys, params)?;

    let block = blocks.last().expect("process_batch is called with blocks");
    let height = BlockHeight::try_from(block.height)
        .map_err(|_| ScanError::InvalidCompactBlock(BlockHeight::from(0)))?;
    let hash: [u8; 32] = block
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| ScanError::InvalidCompactBlock(height))?;
    let cursor = Cursor {
        height,
        hash: BlockHash(hash),
    };
    account
        .apply_transactions(cursor, &transactions)
        .map_err(|source| SyncError::Account { source })?;

    account
        .apply_blocks(cursor, blocks, &full_transactions)
        .map_err(|source| SyncError::Account { source })?;

    // update_with only has ordinary output nullifiers. Reload the watch list
    // the account just stored, so the next batch also sees anchors and name
    // tips written by this one.
    let Resume {
        nullifiers: reloaded,
        ..
    } = account
        .resume()
        .map_err(|source| SyncError::Account { source })?;
    *nullifiers = reloaded;

    Ok(cursor)
}
