pub mod chain;
pub mod decrypt;
pub mod scan;

use std::error::Error;
use std::time::Duration;

use self::chain::{LwdClient, RpcError};
use self::decrypt::ScanningKeys;
use self::scan::{scan, scan_compact, Nullifiers, ScanError, WalletTx};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

const OUTPUTS_PER_BATCH: usize = 100_000;
const BLOCKS_PER_BATCH: usize = 1_000;

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

    fn rewind(&self, to: BlockHeight) -> Result<(), Box<dyn Error + Send + Sync>>;

    fn apply(
        &self,
        at: Cursor,
        transactions: &[WalletTx],
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
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

pub(crate) async fn run<A: Account>(
    mut client: LwdClient,
    keys: &ScanningKeys,
    network: Network,
    account: &A,
) -> Result<(), SyncError> {    let mut rewind_by = 1;

    let mut recent_hashes: Vec<(BlockHeight, BlockHash)> = Vec::with_capacity(100);

    'outer: loop {
        let (tip, _) = client.latest_block().await?;
        let Resume {
            birthday,
            checkpoint,
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

        let mut prior = checkpoint.map(|cursor| (cursor.height, cursor.hash));

        let mut blocks = Vec::with_capacity(BLOCKS_PER_BATCH);
        let mut output_count = 0;

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

            if let Some(at) = client.detect_reorg(prior, prev_hash) {
                let rewind_to = at.saturating_sub(rewind_by);
                account
                    .rewind(rewind_to)
                    .map_err(|source| SyncError::Account { source })?;
                rewind_by = rewind_by.saturating_mul(2);
                let Resume {
                    nullifiers: new_nf, ..
                } = account
                    .resume()
                    .map_err(|source| SyncError::Account { source })?;
                nullifiers = new_nf;
                recent_hashes.retain(|(h, _)| *h < rewind_to);
                let (tip, _) = client.latest_block().await?;
                stream = client
                    .blocks(rewind_to.saturating_sub(1), tip)
                    .await?;
                prior = if recent_hashes.len() >= 2 {
                    Some(recent_hashes[recent_hashes.len() - 2])
                } else {
                    None
                };
                blocks.clear();
                output_count = 0;
                continue;
            }

            let block_hash = BlockHash(
                block
                    .hash
                    .as_slice()
                    .try_into()
                    .expect("lightwalletd block hashes are 32 bytes"),
            );
            prior = Some((height, block_hash));

            recent_hashes.push((height, block_hash));
            if recent_hashes.len() > 100 {
                recent_hashes.remove(0);
            }

            let block_output_count = block
                .vtx
                .iter()
                .map(|tx| tx.outputs.len() + tx.actions.len() + tx.ironwood_actions.len())
                .sum::<usize>();

            if !blocks.is_empty()
                && (blocks.len() == BLOCKS_PER_BATCH
                    || output_count + block_output_count > OUTPUTS_PER_BATCH)
            {
                let cursor = apply_blocks(
                    &mut fetch_client,
                    keys,
                    network,
                    account,
                    &mut nullifiers,
                    &blocks,
                )
                .await?;
                prior = Some((cursor.height, cursor.hash));
                rewind_by = 1;
                blocks.clear();
                output_count = 0;
            }

            output_count += block_output_count;
            blocks.push(block);
        }

        if !blocks.is_empty() {
            apply_blocks(
                &mut fetch_client,
                keys,
                network,
                account,
                &mut nullifiers,
                &blocks,
            )
            .await?;
        }

        continue 'outer;
    }
}

async fn apply_blocks<A: Account>(
    client: &mut LwdClient,
    keys: &ScanningKeys,
    network: Network,
    account: &A,
    nullifiers: &mut Nullifiers,
    blocks: &[crate::proto::CompactBlock],
) -> Result<Cursor, SyncError> {
    let mut transactions = scan_compact(blocks, keys, network, nullifiers)?;

    nullifiers.update_with(&transactions);

    let txids: Vec<(TxId, BlockHeight)> = transactions.iter().map(|t| (t.txid, t.height)).collect();
    let raw_transactions = client.fetch_raw_transactions(&txids).await?;

    let mut full_transactions = Vec::with_capacity(raw_transactions.len());
    for (txid, height, raw) in raw_transactions {
        let branch_id = BranchId::for_height(&network, height);
        let parsed = Transaction::read(raw.data.as_slice(), branch_id)
            .map_err(|source| SyncError::Transaction { txid, source })?;
        full_transactions.push((txid, height, parsed));
    }

    scan(&mut transactions, &full_transactions, keys, network)?;

    let block = blocks.last().expect("apply_blocks is called with blocks");
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
        .apply(cursor, &transactions)
        .map_err(|source| SyncError::Account { source })?;

    Ok(cursor)
}