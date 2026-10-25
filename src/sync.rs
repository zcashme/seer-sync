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
/// below an applied one is final.
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
    /// `to` is a block the account applied (or one below its birthday), at or
    /// below the current checkpoint.
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
    let mut rewind_by = 1;

    // Hashes of the last applied blocks, oldest first: the chain a rewind lands on.
    let mut recent_hashes: Vec<(BlockHeight, BlockHash)> =
        Vec::with_capacity(MAX_REORG_DEPTH as usize);

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
            let prev_hash = BlockHash(
                block
                    .prev_hash
                    .as_slice()
                    .try_into()
                    .expect("lightwalletd block hashes are 32 bytes"),
            );

            if let Some(at) = client.detect_reorg(prior, prev_hash) {
                // Unapplied blocks are only a download cache; the account's
                // checkpoint is the one record of what is scanned. Undo applied
                // blocks only when the fork reaches them, then start over from
                // the checkpoint.
                let checkpoint = account
                    .resume()
                    .map_err(|source| SyncError::Account { source })?
                    .checkpoint;
                if checkpoint.is_some_and(|cursor| at <= cursor.height) {
                    let to =
                        rewind_target(&mut client, &recent_hashes, at, rewind_by, birthday).await?;
                    account
                        .rewind(to)
                        .map_err(|source| SyncError::Account { source })?;
                    recent_hashes.retain(|(height, _)| *height <= to.height);
                    rewind_by = rewind_by.saturating_mul(2);
                }
                continue 'outer;
            }

            prior = Some((block_height(&block), block_hash(&block)));

            let block_output_count = block_output_count(&block);

            if !blocks.is_empty()
                && (blocks.len() == BLOCKS_PER_BATCH
                    || output_count + block_output_count > OUTPUTS_PER_BATCH)
            {
                process_batch(
                    &mut fetch_client,
                    keys,
                    params,
                    account,
                    &mut nullifiers,
                    &blocks,
                )
                .await?;
                remember(&mut recent_hashes, &blocks);
                rewind_by = 1;
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
            remember(&mut recent_hashes, &blocks);
            rewind_by = 1;
        }

        continue 'outer;
    }
}

/// The block to rewind to: `rewind_by` below `at`, on the chain the account
/// applied.
async fn rewind_target(
    client: &mut LwdClient,
    recent_hashes: &[(BlockHeight, BlockHash)],
    at: BlockHeight,
    rewind_by: u32,
    birthday: BlockHeight,
) -> Result<Cursor, RpcError> {
    let height = at.saturating_sub(rewind_by);
    if let Some(&(height, hash)) = recent_hashes.iter().find(|(h, _)| *h == height) {
        return Ok(Cursor { height, hash });
    }
    // The applied hash is unknown (e.g. just after a restart), so the server's
    // hash must stand in. That is only safe below any possible fork: past the
    // deepest reorg, or below the birthday where nothing was applied.
    let height = at
        .saturating_sub(MAX_REORG_DEPTH)
        .max(birthday.saturating_sub(1));
    let hash = client.block_hash(height).await?;
    Ok(Cursor { height, hash })
}

fn remember(
    recent_hashes: &mut Vec<(BlockHeight, BlockHash)>,
    blocks: &[crate::proto::CompactBlock],
) {
    recent_hashes.extend(
        blocks
            .iter()
            .map(|block| (block_height(block), block_hash(block))),
    );
    let excess = recent_hashes.len().saturating_sub(MAX_REORG_DEPTH as usize);
    recent_hashes.drain(..excess);
}

fn block_height(block: &crate::proto::CompactBlock) -> BlockHeight {
    BlockHeight::from_u32(
        u32::try_from(block.height)
            .expect("lightwalletd block heights fit Zcash's block-height type"),
    )
}

fn block_hash(block: &crate::proto::CompactBlock) -> BlockHash {
    BlockHash(
        block
            .hash
            .as_slice()
            .try_into()
            .expect("lightwalletd block hashes are 32 bytes"),
    )
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::codegen::BoxStream;
    use tonic::{Request, Response, Status};
    use zcash_protocol::consensus::Network;

    use super::*;
    use crate::db::Db;
    use crate::proto::server::compact_tx_streamer_server::{
        CompactTxStreamer, CompactTxStreamerServer,
    };
    use crate::proto::server::{BlockId, BlockRange, ChainSpec, CompactBlock};

    const OLD: u8 = 1;
    const NEW: u8 = 2;

    /// Chains `OLD` and `NEW` share every block below `fork`; byte 4 of a
    /// hash names the chain (0 when shared).
    fn hash(height: u32, fork: u32, chain: u8) -> Vec<u8> {
        let mut hash = vec![0; 32];
        hash[..4].copy_from_slice(&height.to_le_bytes());
        hash[4] = if height < fork { 0 } else { chain };
        hash
    }

    /// A block as the assertions compare it: height and chain byte.
    fn seen(height: u32, hash: &[u8]) -> (u32, u8) {
        assert_eq!(
            hash[..4],
            height.to_le_bytes(),
            "hash belongs to its height"
        );
        (height, hash[4])
    }

    fn block(height: u32, fork: u32, chain: u8) -> CompactBlock {
        CompactBlock {
            height: height.into(),
            hash: hash(height, fork, chain),
            prev_hash: hash(height - 1, fork, chain),
            ..Default::default()
        }
    }

    /// Mock lightwalletd serving `chain`. Each `GetBlockRange` call first takes
    /// the next scripted reply, which can switch chains mid-stream.
    struct Lightwalletd {
        tip: u32,
        fork: u32,
        chain: u8,
        script: Mutex<Vec<Vec<CompactBlock>>>,
    }

    impl Lightwalletd {
        fn new(tip: u32, fork: u32, chain: u8, script: Vec<Vec<CompactBlock>>) -> Self {
            Self {
                tip,
                fork,
                chain,
                script: Mutex::new(script),
            }
        }
    }

    #[tonic::async_trait]
    impl CompactTxStreamer for Lightwalletd {
        async fn get_latest_block(
            &self,
            _: Request<ChainSpec>,
        ) -> Result<Response<BlockId>, Status> {
            Ok(Response::new(BlockId {
                height: self.tip.into(),
                hash: hash(self.tip, self.fork, self.chain),
            }))
        }

        async fn get_block(
            &self,
            request: Request<BlockId>,
        ) -> Result<Response<CompactBlock>, Status> {
            let height = request.into_inner().height as u32;
            Ok(Response::new(block(height, self.fork, self.chain)))
        }

        async fn get_block_range(
            &self,
            request: Request<BlockRange>,
        ) -> Result<Response<BoxStream<CompactBlock>>, Status> {
            let range = request.into_inner();
            let scripted = {
                let mut script = self.script.lock().unwrap();
                (!script.is_empty()).then(|| script.remove(0))
            };
            let blocks = scripted.unwrap_or_else(|| {
                let from = range.start.unwrap().height as u32;
                let to = range.end.unwrap().height as u32;
                (from..=to)
                    .map(|height| block(height, self.fork, self.chain))
                    .collect()
            });
            Ok(Response::new(Box::pin(tokio_stream::iter(
                blocks.into_iter().map(Ok),
            ))))
        }
    }

    /// The reference `Db`, plus every block handed to the account and every
    /// rewind. `resume` fails once the checkpoint reaches `stop_at`, which is
    /// how a test ends `run`.
    struct Recorder {
        db: Db,
        stop_at: AtomicU32,
        scanned: Mutex<Vec<(u32, u8)>>,
        rewinds: Mutex<Vec<(u32, u8)>>,
    }

    impl Recorder {
        fn new(birthday: u32) -> Self {
            let db = Db::open_memory().unwrap();
            db.init_account(BlockHeight::from_u32(birthday)).unwrap();
            Self {
                db,
                stop_at: AtomicU32::new(0),
                scanned: Mutex::new(Vec::new()),
                rewinds: Mutex::new(Vec::new()),
            }
        }

        fn checkpoint(&self) -> (u32, u8) {
            let cursor = self.db.resume().unwrap().checkpoint.unwrap();
            seen(u32::from(cursor.height), &cursor.hash.0)
        }

        fn take_scanned(&self) -> Vec<(u32, u8)> {
            std::mem::take(&mut self.scanned.lock().unwrap())
        }

        fn rewinds(&self) -> Vec<(u32, u8)> {
            self.rewinds.lock().unwrap().clone()
        }
    }

    impl Account for Recorder {
        fn resume(&self) -> Result<Resume, Box<dyn Error + Send + Sync>> {
            let resume = self.db.resume()?;
            let stop_at = self.stop_at.load(Ordering::SeqCst);
            if resume
                .checkpoint
                .is_some_and(|cursor| u32::from(cursor.height) >= stop_at)
            {
                return Err("synced to the test tip".into());
            }
            Ok(resume)
        }

        fn rewind(&self, to: Cursor) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.rewinds
                .lock()
                .unwrap()
                .push(seen(u32::from(to.height), &to.hash.0));
            self.db.rewind(to)
        }

        fn apply_transactions(
            &self,
            at: Cursor,
            transactions: &[WalletTx],
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.db.apply_transactions(at, transactions)
        }

        fn apply_blocks(
            &self,
            _: Cursor,
            blocks: &[crate::proto::CompactBlock],
            _: &[(TxId, BlockHeight, Transaction)],
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.scanned.lock().unwrap().extend(
                blocks
                    .iter()
                    .map(|block| seen(block.height as u32, &block.hash)),
            );
            Ok(())
        }
    }

    /// Runs the engine against `lwd` until `account` has applied `lwd.tip`.
    async fn sync_to_tip(lwd: Lightwalletd, account: &Recorder) {
        account.stop_at.store(lwd.tip, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(CompactTxStreamerServer::new(lwd))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let client = LwdClient::connect(url.leak()).await.unwrap();
        let keys = ScanningKeys {
            sapling: Vec::new(),
            orchard: Vec::new(),
        };

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            run(client, &keys, &Network::MainNetwork, account),
        )
        .await
        .expect("run reaches the tip");
        match result {
            Err(SyncError::Account { source })
                if source.to_string() == "synced to the test tip" => {}
            other => panic!("run ended early: {other:?}"),
        }
    }

    fn chain(heights: impl IntoIterator<Item = u32>, fork: u32, chain: u8) -> Vec<(u32, u8)> {
        heights
            .into_iter()
            .map(|height| seen(height, &hash(height, fork, chain)))
            .collect()
    }

    #[tokio::test]
    async fn batch_boundary_is_not_a_reorg() {
        let account = Recorder::new(100);

        sync_to_tip(Lightwalletd::new(1200, 1200, NEW, Vec::new()), &account).await;

        assert_eq!(account.take_scanned(), chain(100..=1200, 1200, NEW));
        assert!(account.rewinds().is_empty());
    }

    #[tokio::test]
    async fn reorg_above_the_checkpoint_needs_no_rewind() {
        // The server switches chains mid-stream: OLD up to 110, then NEW 111.
        let switched = (100..=110)
            .map(|height| block(height, 109, OLD))
            .chain([block(111, 109, NEW)])
            .collect();
        let account = Recorder::new(100);

        sync_to_tip(Lightwalletd::new(120, 109, NEW, vec![switched]), &account).await;

        assert_eq!(account.take_scanned(), chain(100..=120, 109, NEW));
        assert!(account.rewinds().is_empty(), "nothing was applied yet");
        assert_eq!(account.checkpoint(), (120, NEW));
    }

    #[tokio::test]
    async fn reorg_at_the_checkpoint_walks_back_to_the_fork() {
        // The first stream ends at OLD 110 and is applied; the next one is NEW.
        let old = (100..=110).map(|height| block(height, 109, OLD)).collect();
        let account = Recorder::new(100);

        sync_to_tip(Lightwalletd::new(120, 109, NEW, vec![old]), &account).await;

        // 109 is still on OLD, so the seam fails again; 107 is shared.
        assert_eq!(account.rewinds(), vec![(109, OLD), (107, 0)]);
        assert_eq!(
            account.take_scanned(),
            [chain(100..=110, 109, OLD), chain(108..=120, 109, NEW)].concat()
        );
        assert_eq!(account.checkpoint(), (120, NEW));
    }

    #[tokio::test]
    async fn reorg_after_a_restart_drops_below_the_reorg_limit() {
        let account = Recorder::new(1);
        sync_to_tip(Lightwalletd::new(110, 109, OLD, Vec::new()), &account).await;
        assert_eq!(account.take_scanned(), chain(1..=110, 109, OLD));

        // A new `run` has no applied hashes, so it trusts the server's hash
        // only MAX_REORG_DEPTH below the checkpoint.
        sync_to_tip(Lightwalletd::new(120, 109, NEW, Vec::new()), &account).await;

        assert_eq!(account.rewinds(), vec![(10, 0)]);
        assert_eq!(account.take_scanned(), chain(11..=120, 109, NEW));
        assert_eq!(account.checkpoint(), (120, NEW));
    }
}
