pub mod chain;
pub mod scan;

use crate::sync::chain::{ChainError, DEFAULT_CHUNK_OUTPUTS, LwdClient};
use crate::sync::scan::{enrich_memos, scan_compact, scan_sent, CompactScan, Note, Pool, Spend};
use crate::BlockHeight;
use crate::ViewKey;
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use zcash_protocol::consensus::Network;

const MAX_TRANSPORT_RETRIES: usize = 4;

pub type AccountError = Box<dyn std::error::Error + Send + Sync>;

#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Key(#[from] crate::key::KeyError),
    #[error("wallet: {0}")]
    Account(#[source] AccountError),
}

pub struct Cursor {
    pub height: BlockHeight,
    pub hash: Option<[u8; 32]>,
}

pub trait Account {
    fn checkpoint(&self) -> Option<Cursor>;
    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError>;
    fn owns_nf(&self, pool: Pool, nf: &[u8; 32]) -> Result<bool, AccountError>;
    fn apply(&self, at: Cursor, notes: &[Note], spends: &[Spend]) -> Result<(), AccountError>;
}

pub async fn run<A: Account>(
    client: LwdClient,
    keys: &ViewKey,
    network: &Network,
    birthday: u32,
    account: &A,
) -> Result<(), SyncError> {
    let mut fetch_client = client.clone();
    let tip = BlockHeight::from_u32(chain::tip_height(&mut fetch_client).await?);

    let mut rewind_by: u32 = 1;
    let mut transport_attempts: usize = 0;

    loop {
        let (start, seam) = match account.checkpoint() {
            Some(c) => (BlockHeight::from_u32(u32::from(c.height) + 1), c.hash),
            None => (BlockHeight::from_u32(birthday), None),
        };
        if start > tip {
            return Ok(());
        }
        let mut stream =
            chain::blocks(client.clone(), u32::from(start), u32::from(tip), DEFAULT_CHUNK_OUTPUTS, seam);

        loop {
            let Some(item) = stream.next().await else {
                return Ok(());
            };
            match item {
                Ok(batch) => {
                    let Some(last) = batch.last() else { continue };
                    let height = BlockHeight::from_u32(last.height as u32);
                    let hash: [u8; 32] = last.hash[..].try_into().unwrap_or([0u8; 32]);

                    let CompactScan { notes: incoming, spends } = scan_compact(&batch, keys);

                    let batch_nfs: HashSet<(Pool, [u8; 32])> = incoming
                        .iter()
                        .filter_map(|n| n.nullifier.map(|nf| (n.pool(), nf)))
                        .collect();
                    let mut owned_spends = Vec::new();
                    for s in &spends {
                        let mine = batch_nfs.contains(&(s.pool, s.nf))
                            || account.owns_nf(s.pool, &s.nf).map_err(SyncError::Account)?;
                        if mine {
                            owned_spends.push(s.clone());
                        }
                    }

                    let mut txids: Vec<[u8; 32]> = incoming
                        .iter()
                        .map(|n| n.txid)
                        .chain(owned_spends.iter().map(|s| s.txid))
                        .collect();
                    txids.sort_unstable();
                    txids.dedup();
                    let mut raw_txs = Vec::with_capacity(txids.len());
                    for txid in txids {
                        let raw = chain::fetch_raw_transaction(&mut fetch_client, &txid).await?;
                        raw_txs.push((txid, raw));
                    }

                    let tx_index: HashMap<[u8; 32], u32> = batch
                        .iter()
                        .flat_map(|b| b.vtx.iter())
                        .filter_map(|tx| {
                            tx.txid[..].try_into().ok().map(|id: [u8; 32]| (id, tx.index as u32))
                        })
                        .collect();

                    let incoming = enrich_memos(keys, network, &raw_txs, incoming);
                    let sent = scan_sent(keys, network, &raw_txs, &incoming, &tx_index);
                    let notes: Vec<Note> = incoming.into_iter().chain(sent).collect();
                    account
                        .apply(Cursor { height, hash: Some(hash) }, &notes, &owned_spends)
                        .map_err(SyncError::Account)?;

                    transport_attempts = 0;
                    rewind_by = 1;
                }
                Err(ChainError::Reorg(at)) => {
                    account
                        .rewind(BlockHeight::from_u32(at.saturating_sub(rewind_by)))
                        .map_err(SyncError::Account)?;
                    rewind_by = rewind_by.saturating_mul(2);
                    break;
                }
                Err(e) => {
                    if transport_attempts < MAX_TRANSPORT_RETRIES {
                        transport_attempts += 1;
                        break;
                    }
                    return Err(SyncError::Chain(e));
                }
            }
        }
    }
}
