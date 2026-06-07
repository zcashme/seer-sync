
pub mod chain;
pub mod scan;

use crate::sync::chain::{DEFAULT_CHUNK_OUTPUTS, LwdClient};
use crate::sync::scan::{enrich_memos, scan_compact, scan_sent, CompactScan, Note, Pool, Spend};
use crate::BlockHeight;
use crate::ViewKey;
use anyhow::Context;
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use zcash_protocol::consensus::Network;

const MAX_TRANSPORT_RETRIES: usize = 4;

/// Drives a linear sync over `client`.
///
/// The four closures are the engine's only contact with the outside world:
/// * `resume_point` — where to (re)start, and the seam hash to check for reorgs.
/// * `rewind` — undo state down to a height after a reorg.
/// * `owns_nf` — does a note with this nullifier belong to us? Answered against
///   the caller's store, so a spend of a note received in an earlier batch is
///   still recognized. Spends seen within the current batch are matched locally.
/// * `sink` — persist a batch: the notes found and the spends of our own notes.
pub async fn run<R, W, O, F>(
    client: LwdClient,
    keys: &ViewKey,
    network: &Network,
    mut resume_point: R,
    mut rewind: W,
    mut owns_nf: O,
    mut sink: F,
) -> anyhow::Result<()>
where
    R: FnMut() -> (BlockHeight, Option<[u8; 32]>),
    W: FnMut(BlockHeight) -> anyhow::Result<()>,
    O: FnMut(Pool, &[u8; 32]) -> anyhow::Result<bool>,
    F: FnMut(BlockHeight, [u8; 32], &[Note], &[Spend]) -> anyhow::Result<()>,
{
    let mut fetch_client = client.clone();
    let tip = BlockHeight::from_u32(chain::tip_height(&mut fetch_client).await.context("tip height")?);

    let mut rewind_by: u32 = 1;
    let mut transport_attempts: usize = 0;

    loop {
        let (start, seam) = resume_point();
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

                    // Recognize spends of our own notes: match each revealed
                    // nullifier against this batch's incoming notes, then against
                    // the caller's store for notes received in earlier batches.
                    let batch_nfs: HashSet<(Pool, [u8; 32])> = incoming
                        .iter()
                        .filter_map(|n| n.nullifier.map(|nf| (n.pool(), nf)))
                        .collect();
                    let mut owned_spends = Vec::new();
                    for s in &spends {
                        let mine = batch_nfs.contains(&(s.pool, s.nf))
                            || owns_nf(s.pool, &s.nf).context("checking nullifier ownership")?;
                        if mine {
                            owned_spends.push(s.clone());
                        }
                    }

                    // Fetch full transactions for every tx that touches us — one
                    // that pays us (an incoming note) or one that spends our notes
                    // (the latter catches a send that returns no change).
                    let mut txids: Vec<[u8; 32]> = incoming
                        .iter()
                        .map(|n| n.txid)
                        .chain(owned_spends.iter().map(|s| s.txid))
                        .collect();
                    txids.sort_unstable();
                    txids.dedup();
                    let mut raw_txs = Vec::with_capacity(txids.len());
                    for txid in txids {
                        let raw = chain::fetch_raw_transaction(&mut fetch_client, &txid)
                            .await
                            .context("fetching transaction for memo")?;
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
                    sink(height, hash, &notes, &owned_spends)?;

                    transport_attempts = 0;
                    rewind_by = 1;
                }
                Err(e) if e.downcast_ref::<chain::Reorg>().is_some() => {
                    let chain::Reorg(at) = e.downcast::<chain::Reorg>().expect("downcast checked");
                    rewind(BlockHeight::from_u32(at.saturating_sub(rewind_by)))?;
                    rewind_by = rewind_by.saturating_mul(2);
                    break;
                }
                Err(e) => {
                    if transport_attempts < MAX_TRANSPORT_RETRIES {
                        transport_attempts += 1;
                        break;
                    }
                    return Err(e).context("streaming blocks");
                }
            }
        }
    }
}
