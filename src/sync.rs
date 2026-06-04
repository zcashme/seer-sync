
pub mod chain;
pub mod scan;

use crate::sync::chain::{DEFAULT_CHUNK_OUTPUTS, LwdClient};
use crate::sync::scan::{enrich_memos, scan_compact, Note};
use crate::BlockHeight;
use anyhow::Context;
use crate::UnifiedFullViewingKey;
use futures::StreamExt;
use zcash_protocol::consensus::Network;

const MAX_TRANSPORT_RETRIES: usize = 4;

pub async fn run<R, W, F>(
    client: LwdClient,
    keys: &UnifiedFullViewingKey,
    network: &Network,
    mut resume_point: R,
    mut rewind: W,
    mut sink: F,
) -> anyhow::Result<()>
where
    R: FnMut() -> (BlockHeight, Option<[u8; 32]>),
    W: FnMut(BlockHeight) -> anyhow::Result<()>,
    F: FnMut(BlockHeight, [u8; 32], &[Note]) -> anyhow::Result<()>,
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

                    let mut notes = scan_compact(&batch, keys);
                    let mut txids: Vec<[u8; 32]> = notes.iter().map(|n| n.txid).collect();
                    txids.sort_unstable();
                    txids.dedup();
                    let mut raw_txs = Vec::with_capacity(txids.len());
                    for txid in txids {
                        let raw = chain::fetch_raw_transaction(&mut fetch_client, &txid)
                            .await
                            .context("fetching transaction for memo")?;
                        raw_txs.push((txid, raw));
                    }
                    enrich_memos(keys, network, &raw_txs, &mut notes)
                        .context("enriching memos")?;
                    sink(height, hash, &notes)?;

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
