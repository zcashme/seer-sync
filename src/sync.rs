
pub mod chain;
pub mod scan;

use crate::keys::ScanningKeys;
use crate::sync::chain::{DEFAULT_CHUNK_OUTPUTS, LwdClient};
use crate::sync::scan::{scan, Transactions};
use crate::BlockHeight;
use anyhow::Context;
use futures::StreamExt;
use zcash_protocol::consensus::Network;

const MAX_TRANSPORT_RETRIES: usize = 4;

pub async fn run<R, W, F>(
    client: LwdClient,
    keys: &ScanningKeys,
    network: &Network,
    mut resume_point: R,
    mut rewind: W,
    mut sink: F,
) -> anyhow::Result<()>
where
    R: FnMut() -> (BlockHeight, Option<[u8; 32]>),
    W: FnMut(BlockHeight) -> anyhow::Result<()>,
    F: FnMut(BlockHeight, [u8; 32], &Transactions) -> anyhow::Result<()>,
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

                    let txs = scan(&mut fetch_client, &batch, keys, network)
                        .await
                        .context("scanning chunk")?;
                    sink(height, hash, &txs)?;

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
