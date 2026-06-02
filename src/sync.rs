//! Syncing: keep current with the chain.
//!
//! Two things, by feature:
//!
//! - [`scan`] (core, sans-IO) is the pure decryptor — `&[CompactBlock] + keys →
//!   Transactions`. No network, no loop. *"What in these blocks is mine?"*
//! - the rest (`lwd`) is the live process: [`chain`] fetches compact blocks from
//!   lightwalletd, [`enrich`] recovers their memos, and [`run`] is the loop that
//!   ties them to [`scan`] and keeps a consumer current. *"Stay synced."*
//!
//! [`run`] is persistence-free: the consumer supplies three closures over its
//! own store — `resume_point` (where to start + the seam hash), `rewind` (drop
//! state above a height), and `sink` (apply a chunk) — and `run` drives the
//! sweep, handling transport faults and reorgs inline. The engine reads no
//! consumer state and exposes no outcome to match: it returns when synced.

pub mod scan;

#[cfg(feature = "lwd")]
pub mod chain;
#[cfg(feature = "lwd")]
pub mod enrich;

/// Transient transport failures to absorb (reconnect + resume) before giving up.
#[cfg(feature = "lwd")]
const MAX_TRANSPORT_RETRIES: usize = 4;

/// Sync a consumer forward to the chain tip.
///
/// `resume_point` reports `(start, seam)` from the consumer's persisted cursor
/// (the seam is the hash of the block before `start`, for continuity across the
/// resume boundary; `None` on a cold start). `sink` applies one chunk — given
/// the chunk's last height (the new scanned watermark), that block's hash (the
/// seam to record), and the [`scan::Transactions`] found (usually empty, but
/// still applied so the cursor advances). `rewind` drops everything above a
/// height when a reorg is detected.
///
/// Both faults are handled inline: a dropped stream reconnects and resumes from
/// the consumer's cursor; a reorg calls `rewind` with a doubling walk-back
/// (1, 2, 4, … blocks until the seam reconnects) and re-resumes. Returns once
/// the tip is reached.
#[cfg(feature = "lwd")]
pub async fn run<R, W, F>(
    client: crate::sync::chain::LwdClient,
    keys: &crate::keys::ScanningKeys,
    network: &zcash_protocol::consensus::Network,
    mut resume_point: R,
    mut rewind: W,
    mut sink: F,
) -> anyhow::Result<()>
where
    R: FnMut() -> (crate::BlockHeight, Option<[u8; 32]>),
    W: FnMut(crate::BlockHeight) -> anyhow::Result<()>,
    F: FnMut(crate::BlockHeight, [u8; 32], &crate::sync::scan::Transactions) -> anyhow::Result<()>,
{
    use crate::sync::chain::{self, DEFAULT_CHUNK_OUTPUTS};
    use crate::sync::enrich::enrich_memos;
    use crate::sync::scan::scan;
    use anyhow::Context;
    use futures::StreamExt;

    // A cheap clone sharing the gRPC channel, for fetching full transactions
    // (memo enrichment) while the block stream owns its own client.
    let mut fetch_client = client.clone();
    let tip = chain::tip_height(&mut fetch_client).await.context("tip height")?;

    let mut rewind_by: u32 = 1;
    let mut transport_attempts: usize = 0;

    // Outer loop: (re-)resume from the consumer's cursor. Re-entered after a
    // reorg rewind or a transport reconnect.
    loop {
        let (start, seam) = resume_point();
        if start > tip {
            return Ok(());
        }
        let mut stream = chain::blocks(client.clone(), start, tip, DEFAULT_CHUNK_OUTPUTS, seam);

        // Inner loop: consume chunks until the stream ends, a reorg, or a fault.
        loop {
            let Some(item) = stream.next().await else {
                // Stream drained cleanly — reached the tip.
                return Ok(());
            };
            match item {
                Ok(batch) => {
                    let Some(last) = batch.last() else { continue };
                    let height = last.height as crate::BlockHeight;
                    let hash: [u8; 32] = last.hash[..].try_into().unwrap_or([0u8; 32]);

                    let mut txs = scan(&batch, keys);
                    enrich_memos(&mut fetch_client, keys, network, &mut txs).await;
                    sink(height, hash, &txs)?;

                    // Forward progress clears both backoffs.
                    transport_attempts = 0;
                    rewind_by = 1;
                }
                // Reorg: only the consumer can rewind its store. Walk back and
                // re-resume; double the step until the seam reconnects.
                Err(e) if e.downcast_ref::<chain::Reorg>().is_some() => {
                    let chain::Reorg(at) = e.downcast::<chain::Reorg>().expect("downcast checked");
                    rewind(at.saturating_sub(rewind_by))?;
                    rewind_by = rewind_by.saturating_mul(2);
                    break;
                }
                // Transport fault: reconnect and resume from the consumer's
                // cursor (which reflects the last applied chunk).
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
