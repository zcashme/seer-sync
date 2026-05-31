//! Streaming scan — overlap block download with rayon trial-decrypt.
//!
//! These consume *any* stream of compact-block batches and know nothing about
//! where the blocks come from. Pair them with [`crate::chain::blocks`], a file
//! fixture, or a mock. Each received batch is handed to rayon via
//! [`tokio::task::spawn_blocking`], so the executor stays free to drive the
//! producer concurrently:
//!
//! ```text
//!  producer  [ batch 1 ]  [ batch 2 ]  [ batch 3 ]
//!  rayon                  [ scan 1  ]  [ scan 2  ]
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use futures::{Stream, StreamExt};

use crate::keys::{FvkKeys, IvkKeys};
use crate::proto::CompactBlock;

use super::types::{IncomingNoteView, ScanEvent, TransparentReceived, TransparentSpend};
use super::{scan_fvk, scan_ivk};

/// Scan a stream of block batches with an incoming-only key.
///
/// Returns every note received by `keys` across the stream. Any `Err` batch
/// (e.g. a reorg or transport failure from the producer) aborts the scan.
pub async fn scan_stream_ivk(
    keys: Arc<IvkKeys>,
    stream: impl Stream<Item = Result<Vec<CompactBlock>>>,
) -> Result<Vec<IncomingNoteView>> {
    futures::pin_mut!(stream);
    let mut notes = Vec::new();

    while let Some(batch) = stream.next().await {
        let batch = batch?;
        let k = Arc::clone(&keys);
        let batch_notes =
            tokio::task::spawn_blocking(move || scan_ivk(&batch, &k).into_iter().collect::<Vec<_>>())
                .await?;
        notes.extend(batch_notes);
    }

    Ok(notes)
}

/// Aggregated output of [`scan_stream_fvk`].
pub struct StreamFvkResult {
    /// All scan events (incoming notes + spend detections) across the stream.
    pub events: Vec<ScanEvent>,
    /// Final Sapling leaf count after the last block.
    pub sapling_leaf_count: u64,
    /// All transparent outputs encountered (caller filters by script).
    pub transparent_received: Vec<TransparentReceived>,
    /// All transparent inputs (potential spends of watched UTXOs).
    pub transparent_spends: Vec<TransparentSpend>,
}

/// Scan a stream of block batches with full viewing keys.
///
/// `sapling_start_pos` must equal the Sapling tree leaf count before the first
/// block. The counter is threaded across batches so positions stay correct.
/// `known_nullifiers` are matched against compact spends to emit
/// [`ScanEvent::Spent`].
pub async fn scan_stream_fvk(
    keys: Arc<FvkKeys>,
    stream: impl Stream<Item = Result<Vec<CompactBlock>>>,
    sapling_start_pos: u64,
    known_nullifiers: Arc<HashSet<[u8; 32]>>,
) -> Result<StreamFvkResult> {
    futures::pin_mut!(stream);

    let mut events = Vec::new();
    let mut transparent_received = Vec::new();
    let mut transparent_spends = Vec::new();
    let mut leaf_count = sapling_start_pos;

    while let Some(batch) = stream.next().await {
        let batch = batch?;
        let k = Arc::clone(&keys);
        let nf = Arc::clone(&known_nullifiers);
        let start_pos = leaf_count;

        let result =
            tokio::task::spawn_blocking(move || scan_fvk(&batch, &k, start_pos, &nf)).await?;

        leaf_count = result.sapling_leaf_count;
        events.extend(result.events);
        transparent_received.extend(result.transparent_received);
        transparent_spends.extend(result.transparent_spends);
    }

    Ok(StreamFvkResult {
        events,
        sapling_leaf_count: leaf_count,
        transparent_received,
        transparent_spends,
    })
}
