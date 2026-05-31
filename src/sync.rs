//! High-level sync orchestration — pipelines async download with rayon decrypt.
//!
//! The fundamental challenge in chain sync is that the two bottlenecks —
//! **network I/O** (fetching compact blocks) and **CPU** (trial decryption) —
//! are otherwise sequential.  This module overlaps them:
//!
//! ```text
//!  time ──────────────────────────────────────────────────────────────▶
//!
//!  tokio   [  fetch batch 1  ]  [  fetch batch 2  ]  [  fetch batch 3  ]
//!  rayon                        [  decrypt batch 1  ]  [  decrypt batch 2  ]
//! ```
//!
//! # Architecture
//!
//! 1. A tokio task streams compact blocks from lightwalletd and groups them
//!    into memory-adaptive batches using [`crate::chain::adaptive_chunk_size`].
//! 2. Batches are sent over a [`tokio::sync::mpsc::channel`] with **capacity 1**.
//!    This single-slot buffer means the downloader can be at most one batch
//!    ahead — providing natural backpressure and bounding peak RAM to
//!    ≤ 2 × batch size.
//! 3. The main task receives each batch and runs trial-decrypt via
//!    [`tokio::task::spawn_blocking`], which hands the work to rayon without
//!    blocking the tokio executor, so the downloader continues prefetching
//!    the next batch concurrently.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::chain::{adaptive_chunk_size, fetch_blocks_chunked, LwdClient};
use crate::keys::IvkKeys;
use crate::proto::CompactBlock;
use crate::scan::{scan_ivk, IncomingNoteView};

// ─── IVK streaming scan ───────────────────────────────────────────────────────

/// Scan blocks `[from, to]` with an incoming-only key, pipelining download
/// and decrypt.
///
/// The returned `Vec` contains all notes received by the key in that range.
/// Keys are wrapped in [`Arc`] so the caller can retain a reference while
/// the scanning task borrows it concurrently.
///
/// # Memory
///
/// Peak memory is approximately `2 × adaptive_chunk_size() × BYTES_PER_OUTPUT`,
/// regardless of the total range size.
pub async fn stream_scan_ivk(
    mut client: LwdClient,
    keys: Arc<IvkKeys>,
    from: u32,
    to: u32,
) -> Result<Vec<IncomingNoteView>> {
    let chunk_size = adaptive_chunk_size();
    // Capacity 1: downloader can be exactly one batch ahead of the decryptor.
    let (batch_tx, mut batch_rx) = mpsc::channel::<Vec<CompactBlock>>(1);

    let downloader = tokio::spawn(async move {
        let chunks = fetch_blocks_chunked(&mut client, from, to, chunk_size).await?;
        for chunk in chunks {
            if batch_tx.send(chunk).await.is_err() {
                break; // consumer dropped
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut notes: Vec<IncomingNoteView> = Vec::new();

    while let Some(batch) = batch_rx.recv().await {
        let k = Arc::clone(&keys);
        // spawn_blocking hands work to the blocking thread pool; the tokio
        // executor remains free to drive the downloader task concurrently.
        let batch_notes = tokio::task::spawn_blocking(move || {
            scan_ivk(&batch, &k).into_iter().collect::<Vec<_>>()
        })
        .await?;
        notes.extend(batch_notes);
    }

    downloader.await??;
    Ok(notes)
}

// ─── FVK streaming scan ───────────────────────────────────────────────────────

/// Aggregated output of a [`stream_scan_fvk`] call.
pub struct StreamFvkResult {
    /// All scan events (incoming notes + spend detections) across the range.
    pub events: Vec<crate::scan::ScanEvent>,
    /// Final Sapling leaf count after the last block.
    pub sapling_leaf_count: u64,
    /// All transparent outputs encountered (caller filters by script).
    pub transparent_received: Vec<crate::scan::TransparentReceived>,
    /// All transparent inputs (potential spends of watched UTXOs).
    pub transparent_spends: Vec<crate::scan::TransparentSpend>,
}

/// Scan blocks `[from, to]` with full viewing keys, pipelining download and
/// decrypt.
///
/// `sapling_start_pos` must equal the Sapling tree leaf count before `from`.
/// Derive it from [`crate::tree::TreeSize`] or your persisted [`crate::db`]
/// sync cursor.
///
/// `known_nullifiers` is the set of nullifiers previously seen as wallet
/// outputs — any match in a compact spend triggers a [`crate::scan::ScanEvent::Spent`].
pub async fn stream_scan_fvk(
    mut client: LwdClient,
    keys: Arc<crate::keys::FvkKeys>,
    from: u32,
    to: u32,
    sapling_start_pos: u64,
    known_nullifiers: Arc<std::collections::HashSet<[u8; 32]>>,
) -> Result<StreamFvkResult> {
    let chunk_size = adaptive_chunk_size();
    let (batch_tx, mut batch_rx) = mpsc::channel::<Vec<CompactBlock>>(1);

    let downloader = tokio::spawn(async move {
        let chunks = fetch_blocks_chunked(&mut client, from, to, chunk_size).await?;
        for chunk in chunks {
            if batch_tx.send(chunk).await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut all_events = Vec::new();
    let mut all_transparent_received = Vec::new();
    let mut all_transparent_spends = Vec::new();
    let mut leaf_count = sapling_start_pos;

    while let Some(batch) = batch_rx.recv().await {
        let k = Arc::clone(&keys);
        let nf = Arc::clone(&known_nullifiers);
        let start_pos = leaf_count;

        let result = tokio::task::spawn_blocking(move || {
            crate::scan::scan_fvk(&batch, &k, start_pos, &nf)
        })
        .await?;

        leaf_count = result.sapling_leaf_count;
        all_events.extend(result.events);
        all_transparent_received.extend(result.transparent_received);
        all_transparent_spends.extend(result.transparent_spends);
    }

    downloader.await??;

    Ok(StreamFvkResult {
        events: all_events,
        sapling_leaf_count: leaf_count,
        transparent_received: all_transparent_received,
        transparent_spends: all_transparent_spends,
    })
}
