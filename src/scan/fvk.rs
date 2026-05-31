//! FVK path — incoming + spend detection + transparent balance.

use std::collections::{HashMap, HashSet};

use rayon::prelude::*;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::batch;

use crate::keys::FvkKeys;
use crate::proto::CompactBlock;

use super::parsers::{
    decrypt_orchard_block, parse_sapling_output, rseed_bytes_sapling, txid_bytes,
};
use super::types::{
    FvkScanResult, IncomingNoteView, Recipient, ScanEvent, ShieldedPool, TransparentReceived,
    TransparentSpend,
};

/// Trial-decrypt `blocks` using Full Viewing Keys.
///
/// In addition to incoming note detection, this path:
/// - Tracks all Sapling note commitments to maintain the leaf-position counter
/// - Matches received nullifiers against compact spend sets
/// - Emits [`ScanEvent::Spent`] for any `known_nullifiers` seen as spends
/// - Collects transparent inputs/outputs for t-balance accounting
///
/// `sapling_start_pos` must equal the number of Sapling note commitments
/// already processed before the first block in `blocks`. Use
/// [`crate::tree::TreeSize`] to derive this value from block metadata.
pub fn scan_fvk(
    blocks: &[CompactBlock],
    keys: &FvkKeys,
    sapling_start_pos: u64,
    known_nullifiers: &HashSet<[u8; 32]>,
) -> FvkScanResult {
    let orchard_ivk_slice = keys.orchard_ivk.as_ref().map_or(&[][..], std::slice::from_ref);
    let sapling_ivk_slice = keys.sapling_ivk.as_ref().map_or(&[][..], std::slice::from_ref);

    // ── Phase 1: serial Sapling leaf-position assignment ─────────────────────
    // Every cmu must be counted in order; within each block all outputs are
    // batched together so the key-agreement setup is paid once per block.
    struct SaplingHit {
        block_idx: usize,
        tx_idx: usize,
        output_idx: usize,
        leaf_pos: u64,
    }

    let mut sapling_leaf_count = sapling_start_pos;
    let mut sapling_hit_positions: Vec<SaplingHit> = Vec::new();

    if !sapling_ivk_slice.is_empty() {
        for (block_idx, block) in blocks.iter().enumerate() {
            let mut entries: Vec<(usize, usize, u64, CompactOutputDescription)> = Vec::new();

            for (tx_idx, compact_tx) in block.vtx.iter().enumerate() {
                let tx_start = sapling_leaf_count;
                sapling_leaf_count += compact_tx.outputs.len() as u64;

                for (out_idx, proto) in compact_tx.outputs.iter().enumerate() {
                    if let Some(output) = parse_sapling_output(proto) {
                        entries.push((tx_idx, out_idx, tx_start + out_idx as u64, output));
                    }
                }
            }

            let batch_inputs: Vec<(SaplingDomain, CompactOutputDescription)> = entries
                .iter()
                .map(|(_, _, _, o)| (SaplingDomain::new(Zip212Enforcement::On), o.clone()))
                .collect();

            for (i, result) in
                batch::try_compact_note_decryption(sapling_ivk_slice, &batch_inputs)
                    .into_iter()
                    .enumerate()
            {
                if result.is_some() {
                    let (tx_idx, output_idx, leaf_pos, _) = entries[i];
                    sapling_hit_positions.push(SaplingHit {
                        block_idx,
                        tx_idx,
                        output_idx,
                        leaf_pos,
                    });
                }
            }
        }
    }

    let sapling_hits: HashMap<(usize, usize, usize), u64> = sapling_hit_positions
        .iter()
        .map(|h| ((h.block_idx, h.tx_idx, h.output_idx), h.leaf_pos))
        .collect();

    // ── Phase 2: collect all compact spend nullifiers ─────────────────────────
    struct SpendRecord {
        nullifier: [u8; 32],
        height: u32,
    }
    let mut orchard_spends: Vec<SpendRecord> = Vec::new();
    let mut sapling_spends: Vec<SpendRecord> = Vec::new();

    for block in blocks {
        let height = block.height as u32;
        for compact_tx in &block.vtx {
            for action in &compact_tx.actions {
                if let Ok(nf) = action.nullifier.as_slice().try_into() {
                    orchard_spends.push(SpendRecord { nullifier: nf, height });
                }
            }
            for spend in &compact_tx.spends {
                if let Ok(nf) = spend.nf.as_slice().try_into() {
                    sapling_spends.push(SpendRecord { nullifier: nf, height });
                }
            }
        }
    }

    // ── Phase 3: parallel decrypt — one batch per pool per block ─────────────
    struct RawNote {
        height: u32,
        tx_id: [u8; 32],
        output_index: usize,
        pool: ShieldedPool,
        value_zat: u64,
        recipient: Recipient,
        rseed: [u8; 32],
        rho: Option<[u8; 32]>,
        sapling_leaf_pos: Option<u64>,
    }

    let raw_notes: Vec<RawNote> = blocks
        .par_iter()
        .enumerate()
        .flat_map_iter(|(block_idx, block)| {
            let height = block.height as u32;
            let mut notes = Vec::new();

            // Orchard: shared block-level batch helper (identical to IVK path).
            for (ti, ai, ca, note, recipient) in decrypt_orchard_block(block, orchard_ivk_slice) {
                notes.push(RawNote {
                    height,
                    tx_id: txid_bytes(&block.vtx[ti].txid),
                    output_index: ai,
                    pool: ShieldedPool::Orchard,
                    value_zat: note.value().inner(),
                    recipient: Recipient::Orchard(recipient),
                    rseed: note.rseed().as_bytes().clone(),
                    rho: Some(ca.nullifier().to_bytes()),
                    sapling_leaf_pos: None,
                });
            }

            // Sapling: batch re-decrypt only the Phase-1 hits for this block.
            if !sapling_ivk_slice.is_empty() {
                let hits = &sapling_hits;
                let hit_entries = block
                    .vtx
                    .iter()
                    .enumerate()
                    .flat_map(|(ti, ctxn)| {
                        ctxn.outputs.iter().enumerate().filter_map(move |(oi, proto)| {
                            let leaf_pos = hits.get(&(block_idx, ti, oi)).copied()?;
                            let output = parse_sapling_output(proto)?;
                            Some((ti, oi, leaf_pos, output))
                        })
                    })
                    .collect::<Vec<_>>();

                if !hit_entries.is_empty() {
                    let ivk = keys.sapling_ivk.as_ref().unwrap();
                    let batch_inputs = hit_entries
                        .iter()
                        .map(|(_, _, _, o)| (SaplingDomain::new(Zip212Enforcement::On), o.clone()))
                        .collect::<Vec<_>>();

                    for (i, result) in
                        batch::try_compact_note_decryption(std::slice::from_ref(ivk), &batch_inputs)
                            .into_iter()
                            .enumerate()
                    {
                        if let Some(((note, recipient), _)) = result {
                            let (ti, oi, leaf_pos, _) = &hit_entries[i];
                            notes.push(RawNote {
                                height,
                                tx_id: txid_bytes(&block.vtx[*ti].txid),
                                output_index: *oi,
                                pool: ShieldedPool::Sapling,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Sapling(recipient),
                                rseed: rseed_bytes_sapling(&note),
                                rho: None,
                                sapling_leaf_pos: Some(*leaf_pos),
                            });
                        }
                    }
                }
            }

            notes
        })
        .collect();

    // ── Phase 4: spend matching ───────────────────────────────────────────────
    let mut events: Vec<ScanEvent> = raw_notes
        .into_iter()
        .map(|raw| {
            ScanEvent::Incoming(IncomingNoteView {
                height: raw.height,
                tx_id: raw.tx_id,
                output_index: raw.output_index,
                pool: raw.pool,
                value_zat: raw.value_zat,
                recipient: raw.recipient,
                rseed: raw.rseed,
                rho: raw.rho,
                sapling_leaf_pos: raw.sapling_leaf_pos,
                nullifier: None,
            })
        })
        .collect();

    for spend in orchard_spends.iter().chain(sapling_spends.iter()) {
        if known_nullifiers.contains(&spend.nullifier) {
            events.push(ScanEvent::Spent { nullifier: spend.nullifier, height: spend.height });
        }
    }

    // ── Phase 5: transparent inputs/outputs ──────────────────────────────────
    let mut transparent_received: Vec<TransparentReceived> = Vec::new();
    let mut transparent_spends_out: Vec<TransparentSpend> = Vec::new();

    for block in blocks {
        let height = block.height as u32;
        for compact_tx in &block.vtx {
            let txid = txid_bytes(&compact_tx.txid);

            for (output_index, vout) in compact_tx.vout.iter().enumerate() {
                if vout.value > 0 {
                    transparent_received.push(TransparentReceived {
                        height,
                        tx_id: txid,
                        output_index: output_index as u32,
                        value_zat: vout.value,
                        script: vout.script_pub_key.clone(),
                    });
                }
            }

            for vin in &compact_tx.vin {
                if let Ok(prevout_txid) = vin.prevout_txid.as_slice().try_into() {
                    transparent_spends_out.push(TransparentSpend {
                        height,
                        tx_id: txid,
                        prevout_txid,
                        prevout_index: vin.prevout_index,
                    });
                }
            }
        }
    }

    FvkScanResult {
        events,
        sapling_leaf_count,
        transparent_received,
        transparent_spends: transparent_spends_out,
    }
}
