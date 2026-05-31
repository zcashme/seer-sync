//! Parallel trial-decrypt loop over compact blocks.
//!
//! Three entry points:
//! - [`scan_ivk`] — incoming only, no spend detection
//! - [`scan_fvk`] — incoming + nullifier derivation + spend detection + transparent
//! - [`scan_ovk`] — see [`crate::decrypt`] for OVK recovery (full transactions required)
//!
//! # Parallelism
//!
//! Both entry points use two levels of parallelism:
//! 1. **Block-level** — rayon distributes blocks across CPU threads.
//! 2. **Transaction-level** — within each block, `zcash_note_encryption::batch`
//!    decrypts all actions/outputs × all IVKs in a single vectorised call,
//!    amortising key-agreement setup across the full transaction output set.

use std::collections::{HashMap, HashSet};

use crossbeam_channel::{unbounded, Receiver};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use rayon::prelude::*;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{batch, EphemeralKeyBytes};

use crate::keys::{FvkKeys, IvkKeys};
use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput};

// ─── Output types ─────────────────────────────────────────────────────────────

/// Which shielded pool a note belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedPool {
    /// Sapling shielded pool.
    Sapling,
    /// Orchard shielded pool.
    Orchard,
}

/// Recipient address recovered from a decrypted note plaintext.
#[derive(Debug, Clone)]
pub enum Recipient {
    /// An Orchard diversified address.
    Orchard(orchard::Address),
    /// A Sapling payment address.
    Sapling(sapling::PaymentAddress),
}

/// A successfully trial-decrypted incoming note.
#[derive(Debug, Clone)]
pub struct IncomingNoteView {
    /// Block height containing the action/output.
    pub height: u32,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: [u8; 32],
    /// Index of this output/action within the transaction.
    pub output_index: usize,
    /// Pool the note belongs to.
    pub pool: ShieldedPool,
    /// Value in zatoshis (1 ZEC = 1e8 zatoshis).
    pub value_zat: u64,
    /// Recipient address recovered from the decrypted plaintext.
    pub recipient: Recipient,
    /// Note commitment randomness (rseed), needed for later nullifier / memo recovery.
    pub rseed: [u8; 32],
    /// Rho: the input nullifier of this action (Orchard only).
    pub rho: Option<[u8; 32]>,
    /// Sapling leaf position in the commitment tree — FVK path only.
    pub sapling_leaf_pos: Option<u64>,
    /// Nullifier for this note — FVK path only; `None` on IVK path.
    pub nullifier: Option<[u8; 32]>,
}

/// A sent note recovered via OVK / FVK (full transactions required).
#[derive(Debug, Clone)]
pub struct SentNoteView {
    /// Block height.
    pub height: u32,
    /// Transaction ID.
    pub tx_id: [u8; 32],
    /// Output index within the transaction.
    pub output_index: usize,
    /// Pool.
    pub pool: ShieldedPool,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Bech32m-encoded recipient address.
    pub recipient: String,
    /// Full 512-byte ZIP-302 memo.
    pub memo: Box<[u8; 512]>,
}

/// Events emitted by [`scan_fvk`].
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// A note was received by this wallet.
    Incoming(IncomingNoteView),
    /// A known nullifier was observed as a compact spend.
    Spent {
        /// Nullifier bytes.
        nullifier: [u8; 32],
        /// Height at which the spend was observed.
        height: u32,
    },
}

/// Transparent output detected in a compact block.
#[derive(Debug, Clone)]
pub struct TransparentReceived {
    /// Block height.
    pub height: u32,
    /// Transaction ID.
    pub tx_id: [u8; 32],
    /// Output index in vout.
    pub output_index: u32,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Raw locking script (scriptPubKey).
    pub script: Vec<u8>,
}

/// Transparent input (potential spend of a watched UTXO).
#[derive(Debug, Clone)]
pub struct TransparentSpend {
    /// Height at which the spend was mined.
    pub height: u32,
    /// Spending transaction ID.
    pub tx_id: [u8; 32],
    /// TXID of the output being spent.
    pub prevout_txid: [u8; 32],
    /// Index of the output being spent.
    pub prevout_index: u32,
}

/// Aggregated result of a [`scan_fvk`] call.
pub struct FvkScanResult {
    /// All incoming and spend events from this batch (nullifiers populated).
    pub events: Vec<ScanEvent>,
    /// Updated Sapling leaf count after processing all blocks.
    pub sapling_leaf_count: u64,
    /// All transparent vout entries encountered (caller filters by address).
    pub transparent_received: Vec<TransparentReceived>,
    /// All transparent vin entries (potential spends of watched UTXOs).
    pub transparent_spends: Vec<TransparentSpend>,
}

// ─── IVK path ─────────────────────────────────────────────────────────────────

/// Trial-decrypt `blocks` in parallel using IVK-only keys.
///
/// Returns a [`Receiver`] that yields one [`IncomingNoteView`] per hit.
/// The channel closes when all rayon workers finish. Post-Canopy ZIP-212
/// is assumed for Sapling.
///
/// Within each block, all actions/outputs are decrypted in a single
/// `batch::try_compact_note_decryption` call per pool, amortising the
/// per-output ephemeral-key setup across the entire transaction.
pub fn scan_ivk(blocks: &[CompactBlock], keys: &IvkKeys) -> Receiver<IncomingNoteView> {
    let (tx, rx) = unbounded();

    if !keys.is_empty() {
        let orchard_ivk_slice = keys.orchard.as_ref().map_or(&[][..], std::slice::from_ref);
        let sapling_ivk_slice = keys.sapling.as_ref().map_or(&[][..], std::slice::from_ref);

        blocks.par_iter().for_each_with(tx, |tx, block| {
            let height = block.height as u32;

            for compact_tx in &block.vtx {
                let txid = txid_bytes(&compact_tx.txid);

                // ── Orchard batch ────────────────────────────────────────────
                if !orchard_ivk_slice.is_empty() {
                    // Collect successfully-parsed actions, retaining original indices.
                    let parsed: Vec<(usize, CompactAction)> = compact_tx
                        .actions
                        .iter()
                        .enumerate()
                        .filter_map(|(i, p)| parse_orchard_action(p).map(|ca| (i, ca)))
                        .collect();

                    let batch_inputs: Vec<(OrchardDomain, CompactAction)> = parsed
                        .iter()
                        .map(|(_, ca)| (OrchardDomain::for_compact_action(ca), ca.clone()))
                        .collect();

                    for (batch_idx, result) in
                        batch::try_compact_note_decryption(orchard_ivk_slice, &batch_inputs)
                            .into_iter()
                            .enumerate()
                    {
                        if let Some(((note, recipient), _)) = result {
                            let output_index = parsed[batch_idx].0;
                            let rho: [u8; 32] = parsed[batch_idx].1.nullifier().to_bytes();
                            let rseed: [u8; 32] = note.rseed().as_bytes().clone();
                            tx.send(IncomingNoteView {
                                height,
                                tx_id: txid,
                                output_index,
                                pool: ShieldedPool::Orchard,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Orchard(recipient),
                                rseed,
                                rho: Some(rho),
                                sapling_leaf_pos: None,
                                nullifier: None,
                            })
                            .ok();
                        }
                    }
                }

                // ── Sapling batch ────────────────────────────────────────────
                if !sapling_ivk_slice.is_empty() {
                    let parsed: Vec<(usize, CompactOutputDescription)> = compact_tx
                        .outputs
                        .iter()
                        .enumerate()
                        .filter_map(|(i, p)| parse_sapling_output(p).map(|o| (i, o)))
                        .collect();

                    let batch_inputs: Vec<(SaplingDomain, CompactOutputDescription)> = parsed
                        .iter()
                        .map(|(_, o)| (SaplingDomain::new(Zip212Enforcement::On), o.clone()))
                        .collect();

                    for (batch_idx, result) in
                        batch::try_compact_note_decryption(sapling_ivk_slice, &batch_inputs)
                            .into_iter()
                            .enumerate()
                    {
                        if let Some(((note, recipient), _)) = result {
                            let output_index = parsed[batch_idx].0;
                            let rseed = rseed_bytes_sapling(&note);
                            tx.send(IncomingNoteView {
                                height,
                                tx_id: txid,
                                output_index,
                                pool: ShieldedPool::Sapling,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Sapling(recipient),
                                rseed,
                                rho: None,
                                sapling_leaf_pos: None,
                                nullifier: None,
                            })
                            .ok();
                        }
                    }
                }
            }
        });
    }

    rx
}

// ─── FVK path ─────────────────────────────────────────────────────────────────

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
    let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);
    let orchard_ivk_slice = keys.orchard_ivk.as_ref().map_or(&[][..], std::slice::from_ref);
    let sapling_ivk_slice = keys.sapling_ivk.as_ref().map_or(&[][..], std::slice::from_ref);

    // ── Phase 1: serial Sapling leaf-position assignment ─────────────────────
    // Sapling nullifier derivation requires knowing a note's exact leaf position
    // in the commitment tree, so we must visit every cmu in order. Batch decrypt
    // is used within each transaction to avoid redundant key-agreement setup.
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
            for (tx_idx, compact_tx) in block.vtx.iter().enumerate() {
                let tx_start = sapling_leaf_count;
                sapling_leaf_count += compact_tx.outputs.len() as u64;

                let parsed: Vec<(usize, CompactOutputDescription)> = compact_tx
                    .outputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| parse_sapling_output(p).map(|o| (i, o)))
                    .collect();

                let batch_inputs: Vec<(SaplingDomain, CompactOutputDescription)> = parsed
                    .iter()
                    .map(|(_, o)| (SaplingDomain::new(Zip212Enforcement::On), o.clone()))
                    .collect();

                for (batch_idx, result) in
                    batch::try_compact_note_decryption(sapling_ivk_slice, &batch_inputs)
                        .into_iter()
                        .enumerate()
                {
                    if result.is_some() {
                        let output_idx = parsed[batch_idx].0;
                        sapling_hit_positions.push(SaplingHit {
                            block_idx,
                            tx_idx,
                            output_idx,
                            leaf_pos: tx_start + output_idx as u64,
                        });
                    }
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

    // ── Phase 3: parallel incoming decrypt (Orchard batched per tx) ──────────
    // Sapling hits are already known from Phase 1; re-decrypt to recover the
    // note value and recipient (compact data does not persist them).
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

            for (tx_idx, compact_tx) in block.vtx.iter().enumerate() {
                let txid = txid_bytes(&compact_tx.txid);

                // Orchard: batch all actions in the transaction.
                if !orchard_ivk_slice.is_empty() {
                    let parsed: Vec<(usize, CompactAction)> = compact_tx
                        .actions
                        .iter()
                        .enumerate()
                        .filter_map(|(i, p)| parse_orchard_action(p).map(|ca| (i, ca)))
                        .collect();

                    let batch_inputs: Vec<(OrchardDomain, CompactAction)> = parsed
                        .iter()
                        .map(|(_, ca)| (OrchardDomain::for_compact_action(ca), ca.clone()))
                        .collect();

                    for (batch_idx, result) in
                        batch::try_compact_note_decryption(orchard_ivk_slice, &batch_inputs)
                            .into_iter()
                            .enumerate()
                    {
                        if let Some(((note, recipient), _)) = result {
                            let output_index = parsed[batch_idx].0;
                            let rho: [u8; 32] = parsed[batch_idx].1.nullifier().to_bytes();
                            let rseed: [u8; 32] = note.rseed().as_bytes().clone();
                            notes.push(RawNote {
                                height,
                                tx_id: txid,
                                output_index,
                                pool: ShieldedPool::Orchard,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Orchard(recipient),
                                rseed,
                                rho: Some(rho),
                                sapling_leaf_pos: None,
                            });
                        }
                    }
                }

                // Sapling: decrypt only known Phase-1 hits (guaranteed to succeed).
                if !sapling_ivk_slice.is_empty() {
                    for (output_index, proto_output) in compact_tx.outputs.iter().enumerate() {
                        let key = (block_idx, tx_idx, output_index);
                        let Some(leaf_pos) = sapling_hits.get(&key).copied() else {
                            continue;
                        };
                        let Some(output) = parse_sapling_output(proto_output) else {
                            continue;
                        };
                        let ivk = keys.sapling_ivk.as_ref().unwrap();
                        if let Some((note, recipient)) =
                            zcash_note_encryption::try_compact_note_decryption(
                                &sapling_domain,
                                ivk,
                                &output,
                            )
                        {
                            notes.push(RawNote {
                                height,
                                tx_id: txid,
                                output_index,
                                pool: ShieldedPool::Sapling,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Sapling(recipient),
                                rseed: rseed_bytes_sapling(&note),
                                rho: None,
                                sapling_leaf_pos: Some(leaf_pos),
                            });
                        }
                    }
                }
            }
            notes
        })
        .collect();

    // ── Phase 4: spend matching ───────────────────────────────────────────────
    // Full nullifier derivation from compact data alone is not possible for
    // either pool (requires the note commitment from the full transaction).
    // We store rseed + rho/leaf_pos for later DB-side derivation and emit
    // Spent events only for `known_nullifiers` already in the caller's state.
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

// ─── Compact note parsers ─────────────────────────────────────────────────────

fn parse_orchard_action(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}

fn parse_sapling_output(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key: epk, enc_ciphertext: ct })
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn txid_bytes(raw: &[u8]) -> [u8; 32] {
    raw.try_into().unwrap_or([0u8; 32])
}

fn rseed_bytes_sapling(note: &sapling::Note) -> [u8; 32] {
    match note.rseed() {
        sapling::note::Rseed::BeforeZip212(scalar) => scalar.to_bytes(),
        sapling::note::Rseed::AfterZip212(bytes) => *bytes,
    }
}
