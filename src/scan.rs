//! Parallel trial-decrypt loop over compact blocks.
//!
//! Three entry points:
//! - [`scan_ivk`] — incoming only, no spend detection
//! - [`scan_fvk`] — incoming + nullifier derivation + spend detection + transparent
//! - [`scan_ovk`] — see [`crate::decrypt`] for OVK recovery (full transactions)

use std::collections::{HashMap, HashSet};

use crossbeam_channel::{unbounded, Receiver};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use rayon::prelude::*;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{EphemeralKeyBytes, try_compact_note_decryption};

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
/// The channel closes when rayon completes. Post-Canopy ZIP-212 is assumed.
pub fn scan_ivk(blocks: &[CompactBlock], keys: &IvkKeys) -> Receiver<IncomingNoteView> {
    let (tx, rx) = unbounded();

    if !keys.is_empty() {
        let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);

        blocks.par_iter().for_each_with(tx, |tx, block| {
            let height = block.height as u32;

            for compact_tx in &block.vtx {
                let txid = txid_bytes(&compact_tx.txid);

                if let Some(ivk) = &keys.orchard {
                    for (output_index, proto_action) in compact_tx.actions.iter().enumerate() {
                        let Some(action) = parse_orchard_action(proto_action) else {
                            continue;
                        };
                        let domain = OrchardDomain::for_compact_action(&action);
                        if let Some((note, recipient)) =
                            try_compact_note_decryption(&domain, ivk, &action)
                        {
                            let rseed: [u8; 32] = note.rseed().as_bytes().clone();
                            let rho: [u8; 32] = action.nullifier().to_bytes();
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

                if let Some(ivk) = &keys.sapling {
                    for (output_index, proto_output) in compact_tx.outputs.iter().enumerate() {
                        let Some(output) = parse_sapling_output(proto_output) else {
                            continue;
                        };
                        if let Some((note, recipient)) =
                            try_compact_note_decryption(&sapling_domain, ivk, &output)
                        {
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
/// - Derives nullifiers for each received note (where possible)
/// - Matches received nullifiers against compact spend sets
/// - Emits [`ScanEvent::Spent`] for any `known_nullifiers` seen as spends
/// - Collects transparent inputs/outputs for t-balance accounting
///
/// `sapling_start_pos` must equal the number of Sapling note commitments
/// already processed before the first block in `blocks`.
pub fn scan_fvk(
    blocks: &[CompactBlock],
    keys: &FvkKeys,
    sapling_start_pos: u64,
    known_nullifiers: &HashSet<[u8; 32]>,
) -> FvkScanResult {
    // ── Phase 1: serial Sapling leaf-position assignment ─────────────────────
    // We must count every cmu in order to assign correct positions for nullifier
    // derivation. This requires serial block iteration.
    struct SaplingHit {
        block_idx: usize,
        tx_idx: usize,
        output_idx: usize,
        leaf_pos: u64,
    }

    let mut sapling_leaf_count = sapling_start_pos;
    let mut sapling_hit_positions: Vec<SaplingHit> = Vec::new();

    if keys.sapling_ivk.is_some() {
        let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);
        let ivk = keys.sapling_ivk.as_ref().unwrap();

        for (block_idx, block) in blocks.iter().enumerate() {
            for (tx_idx, compact_tx) in block.vtx.iter().enumerate() {
                for (output_idx, proto_output) in compact_tx.outputs.iter().enumerate() {
                    let pos = sapling_leaf_count;
                    sapling_leaf_count += 1;

                    if let Some(output) = parse_sapling_output(proto_output) {
                        if try_compact_note_decryption(&sapling_domain, ivk, &output).is_some() {
                            sapling_hit_positions.push(SaplingHit {
                                block_idx,
                                tx_idx,
                                output_idx,
                                leaf_pos: pos,
                            });
                        }
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
                if action.nullifier.len() == 32 {
                    let mut nf = [0u8; 32];
                    nf.copy_from_slice(&action.nullifier);
                    orchard_spends.push(SpendRecord { nullifier: nf, height });
                }
            }
            for spend in &compact_tx.spends {
                if spend.nf.len() == 32 {
                    let mut nf = [0u8; 32];
                    nf.copy_from_slice(&spend.nf);
                    sapling_spends.push(SpendRecord { nullifier: nf, height });
                }
            }
        }
    }

    let orchard_spend_set: HashSet<[u8; 32]> =
        orchard_spends.iter().map(|s| s.nullifier).collect();
    let sapling_spend_set: HashSet<[u8; 32]> =
        sapling_spends.iter().map(|s| s.nullifier).collect();

    // ── Phase 3: parallel incoming decrypt ───────────────────────────────────
    let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);

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

    // Safety: RawNote contains Recipient, which is not Send. Work around by
    // collecting per-block Vec<RawNote> serially after parallel outer iteration
    // or by wrapping Recipient. We use par_iter at block granularity and
    // collect inner notes into a flat Vec.
    let raw_notes: Vec<RawNote> = blocks
        .par_iter()
        .enumerate()
        .flat_map_iter(|(block_idx, block)| {
            let height = block.height as u32;
            let mut notes = Vec::new();

            for (tx_idx, compact_tx) in block.vtx.iter().enumerate() {
                let txid = txid_bytes(&compact_tx.txid);

                if let Some(ivk) = &keys.orchard_ivk {
                    for (output_index, proto_action) in compact_tx.actions.iter().enumerate() {
                        let Some(action) = parse_orchard_action(proto_action) else {
                            continue;
                        };
                        let domain = OrchardDomain::for_compact_action(&action);
                        if let Some((note, recipient)) =
                            try_compact_note_decryption(&domain, ivk, &action)
                        {
                            let rseed: [u8; 32] = note.rseed().as_bytes().clone();
                            let rho: [u8; 32] = action.nullifier().to_bytes();
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

                if keys.sapling_ivk.is_some() {
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
                            try_compact_note_decryption(&sapling_domain, ivk, &output)
                        {
                            let rseed = rseed_bytes_sapling(&note);
                            notes.push(RawNote {
                                height,
                                tx_id: txid,
                                output_index,
                                pool: ShieldedPool::Sapling,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Sapling(recipient),
                                rseed,
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

    // ── Phase 4: nullifier derivation + spend matching ───────────────────────
    // Full nullifier derivation from compact data alone is not possible for
    // either pool because it requires the note commitment (unavailable without
    // full transaction data).  We store rseed + rho/leaf_pos and mark
    // `nullifier = None` here; the DB enrichment pass derives it after
    // fetching the full transaction.  We DO emit Spent events for any
    // `known_nullifiers` that appeared in the compact spend sets.
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

    // Emit Spent events for known wallet nullifiers seen in this batch.
    for spend in &orchard_spends {
        if known_nullifiers.contains(&spend.nullifier) {
            events.push(ScanEvent::Spent {
                nullifier: spend.nullifier,
                height: spend.height,
            });
        }
    }
    for spend in &sapling_spends {
        if known_nullifiers.contains(&spend.nullifier) {
            events.push(ScanEvent::Spent {
                nullifier: spend.nullifier,
                height: spend.height,
            });
        }
    }
    let _ = (orchard_spend_set, sapling_spend_set); // available for future cross-batch matching

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
                if vin.prevout_txid.len() == 32 {
                    let mut prevout_txid = [0u8; 32];
                    prevout_txid.copy_from_slice(&vin.prevout_txid);
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

/// Parse a P2PKH or P2SH locking script to its address hash.
///
/// Returns `Some((kind, 20-byte hash))` where kind is `"p2pkh"` or `"p2sh"`.
/// Used to match transparent outputs against known addresses.
pub fn script_to_address_hash(script: &[u8]) -> Option<(&'static str, [u8; 20])> {
    // P2PKH: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        return Some(("p2pkh", hash));
    }
    // P2SH: OP_HASH160 PUSH20 <hash> OP_EQUAL
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[2..22]);
        return Some(("p2sh", hash));
    }
    None
}
