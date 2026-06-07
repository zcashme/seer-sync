
use std::collections::{HashMap, HashSet};

use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::memo::MemoBytes;

use crate::decrypt;
use crate::key::{encode_orchard_recipient, encode_sapling_recipient, OrchardIncoming, SaplingIncoming};
use crate::proto::{CompactBlock, CompactTx, RawTransaction};
use crate::ViewKey;

pub enum ShieldedNote {
    Sapling(sapling::Note),
    Orchard(orchard::Note),
}

/// Which shielded pool a note or spend belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pool {
    Sapling,
    Orchard,
}

pub struct Note {
    pub note: ShieldedNote,
    pub height: BlockHeight,
    pub txid: [u8; 32],
    pub tx_index: u32,
    pub output_index: u32,
    pub nullifier: Option<[u8; 32]>,
    pub memo: Option<MemoBytes>,
    pub is_sent: bool,
    /// Destination of a sent output, as a unified address (`u1…`). `Some` only
    /// when `is_sent`; recovered alongside the note via the OVK.
    pub recipient: Option<String>,
}

impl Note {
    /// The pool this note belongs to.
    pub fn pool(&self) -> Pool {
        match self.note {
            ShieldedNote::Sapling(_) => Pool::Sapling,
            ShieldedNote::Orchard(_) => Pool::Orchard,
        }
    }
}

/// A nullifier revealed by a block, identifying the note it spends. We keep the
/// `txid` so a spend of one of our notes can flag its transaction for sent-output
/// recovery, and the `height` so the spend can be recorded against the note.
#[derive(Debug, Clone)]
pub struct Spend {
    pub txid: [u8; 32],
    pub nf: [u8; 32],
    pub pool: Pool,
    pub height: BlockHeight,
}

/// What a compact-block scan yields: the incoming notes detected, plus every
/// spend nullifier seen (used to recognize spends of our own notes). `spends` is
/// empty for a key that cannot derive nullifiers (a UIVK).
pub struct CompactScan {
    pub notes: Vec<Note>,
    pub spends: Vec<Spend>,
}

pub(crate) fn enrich_memos(
    keys: &ViewKey,
    network: &Network,
    raw_txs: &[([u8; 32], RawTransaction)],
    mut notes: Vec<Note>,
) -> Vec<Note> {
    let sapling = &keys.sapling;
    let orchard = &keys.orchard;

    for (txid, raw) in raw_txs {
        let height = BlockHeight::from_u32(raw.height as u32);
        let tx = match Transaction::read(&raw.data[..], BranchId::for_height(network, height)) {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        for note in notes.iter_mut().filter(|n| &n.txid == txid && n.memo.is_none()) {
            let is_sapling = matches!(note.note, ShieldedNote::Sapling(_));
            let output_index = note.output_index as usize;
            let note_height = note.height;

            if is_sapling {
                if let Some(bundle) = tx.sapling_bundle() {
                    if let Some(output) = bundle.shielded_outputs().get(output_index) {
                        let zip212 = zip212_enforcement(network, note_height);
                        for s in sapling {
                            if let Some((.., memo)) =
                                decrypt::try_decrypt_sapling(output, &s.ivk, zip212)
                            {
                                note.memo = Some(memo);
                                break;
                            }
                        }
                    }
                }
            } else if let Some(bundle) = tx.orchard_bundle() {
                if let Some(action) = bundle.actions().get(output_index) {
                    for o in orchard {
                        if let Some((.., memo)) = decrypt::try_decrypt_orchard(action, &o.ivk) {
                            note.memo = Some(memo);
                            break;
                        }
                    }
                }
            }
        }
    }
    notes
}

pub fn scan_compact(blocks: &[CompactBlock], keys: &ViewKey) -> CompactScan {
    let sapling = keys.sapling.as_slice();
    let orchard = keys.orchard.as_slice();
    let collect_spends = keys.can_derive_nullifiers();

    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads <= 1 || blocks.len() < 64 {
        return scan_compact_serial(blocks, sapling, orchard, collect_spends);
    }

    let chunk = blocks.len().div_ceil(threads);
    std::thread::scope(|s| {
        let handles: Vec<_> = blocks
            .chunks(chunk)
            .map(|c| s.spawn(move || scan_compact_serial(c, sapling, orchard, collect_spends)))
            .collect();
        let mut merged = CompactScan { notes: Vec::new(), spends: Vec::new() };
        for h in handles {
            let part = h.join().expect("scan thread panicked");
            merged.notes.extend(part.notes);
            merged.spends.extend(part.spends);
        }
        merged
    })
}

fn scan_compact_serial(
    blocks: &[CompactBlock],
    sapling: &[SaplingIncoming],
    orchard: &[OrchardIncoming],
    collect_spends: bool,
) -> CompactScan {
    let mut out = Vec::new();
    let mut spends = Vec::new();

    for block in blocks {
        let height = BlockHeight::from_u32(block.height as u32);

        // Every nullifier the block reveals, so a spend of one of our notes can
        // be recognized later by matching against the notes we've recorded.
        if collect_spends {
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                for spend in &tx.spends {
                    if let Ok(nf) = spend.nf[..].try_into() {
                        spends.push(Spend { txid, nf, pool: Pool::Sapling, height });
                    }
                }
                for act in &tx.actions {
                    if let Ok(nf) = act.nullifier[..].try_into() {
                        spends.push(Spend { txid, nf, pool: Pool::Orchard, height });
                    }
                }
            }
        }

        if !sapling.is_empty() {
            let block_start = block.chain_metadata.as_ref().map(|m| {
                let after = m.sapling_commitment_tree_size as u64;
                let in_block: u64 = block.vtx.iter().map(|tx| tx.outputs.len() as u64).sum();
                after.saturating_sub(in_block)
            });

            let mut descs = Vec::new();
            let mut meta: Vec<([u8; 32], u32, u32, Option<u64>)> = Vec::new();
            let mut leaf = 0u64;
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                let tx_index = tx.index as u32;
                for (oi, output) in tx.outputs.iter().enumerate() {
                    let pos = block_start.map(|s| s + leaf);
                    leaf += 1;
                    if let Some(desc) = decrypt::parse_sapling(output) {
                        descs.push(desc);
                        meta.push((txid, tx_index, oi as u32, pos));
                    }
                }
            }

            for scope in sapling {
                for (i, hit) in
                    decrypt::try_compact_sapling(&scope.ivk, descs.clone()).into_iter().enumerate()
                {
                    if let Some((note, _recipient)) = hit {
                        let (txid, tx_index, output_index, position) = meta[i];
                        let nullifier = match (scope.nk.as_ref(), position) {
                            (Some(nk), Some(pos)) => Some(note.nf(nk, pos).0),
                            _ => None,
                        };
                        out.push(Note {
                            note: ShieldedNote::Sapling(note),
                            height,
                            txid,
                            tx_index,
                            output_index,
                            nullifier,
                            memo: None,
                            is_sent: false,
                            recipient: None,
                        });
                    }
                }
            }
        }

        if !orchard.is_empty() {
            let mut actions = Vec::new();
            let mut meta: Vec<([u8; 32], u32, u32)> = Vec::new();
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                let tx_index = tx.index as u32;
                for (ai, act) in tx.actions.iter().enumerate() {
                    if let Some(action) = decrypt::parse_orchard(act) {
                        actions.push(action);
                        meta.push((txid, tx_index, ai as u32));
                    }
                }
            }

            for scope in orchard {
                for (i, hit) in
                    decrypt::try_compact_orchard(&scope.ivk, actions.clone()).into_iter().enumerate()
                {
                    if let Some((note, _recipient)) = hit {
                        let (txid, tx_index, output_index) = meta[i];
                        let nullifier =
                            scope.fvk.as_ref().map(|fvk| note.nullifier(fvk).to_bytes());
                        out.push(Note {
                            note: ShieldedNote::Orchard(note),
                            height,
                            txid,
                            tx_index,
                            output_index,
                            nullifier,
                            memo: None,
                            is_sent: false,
                            recipient: None,
                        });
                    }
                }
            }
        }
    }

    CompactScan { notes: out, spends }
}

/// Recovers, via the OVK, the outputs *you* sent in `raw_txs`, skipping any
/// output already detected as incoming (`claimed_notes`). `tx_index` maps each
/// txid to its position in the block so a recovered note records its real index.
///
/// Returns the sent notes; the caller appends them to the incoming ones.
pub fn scan_sent(
    keys: &ViewKey,
    network: &Network,
    raw_txs: &[([u8; 32], RawTransaction)],
    claimed_notes: &[Note],
    tx_index: &HashMap<[u8; 32], u32>,
) -> Vec<Note> {
    let sapling_ovks = &keys.sapling_ovks;
    let orchard_ovks = &keys.orchard_ovks;

    let claimed: HashSet<(Pool, [u8; 32], u32)> =
        claimed_notes.iter().map(|n| (n.pool(), n.txid, n.output_index)).collect();

    let mut out = Vec::new();

    for (txid, raw) in raw_txs {
        let height = BlockHeight::from_u32(raw.height as u32);
        let tx = match Transaction::read(&raw.data[..], BranchId::for_height(network, height)) {
            Ok(tx) => tx,
            Err(_) => continue,
        };
        let index = tx_index.get(txid).copied().unwrap_or(0);

        if let Some(bundle) = tx.sapling_bundle() {
            let zip212 = zip212_enforcement(network, height);
            for (oi, output) in bundle.shielded_outputs().iter().enumerate() {
                if claimed.contains(&(Pool::Sapling, *txid, oi as u32)) {
                    continue;
                }
                for ovk in sapling_ovks {
                    if let Some((note, recipient, memo)) =
                        decrypt::try_decrypt_sapling_sent(output, ovk, zip212)
                    {
                        out.push(Note {
                            note: ShieldedNote::Sapling(note),
                            height,
                            txid: *txid,
                            tx_index: index,
                            output_index: oi as u32,
                            nullifier: None,
                            memo: Some(memo),
                            is_sent: true,
                            recipient: encode_sapling_recipient(network, recipient),
                        });
                        break;
                    }
                }
            }
        }

        if let Some(bundle) = tx.orchard_bundle() {
            for (ai, action) in bundle.actions().iter().enumerate() {
                if claimed.contains(&(Pool::Orchard, *txid, ai as u32)) {
                    continue;
                }
                for ovk in orchard_ovks {
                    if let Some((note, recipient, memo)) =
                        decrypt::try_decrypt_orchard_sent(action, ovk)
                    {
                        out.push(Note {
                            note: ShieldedNote::Orchard(note),
                            height,
                            txid: *txid,
                            tx_index: index,
                            output_index: ai as u32,
                            nullifier: None,
                            memo: Some(memo),
                            is_sent: true,
                            recipient: encode_orchard_recipient(network, recipient),
                        });
                        break;
                    }
                }
            }
        }
    }

    out
}

fn txid_of(tx: &CompactTx) -> Option<[u8; 32]> {
    tx.txid[..].try_into().ok()
}
