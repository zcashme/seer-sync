use std::collections::{HashMap, HashSet};

use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::TxId;

use crate::decrypt;
use crate::key::{
    encode_orchard_recipient, encode_sapling_recipient, OrchardIncoming, SaplingIncoming,
};
use crate::proto::{CompactBlock, CompactTx, RawTransaction};
use crate::ViewKey;

pub enum ShieldedNote {
    Sapling(sapling::Note),
    Orchard(orchard::Note),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pool {
    Sapling,
    Orchard,
}

pub struct Note {
    pub note: ShieldedNote,
    pub height: BlockHeight,
    pub txid: TxId,
    pub tx_index: u32,
    pub output_index: u32,
    pub nullifier: Option<[u8; 32]>,
    pub memo: Option<MemoBytes>,
    pub is_sent: bool,
    pub recipient: Option<String>,
}

impl Note {
    pub fn pool(&self) -> Pool {
        match self.note {
            ShieldedNote::Sapling(_) => Pool::Sapling,
            ShieldedNote::Orchard(_) => Pool::Orchard,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Spend {
    pub txid: TxId,
    pub nf: [u8; 32],
    pub pool: Pool,
    pub height: BlockHeight,
}

pub struct CompactScan {
    pub notes: Vec<Note>,
    pub spends: Vec<Spend>,
}

/// An Orchard note commitment as it appears on chain, with its absolute leaf
/// position in the note-commitment tree.
///
/// `cmx` is public data — surfacing it needs no viewing key. Consumers building
/// note-commitment-tree witnesses (e.g. to prove a note's inclusion) ingest
/// these via [`scan_commitments`]; ordinary view-key sync ignores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    /// Absolute leaf position in the Orchard note-commitment tree.
    pub position: u64,
    /// The `cmx` (x-coordinate of the output note's commitment).
    pub cmx: [u8; 32],
}

/// Parse fetched raw transactions once; both phase-2 passes (memo enrichment
/// and sent recovery) consume the parsed list. Unparseable transactions are
/// dropped, matching the per-pass skip they got before.
pub(crate) fn parse_transactions(
    network: &Network,
    raw_txs: &[(TxId, RawTransaction)],
) -> Vec<(TxId, BlockHeight, Transaction)> {
    raw_txs
        .iter()
        .filter_map(|(txid, raw)| {
            let height = BlockHeight::from_u32(raw.height as u32);
            Transaction::read(&raw.data[..], BranchId::for_height(network, height))
                .ok()
                .map(|tx| (*txid, height, tx))
        })
        .collect()
}

pub(crate) fn enrich_memos(
    keys: &ViewKey,
    network: &Network,
    txs: &[(TxId, BlockHeight, Transaction)],
    mut notes: Vec<Note>,
) -> Vec<Note> {
    let sapling = &keys.sapling;
    let orchard = &keys.orchard;

    for (txid, _, tx) in txs {
        for note in notes
            .iter_mut()
            .filter(|n| &n.txid == txid && n.memo.is_none())
        {
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
        let mut merged = CompactScan {
            notes: Vec::new(),
            spends: Vec::new(),
        };
        for h in handles {
            let part = h.join().expect("scan thread panicked");
            merged.notes.extend(part.notes);
            merged.spends.extend(part.spends);
        }
        merged
    })
}

/// Extract every Orchard note commitment in `blocks`, in tree order, each tagged
/// with its absolute leaf position.
///
/// Independent of any viewing key — this is the public commitment firehose used
/// to build note-commitment-tree witnesses. A leaf's position is derived from
/// the block's `orchardCommitmentTreeSize` metadata (the tree size as of the end
/// of the block) minus the actions in that block. Blocks missing that metadata
/// are skipped — pre-NU5 blocks carry no Orchard actions, so there is nothing to
/// position.
pub fn scan_commitments(blocks: &[CompactBlock]) -> Vec<Commitment> {
    let mut out = Vec::new();
    for block in blocks {
        let Some(meta) = block.chain_metadata.as_ref() else {
            continue;
        };
        let in_block: u64 = block.vtx.iter().map(|tx| tx.actions.len() as u64).sum();
        let Some(mut pos) = (meta.orchard_commitment_tree_size as u64).checked_sub(in_block) else {
            continue;
        };
        for tx in &block.vtx {
            for act in &tx.actions {
                if let Ok(cmx) = act.cmx[..].try_into() {
                    out.push(Commitment { position: pos, cmx });
                }
                // Every Orchard action appends exactly one leaf; advance the
                // position even on the (unreachable) malformed-cmx case so later
                // leaves stay correctly aligned.
                pos += 1;
            }
        }
    }
    out
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

        if collect_spends {
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                for spend in &tx.spends {
                    if let Ok(nf) = spend.nf[..].try_into() {
                        spends.push(Spend {
                            txid,
                            nf,
                            pool: Pool::Sapling,
                            height,
                        });
                    }
                }
                for act in &tx.actions {
                    if let Ok(nf) = act.nullifier[..].try_into() {
                        spends.push(Spend {
                            txid,
                            nf,
                            pool: Pool::Orchard,
                            height,
                        });
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
            let mut meta: Vec<(TxId, u32, u32, Option<u64>)> = Vec::new();
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

            let ivks: Vec<_> = sapling.iter().map(|s| s.ivk.clone()).collect();
            for (i, hit) in decrypt::try_compact_sapling(&ivks, descs)
                .into_iter()
                .enumerate()
            {
                if let Some((note, _recipient, scope)) = hit {
                    let (txid, tx_index, output_index, position) = meta[i];
                    let nullifier = match (sapling[scope].nk.as_ref(), position) {
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

        if !orchard.is_empty() {
            let mut actions = Vec::new();
            let mut meta: Vec<(TxId, u32, u32)> = Vec::new();
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

            let ivks: Vec<_> = orchard.iter().map(|o| o.ivk.clone()).collect();
            for (i, hit) in decrypt::try_compact_orchard(&ivks, actions)
                .into_iter()
                .enumerate()
            {
                if let Some((note, _recipient, scope)) = hit {
                    let (txid, tx_index, output_index) = meta[i];
                    let nullifier = orchard[scope]
                        .fvk
                        .as_ref()
                        .map(|fvk| note.nullifier(fvk).to_bytes());
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

    CompactScan { notes: out, spends }
}

pub(crate) fn scan_sent(
    keys: &ViewKey,
    network: &Network,
    txs: &[(TxId, BlockHeight, Transaction)],
    claimed_notes: &[Note],
    tx_index: &HashMap<TxId, u32>,
) -> Vec<Note> {
    let sapling_ovks = &keys.sapling_ovks;
    let orchard_ovks = &keys.orchard_ovks;

    let claimed: HashSet<(Pool, TxId, u32)> = claimed_notes
        .iter()
        .map(|n| (n.pool(), n.txid, n.output_index))
        .collect();

    let mut out = Vec::new();

    for (txid, height, tx) in txs {
        let height = *height;
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

fn txid_of(tx: &CompactTx) -> Option<TxId> {
    tx.txid[..].try_into().ok().map(TxId::from_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ChainMetadata, CompactOrchardAction};

    fn action(cmx_byte: u8) -> CompactOrchardAction {
        CompactOrchardAction {
            cmx: vec![cmx_byte; 32],
            ..Default::default()
        }
    }

    #[test]
    fn scan_commitments_positions_from_tree_size() {
        // Tree size 5 at end of block, 3 actions across two txs → first leaf at 2.
        let block = CompactBlock {
            height: 100,
            chain_metadata: Some(ChainMetadata {
                orchard_commitment_tree_size: 5,
                ..Default::default()
            }),
            vtx: vec![
                CompactTx {
                    actions: vec![action(0xaa), action(0xbb)],
                    ..Default::default()
                },
                CompactTx {
                    actions: vec![action(0xcc)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let got = scan_commitments(&[block]);
        assert_eq!(
            got.iter()
                .map(|c| (c.position, c.cmx[0]))
                .collect::<Vec<_>>(),
            vec![(2, 0xaa), (3, 0xbb), (4, 0xcc)],
        );
    }

    #[test]
    fn scan_commitments_skips_blocks_without_metadata() {
        let block = CompactBlock {
            height: 50,
            chain_metadata: None,
            vtx: vec![CompactTx {
                actions: vec![action(0x11)],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(scan_commitments(&[block]).is_empty());
    }
}
