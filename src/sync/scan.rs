
use anyhow::Result;
use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use sapling::keys::PreparedIncomingViewingKey as SaplingPreparedIvk;
use sapling::NullifierDerivingKey;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::memo::MemoBytes;
use zip32::Scope;

use crate::note::decrypt;
use crate::proto::{CompactBlock, CompactTx, RawTransaction};

pub enum ShieldedNote {
    Sapling(sapling::Note),
    Orchard(orchard::Note),
}

pub struct Note {
    pub note: ShieldedNote,
    pub height: BlockHeight,
    pub txid: [u8; 32],
    pub tx_index: u32,
    pub output_index: u32,
    pub nullifier: Option<[u8; 32]>,
    pub memo: Option<MemoBytes>,
}

pub fn enrich_memos(
    keys: &UnifiedFullViewingKey,
    network: &Network,
    raw_txs: &[([u8; 32], RawTransaction)],
    notes: &mut Vec<Note>,
) -> Result<()> {
    let sapling_ivks: Vec<SaplingPreparedIvk> =
        sapling_scopes(keys).into_iter().map(|s| s.ivk).collect();
    let orchard_ivks: Vec<OrchardPreparedIvk> =
        orchard_scopes(keys).into_iter().map(|s| s.ivk).collect();

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
                        for ivk in &sapling_ivks {
                            if let Some((.., memo)) = decrypt::try_decrypt_sapling(output, ivk, zip212) {
                                note.memo = Some(memo);
                                break;
                            }
                        }
                    }
                }
            } else if let Some(bundle) = tx.orchard_bundle() {
                if let Some(action) = bundle.actions().get(output_index) {
                    for ivk in &orchard_ivks {
                        if let Some((.., memo)) = decrypt::try_decrypt_orchard(action, ivk) {
                            note.memo = Some(memo);
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

struct SaplingScope {
    ivk: SaplingPreparedIvk,
    nk: NullifierDerivingKey,
}

struct OrchardScope {
    ivk: OrchardPreparedIvk,
}

fn sapling_scopes(keys: &UnifiedFullViewingKey) -> Vec<SaplingScope> {
    keys.sapling()
        .map(|dfvk| {
            [Scope::External, Scope::Internal]
                .into_iter()
                .map(|scope| SaplingScope {
                    ivk: SaplingPreparedIvk::new(&dfvk.to_ivk(scope)),
                    nk: dfvk.to_nk(scope),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn orchard_scopes(keys: &UnifiedFullViewingKey) -> Vec<OrchardScope> {
    keys.orchard()
        .map(|fvk| {
            [Scope::External, Scope::Internal]
                .into_iter()
                .map(|scope| OrchardScope {
                    ivk: OrchardPreparedIvk::new(&fvk.to_ivk(scope)),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn scan_compact(blocks: &[CompactBlock], keys: &UnifiedFullViewingKey) -> Vec<Note> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads <= 1 || blocks.len() < 64 {
        return scan_compact_serial(blocks, keys);
    }

    let chunk = blocks.len().div_ceil(threads);
    std::thread::scope(|s| {
        let handles: Vec<_> =
            blocks.chunks(chunk).map(|c| s.spawn(move || scan_compact_serial(c, keys))).collect();
        handles.into_iter().flat_map(|h| h.join().expect("scan thread panicked")).collect()
    })
}

fn scan_compact_serial(blocks: &[CompactBlock], keys: &UnifiedFullViewingKey) -> Vec<Note> {
    let sapling = sapling_scopes(keys);
    let orchard = orchard_scopes(keys);
    let orchard_fvk = keys.orchard();

    let mut out = Vec::new();

    for block in blocks {
        let height = BlockHeight::from_u32(block.height as u32);

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

            for scope in &sapling {
                for (i, hit) in
                    decrypt::try_compact_sapling(&scope.ivk, descs.clone()).into_iter().enumerate()
                {
                    if let Some((note, _recipient)) = hit {
                        let (txid, tx_index, output_index, position) = meta[i];
                        let Some(nullifier) = position.map(|pos| note.nf(&scope.nk, pos).0) else {
                            continue;
                        };
                        out.push(Note {
                            note: ShieldedNote::Sapling(note),
                            height,
                            txid,
                            tx_index,
                            output_index,
                            nullifier: Some(nullifier),
                            memo: None,
                        });
                    }
                }
            }
        }

        if let Some(fvk) = orchard_fvk {
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

            for scope in &orchard {
                for (i, hit) in
                    decrypt::try_compact_orchard(&scope.ivk, actions.clone()).into_iter().enumerate()
                {
                    if let Some((note, _recipient)) = hit {
                        let (txid, tx_index, output_index) = meta[i];
                        let nullifier = note.nullifier(fvk).to_bytes();
                        out.push(Note {
                            note: ShieldedNote::Orchard(note),
                            height,
                            txid,
                            tx_index,
                            output_index,
                            nullifier: Some(nullifier),
                            memo: None,
                        });
                    }
                }
            }
        }
    }

    out
}

pub fn scan_sent(
    keys: &UnifiedFullViewingKey,
    network: &Network,
    raw_txs: &[([u8; 32], RawTransaction)],
    notes: &mut Vec<Note>,
) -> Result<()> {
    let sapling_ovks: Vec<_> = keys
        .sapling()
        .map(|dfvk| {
            [Scope::External, Scope::Internal]
                .into_iter()
                .map(|scope| dfvk.to_ovk(scope))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let orchard_ovks: Vec<_> = keys
        .orchard()
        .map(|fvk| {
            [Scope::External, Scope::Internal]
                .into_iter()
                .map(|scope| fvk.to_ovk(scope))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let claimed: std::collections::HashSet<([u8; 32], u32)> =
        notes.iter().map(|n| (n.txid, n.output_index)).collect();

    for (txid, raw) in raw_txs {
        let height = BlockHeight::from_u32(raw.height as u32);
        let tx = match Transaction::read(&raw.data[..], BranchId::for_height(network, height)) {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        if let Some(bundle) = tx.sapling_bundle() {
            let zip212 = zip212_enforcement(network, height);
            for (oi, output) in bundle.shielded_outputs().iter().enumerate() {
                if claimed.contains(&(*txid, oi as u32)) {
                    continue;
                }
                for ovk in &sapling_ovks {
                    if let Some((note, _, memo)) =
                        decrypt::try_decrypt_sapling_sent(output, ovk, zip212)
                    {
                        notes.push(Note {
                            note: ShieldedNote::Sapling(note),
                            height,
                            txid: *txid,
                            tx_index: 0,
                            output_index: oi as u32,
                            nullifier: None,
                            memo: Some(memo),
                        });
                        break;
                    }
                }
            }
        }

        if let Some(bundle) = tx.orchard_bundle() {
            for (ai, action) in bundle.actions().iter().enumerate() {
                if claimed.contains(&(*txid, ai as u32)) {
                    continue;
                }
                for ovk in &orchard_ovks {
                    if let Some((note, _, memo)) =
                        decrypt::try_decrypt_orchard_sent(action, ovk)
                    {
                        notes.push(Note {
                            note: ShieldedNote::Orchard(note),
                            height,
                            txid: *txid,
                            tx_index: 0,
                            output_index: ai as u32,
                            nullifier: None,
                            memo: Some(memo),
                        });
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn txid_of(tx: &CompactTx) -> Option<[u8; 32]> {
    tx.txid[..].try_into().ok()
}
