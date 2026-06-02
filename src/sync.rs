//! Trial-decrypt compact blocks with a viewing key — and, with a full key,
//! detect spends and compute a balance.
//!
//! [`scan`] is the sans-IO core: it runs the `sapling` / `orchard` batch
//! trial-decryption over every compact output and action and returns rich
//! per-note records (transaction id, output/action index, leaf position, and —
//! with a full key — the derived nullifier) plus every spend observed. [`sync`]
//! is a thin projection of that into received notes and a balance; the
//! persistence engine (`feature = "db"`) projects the same records into rows.
//!
//! Sapling nullifiers and leaf positions need the tree size lightwalletd stamps
//! on each block's `chain_metadata`; Orchard nullifiers derive from the key and
//! the action's `rho` directly.

use std::collections::HashSet;

pub mod chain;
pub mod enrich;
#[cfg(feature = "db")]
pub mod engine;

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{batch, EphemeralKeyBytes};

use crate::keys::ScanningKeys;
use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput};

/// A shielded pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pool {
    /// The Sapling pool.
    Sapling,
    /// The Orchard pool.
    Orchard,
}

/// A Sapling note found while scanning, with everything needed to persist it.
pub struct ScannedSapling {
    /// Transaction id (32 bytes, protocol byte order).
    pub txid: [u8; 32],
    /// Index of the transaction within its block.
    pub tx_index: u32,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Block height the note was mined at.
    pub height: u32,
    /// The decrypted note.
    pub note: sapling::Note,
    /// Recipient address recovered from the plaintext.
    pub recipient: sapling::PaymentAddress,
    /// Derived nullifier; `Some` only with a full key and a known leaf position.
    pub nf: Option<[u8; 32]>,
    /// Leaf position in the Sapling commitment tree, if the block carried the
    /// `chain_metadata` needed to compute it.
    pub position: Option<u64>,
    /// Raw 512-byte ZIP-302 memo. `None` until full-transaction enrichment fills
    /// it — compact blocks truncate the ciphertext before the memo. Stored raw;
    /// decode with [`crate::note::memo`].
    pub memo: Option<Box<[u8; 512]>>,
}

/// An Orchard note found while scanning, with everything needed to persist it.
pub struct ScannedOrchard {
    /// Transaction id (32 bytes, protocol byte order).
    pub txid: [u8; 32],
    /// Index of the transaction within its block.
    pub tx_index: u32,
    /// Action index within the transaction.
    pub action_index: u32,
    /// Block height the note was mined at.
    pub height: u32,
    /// The decrypted note.
    pub note: orchard::Note,
    /// Recipient address recovered from the plaintext.
    pub recipient: orchard::Address,
    /// Derived nullifier; `Some` only with a full key.
    pub nf: Option<[u8; 32]>,
    /// Leaf position in the Orchard commitment tree, if known.
    pub position: Option<u64>,
    /// Raw 512-byte ZIP-302 memo. `None` until full-transaction enrichment fills
    /// it — compact blocks truncate the ciphertext before the memo. Stored raw;
    /// decode with [`crate::note::memo`].
    pub memo: Option<Box<[u8; 512]>>,
}

/// A nullifier revealed as spent in a scanned block.
pub struct SpendSeen {
    /// Pool the spend belongs to.
    pub pool: Pool,
    /// The revealed nullifier.
    pub nf: [u8; 32],
    /// Transaction id that revealed it.
    pub txid: [u8; 32],
    /// Block height of that transaction.
    pub height: u32,
    /// Index of that transaction within its block.
    pub tx_index: u32,
}

/// Everything one pass over a range of blocks turned up.
#[derive(Default)]
pub struct Scanned {
    /// Sapling notes received.
    pub sapling: Vec<ScannedSapling>,
    /// Orchard notes received.
    pub orchard: Vec<ScannedOrchard>,
    /// Every spend observed (across both pools).
    pub spends: Vec<SpendSeen>,
}

/// A note received while scanning (in-memory projection).
pub struct ReceivedNote<N, A> {
    /// Block height the note was received at.
    pub height: u32,
    /// The decrypted note (the `sapling` / `orchard` crate's own type).
    pub note: N,
    /// Recipient address recovered from the plaintext.
    pub recipient: A,
    /// Whether the note was seen spent within the scanned range.
    pub spent: bool,
}

/// Notes received across the scanned blocks, grouped by pool.
#[derive(Default)]
pub struct Received {
    /// Sapling notes received.
    pub sapling: Vec<ReceivedNote<sapling::Note, sapling::PaymentAddress>>,
    /// Orchard notes received.
    pub orchard: Vec<ReceivedNote<orchard::Note, orchard::Address>>,
}

/// Received / spent / unspent totals, in zatoshis.
#[derive(Debug, Default, Clone, Copy)]
pub struct Balance {
    /// Total value of all notes received.
    pub received: u64,
    /// Total value of received notes seen spent within the scanned range.
    pub spent: u64,
    /// `received - spent`.
    pub unspent: u64,
}

impl Received {
    /// Sum received, spent, and unspent value across both pools.
    pub fn balance(&self) -> Balance {
        let received = self.sapling.iter().map(|n| n.note.value().inner()).sum::<u64>()
            + self.orchard.iter().map(|n| n.note.value().inner()).sum::<u64>();
        let spent = self.sapling.iter().filter(|n| n.spent).map(|n| n.note.value().inner()).sum::<u64>()
            + self.orchard.iter().filter(|n| n.spent).map(|n| n.note.value().inner()).sum::<u64>();
        Balance { received, spent, unspent: received - spent }
    }
}

/// Trial-decrypt every Sapling output and Orchard action in `blocks`, returning
/// rich per-note records and every spend observed. The sans-IO scan core.
///
/// Blocks are independent, so for large ranges the work is split across the
/// available CPUs with scoped threads (std only, no external dependency) and the
/// per-chunk results concatenated in block order. Small inputs run inline.
pub fn scan(blocks: &[CompactBlock], keys: &ScanningKeys) -> Scanned {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads <= 1 || blocks.len() < 64 {
        return scan_serial(blocks, keys);
    }

    let chunk = blocks.len().div_ceil(threads);
    let parts: Vec<Scanned> = std::thread::scope(|s| {
        let handles: Vec<_> =
            blocks.chunks(chunk).map(|c| s.spawn(move || scan_serial(c, keys))).collect();
        handles.into_iter().map(|h| h.join().expect("scan thread panicked")).collect()
    });

    let mut out = Scanned::default();
    for mut p in parts {
        out.sapling.append(&mut p.sapling);
        out.orchard.append(&mut p.orchard);
        out.spends.append(&mut p.spends);
    }
    out
}

/// Single-threaded scan of `blocks` — the body of [`scan`].
fn scan_serial(blocks: &[CompactBlock], keys: &ScanningKeys) -> Scanned {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let sapling_nk = keys.sapling.as_ref().and_then(|k| k.nk.as_ref());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));
    let orchard_nk = keys.orchard.as_ref().and_then(|k| k.nk.as_ref());

    let mut out = Scanned::default();

    for block in blocks {
        let height = block.height as u32;

        if let Some(ivk) = &sapling_ivk {
            // Leaf position of this block's first Sapling output: tree size after
            // the block minus the outputs the block contains.
            let block_start = block.chain_metadata.as_ref().map(|m| {
                let after = m.sapling_commitment_tree_size as u64;
                let in_block: u64 = block.vtx.iter().map(|tx| tx.outputs.len() as u64).sum();
                after.saturating_sub(in_block)
            });

            // Count *every* output for positions, but only feed parseable ones to
            // batch decryption; `meta[i]` aligns with the i-th decryption input.
            let mut inputs: Vec<(SaplingDomain, CompactOutputDescription)> = Vec::new();
            let mut meta: Vec<([u8; 32], u32, u32, Option<u64>)> = Vec::new();
            let mut leaf = 0u64;
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                let tx_index = tx.index as u32;
                for (oi, out) in tx.outputs.iter().enumerate() {
                    let pos = block_start.map(|s| s + leaf);
                    leaf += 1;
                    if let Some(desc) = parse_sapling(out) {
                        inputs.push((SaplingDomain::new(Zip212Enforcement::On), desc));
                        meta.push((txid, tx_index, oi as u32, pos));
                    }
                }
            }

            for (i, hit) in batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                .into_iter()
                .enumerate()
            {
                if let Some(((note, recipient), _)) = hit {
                    let (txid, tx_index, output_index, position) = meta[i];
                    let nf = match (sapling_nk, position) {
                        (Some(nk), Some(pos)) => Some(note.nf(nk, pos).0),
                        _ => None,
                    };
                    out.sapling.push(ScannedSapling {
                        txid,
                        tx_index,
                        output_index,
                        height,
                        note,
                        recipient,
                        nf,
                        position,
                        memo: None,
                    });
                }
            }
        }

        if let Some(ivk) = &orchard_ivk {
            let block_start = block.chain_metadata.as_ref().map(|m| {
                let after = m.orchard_commitment_tree_size as u64;
                let in_block: u64 = block.vtx.iter().map(|tx| tx.actions.len() as u64).sum();
                after.saturating_sub(in_block)
            });

            let mut inputs: Vec<(OrchardDomain, CompactAction)> = Vec::new();
            let mut meta: Vec<([u8; 32], u32, u32, Option<u64>)> = Vec::new();
            let mut leaf = 0u64;
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                let tx_index = tx.index as u32;
                for (ai, act) in tx.actions.iter().enumerate() {
                    let pos = block_start.map(|s| s + leaf);
                    leaf += 1;
                    if let Some(action) = parse_orchard(act) {
                        inputs.push((OrchardDomain::for_compact_action(&action), action));
                        meta.push((txid, tx_index, ai as u32, pos));
                    }
                }
            }

            for (i, hit) in batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                .into_iter()
                .enumerate()
            {
                if let Some(((note, recipient), _)) = hit {
                    let (txid, tx_index, action_index, position) = meta[i];
                    let nf = orchard_nk.map(|fvk| note.nullifier(fvk).to_bytes());
                    out.orchard.push(ScannedOrchard {
                        txid,
                        tx_index,
                        action_index,
                        height,
                        note,
                        recipient,
                        nf,
                        position,
                        memo: None,
                    });
                }
            }
        }

        // Spends: Orchard actions reveal a nullifier each, Sapling spends carry theirs.
        for tx in &block.vtx {
            let Some(txid) = txid_of(tx) else { continue };
            let tx_index = tx.index as u32;
            for action in &tx.actions {
                if let Ok(nf) = action.nullifier[..].try_into() {
                    out.spends.push(SpendSeen { pool: Pool::Orchard, nf, txid, height, tx_index });
                }
            }
            for spend in &tx.spends {
                if let Ok(nf) = spend.nf[..].try_into() {
                    out.spends.push(SpendSeen { pool: Pool::Sapling, nf, txid, height, tx_index });
                }
            }
        }
    }

    out
}

/// Trial-decrypt every Sapling output and Orchard action in `blocks`, flagging
/// received notes spent when `keys` carries nullifier-deriving keys.
///
/// A thin projection of [`scan`] into in-memory received notes.
pub fn sync(blocks: &[CompactBlock], keys: &ScanningKeys) -> Received {
    let scanned = scan(blocks, keys);
    let spends: HashSet<[u8; 32]> = scanned.spends.iter().map(|s| s.nf).collect();
    let spent_of = |nf: Option<[u8; 32]>| nf.is_some_and(|nf| spends.contains(&nf));

    Received {
        sapling: scanned
            .sapling
            .into_iter()
            .map(|s| ReceivedNote {
                height: s.height,
                note: s.note,
                recipient: s.recipient,
                spent: spent_of(s.nf),
            })
            .collect(),
        orchard: scanned
            .orchard
            .into_iter()
            .map(|s| ReceivedNote {
                height: s.height,
                note: s.note,
                recipient: s.recipient,
                spent: spent_of(s.nf),
            })
            .collect(),
    }
}

/// Transaction id as a fixed array, or `None` if the proto field isn't 32 bytes.
fn txid_of(tx: &crate::proto::CompactTx) -> Option<[u8; 32]> {
    tx.txid[..].try_into().ok()
}

/// Proto → `sapling` compact output. Deserialization glue, not crypto.
fn parse_sapling(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu_bytes: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes))?;
    let ephemeral_key = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let enc_ciphertext = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key, enc_ciphertext })
}

/// Proto → `orchard` compact action. Deserialization glue, not crypto.
fn parse_orchard(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}
