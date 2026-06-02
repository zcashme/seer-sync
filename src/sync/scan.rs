//! The sans-IO core: trial-decrypt compact blocks with a viewing key.
//!
//! [`scan`] runs the `sapling` / `orchard` batch trial-decryption over every
//! compact output and action in a slice of blocks and returns the
//! [`Transactions`] relevant to the key — the receives it recovered and the
//! spends it observed. No network, no async, no persistence: hand it blocks and
//! keys, get findings back. The live-syncing layer ([`crate::sync`]) feeds it
//! blocks off the wire; a consumer persists what comes out.
//!
//! Sapling nullifiers and leaf positions need the tree size lightwalletd stamps
//! on each block's `chain_metadata`; Orchard nullifiers derive from the key and
//! the action's `rho` directly.

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{batch, EphemeralKeyBytes};

use crate::keys::ScanningKeys;
use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactTx};
use crate::BlockHeight;

/// The 512-byte ZIP-302 memo a receive carries once enriched.
pub type RawMemo = Box<[u8; 512]>;

/// One value event relevant to a viewing key — a **receive** or a **spend** —
/// tagged by the height it was found at.
///
/// The two flavors are the open and close of a single note's life, and the
/// **nullifier is the through-line**: a receive derives the note's nullifier
/// (its future spend-tag — `Some` only with a full key), a spend reveals one.
/// When a spend's nullifier matches a receive's, they are the same note. That
/// shared `nf` is why both live under one type rather than as two strangers.
pub enum Tx<N, A> {
    /// An incoming note — born here. Decrypted with the incoming viewing key.
    Receive(Receive<N, A>),
    /// A nullifier revealed on-chain — a note consumed here. A consumer matches
    /// it against the derived `nf` of a receive it knows about.
    Spend(Spend),
}

impl<N, A> Tx<N, A> {
    /// Height this event was found at.
    pub fn height(&self) -> BlockHeight {
        match self {
            Tx::Receive(r) => r.height,
            Tx::Spend(s) => s.height,
        }
    }

    /// The transaction that carried this event.
    pub fn txid(&self) -> &[u8; 32] {
        match self {
            Tx::Receive(r) => &r.txid,
            Tx::Spend(s) => &s.txid,
        }
    }

    /// The nullifier — the lifecycle join key. A receive has one only with a
    /// full key (`None` otherwise); a spend always carries the revealed one.
    pub fn nf(&self) -> Option<[u8; 32]> {
        match self {
            Tx::Receive(r) => r.nf,
            Tx::Spend(s) => Some(s.nf),
        }
    }
}

/// An incoming note recovered by trial decryption, plus the facts that make it
/// yours.
pub struct Receive<N, A> {
    /// Block height the note was received at.
    pub height: BlockHeight,
    /// Transaction id that created the note (32 bytes, protocol byte order).
    pub txid: [u8; 32],
    /// Index of that transaction within its block.
    pub tx_index: u32,
    /// Output index (Sapling) / action index (Orchard) within the transaction.
    pub output_index: u32,
    /// The decrypted note.
    pub note: N,
    /// Recipient address recovered from the plaintext.
    pub recipient: A,
    /// Derived nullifier — `Some` only with a full key. The note's future
    /// spend-tag; matching a [`Spend`] to it closes the note's life.
    pub nf: Option<[u8; 32]>,
    /// Leaf position in the pool's commitment tree, when the block carried the
    /// `chain_metadata` needed to compute it.
    pub position: Option<u64>,
    /// Raw 512-byte ZIP-302 memo. `None` until full-transaction enrichment fills
    /// it (compact blocks truncate the ciphertext before the memo).
    pub memo: Option<RawMemo>,
}

/// A nullifier revealed as spent in a scanned block — thin by nature; the chain
/// discloses only the nullifier, not whose note it was.
pub struct Spend {
    /// Block height of the spending transaction.
    pub height: BlockHeight,
    /// Transaction id that revealed the nullifier.
    pub txid: [u8; 32],
    /// Index of that transaction within its block.
    pub tx_index: u32,
    /// The revealed nullifier — the join key back to the receive that minted it.
    pub nf: [u8; 32],
}

/// Everything one pass over a range of blocks turned up, grouped by pool.
///
/// Pool is a *type* axis, not a structural split: both vecs hold the same `Tx`
/// shape, differing only in the pool's note/address types. Each vec carries
/// both receives and spends for that pool.
#[derive(Default)]
pub struct Transactions {
    /// Orchard events (receives + spends).
    pub orchard: Vec<Tx<orchard::Note, orchard::Address>>,
    /// Sapling events (receives + spends).
    pub sapling: Vec<Tx<sapling::Note, sapling::PaymentAddress>>,
}

impl Transactions {
    /// Move every event of `other` onto the end of `self`, in pool order.
    fn append(&mut self, other: &mut Transactions) {
        self.orchard.append(&mut other.orchard);
        self.sapling.append(&mut other.sapling);
    }
}

/// Trial-decrypt every Sapling output and Orchard action in `blocks`, returning
/// the [`Transactions`] relevant to `keys`.
///
/// Blocks are independent, so for large ranges the work is split across the
/// available CPUs with scoped threads (std only, no external dependency) and the
/// per-chunk results concatenated in block order. Small inputs run inline.
pub fn scan(blocks: &[CompactBlock], keys: &ScanningKeys) -> Transactions {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads <= 1 || blocks.len() < 64 {
        return scan_serial(blocks, keys);
    }

    let chunk = blocks.len().div_ceil(threads);
    let parts: Vec<Transactions> = std::thread::scope(|s| {
        let handles: Vec<_> =
            blocks.chunks(chunk).map(|c| s.spawn(move || scan_serial(c, keys))).collect();
        handles.into_iter().map(|h| h.join().expect("scan thread panicked")).collect()
    });

    let mut out = Transactions::default();
    for mut p in parts {
        out.append(&mut p);
    }
    out
}

/// Single-threaded scan of `blocks` — the body of [`scan`].
fn scan_serial(blocks: &[CompactBlock], keys: &ScanningKeys) -> Transactions {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let sapling_nk = keys.sapling.as_ref().and_then(|k| k.nk.as_ref());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));
    let orchard_nk = keys.orchard.as_ref().and_then(|k| k.nk.as_ref());

    let mut out = Transactions::default();

    for block in blocks {
        let height = block.height as BlockHeight;

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
                    out.sapling.push(Tx::Receive(Receive {
                        height,
                        txid,
                        tx_index,
                        output_index,
                        note,
                        recipient,
                        nf,
                        position,
                        memo: None,
                    }));
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
                    let (txid, tx_index, output_index, position) = meta[i];
                    let nf = orchard_nk.map(|fvk| note.nullifier(fvk).to_bytes());
                    out.orchard.push(Tx::Receive(Receive {
                        height,
                        txid,
                        tx_index,
                        output_index,
                        note,
                        recipient,
                        nf,
                        position,
                        memo: None,
                    }));
                }
            }
        }

        // Spends: every Orchard action reveals a nullifier; every Sapling spend
        // carries one. We emit them all — a consumer matches them against the
        // notes it knows; unmatched ones are simply no-ops.
        for tx in &block.vtx {
            let Some(txid) = txid_of(tx) else { continue };
            let tx_index = tx.index as u32;
            for action in &tx.actions {
                if let Ok(nf) = action.nullifier[..].try_into() {
                    out.orchard.push(Tx::Spend(Spend { height, txid, tx_index, nf }));
                }
            }
            for spend in &tx.spends {
                if let Ok(nf) = spend.nf[..].try_into() {
                    out.sapling.push(Tx::Spend(Spend { height, txid, tx_index, nf }));
                }
            }
        }
    }

    out
}

/// Transaction id as a fixed array, or `None` if the proto field isn't 32 bytes.
fn txid_of(tx: &CompactTx) -> Option<[u8; 32]> {
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
