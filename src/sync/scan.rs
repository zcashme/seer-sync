//! Scanning a range of blocks into the [`Transactions`] relevant to a key, in
//! two phases:
//!
//! 1. [`scan_compact`] — trial-decrypt the compact ciphertext in the blocks
//!    (via [`crate::note::decrypt`]). Cheap, parallel, sans-IO; recovers
//!    receives (without memos — compact ciphertext truncates them) and the
//!    spends observed.
//! 2. [`scan`] then completes those receives: it fetches each owning full
//!    transaction ([`crate::sync::chain`]) and full-decrypts the matching output
//!    ([`crate::note::decrypt`]) to recover the memo. So `scan`'s findings are
//!    always complete; a failed fetch errors the whole chunk.
//!
//! Sapling nullifiers and leaf positions need the tree size lightwalletd stamps
//! on each block's `chain_metadata`; Orchard nullifiers derive from the key and
//! the action's `rho` directly.

use anyhow::{Context, Result};
use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::keys::ScanningKeys;
use crate::note::decrypt;
use crate::proto::{CompactBlock, CompactTx};
use crate::sync::chain::{self, LwdClient};

/// The 512-byte ZIP-302 memo a receive carries once its full ciphertext is decrypted.
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
    /// Raw 512-byte ZIP-302 memo. `None` after phase 1 (compact blocks truncate
    /// the ciphertext before the memo); filled by [`scan`]'s phase 2.
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

/// Scan `blocks` into the **complete** [`Transactions`] relevant to `keys`.
///
/// Phase 1 compact-scans the blocks ([`scan_compact`]); phase 2 fetches each
/// owning full transaction and full-decrypts the matching output to recover its
/// memo. A failed fetch or parse errors the whole chunk — findings are complete
/// or not at all.
pub async fn scan(
    client: &mut LwdClient,
    blocks: &[CompactBlock],
    keys: &ScanningKeys,
    network: &Network,
) -> Result<Transactions> {
    let mut txs = scan_compact(blocks, keys);
    complete_memos(client, keys, network, &mut txs).await?;
    Ok(txs)
}

/// Phase 2: fill every receive's memo by fetching its full transaction and
/// full-decrypting the matching output. Each owning transaction is fetched once;
/// a failed fetch or parse propagates (killing the chunk).
async fn complete_memos(
    client: &mut LwdClient,
    keys: &ScanningKeys,
    network: &Network,
    txs: &mut Transactions,
) -> Result<()> {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));

    // Distinct txids of the receives we need to complete — fetch each once.
    let mut txids: Vec<[u8; 32]> = Vec::new();
    for r in receives(&txs.sapling) {
        txids.push(r.txid);
    }
    for r in receives(&txs.orchard) {
        txids.push(r.txid);
    }
    txids.sort_unstable();
    txids.dedup();

    for txid in txids {
        let raw = chain::fetch_raw_transaction(client, &txid)
            .await
            .context("fetching full transaction for memo")?;
        let height = BlockHeight::from_u32(raw.height as u32);
        let tx = Transaction::read(&raw.data[..], BranchId::for_height(network, height))
            .context("parsing full transaction")?;

        if let (Some(ivk), Some(bundle)) = (&sapling_ivk, tx.sapling_bundle()) {
            let outputs = bundle.shielded_outputs();
            for r in receives_mut(&mut txs.sapling).filter(|r| r.txid == txid && r.memo.is_none()) {
                if let Some(output) = outputs.get(r.output_index as usize) {
                    let zip212 = zip212_enforcement(network, r.height);
                    if let Some((.., memo)) = decrypt::try_decrypt_sapling(output, ivk, zip212) {
                        r.memo = Some(memo);
                    }
                }
            }
        }

        if let (Some(ivk), Some(bundle)) = (&orchard_ivk, tx.orchard_bundle()) {
            let actions = bundle.actions();
            for r in receives_mut(&mut txs.orchard).filter(|r| r.txid == txid && r.memo.is_none()) {
                if let Some(action) = actions.get(r.output_index as usize) {
                    if let Some((.., memo)) = decrypt::try_decrypt_orchard(action, ivk) {
                        r.memo = Some(memo);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Receives only (skip spends) in a pool's event vec.
fn receives<N, A>(v: &[Tx<N, A>]) -> impl Iterator<Item = &Receive<N, A>> {
    v.iter().filter_map(|t| match t {
        Tx::Receive(r) => Some(r),
        Tx::Spend(_) => None,
    })
}

/// Receives only, mutably.
fn receives_mut<N, A>(v: &mut [Tx<N, A>]) -> impl Iterator<Item = &mut Receive<N, A>> {
    v.iter_mut().filter_map(|t| match t {
        Tx::Receive(r) => Some(r),
        Tx::Spend(_) => None,
    })
}

/// Phase 1: trial-decrypt the compact ciphertext in `blocks` into the
/// [`Transactions`] relevant to `keys` — receives (memos unset) and the spends
/// observed. The sans-IO half: cheap and parallel, no network. [`scan`] adds the
/// memos.
///
/// Blocks are independent, so for large ranges the work is split across the
/// available CPUs with scoped threads (std only, no external dependency) and the
/// per-chunk results concatenated in block order. Small inputs run inline.
pub fn scan_compact(blocks: &[CompactBlock], keys: &ScanningKeys) -> Transactions {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads <= 1 || blocks.len() < 64 {
        return scan_compact_serial(blocks, keys);
    }

    let chunk = blocks.len().div_ceil(threads);
    let parts: Vec<Transactions> = std::thread::scope(|s| {
        let handles: Vec<_> =
            blocks.chunks(chunk).map(|c| s.spawn(move || scan_compact_serial(c, keys))).collect();
        handles.into_iter().map(|h| h.join().expect("scan thread panicked")).collect()
    });

    let mut out = Transactions::default();
    for mut p in parts {
        out.append(&mut p);
    }
    out
}

/// Single-threaded compact scan of `blocks` — the body of [`scan_compact`].
fn scan_compact_serial(blocks: &[CompactBlock], keys: &ScanningKeys) -> Transactions {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let sapling_nk = keys.sapling.as_ref().and_then(|k| k.nk.as_ref());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));
    let orchard_nk = keys.orchard.as_ref().and_then(|k| k.nk.as_ref());

    let mut out = Transactions::default();

    for block in blocks {
        let height = BlockHeight::from_u32(block.height as u32);

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

            for (i, hit) in decrypt::try_compact_sapling(ivk, descs).into_iter().enumerate() {
                if let Some((note, recipient)) = hit {
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

            let mut actions = Vec::new();
            let mut meta: Vec<([u8; 32], u32, u32, Option<u64>)> = Vec::new();
            let mut leaf = 0u64;
            for tx in &block.vtx {
                let Some(txid) = txid_of(tx) else { continue };
                let tx_index = tx.index as u32;
                for (ai, act) in tx.actions.iter().enumerate() {
                    let pos = block_start.map(|s| s + leaf);
                    leaf += 1;
                    if let Some(action) = decrypt::parse_orchard(act) {
                        actions.push(action);
                        meta.push((txid, tx_index, ai as u32, pos));
                    }
                }
            }

            for (i, hit) in decrypt::try_compact_orchard(ivk, actions).into_iter().enumerate() {
                if let Some((note, recipient)) = hit {
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
