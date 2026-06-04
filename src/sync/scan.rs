
use anyhow::{Context, Result};
use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use sapling::keys::PreparedIncomingViewingKey as SaplingPreparedIvk;
use sapling::NullifierDerivingKey;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zip32::Scope;

use zcash_protocol::memo::MemoBytes;

use crate::note::decrypt;
use crate::proto::{CompactBlock, CompactTx};
use crate::sync::chain::{self, LwdClient};

pub enum Tx<N, A> {
    Receive(Receive<N, A>),
    Spend(Spend),
}

impl<N, A> Tx<N, A> {
    pub fn height(&self) -> BlockHeight {
        match self {
            Tx::Receive(r) => r.height,
            Tx::Spend(s) => s.height,
        }
    }

    pub fn txid(&self) -> &[u8; 32] {
        match self {
            Tx::Receive(r) => &r.txid,
            Tx::Spend(s) => &s.txid,
        }
    }

    pub fn nf(&self) -> Option<[u8; 32]> {
        match self {
            Tx::Receive(r) => r.nf,
            Tx::Spend(s) => Some(s.nf),
        }
    }
}

pub struct Receive<N, A> {
    pub height: BlockHeight,
    pub txid: [u8; 32],
    pub tx_index: u32,
    pub output_index: u32,
    pub note: N,
    pub recipient: A,
    pub nf: Option<[u8; 32]>,
    pub position: Option<u64>,
    pub memo: Option<MemoBytes>,
    /// `true` when the note was found with the internal-scope viewing key, i.e.
    /// it is our own change rather than a payment received from someone else.
    pub is_change: bool,
}

pub struct Spend {
    pub height: BlockHeight,
    pub txid: [u8; 32],
    pub tx_index: u32,
    pub nf: [u8; 32],
}

#[derive(Default)]
pub struct Transactions {
    pub orchard: Vec<Tx<orchard::Note, orchard::Address>>,
    pub sapling: Vec<Tx<sapling::Note, sapling::PaymentAddress>>,
}

impl Transactions {
    fn append(&mut self, other: &mut Transactions) {
        self.orchard.append(&mut other.orchard);
        self.sapling.append(&mut other.sapling);
    }
}

pub async fn scan(
    client: &mut LwdClient,
    blocks: &[CompactBlock],
    keys: &UnifiedFullViewingKey,
    network: &Network,
) -> Result<Transactions> {
    let mut txs = scan_compact(blocks, keys);
    complete_memos(client, keys, network, &mut txs).await?;
    Ok(txs)
}

async fn complete_memos(
    client: &mut LwdClient,
    keys: &UnifiedFullViewingKey,
    network: &Network,
    txs: &mut Transactions,
) -> Result<()> {
    // Try every scope's IVK: a change note only decrypts under the internal one.
    let sapling_ivks: Vec<SaplingPreparedIvk> =
        sapling_scopes(keys).into_iter().map(|s| s.ivk).collect();
    let orchard_ivks: Vec<OrchardPreparedIvk> =
        orchard_scopes(keys).into_iter().map(|s| s.ivk).collect();

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

        if let Some(bundle) = tx.sapling_bundle() {
            let outputs = bundle.shielded_outputs();
            for r in receives_mut(&mut txs.sapling).filter(|r| r.txid == txid && r.memo.is_none()) {
                if let Some(output) = outputs.get(r.output_index as usize) {
                    let zip212 = zip212_enforcement(network, r.height);
                    for ivk in &sapling_ivks {
                        if let Some((.., memo)) = decrypt::try_decrypt_sapling(output, ivk, zip212) {
                            r.memo = Some(memo);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(bundle) = tx.orchard_bundle() {
            let actions = bundle.actions();
            for r in receives_mut(&mut txs.orchard).filter(|r| r.txid == txid && r.memo.is_none()) {
                if let Some(action) = actions.get(r.output_index as usize) {
                    for ivk in &orchard_ivks {
                        if let Some((.., memo)) = decrypt::try_decrypt_orchard(action, ivk) {
                            r.memo = Some(memo);
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn receives<N, A>(v: &[Tx<N, A>]) -> impl Iterator<Item = &Receive<N, A>> {
    v.iter().filter_map(|t| match t {
        Tx::Receive(r) => Some(r),
        Tx::Spend(_) => None,
    })
}

fn receives_mut<N, A>(v: &mut [Tx<N, A>]) -> impl Iterator<Item = &mut Receive<N, A>> {
    v.iter_mut().filter_map(|t| match t {
        Tx::Receive(r) => Some(r),
        Tx::Spend(_) => None,
    })
}

/// The Sapling viewing material for one scope: a prepared IVK to trial-decrypt
/// with, paired with the nullifier-deriving key for that same scope.
struct SaplingScope {
    ivk: SaplingPreparedIvk,
    nk: NullifierDerivingKey,
    is_change: bool,
}

/// The Orchard viewing material for one scope. Orchard nullifiers derive from
/// the (scope-invariant) full viewing key, so only the IVK varies by scope.
struct OrchardScope {
    ivk: OrchardPreparedIvk,
    is_change: bool,
}

/// Sapling scopes to scan: External finds ordinary receipts, Internal finds our
/// own change. Empty when the key has no Sapling component.
fn sapling_scopes(keys: &UnifiedFullViewingKey) -> Vec<SaplingScope> {
    keys.sapling()
        .map(|dfvk| {
            [Scope::External, Scope::Internal]
                .into_iter()
                .map(|scope| SaplingScope {
                    ivk: SaplingPreparedIvk::new(&dfvk.to_ivk(scope)),
                    nk: dfvk.to_nk(scope),
                    is_change: matches!(scope, Scope::Internal),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Orchard scopes to scan, mirroring [`sapling_scopes`].
fn orchard_scopes(keys: &UnifiedFullViewingKey) -> Vec<OrchardScope> {
    keys.orchard()
        .map(|fvk| {
            [Scope::External, Scope::Internal]
                .into_iter()
                .map(|scope| OrchardScope {
                    ivk: OrchardPreparedIvk::new(&fvk.to_ivk(scope)),
                    is_change: matches!(scope, Scope::Internal),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn scan_compact(blocks: &[CompactBlock], keys: &UnifiedFullViewingKey) -> Transactions {
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

fn scan_compact_serial(blocks: &[CompactBlock], keys: &UnifiedFullViewingKey) -> Transactions {
    // Both scopes, per pool: External finds payments to us, Internal finds our
    // own change. The full viewing key can derive both; an incoming-only key
    // could not, which is why this crate takes a UFVK.
    let sapling = sapling_scopes(keys);
    let orchard = orchard_scopes(keys);
    let orchard_fvk = keys.orchard();

    let mut out = Transactions::default();

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
                    if let Some((note, recipient)) = hit {
                        let (txid, tx_index, output_index, position) = meta[i];
                        let nf = position.map(|pos| note.nf(&scope.nk, pos).0);
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
                            is_change: scope.is_change,
                        }));
                    }
                }
            }
        }

        if let Some(fvk) = orchard_fvk {
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

            for scope in &orchard {
                for (i, hit) in
                    decrypt::try_compact_orchard(&scope.ivk, actions.clone()).into_iter().enumerate()
                {
                    if let Some((note, recipient)) = hit {
                        let (txid, tx_index, output_index, position) = meta[i];
                        let nf = Some(note.nullifier(fvk).to_bytes());
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
                            is_change: scope.is_change,
                        }));
                    }
                }
            }
        }

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

fn txid_of(tx: &CompactTx) -> Option<[u8; 32]> {
    tx.txid[..].try_into().ok()
}
