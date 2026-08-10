use std::collections::HashSet;

use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::{BlockHeight, Network, NetworkUpgrade, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{OutPoint, TxOut};
use zcash_transparent::keys::{IncomingViewingKey as TransparentIvk, NonHardenedChildIndex};
use zcash_script::script::{Code as ScriptCode, Evaluable as _};
use zip32::Scope;

use crate::proto::CompactBlock;
use crate::sync::decrypt::{
    decrypt_compact_ironwood, decrypt_compact_orchard, decrypt_compact_sapling,
    decrypt_full_ironwood, decrypt_full_orchard, decrypt_full_sapling,
    recover_outgoing_ironwood, recover_outgoing_orchard, recover_outgoing_sapling,
    DecryptResult, ScanningKeys,
};

pub(crate) struct Nullifiers {
    pub sapling: Vec<sapling::Nullifier>,
    pub orchard: Vec<orchard::note::Nullifier>,
    pub ironwood: Vec<orchard::note::Nullifier>,
}

pub(crate) struct TransparentScanningKey {
    pub external: zcash_transparent::keys::ExternalIvk,
    pub internal: Option<zcash_transparent::keys::InternalIvk>,
}

pub(crate) struct WalletOutput<Note, Nf, Recipient> {
    pub index: u32,
    pub note: Note,
    pub recipient: Recipient,
    pub nf: Option<Nf>,
    pub position: u64,
    pub scope: Scope,
    pub memo: Option<[u8; 512]>,
    pub is_sent: bool,
    pub is_change: bool,
}

pub(crate) type SaplingOutput =
    WalletOutput<sapling::Note, sapling::Nullifier, sapling::PaymentAddress>;

pub(crate) type OrchardOutput =
    WalletOutput<orchard::Note, orchard::note::Nullifier, orchard::Address>;

pub(crate) struct SaplingSpend {
    pub index: u32,
    pub nf: sapling::Nullifier,
}

pub(crate) struct OrchardSpend {
    pub index: u32,
    pub nf: orchard::note::Nullifier,
}

pub(crate) struct TransparentOutput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub height: BlockHeight,
}

pub(crate) struct TransparentSpend {
    pub txid: TxId,
    pub outpoint: OutPoint,
    pub height: BlockHeight,
}

pub(crate) struct WalletTx {
    pub txid: TxId,
    pub height: BlockHeight,
    pub tx_index: u32,
    pub sapling_outputs: Vec<SaplingOutput>,
    pub sapling_spends: Vec<SaplingSpend>,
    pub orchard_outputs: Vec<OrchardOutput>,
    pub orchard_spends: Vec<OrchardSpend>,
    pub ironwood_outputs: Vec<OrchardOutput>,
    pub ironwood_spends: Vec<OrchardSpend>,
    pub transparent_outputs: Vec<TransparentOutput>,
    pub transparent_spends: Vec<TransparentSpend>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ScanError {
    #[error("invalid compact block at height {0}")]
    InvalidCompactBlock(BlockHeight),
    #[error("block height discontinuity: expected {prev_height} + 1, got {new_height}")]
    BlockHeightDiscontinuity { prev_height: BlockHeight, new_height: BlockHeight },
    #[error("previous hash mismatch at height {0}")]
    PrevHashMismatch(BlockHeight),
    #[error("note commitment tree size unknown for {0:?} at height {1}")]
    TreeSizeUnknown(ShieldedPool, BlockHeight),
    #[error("note commitment tree size mismatch for {0:?} at height {1}: given {given}, computed {computed}")]
    TreeSizeMismatch { pool: ShieldedPool, at_height: BlockHeight, given: u32, computed: u32 },
}

pub(crate) fn scan_compact(
    blocks: &[CompactBlock],
    keys: &ScanningKeys,
    transparent: Option<&TransparentScanningKey>,
    network: Network,
    nullifiers: &Nullifiers,
    outpoints: &HashSet<OutPoint>,
    prior: Option<(BlockHeight, BlockHash)>,
) -> Result<(Vec<WalletTx>, Vec<(TxId, BlockHeight, u32)>), ScanError> {
    let mut txs = Vec::new();
    let mut all_txs = Vec::new();
    let mut prev = prior;
    let mut prev_tree_sizes: Option<(u32, u32, u32)> = None;

    for block in blocks {
        let height = BlockHeight::from(u32::try_from(block.height).map_err(|_| ScanError::InvalidCompactBlock(BlockHeight::from(0)))?);
        let hash: [u8; 32] = block.hash.as_slice().try_into().map_err(|_| ScanError::InvalidCompactBlock(height))?;

        if let Some((prev_height, prev_hash)) = prev {
            if height != prev_height + 1 {
                return Err(ScanError::BlockHeightDiscontinuity { prev_height, new_height: height });
            }
            if block.prev_hash != prev_hash.0.as_slice() {
                return Err(ScanError::PrevHashMismatch(height));
            }
        }

        let start = match prev_tree_sizes {
            Some(sizes) => sizes,
            None => initial_tree_sizes(&network, height, block)?,
        };

        scan_block(block, keys, transparent, &network, nullifiers, outpoints,
            start, &mut txs, &mut all_txs)?;

        prev_tree_sizes = Some(final_tree_sizes(block));
        prev = Some((height, BlockHash(hash)));
    }

    Ok((txs, all_txs))
}

pub(crate) fn scan_full(
    txs: &mut Vec<WalletTx>,
    full_txs: &[(TxId, BlockHeight, u32, Transaction)],
    keys: &ScanningKeys,
    network: Network,
) -> Result<(), ScanError> {
    for (txid, height, tx_index, tx) in full_txs {
        let zip212 = zip212_enforcement(&network, *height);

        let pos = txs.iter().position(|t| t.txid == *txid);
        let wtx = match pos {
            Some(i) => &mut txs[i],
            None => {
                txs.push(WalletTx {
                    txid: *txid, height: *height, tx_index: *tx_index,
                    sapling_outputs: Vec::new(), sapling_spends: Vec::new(),
                    orchard_outputs: Vec::new(), orchard_spends: Vec::new(),
                    ironwood_outputs: Vec::new(), ironwood_spends: Vec::new(),
                    transparent_outputs: Vec::new(), transparent_spends: Vec::new(),
                });
                txs.last_mut().expect("just pushed")
            }
        };

        if let Some(bundle) = tx.sapling_bundle() {
            let outputs = bundle.shielded_outputs();
            let full = decrypt_full_sapling(outputs, keys, zip212);
            for (idx, opt) in full.into_iter().enumerate() {
                if let Some(o) = wtx.sapling_outputs.iter_mut().find(|o| o.index == idx as u32) {
                    if let Some(DecryptResult { memo: Some(memo), .. }) = opt {
                        o.memo = Some(memo);
                    }
                }
            }
            let outgoing = recover_outgoing_sapling(outputs, keys, zip212);
                for (idx, opt) in outgoing.into_iter().enumerate() {
                    if opt.is_some() && !wtx.sapling_outputs.iter().any(|o| o.index == idx as u32) {
                        if let Some(DecryptResult { note, recipient, memo: Some(memo), key_index }) = opt {
                            wtx.sapling_outputs.push(SaplingOutput {
                                index: idx as u32, note, recipient, nf: None,
                                position: 0u64,
                                scope: if key_index == 0 { Scope::External } else { Scope::Internal },
                                memo: Some(memo), is_sent: true, is_change: false,
                            });
                        }
                    }
                }
        }

        if let Some(bundle) = tx.orchard_bundle() {
            let actions: Vec<_> = bundle.actions().iter().cloned().collect();
            let full = decrypt_full_orchard(&actions, keys);
            for (idx, opt) in full.into_iter().enumerate() {
                if let Some(o) = wtx.orchard_outputs.iter_mut().find(|o| o.index == idx as u32) {
                    if let Some(DecryptResult { memo: Some(memo), .. }) = opt {
                        o.memo = Some(memo);
                    }
                }
            }
            let outgoing = recover_outgoing_orchard(&actions, keys);
                for (idx, opt) in outgoing.into_iter().enumerate() {
                    if opt.is_some() && !wtx.orchard_outputs.iter().any(|o| o.index == idx as u32) {
                        if let Some(DecryptResult { note, recipient, memo: Some(memo), key_index }) = opt {
                            wtx.orchard_outputs.push(OrchardOutput {
                                index: idx as u32, note, recipient, nf: None,
                                position: 0u64,
                                scope: if key_index == 0 { Scope::External } else { Scope::Internal },
                                memo: Some(memo), is_sent: true, is_change: false,
                            });
                        }
                    }
                }
        }

        if let Some(bundle) = tx.ironwood_bundle() {
            let actions: Vec<_> = bundle.actions().iter().cloned().collect();
            let full = decrypt_full_ironwood(&actions, keys);
            for (idx, opt) in full.into_iter().enumerate() {
                if let Some(o) = wtx.ironwood_outputs.iter_mut().find(|o| o.index == idx as u32) {
                    if let Some(DecryptResult { memo: Some(memo), .. }) = opt {
                        o.memo = Some(memo);
                    }
                }
            }
            let outgoing = recover_outgoing_ironwood(&actions, keys);
                for (idx, opt) = outgoing.into_iter().enumerate() {
                    if opt.is_some() && !wtx.ironwood_outputs.iter().any(|o| o.index == idx as u32) {
                        if let Some(DecryptResult { note, recipient, memo: Some(memo), key_index }) = opt {
                            wtx.ironwood_outputs.push(OrchardOutput {
                                index: idx as u32, note, recipient, nf: None,
                                position: 0u64,
                                scope: if key_index == 0 { Scope::External } else { Scope::Internal },
                                memo: Some(memo), is_sent: true, is_change: false,
                            });
                        }
                    }
                }
        }
    }

    Ok(())
}

fn scan_block(
    block: &CompactBlock,
    keys: &ScanningKeys,
    transparent: Option<&TransparentScanningKey>,
    network: &Network,
    nullifiers: &Nullifiers,
    outpoints: &HashSet<OutPoint>,
    start_sizes: (u32, u32, u32),
    txs: &mut Vec<WalletTx>,
    all_txs: &mut Vec<(TxId, BlockHeight, u32)>,
) -> Result<(), ScanError> {
    let height = BlockHeight::from(u32::try_from(block.height).map_err(|_| ScanError::InvalidCompactBlock(BlockHeight::from(0)))?);
    let zip212 = zip212_enforcement(network, height);
    let transparent_scripts = transparent.map(|t| derive_transparent_scripts(t, 20));

    let (mut sap_pos, mut orch_pos, mut iorn_pos) = start_sizes;

    for tx in &block.vtx {
        let txid = TxId::from_bytes(tx.txid.as_slice().try_into().map_err(|_| ScanError::InvalidCompactBlock(height))?);
        let tx_index = u32::try_from(tx.index).map_err(|_| ScanError::InvalidCompactBlock(height))?;
        all_txs.push((txid, height, tx_index));

        let mut wtx = WalletTx {
            txid, height, tx_index,
            sapling_outputs: Vec::new(), sapling_spends: Vec::new(),
            orchard_outputs: Vec::new(), orchard_spends: Vec::new(),
            ironwood_outputs: Vec::new(), ironwood_spends: Vec::new(),
            transparent_outputs: Vec::new(), transparent_spends: Vec::new(),
        };

        let sap_decrypted = decrypt_compact_sapling(&tx.outputs, keys, zip212);
        for (idx, opt) in sap_decrypted.into_iter().enumerate() {
            let position = u64::from(sap_pos) + idx as u64;
            if let Some(DecryptResult { note, recipient, key_index, .. }) = opt {
                let key = &keys.sapling[key_index];
                let nf = key.nk.as_ref().map(|nk| note.nf(nk, u64::from(position)));
                wtx.sapling_outputs.push(SaplingOutput {
                    index: idx as u32, note, recipient, nf, position,
                    scope: key.scope, memo: None, is_sent: false, is_change: false,
                });
            }
        }
        sap_pos += u32::try_from(tx.outputs.len()).unwrap();

        for (idx, spend) in tx.spends.iter().enumerate() {
            if let Ok(nf) = sapling::Nullifier::from_slice(spend.nf.as_slice()) {
                if nullifiers.sapling.contains(&nf) {
                    wtx.sapling_spends.push(SaplingSpend { index: idx as u32, nf });
                }
            }
        }

        let orch_decrypted = decrypt_compact_orchard(&tx.actions, keys);
        for (idx, opt) in orch_decrypted.into_iter().enumerate() {
            let position = u64::from(orch_pos) + idx as u64;
            if let Some(DecryptResult { note, recipient, key_index, .. }) = opt {
                let key = &keys.orchard[key_index];
                let nf = key.nk.as_ref().and_then(|fvk| Option::from(note.nullifier(fvk)));
                wtx.orchard_outputs.push(OrchardOutput {
                    index: idx as u32, note, recipient, nf, position,
                    scope: key.scope, memo: None, is_sent: false, is_change: false,
                });
            }
        }
        orch_pos += u32::try_from(tx.actions.len()).unwrap();

        for (idx, action) in tx.actions.iter().enumerate() {
            if let Some(nf_bytes) = action.nullifier.as_slice().try_into().ok() {
                if let Some(nf) = Option::from(orchard::note::Nullifier::from_bytes(nf_bytes)) {
                    if nullifiers.orchard.contains(&nf) {
                        wtx.orchard_spends.push(OrchardSpend { index: idx as u32, nf });
                    }
                }
            }
        }

        let iorn_decrypted = decrypt_compact_ironwood(&tx.ironwood_actions, keys);
        for (idx, opt) in iorn_decrypted.into_iter().enumerate() {
            let position = u64::from(iorn_pos) + idx as u64;
            if let Some(DecryptResult { note, recipient, key_index, .. }) = opt {
                let key = &keys.orchard[key_index];
                let nf = key.nk.as_ref().and_then(|fvk| Option::from(note.nullifier(fvk)));
                wtx.ironwood_outputs.push(OrchardOutput {
                    index: idx as u32, note, recipient, nf, position,
                    scope: key.scope, memo: None, is_sent: false, is_change: false,
                });
            }
        }
        iorn_pos += u32::try_from(tx.ironwood_actions.len()).unwrap();

        for (idx, action) in tx.ironwood_actions.iter().enumerate() {
            if let Some(nf_bytes) = action.nullifier.as_slice().try_into().ok() {
                if let Some(nf) = Option::from(orchard::note::Nullifier::from_bytes(nf_bytes)) {
                    if nullifiers.ironwood.contains(&nf) {
                        wtx.ironwood_spends.push(OrchardSpend { index: idx as u32, nf });
                    }
                }
            }
        }

        if let Some(scripts) = &transparent_scripts {
            for (idx, vout) in tx.vout.iter().enumerate() {
                if scripts.contains(vout.script_pub_key.as_slice()) {
                    let outpoint = OutPoint::new(*txid.as_ref(), idx as u32);
                    let txout = TxOut::new(
                        Zatoshis::from_u64(vout.value).expect("valid value"),
                        Script(ScriptCode(vout.script_pub_key.clone())),
                    );
                    wtx.transparent_outputs.push(TransparentOutput { outpoint, txout, height });
                }
            }
            for vin in &tx.vin {
                if let Some(txid_bytes) = vin.prevout_txid.as_slice().try_into().ok() {
                    let outpoint = OutPoint::new(txid_bytes, vin.prevout_index);
                    if outpoints.contains(&outpoint) {
                        wtx.transparent_spends.push(TransparentSpend { txid, outpoint, height });
                    }
                }
            }
        }

        if !wtx.sapling_outputs.is_empty() || !wtx.sapling_spends.is_empty()
            || !wtx.orchard_outputs.is_empty() || !wtx.orchard_spends.is_empty()
            || !wtx.ironwood_outputs.is_empty() || !wtx.ironwood_spends.is_empty()
            || !wtx.transparent_outputs.is_empty() || !wtx.transparent_spends.is_empty()
        {
            txs.push(wtx);
        }
    }

    if let Some(meta) = &block.chain_metadata {
        if meta.sapling_commitment_tree_size != sap_pos {
            return Err(ScanError::TreeSizeMismatch { pool: ShieldedPool::Sapling, at_height: height, given: meta.sapling_commitment_tree_size, computed: sap_pos });
        }
        if meta.orchard_commitment_tree_size != orch_pos {
            return Err(ScanError::TreeSizeMismatch { pool: ShieldedPool::Orchard, at_height: height, given: meta.orchard_commitment_tree_size, computed: orch_pos });
        }
        if meta.ironwood_commitment_tree_size != iorn_pos {
            return Err(ScanError::TreeSizeMismatch { pool: ShieldedPool::Ironwood, at_height: height, given: meta.ironwood_commitment_tree_size, computed: iorn_pos });
        }
    }

    Ok(())
}

fn initial_tree_sizes(
    network: &Network,
    height: BlockHeight,
    block: &CompactBlock,
) -> Result<(u32, u32, u32), ScanError> {
    fn one(
        network: &Network, height: BlockHeight, pool: ShieldedPool,
        final_size: u32, output_count: usize, activation: NetworkUpgrade,
    ) -> Result<u32, ScanError> {
        if final_size > 0 {
            return final_size.checked_sub(u32::try_from(output_count).unwrap_or(0))
                .ok_or(ScanError::TreeSizeUnknown(pool, height));
        }
        match network.activation_height(activation) {
            Some(act) if height < act => Ok(0),
            Some(_) => Err(ScanError::TreeSizeUnknown(pool, height)),
            None => Ok(0),
        }
    }

    let meta = block.chain_metadata.as_ref();
    let (s, o, i) = match meta {
        Some(m) => (m.sapling_commitment_tree_size, m.orchard_commitment_tree_size, m.ironwood_commitment_tree_size),
        None => (0, 0, 0),
    };
    let sap_count: usize = block.vtx.iter().map(|tx| tx.outputs.len()).sum();
    let orch_count: usize = block.vtx.iter().map(|tx| tx.actions.len()).sum();
    let iorn_count: usize = block.vtx.iter().map(|tx| tx.ironwood_actions.len()).sum();

    Ok((
        one(network, height, ShieldedPool::Sapling, s, sap_count, NetworkUpgrade::Sapling)?,
        one(network, height, ShieldedPool::Orchard, o, orch_count, NetworkUpgrade::Nu5)?,
        one(network, height, ShieldedPool::Ironwood, i, iorn_count, NetworkUpgrade::Nu6_3)?,
    ))
}

fn final_tree_sizes(block: &CompactBlock) -> (u32, u32, u32) {
    if let Some(meta) = &block.chain_metadata {
        (meta.sapling_commitment_tree_size, meta.orchard_commitment_tree_size, meta.ironwood_commitment_tree_size)
    } else {
        let mut s = 0u32; let mut o = 0u32; let mut i = 0u32;
        for tx in &block.vtx {
            s += u32::try_from(tx.outputs.len()).unwrap();
            o += u32::try_from(tx.actions.len()).unwrap();
            i += u32::try_from(tx.ironwood_actions.len()).unwrap();
        }
        (s, o, i)
    }
}

fn derive_transparent_scripts(key: &TransparentScanningKey, gap_limit: u32) -> HashSet<Vec<u8>> {
    let mut scripts = HashSet::new();
    for i in 0..gap_limit {
        let idx = NonHardenedChildIndex::from_index(i).expect("valid index");
        if let Ok(addr) = key.external.derive_address(idx) {
            scripts.insert(addr.script().to_bytes());
        }
        if let Some(internal) = &key.internal {
            if let Ok(addr) = internal.derive_address(idx) {
                scripts.insert(addr.script().to_bytes());
            }
        }
    }
    scripts
}