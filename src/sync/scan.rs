use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;
use zcash_script::script::Code as ScriptCode;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{OutPoint, TxOut};
use zip32::Scope;

use crate::proto::{ChainMetadata, CompactBlock, CompactOrchardAction, GetAddressUtxosReply};
#[cfg(not(feature = "zns-decrypt"))]
use crate::sync::decrypt::decrypt_compact_ironwood;
#[cfg(feature = "zns-decrypt")]
use crate::sync::decrypt::{decrypt_compact_ironwood_relaxed, RelaxedIronwoodOutput};
use crate::sync::decrypt::{
    decrypt_compact_orchard, decrypt_compact_sapling, enrich_ironwood, enrich_orchard,
    enrich_sapling, ScanningKeys,
};

pub struct Nullifiers {
    pub sapling: Vec<sapling::Nullifier>,
    pub orchard: Vec<orchard::note::Nullifier>,
    pub ironwood: Vec<orchard::note::Nullifier>,
}

pub struct WalletOutput<Note, Nf, Recipient> {
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

pub type SaplingOutput = WalletOutput<sapling::Note, sapling::Nullifier, sapling::PaymentAddress>;

pub type OrchardOutput = WalletOutput<orchard::Note, orchard::note::Nullifier, orchard::Address>;

pub struct SaplingSpend {
    pub index: u32,
    pub nf: sapling::Nullifier,
}

pub struct OrchardSpend {
    pub index: u32,
    pub nf: orchard::note::Nullifier,
}

pub struct TransparentOutput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub height: BlockHeight,
}

pub struct TransparentSpend {
    pub txid: TxId,
    pub outpoint: OutPoint,
    pub height: BlockHeight,
}

pub struct WalletTx {
    pub txid: TxId,
    pub height: BlockHeight,
    pub tx_index: u32,
    pub sapling_outputs: Vec<SaplingOutput>,
    pub sapling_spends: Vec<SaplingSpend>,
    pub orchard_outputs: Vec<OrchardOutput>,
    pub orchard_spends: Vec<OrchardSpend>,
    pub ironwood_outputs: Vec<OrchardOutput>,
    pub ironwood_spends: Vec<OrchardSpend>,
    /// Ironwood notes the rseed guard could not self-validate. Unverified —
    /// the caller must check bindings before use.
    #[cfg(feature = "zns-decrypt")]
    pub relaxed_ironwood_outputs: Vec<RelaxedIronwoodOutput>,
    pub transparent_outputs: Vec<TransparentOutput>,
    pub transparent_spends: Vec<TransparentSpend>,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("invalid compact block at height {0}")]
    InvalidCompactBlock(BlockHeight),
    #[error("block height discontinuity: expected {prev_height} + 1, got {new_height}")]
    BlockHeightDiscontinuity {
        prev_height: BlockHeight,
        new_height: BlockHeight,
    },
    #[error("note commitment tree size unknown for {0:?} at height {1}")]
    TreeSizeUnknown(ShieldedPool, BlockHeight),
    #[error("note commitment tree size mismatch for {pool:?} at height {at_height}: given {given}, computed {computed}")]
    TreeSizeMismatch {
        pool: ShieldedPool,
        at_height: BlockHeight,
        given: u32,
        computed: u32,
    },
}

/// Scans until the first block with a kept transaction and returns how many
/// blocks it scanned. Applying that block can change the account's watch list,
/// so later blocks must be matched against the list reloaded after it.
pub fn scan_compact<P: Parameters>(
    blocks: &[CompactBlock],
    keys: &ScanningKeys,
    params: &P,
    nullifiers: &Nullifiers,
) -> Result<(Vec<WalletTx>, usize), ScanError> {
    let mut txs = Vec::new();
    let mut prev_tree_sizes: Option<(u32, u32, u32)> = None;

    for (scanned, block) in blocks.iter().enumerate() {
        let height = BlockHeight::from(
            u32::try_from(block.height)
                .map_err(|_| ScanError::InvalidCompactBlock(BlockHeight::from(0)))?,
        );

        let tree_sizes_at_block_start = match prev_tree_sizes {
            Some(sizes) => sizes,
            None => initial_tree_sizes(height, block)?,
        };

        prev_tree_sizes = Some(scan_block(
            block,
            height,
            keys,
            params,
            nullifiers,
            tree_sizes_at_block_start,
            &mut txs,
        )?);

        if !txs.is_empty() {
            return Ok((txs, scanned + 1));
        }
    }

    Ok((txs, blocks.len()))
}

fn scan_block<P: Parameters>(
    block: &CompactBlock,
    height: BlockHeight,
    keys: &ScanningKeys,
    params: &P,
    nullifiers: &Nullifiers,
    tree_sizes_at_block_start: (u32, u32, u32),
    detected_txs: &mut Vec<WalletTx>,
) -> Result<(u32, u32, u32), ScanError> {
    let zip212 = zip212_enforcement(params, height);

    let (mut sap_pos, mut orch_pos, mut iorn_pos) = tree_sizes_at_block_start;

    for tx in &block.vtx {
        let txid = TxId::from_bytes(
            tx.txid
                .as_slice()
                .try_into()
                .map_err(|_| ScanError::InvalidCompactBlock(height))?,
        );
        let tx_index =
            u32::try_from(tx.index).map_err(|_| ScanError::InvalidCompactBlock(height))?;

        let mut wtx = WalletTx {
            txid,
            height,
            tx_index,
            sapling_outputs: Vec::new(),
            sapling_spends: Vec::new(),
            orchard_outputs: Vec::new(),
            orchard_spends: Vec::new(),
            ironwood_outputs: Vec::new(),
            ironwood_spends: Vec::new(),
            transparent_outputs: Vec::new(),
            transparent_spends: Vec::new(),
            #[cfg(feature = "zns-decrypt")]
            relaxed_ironwood_outputs: Vec::new(),
        };

        let sap_decrypted = decrypt_compact_sapling(&tx.outputs, keys, zip212);
        for (idx, opt) in sap_decrypted.into_iter().enumerate() {
            let position = u64::from(sap_pos) + idx as u64;
            if let Some(((note, recipient), key_index)) = opt {
                let key = &keys.sapling[key_index];
                let nf = key.nk.as_ref().map(|nk| note.nf(nk, position));
                wtx.sapling_outputs.push(SaplingOutput {
                    index: idx as u32,
                    note,
                    recipient,
                    nf,
                    position,
                    scope: key.scope,
                    memo: None,
                    is_sent: false,
                    is_change: key.scope == Scope::Internal,
                });
            }
        }
        sap_pos += u32::try_from(tx.outputs.len()).unwrap();

        for (idx, spend) in tx.spends.iter().enumerate() {
            if let Ok(nf) = sapling::Nullifier::from_slice(spend.nf.as_slice()) {
                if nullifiers.sapling.contains(&nf) {
                    wtx.sapling_spends.push(SaplingSpend {
                        index: idx as u32,
                        nf,
                    });
                }
            }
        }

        let orch_decrypted = decrypt_compact_orchard(&tx.actions, keys);
        for (idx, opt) in orch_decrypted.into_iter().enumerate() {
            let position = u64::from(orch_pos) + idx as u64;
            if let Some(((note, recipient), key_index)) = opt {
                let key = &keys.orchard[key_index];
                let nf = key
                    .nk
                    .as_ref()
                    .and_then(|fvk| Option::from(note.nullifier(fvk)));
                wtx.orchard_outputs.push(OrchardOutput {
                    index: idx as u32,
                    note,
                    recipient,
                    nf,
                    position,
                    scope: key.scope,
                    memo: None,
                    is_sent: false,
                    is_change: key.scope == Scope::Internal,
                });
            }
        }
        orch_pos += u32::try_from(tx.actions.len()).unwrap();

        for (idx, action) in tx.actions.iter().enumerate() {
            if let Some(nf) = action_nullifier(action) {
                if nullifiers.orchard.contains(&nf) {
                    wtx.orchard_spends.push(OrchardSpend {
                        index: idx as u32,
                        nf,
                    });
                }
            }
        }

        #[cfg(not(feature = "zns-decrypt"))]
        {
            let iorn_decrypted = decrypt_compact_ironwood(&tx.ironwood_actions, keys);
            for (idx, opt) in iorn_decrypted.into_iter().enumerate() {
                let position = u64::from(iorn_pos) + idx as u64;
                if let Some(((note, recipient), key_index)) = opt {
                    let key = &keys.orchard[key_index];
                    let nf = key
                        .nk
                        .as_ref()
                        .and_then(|fvk| Option::from(note.nullifier(fvk)));
                    wtx.ironwood_outputs.push(OrchardOutput {
                        index: idx as u32,
                        note,
                        recipient,
                        nf,
                        position,
                        scope: key.scope,
                        memo: None,
                        is_sent: false,
                        is_change: key.scope == Scope::Internal,
                    });
                }
            }
        }
        #[cfg(feature = "zns-decrypt")]
        {
            let (iorn_decrypted, relaxed_hits) =
                decrypt_compact_ironwood_relaxed(&tx.ironwood_actions, keys);
            for (idx, opt) in iorn_decrypted.into_iter().enumerate() {
                let position = u64::from(iorn_pos) + idx as u64;
                if let Some(((note, recipient), key_index)) = opt {
                    let key = &keys.orchard[key_index];
                    let nf = key
                        .nk
                        .as_ref()
                        .and_then(|fvk| Option::from(note.nullifier(fvk)));
                    wtx.ironwood_outputs.push(OrchardOutput {
                        index: idx as u32,
                        note,
                        recipient,
                        nf,
                        position,
                        scope: key.scope,
                        memo: None,
                        is_sent: false,
                        is_change: key.scope == Scope::Internal,
                    });
                }
            }
            wtx.relaxed_ironwood_outputs.extend(relaxed_hits);
        }
        iorn_pos += u32::try_from(tx.ironwood_actions.len()).unwrap();

        // Watched nullifiers decide whether this transaction is interesting.
        // A transaction with no wallet output and no watched spend stays out.
        for (idx, action) in tx.ironwood_actions.iter().enumerate() {
            if let Some(nf) = action_nullifier(action) {
                if nullifiers.ironwood.contains(&nf) {
                    wtx.ironwood_spends.push(OrchardSpend {
                        index: idx as u32,
                        nf,
                    });
                }
            }
        }

        #[cfg(feature = "zns-decrypt")]
        let detected_relaxed = !wtx.relaxed_ironwood_outputs.is_empty();
        #[cfg(not(feature = "zns-decrypt"))]
        let detected_relaxed = false;

        let detected = !wtx.sapling_outputs.is_empty()
            || !wtx.sapling_spends.is_empty()
            || !wtx.orchard_outputs.is_empty()
            || !wtx.orchard_spends.is_empty()
            || !wtx.ironwood_outputs.is_empty()
            || !wtx.ironwood_spends.is_empty()
            || detected_relaxed;

        if detected {
            // This transaction is already kept. Record every Ironwood action
            // nullifier on it, one each. A second copy of one nullifier is
            // counted as two spends.
            let mut spends: Vec<OrchardSpend> = Vec::with_capacity(tx.ironwood_actions.len());
            for (idx, action) in tx.ironwood_actions.iter().enumerate() {
                let Some(nf) = action_nullifier(action) else {
                    continue;
                };
                if spends.iter().any(|spend| spend.nf == nf) {
                    continue;
                }
                spends.push(OrchardSpend {
                    index: idx as u32,
                    nf,
                });
            }
            wtx.ironwood_spends = spends;
            detected_txs.push(wtx);
        }
    }

    let meta = chain_metadata(block, height)?;
    if meta.sapling_commitment_tree_size != sap_pos {
        return Err(ScanError::TreeSizeMismatch {
            pool: ShieldedPool::Sapling,
            at_height: height,
            given: meta.sapling_commitment_tree_size,
            computed: sap_pos,
        });
    }
    if meta.orchard_commitment_tree_size != orch_pos {
        return Err(ScanError::TreeSizeMismatch {
            pool: ShieldedPool::Orchard,
            at_height: height,
            given: meta.orchard_commitment_tree_size,
            computed: orch_pos,
        });
    }
    if meta.ironwood_commitment_tree_size != iorn_pos {
        return Err(ScanError::TreeSizeMismatch {
            pool: ShieldedPool::Ironwood,
            at_height: height,
            given: meta.ironwood_commitment_tree_size,
            computed: iorn_pos,
        });
    }

    Ok((sap_pos, orch_pos, iorn_pos))
}

fn action_nullifier(action: &CompactOrchardAction) -> Option<orchard::note::Nullifier> {
    action
        .nullifier
        .as_slice()
        .try_into()
        .ok()
        .and_then(|bytes| orchard::note::Nullifier::from_bytes(bytes).into())
}

pub fn scan<P: Parameters>(
    txs: &mut [WalletTx],
    full_txs: &[(TxId, BlockHeight, Transaction)],
    keys: &ScanningKeys,
    params: &P,
) {
    for (txid, height, tx) in full_txs {
        let Some(wtx) = txs.iter_mut().find(|t| t.txid == *txid) else {
            continue;
        };
        if let Some(bundle) = tx.sapling_bundle() {
            enrich_sapling(
                bundle,
                keys,
                zip212_enforcement(params, *height),
                &mut wtx.sapling_outputs,
            );
        }
        if let Some(bundle) = tx.orchard_bundle() {
            enrich_orchard(bundle, keys, &mut wtx.orchard_outputs);
        }
        if let Some(bundle) = tx.ironwood_bundle() {
            #[cfg(not(feature = "zns-decrypt"))]
            enrich_ironwood(bundle, keys, &mut wtx.ironwood_outputs);
            #[cfg(feature = "zns-decrypt")]
            enrich_ironwood(
                bundle,
                keys,
                &mut wtx.ironwood_outputs,
                &mut wtx.relaxed_ironwood_outputs,
            );
        }
    }
}

/// Every bundled lightwalletd sends tree sizes, and positions can't be known
/// without them.
fn chain_metadata(block: &CompactBlock, height: BlockHeight) -> Result<&ChainMetadata, ScanError> {
    block
        .chain_metadata
        .as_ref()
        .ok_or(ScanError::InvalidCompactBlock(height))
}

/// A reported size of 0 is an empty tree: protobuf leaves zero fields off the
/// wire, so it can't be told apart from a pool the server left out. A server
/// that leaves one out fails scan_block's end-of-block check instead.
fn initial_tree_sizes(
    height: BlockHeight,
    block: &CompactBlock,
) -> Result<(u32, u32, u32), ScanError> {
    let meta = chain_metadata(block, height)?;
    let start = |pool, end: u32, outputs: usize| {
        u32::try_from(outputs)
            .ok()
            .and_then(|outputs| end.checked_sub(outputs))
            .ok_or(ScanError::TreeSizeUnknown(pool, height))
    };
    let outputs = |count: fn(&crate::proto::CompactTx) -> usize| block.vtx.iter().map(count).sum();

    Ok((
        start(
            ShieldedPool::Sapling,
            meta.sapling_commitment_tree_size,
            outputs(|tx| tx.outputs.len()),
        )?,
        start(
            ShieldedPool::Orchard,
            meta.orchard_commitment_tree_size,
            outputs(|tx| tx.actions.len()),
        )?,
        start(
            ShieldedPool::Ironwood,
            meta.ironwood_commitment_tree_size,
            outputs(|tx| tx.ironwood_actions.len()),
        )?,
    ))
}

pub fn scan_transparent(utxos: &[GetAddressUtxosReply]) -> Vec<TransparentOutput> {
    let mut outputs = Vec::with_capacity(utxos.len());
    for utxo in utxos {
        let txid = match utxo.txid.as_slice().try_into() {
            Ok(bytes) => TxId::from_bytes(bytes),
            Err(_) => continue,
        };
        let index = match u32::try_from(utxo.index) {
            Ok(idx) => idx,
            Err(_) => continue,
        };
        let value = match Zatoshis::from_nonnegative_i64(utxo.value_zat) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let height = match BlockHeight::try_from(utxo.height) {
            Ok(h) => h,
            Err(_) => continue,
        };
        outputs.push(TransparentOutput {
            outpoint: OutPoint::new(*txid.as_ref(), index),
            txout: TxOut::new(value, Script(ScriptCode(utxo.script.clone()))),
            height,
        });
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CompactSaplingSpend, CompactTx};
    use crate::sync::decrypt::ScanningKeys;
    use zcash_protocol::consensus::Network;

    fn nf_bytes(tag: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes
    }

    fn ironwood_action(tag: u8) -> CompactOrchardAction {
        CompactOrchardAction {
            nullifier: nf_bytes(tag).to_vec(),
            cmx: Vec::new(),
            ephemeral_key: Vec::new(),
            ciphertext: Vec::new(),
        }
    }

    fn orchard_nf(tag: u8) -> orchard::note::Nullifier {
        action_nullifier(&ironwood_action(tag)).expect("nullifier")
    }

    fn block(
        ironwood: Vec<CompactOrchardAction>,
        spends: Vec<CompactSaplingSpend>,
    ) -> CompactBlock {
        let chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: ironwood.len() as u32,
        });
        CompactBlock {
            height: 1,
            hash: vec![0; 32],
            prev_hash: vec![0; 32],
            time: 0,
            header: Vec::new(),
            vtx: vec![CompactTx {
                index: 0,
                txid: vec![9; 32],
                fee: 0,
                spends,
                outputs: Vec::new(),
                actions: Vec::new(),
                ironwood_actions: ironwood,
                vin: Vec::new(),
                vout: Vec::new(),
            }],
            chain_metadata,
        }
    }

    fn keys() -> ScanningKeys {
        ScanningKeys {
            sapling: Vec::new(),
            orchard: Vec::new(),
        }
    }

    fn scan_one(
        ironwood: Vec<CompactOrchardAction>,
        sapling_spends: Vec<CompactSaplingSpend>,
        nullifiers: &Nullifiers,
    ) -> Vec<WalletTx> {
        scan_compact(
            &[block(ironwood, sapling_spends)],
            &keys(),
            &Network::MainNetwork,
            nullifiers,
        )
        .expect("scan")
        .0
    }

    fn spend_tags(tx: &WalletTx) -> Vec<(u32, u8)> {
        tx.ironwood_spends
            .iter()
            .map(|spend| (spend.index, spend.nf.to_bytes()[0]))
            .collect()
    }

    #[test]
    fn unwatched_ironwood_transaction_is_dropped() {
        let txs = scan_one(
            vec![ironwood_action(1), ironwood_action(2)],
            Vec::new(),
            &Nullifiers {
                sapling: Vec::new(),
                orchard: Vec::new(),
                ironwood: Vec::new(),
            },
        );
        assert!(txs.is_empty());
    }

    #[test]
    fn kept_transaction_records_every_ironwood_nullifier_once() {
        let txs = scan_one(
            vec![ironwood_action(1), ironwood_action(2)],
            Vec::new(),
            &Nullifiers {
                sapling: Vec::new(),
                orchard: Vec::new(),
                ironwood: vec![orchard_nf(1)],
            },
        );
        assert_eq!(txs.len(), 1);
        assert_eq!(spend_tags(&txs[0]), vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn other_wallet_spend_still_records_every_ironwood_nullifier() {
        let raw = nf_bytes(7);
        let sapling_nf = sapling::Nullifier::from_slice(&raw).expect("sapling nullifier");
        let txs = scan_one(
            vec![ironwood_action(1), ironwood_action(2)],
            vec![CompactSaplingSpend { nf: raw.to_vec() }],
            &Nullifiers {
                sapling: vec![sapling_nf],
                orchard: Vec::new(),
                ironwood: Vec::new(),
            },
        );
        assert_eq!(txs.len(), 1);
        assert_eq!(spend_tags(&txs[0]), vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn scan_stops_after_the_first_block_with_a_kept_transaction() {
        let nullifiers = Nullifiers {
            sapling: Vec::new(),
            orchard: Vec::new(),
            ironwood: vec![orchard_nf(1), orchard_nf(2)],
        };
        let mut blocks = [
            block(vec![ironwood_action(3)], Vec::new()),
            block(vec![ironwood_action(1)], Vec::new()),
            block(vec![ironwood_action(2)], Vec::new()),
        ];
        // Each block adds one leaf to the Ironwood tree.
        for (size, block) in (1..).zip(&mut blocks) {
            block
                .chain_metadata
                .as_mut()
                .unwrap()
                .ironwood_commitment_tree_size = size;
        }
        let (txs, scanned) =
            scan_compact(&blocks, &keys(), &Network::MainNetwork, &nullifiers).expect("scan");
        assert_eq!(scanned, 2);
        assert_eq!(txs.len(), 1);
        assert_eq!(spend_tags(&txs[0]), vec![(0, 1)]);
    }

    #[test]
    fn empty_ironwood_tree_after_activation_starts_at_zero() {
        // Mainnet's Ironwood activation block, as lightwalletd serves it: the
        // tree is still empty, so its size is 0 and left off the wire.
        let mut block = block(Vec::new(), Vec::new());
        block.height = 3_428_143;
        block.chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: 73_938_243,
            orchard_commitment_tree_size: 50_227_880,
            ironwood_commitment_tree_size: 0,
        });
        let sizes = initial_tree_sizes(BlockHeight::from_u32(3_428_143), &block)
            .expect("an empty tree has a known size");
        assert_eq!(sizes, (73_938_243, 50_227_880, 0));
    }

    #[test]
    fn block_without_chain_metadata_is_rejected() {
        let mut block = block(Vec::new(), Vec::new());
        block.chain_metadata = None;
        let scanned = scan_compact(
            &[block],
            &keys(),
            &Network::MainNetwork,
            &Nullifiers {
                sapling: Vec::new(),
                orchard: Vec::new(),
                ironwood: Vec::new(),
            },
        );
        assert!(matches!(scanned, Err(ScanError::InvalidCompactBlock(_))));
    }
}
