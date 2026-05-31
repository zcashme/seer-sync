//! IVK path — incoming-only trial decryption, no spend detection.

use crossbeam_channel::{unbounded, Receiver};
use orchard::note_encryption::OrchardDomain;
use rayon::prelude::*;
use sapling::note_encryption::{SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::batch;

use crate::keys::IvkKeys;
use crate::proto::CompactBlock;

use super::parsers::{parse_orchard_action, parse_sapling_output, rseed_bytes_sapling, txid_bytes};
use super::types::{IncomingNoteView, Recipient, ShieldedPool};

/// Trial-decrypt `blocks` in parallel using IVK-only keys.
///
/// Returns a [`Receiver`] that yields one [`IncomingNoteView`] per hit.
/// The channel closes when all rayon workers finish. Post-Canopy ZIP-212
/// is assumed for Sapling.
///
/// Two levels of parallelism: rayon distributes blocks across threads, and
/// within each block a single `batch::try_compact_note_decryption` call
/// covers all actions/outputs × all IVKs simultaneously.
pub fn scan_ivk(blocks: &[CompactBlock], keys: &IvkKeys) -> Receiver<IncomingNoteView> {
    let (tx, rx) = unbounded();

    if !keys.is_empty() {
        let orchard_ivk_slice = keys.orchard.as_ref().map_or(&[][..], std::slice::from_ref);
        let sapling_ivk_slice = keys.sapling.as_ref().map_or(&[][..], std::slice::from_ref);

        blocks.par_iter().for_each_with(tx, |tx, block| {
            let height = block.height as u32;

            // ── Orchard: one batch for ALL actions in this block ─────────────
            if !orchard_ivk_slice.is_empty() {
                let indexed = block
                    .vtx
                    .iter()
                    .enumerate()
                    .flat_map(|(ti, ctxn)| {
                        ctxn.actions
                            .iter()
                            .enumerate()
                            .filter_map(move |(ai, p)| {
                                parse_orchard_action(p).map(|ca| (ti, ai, ca))
                            })
                    })
                    .collect::<Vec<_>>();

                let batch_inputs = indexed
                    .iter()
                    .map(|(_, _, ca)| (OrchardDomain::for_compact_action(ca), ca.clone()))
                    .collect::<Vec<_>>();

                for (i, result) in
                    batch::try_compact_note_decryption(orchard_ivk_slice, &batch_inputs)
                        .into_iter()
                        .enumerate()
                {
                    if let Some(((note, recipient), _)) = result {
                        let (ti, ai, ca) = &indexed[i];
                        tx.send(IncomingNoteView {
                            height,
                            tx_id: txid_bytes(&block.vtx[*ti].txid),
                            output_index: *ai,
                            pool: ShieldedPool::Orchard,
                            value_zat: note.value().inner(),
                            recipient: Recipient::Orchard(recipient),
                            rseed: note.rseed().as_bytes().clone(),
                            rho: Some(ca.nullifier().to_bytes()),
                            sapling_leaf_pos: None,
                            nullifier: None,
                        })
                        .ok();
                    }
                }
            }

            // ── Sapling: one batch for ALL outputs in this block ─────────────
            if !sapling_ivk_slice.is_empty() {
                let indexed = block
                    .vtx
                    .iter()
                    .enumerate()
                    .flat_map(|(ti, ctxn)| {
                        ctxn.outputs
                            .iter()
                            .enumerate()
                            .filter_map(move |(oi, p)| {
                                parse_sapling_output(p).map(|o| (ti, oi, o))
                            })
                    })
                    .collect::<Vec<_>>();

                let batch_inputs = indexed
                    .iter()
                    .map(|(_, _, o)| (SaplingDomain::new(Zip212Enforcement::On), o.clone()))
                    .collect::<Vec<_>>();

                for (i, result) in
                    batch::try_compact_note_decryption(sapling_ivk_slice, &batch_inputs)
                        .into_iter()
                        .enumerate()
                {
                    if let Some(((note, recipient), _)) = result {
                        let (ti, oi, _) = &indexed[i];
                        tx.send(IncomingNoteView {
                            height,
                            tx_id: txid_bytes(&block.vtx[*ti].txid),
                            output_index: *oi,
                            pool: ShieldedPool::Sapling,
                            value_zat: note.value().inner(),
                            recipient: Recipient::Sapling(recipient),
                            rseed: rseed_bytes_sapling(&note),
                            rho: None,
                            sapling_leaf_pos: None,
                            nullifier: None,
                        })
                        .ok();
                    }
                }
            }
        });
    }

    rx
}
