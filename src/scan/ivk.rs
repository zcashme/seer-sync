//! IVK path — incoming-only trial decryption, no spend detection.

use crossbeam_channel::{unbounded, Receiver};
use rayon::prelude::*;

use crate::keys::IvkKeys;
use crate::proto::CompactBlock;

use super::parsers::{decrypt_orchard_block, decrypt_sapling_block, rseed_bytes_sapling, txid_bytes};
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

            for (ti, ai, ca, note, recipient) in decrypt_orchard_block(block, orchard_ivk_slice) {
                tx.send(IncomingNoteView {
                    height,
                    tx_id: txid_bytes(&block.vtx[ti].txid),
                    output_index: ai,
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

            for (ti, oi, note, recipient) in decrypt_sapling_block(block, sapling_ivk_slice) {
                tx.send(IncomingNoteView {
                    height,
                    tx_id: txid_bytes(&block.vtx[ti].txid),
                    output_index: oi,
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
        });
    }

    rx
}
