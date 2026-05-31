//! Parallel trial-decrypt loop over compact blocks.
//!
//! Profile via: cargo bench --bench decrypt

use crossbeam_channel::{Receiver, unbounded};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use rayon::prelude::*;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{EphemeralKeyBytes, try_compact_note_decryption};

use crate::keys::Keys;
use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput};

/// Which shielded pool a note belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedPool {
    /// Sapling shielded pool.
    Sapling,
    /// Orchard shielded pool.
    Orchard,
}

/// The address that received a note, pool-typed.
#[derive(Debug, Clone)]
pub enum Recipient {
    /// An Orchard diversified address.
    Orchard(orchard::Address),
    /// A Sapling payment address.
    Sapling(sapling::PaymentAddress),
}

/// A successfully trial-decrypted incoming note.
#[derive(Debug, Clone)]
pub struct IncomingNoteView {
    /// Block height containing the action/output.
    pub height: u32,
    /// Pool the note belongs to.
    pub pool: ShieldedPool,
    /// Value in zatoshis (1 ZEC = 1e8 zatoshis).
    pub value_zat: u64,
    /// Recipient address recovered from the decrypted plaintext.
    pub recipient: Recipient,
}

/// Trial-decrypt `blocks` in parallel using rayon.
///
/// Returns a [`Receiver`] that yields one [`IncomingNoteView`] per successful
/// decrypt. The channel closes automatically when all rayon workers finish —
/// draining with `for note in rx` is sufficient to know the scan is done.
///
/// Assumes Sapling outputs use ZIP-212 strict enforcement (post-Canopy).
pub fn sync(blocks: &[CompactBlock], keys: &Keys) -> Receiver<IncomingNoteView> {
    let (tx, rx) = unbounded();

    if !keys.is_empty() {
        let sapling_domain = SaplingDomain::new(Zip212Enforcement::On);

        blocks.par_iter().for_each_with(tx, |tx, block| {
            let height = block.height as u32;

            for compact_tx in &block.vtx {
                if let Some(ivk) = &keys.orchard {
                    for proto_action in &compact_tx.actions {
                        let Some(action) = parse_orchard_action(proto_action) else {
                            continue;
                        };
                        let domain = OrchardDomain::for_compact_action(&action);
                        if let Some((note, recipient)) =
                            try_compact_note_decryption(&domain, ivk, &action)
                        {
                            tx.send(IncomingNoteView {
                                height,
                                pool: ShieldedPool::Orchard,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Orchard(recipient),
                            })
                            .ok();
                        }
                    }
                }

                if let Some(ivk) = &keys.sapling {
                    for proto_output in &compact_tx.outputs {
                        let Some(output) = parse_sapling_output(proto_output) else {
                            continue;
                        };
                        if let Some((note, recipient)) =
                            try_compact_note_decryption(&sapling_domain, ivk, &output)
                        {
                            tx.send(IncomingNoteView {
                                height,
                                pool: ShieldedPool::Sapling,
                                value_zat: note.value().inner(),
                                recipient: Recipient::Sapling(recipient),
                            })
                            .ok();
                        }
                    }
                }
            }
        });
    }

    rx
}

fn parse_orchard_action(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}

fn parse_sapling_output(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key: epk, enc_ciphertext: ct })
}
