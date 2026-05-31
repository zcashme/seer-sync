//! Trial-decrypt compact blocks with a viewing key.
//!
//! The whole job: take the incoming viewing keys, run the `sapling` / `orchard`
//! batch trial-decryption over every compact output and action, and return the
//! hits as the note crates' own `(height, Note, recipient)` — no wrapper types.

pub mod chain;

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{batch, EphemeralKeyBytes};

use crate::keys::ScanningKeys;
use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput};

/// Notes received across the scanned blocks, grouped by pool.
///
/// Each entry is `(block_height, note, recipient)` in the `sapling` / `orchard`
/// crates' own types.
#[derive(Default)]
pub struct Received {
    /// Sapling notes received.
    pub sapling: Vec<(u32, sapling::Note, sapling::PaymentAddress)>,
    /// Orchard notes received.
    pub orchard: Vec<(u32, orchard::Note, orchard::Address)>,
}

/// Trial-decrypt every Sapling output and Orchard action in `blocks`.
///
/// Each block is decrypted as a single batch per pool, amortising the
/// key-agreement setup across all of that block's outputs.
pub fn sync(blocks: &[CompactBlock], keys: &ScanningKeys) -> Received {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));

    let mut received = Received::default();

    for block in blocks {
        let height = block.height as u32;

        if let Some(ivk) = &sapling_ivk {
            let inputs: Vec<(SaplingDomain, CompactOutputDescription)> = block
                .vtx
                .iter()
                .flat_map(|tx| &tx.outputs)
                .filter_map(parse_sapling)
                .map(|o| (SaplingDomain::new(Zip212Enforcement::On), o))
                .collect();
            for ((note, recipient), _) in
                batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                    .into_iter()
                    .flatten()
            {
                received.sapling.push((height, note, recipient));
            }
        }

        if let Some(ivk) = &orchard_ivk {
            let inputs: Vec<(OrchardDomain, CompactAction)> = block
                .vtx
                .iter()
                .flat_map(|tx| &tx.actions)
                .filter_map(parse_orchard)
                .map(|a| (OrchardDomain::for_compact_action(&a), a))
                .collect();
            for ((note, recipient), _) in
                batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                    .into_iter()
                    .flatten()
            {
                received.orchard.push((height, note, recipient));
            }
        }
    }

    received
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
