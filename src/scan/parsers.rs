//! Proto → domain-type parsers and byte-extraction utilities.
//!
//! All items are `pub(super)` — only the sibling scan modules use them.

use orchard::note_encryption::CompactAction;
use sapling::note_encryption::CompactOutputDescription;
use zcash_note_encryption::EphemeralKeyBytes;

use crate::proto::{CompactOrchardAction, CompactSaplingOutput};

pub(super) fn parse_orchard_action(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}

pub(super) fn parse_sapling_output(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key: epk, enc_ciphertext: ct })
}

pub(super) fn txid_bytes(raw: &[u8]) -> [u8; 32] {
    raw.try_into().unwrap_or([0u8; 32])
}

pub(super) fn rseed_bytes_sapling(note: &sapling::Note) -> [u8; 32] {
    match note.rseed() {
        sapling::note::Rseed::BeforeZip212(scalar) => scalar.to_bytes(),
        sapling::note::Rseed::AfterZip212(bytes) => *bytes,
    }
}
