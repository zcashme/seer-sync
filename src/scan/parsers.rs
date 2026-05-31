//! Proto → domain-type parsers, byte utilities, and block-level batch helpers.
//!
//! All items are `pub(super)` — only the sibling scan modules use them.

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling::note_encryption::{
    CompactOutputDescription, PreparedIncomingViewingKey as SaplingPreparedIvk, SaplingDomain,
    Zip212Enforcement,
};
use zcash_note_encryption::{batch, EphemeralKeyBytes};

use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput};

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

/// Batch-decrypt all Orchard actions in one compact block.
///
/// Collects every parseable action across all transactions, runs a single
/// `batch::try_compact_note_decryption` call, and returns
/// `(tx_idx, action_idx, action, note, recipient)` for each hit.
///
/// Both [`super::ivk::scan_ivk`] and [`super::fvk::scan_fvk`] use this —
/// the Orchard decrypt logic is identical on both paths.
pub(super) fn decrypt_orchard_block(
    block: &CompactBlock,
    ivk_slice: &[OrchardPreparedIvk],
) -> Vec<(usize, usize, CompactAction, orchard::Note, orchard::Address)> {
    if ivk_slice.is_empty() {
        return Vec::new();
    }

    let indexed: Vec<(usize, usize, CompactAction)> = block
        .vtx
        .iter()
        .enumerate()
        .flat_map(|(ti, ctxn)| {
            ctxn.actions
                .iter()
                .enumerate()
                .filter_map(move |(ai, p)| parse_orchard_action(p).map(|ca| (ti, ai, ca)))
        })
        .collect();

    let batch_inputs: Vec<(OrchardDomain, CompactAction)> = indexed
        .iter()
        .map(|(_, _, ca)| (OrchardDomain::for_compact_action(ca), ca.clone()))
        .collect();

    indexed
        .into_iter()
        .zip(batch::try_compact_note_decryption(ivk_slice, &batch_inputs))
        .filter_map(|((ti, ai, ca), result)| {
            result.map(|((note, recipient), _)| (ti, ai, ca, note, recipient))
        })
        .collect()
}

/// Batch-decrypt all Sapling outputs in one compact block.
///
/// Returns `(tx_idx, output_idx, note, recipient)` for each hit.
/// Used by the IVK path; the FVK path uses its own leaf-position-aware
/// variant in Phase 1.
pub(super) fn decrypt_sapling_block(
    block: &CompactBlock,
    ivk_slice: &[SaplingPreparedIvk],
) -> Vec<(usize, usize, sapling::Note, sapling::PaymentAddress)> {
    if ivk_slice.is_empty() {
        return Vec::new();
    }

    let indexed: Vec<(usize, usize, CompactOutputDescription)> = block
        .vtx
        .iter()
        .enumerate()
        .flat_map(|(ti, ctxn)| {
            ctxn.outputs
                .iter()
                .enumerate()
                .filter_map(move |(oi, p)| parse_sapling_output(p).map(|o| (ti, oi, o)))
        })
        .collect();

    let batch_inputs: Vec<(SaplingDomain, CompactOutputDescription)> = indexed
        .iter()
        .map(|(_, _, o)| (SaplingDomain::new(Zip212Enforcement::On), o.clone()))
        .collect();

    indexed
        .into_iter()
        .zip(batch::try_compact_note_decryption(ivk_slice, &batch_inputs))
        .filter_map(|((ti, oi, _), result)| {
            result.map(|((note, recipient), _)| (ti, oi, note, recipient))
        })
        .collect()
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
