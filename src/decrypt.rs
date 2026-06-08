use orchard::{
    keys::{OutgoingViewingKey as OrchardOvk, PreparedIncomingViewingKey as OrchardPreparedIvk},
    note_encryption::{CompactAction, OrchardDomain},
    Action,
};
use sapling::{
    bundle::OutputDescription,
    keys::{OutgoingViewingKey as SaplingOvk, PreparedIncomingViewingKey as SaplingPreparedIvk},
    note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement},
};
use zcash_note_encryption::{batch, try_note_decryption, try_output_recovery_with_ovk, EphemeralKeyBytes};
use zcash_protocol::memo::MemoBytes;

use crate::proto::{CompactOrchardAction, CompactSaplingOutput};

pub(crate) fn try_compact_sapling(
    ivk: &SaplingPreparedIvk,
    descs: Vec<CompactOutputDescription>,
) -> Vec<Option<(sapling::Note, sapling::PaymentAddress)>> {
    let inputs: Vec<(SaplingDomain, CompactOutputDescription)> = descs
        .into_iter()
        .map(|d| (SaplingDomain::new(Zip212Enforcement::On), d))
        .collect();
    batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
        .into_iter()
        .map(|hit| hit.map(|((note, recipient), _)| (note, recipient)))
        .collect()
}

pub(crate) fn try_compact_orchard(
    ivk: &OrchardPreparedIvk,
    actions: Vec<CompactAction>,
) -> Vec<Option<(orchard::Note, orchard::Address)>> {
    let inputs: Vec<(OrchardDomain, CompactAction)> = actions
        .into_iter()
        .map(|a| (OrchardDomain::for_compact_action(&a), a))
        .collect();
    batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
        .into_iter()
        .map(|hit| hit.map(|((note, recipient), _)| (note, recipient)))
        .collect()
}

pub(crate) fn parse_sapling(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu_bytes: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes))?;
    let ephemeral_key = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let enc_ciphertext = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key, enc_ciphertext })
}

pub(crate) fn parse_orchard(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}

pub fn try_decrypt_orchard<A>(
    action: &Action<A>,
    ivk: &OrchardPreparedIvk,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    let (note, recipient, memo) =
        try_note_decryption(&OrchardDomain::for_action(action), ivk, action)?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}

pub fn try_decrypt_sapling<Proof>(
    output: &OutputDescription<Proof>,
    ivk: &SaplingPreparedIvk,
    zip212: Zip212Enforcement,
) -> Option<(sapling::Note, sapling::PaymentAddress, MemoBytes)> {
    let (note, recipient, memo) =
        try_note_decryption(&SaplingDomain::new(zip212), ivk, output)?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}

pub(crate) fn try_decrypt_orchard_sent<A>(
    action: &Action<A>,
    ovk: &OrchardOvk,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    let (note, recipient, memo) = try_output_recovery_with_ovk(
        &OrchardDomain::for_action(action),
        ovk,
        action,
        action.cv_net(),
        &action.encrypted_note().out_ciphertext,
    )?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}

pub(crate) fn try_decrypt_sapling_sent<Proof>(
    output: &OutputDescription<Proof>,
    ovk: &SaplingOvk,
    zip212: Zip212Enforcement,
) -> Option<(sapling::Note, sapling::PaymentAddress, MemoBytes)> {
    let (note, recipient, memo) = try_output_recovery_with_ovk(
        &SaplingDomain::new(zip212),
        ovk,
        output,
        output.cv(),
        output.out_ciphertext(),
    )?;
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}
