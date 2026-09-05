use orchard::note_encryption::CompactAction;
#[cfg(not(feature = "zns-decrypt"))]
use orchard::note_encryption::IronwoodDomain;
use orchard::note_encryption::OrchardDomain;
#[cfg(feature = "zns-decrypt")]
use orchard::note_encryption::{CandidateNote, ZnsIronwoodDomain};
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_note_encryption::{
    batch::{try_compact_note_decryption, try_note_decryption as batch_try_note_decryption},
    try_note_decryption, try_output_recovery_with_ovk, EphemeralKeyBytes, COMPACT_NOTE_SIZE,
};
use zip32::Scope;

use crate::proto::{CompactOrchardAction, CompactSaplingOutput};

pub struct ScanningKey<Ivk, Nk, Ovk> {
    pub ivk: Ivk,
    pub nk: Option<Nk>,
    pub ovk: Option<Ovk>,
    pub scope: Scope,
}

pub struct ScanningKeys {
    pub sapling: Vec<
        ScanningKey<
            sapling::note_encryption::PreparedIncomingViewingKey,
            sapling::NullifierDerivingKey,
            sapling::keys::OutgoingViewingKey,
        >,
    >,
    pub orchard: Vec<
        ScanningKey<
            orchard::keys::PreparedIncomingViewingKey,
            orchard::keys::FullViewingKey,
            orchard::keys::OutgoingViewingKey,
        >,
    >,
}

impl ScanningKeys {
    pub fn from_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        let mut sapling = Vec::new();
        let mut orchard = Vec::new();

        if let Some(dfvk) = ufvk.sapling() {
            for scope in [Scope::External, Scope::Internal] {
                sapling.push(ScanningKey {
                    ivk: sapling::note_encryption::PreparedIncomingViewingKey::new(
                        &dfvk.to_ivk(scope),
                    ),
                    nk: Some(dfvk.to_nk(scope)),
                    ovk: Some(dfvk.to_ovk(scope)),
                    scope,
                });
            }
        }

        if let Some(fvk) = ufvk.orchard() {
            for scope in [Scope::External, Scope::Internal] {
                orchard.push(ScanningKey {
                    ivk: fvk.to_ivk(scope).prepare(),
                    nk: Some(fvk.clone()),
                    ovk: Some(fvk.to_ovk(scope)),
                    scope,
                });
            }
        }

        ScanningKeys { sapling, orchard }
    }

    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        let mut sapling = Vec::new();
        let mut orchard = Vec::new();

        if let Some(ivk) = uivk.sapling().as_ref() {
            sapling.push(ScanningKey {
                ivk: ivk.prepare(),
                nk: None,
                ovk: None,
                scope: Scope::External,
            });
        }

        if let Some(ivk) = uivk.orchard().as_ref() {
            orchard.push(ScanningKey {
                ivk: ivk.prepare(),
                nk: None,
                ovk: None,
                scope: Scope::External,
            });
        }

        ScanningKeys { sapling, orchard }
    }
}

pub(crate) struct DecryptResult<Note, Recipient> {
    pub note: Note,
    pub recipient: Recipient,
    pub memo: Option<[u8; 512]>,
    pub key_index: usize,
}

pub(crate) fn decrypt_compact_sapling(
    outputs: &[CompactSaplingOutput],
    keys: &ScanningKeys,
    zip212: Zip212Enforcement,
) -> Vec<Option<DecryptResult<sapling::Note, sapling::PaymentAddress>>> {
    let ivks: Vec<_> = keys.sapling.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return (0..outputs.len()).map(|_| None).collect();
    }

    let mut pairs = Vec::new();
    let mut indices = Vec::new();
    for (i, o) in outputs.iter().enumerate() {
        if let Some(co) = parse_compact_sapling(o) {
            pairs.push((SaplingDomain::new(zip212), co));
            indices.push(i);
        }
    }

    let raw = try_compact_note_decryption(&ivks, &pairs);

    let mut results: Vec<Option<DecryptResult<sapling::Note, sapling::PaymentAddress>>> =
        (0..outputs.len()).map(|_| None).collect();
    for (idx, r) in indices.into_iter().zip(raw.into_iter()) {
        if let Some(((note, recipient), key_index)) = r {
            results[idx] = Some(DecryptResult {
                note,
                recipient,
                memo: None,
                key_index,
            });
        }
    }
    results
}

pub(crate) fn decrypt_compact_orchard(
    actions: &[CompactOrchardAction],
    keys: &ScanningKeys,
) -> Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> {
    let ivks: Vec<_> = keys.orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return (0..actions.len()).map(|_| None).collect();
    }

    let mut pairs = Vec::new();
    let mut indices = Vec::new();
    for (i, a) in actions.iter().enumerate() {
        if let Some(ca) = parse_compact_orchard(a) {
            pairs.push((OrchardDomain::for_compact_action(&ca), ca));
            indices.push(i);
        }
    }

    let raw = try_compact_note_decryption(&ivks, &pairs);

    let mut results: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    for (idx, r) in indices.into_iter().zip(raw.into_iter()) {
        if let Some(((note, recipient), key_index)) = r {
            results[idx] = Some(DecryptResult {
                note,
                recipient,
                memo: None,
                key_index,
            });
        }
    }
    results
}

#[cfg(not(feature = "zns-decrypt"))]
pub(crate) fn decrypt_compact_ironwood(
    actions: &[CompactOrchardAction],
    keys: &ScanningKeys,
) -> Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> {
    let ivks: Vec<_> = keys.orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return (0..actions.len()).map(|_| None).collect();
    }

    let mut pairs = Vec::new();
    let mut indices = Vec::new();
    for (i, a) in actions.iter().enumerate() {
        if let Some(ca) = parse_compact_orchard(a) {
            pairs.push((IronwoodDomain::for_compact_action(&ca), ca));
            indices.push(i);
        }
    }

    let raw = try_compact_note_decryption(&ivks, &pairs);

    let mut results: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    for (idx, r) in indices.into_iter().zip(raw.into_iter()) {
        if let Some(((note, recipient), key_index)) = r {
            results[idx] = Some(DecryptResult {
                note,
                recipient,
                memo: None,
                key_index,
            });
        }
    }
    results
}

pub(crate) fn decrypt_full_sapling(
    outputs: &[sapling::bundle::OutputDescription<sapling::bundle::GrothProofBytes>],
    keys: &ScanningKeys,
    zip212: Zip212Enforcement,
) -> Vec<Option<DecryptResult<sapling::Note, sapling::PaymentAddress>>> {
    let ivks: Vec<_> = keys.sapling.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return (0..outputs.len()).map(|_| None).collect();
    }

    let pairs: Vec<_> = outputs
        .iter()
        .map(|o| (SaplingDomain::new(zip212), o.clone()))
        .collect();

    batch_try_note_decryption(&ivks, &pairs)
        .into_iter()
        .map(|r| {
            r.map(|((note, recipient, memo), key_index)| DecryptResult {
                note,
                recipient,
                memo: Some(memo),
                key_index,
            })
        })
        .collect()
}

pub(crate) fn decrypt_full_orchard<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> {
    let ivks: Vec<_> = keys.orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return (0..actions.len()).map(|_| None).collect();
    }

    actions
        .iter()
        .map(|action| {
            let domain = OrchardDomain::for_action(action);
            for (key_index, ivk) in ivks.iter().enumerate() {
                if let Some((note, recipient, memo)) =
                    try_note_decryption(&domain, ivk, action)
                {
                    return Some(DecryptResult {
                        note,
                        recipient,
                        memo: Some(memo),
                        key_index,
                    });
                }
            }
            None
        })
        .collect()
}

#[cfg(not(feature = "zns-decrypt"))]
pub(crate) fn decrypt_full_ironwood<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> {
    let ivks: Vec<_> = keys.orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return (0..actions.len()).map(|_| None).collect();
    }

    actions
        .iter()
        .map(|action| {
            let domain = IronwoodDomain::for_action(action);
            for (key_index, ivk) in ivks.iter().enumerate() {
                if let Some((note, recipient, memo)) =
                    try_note_decryption(&domain, ivk, action)
                {
                    return Some(DecryptResult {
                        note,
                        recipient,
                        memo: Some(memo),
                        key_index,
                    });
                }
            }
            None
        })
        .collect()
}

pub(crate) fn recover_outgoing_sapling(
    outputs: &[sapling::bundle::OutputDescription<sapling::bundle::GrothProofBytes>],
    keys: &ScanningKeys,
    zip212: Zip212Enforcement,
) -> Vec<Option<DecryptResult<sapling::Note, sapling::PaymentAddress>>> {
    let ovks: Vec<&sapling::keys::OutgoingViewingKey> = keys
        .sapling
        .iter()
        .filter_map(|k| k.ovk.as_ref())
        .collect();

    if ovks.is_empty() {
        return (0..outputs.len()).map(|_| None).collect();
    }

    let domain = SaplingDomain::new(zip212);

    outputs
        .iter()
        .map(|output| {
            for (i, ovk) in ovks.iter().enumerate() {
                if let Some((note, recipient, memo)) = try_output_recovery_with_ovk(
                    &domain,
                    ovk,
                    output,
                    output.cv(),
                    output.out_ciphertext(),
                ) {
                    return Some(DecryptResult {
                        note,
                        recipient,
                        memo: Some(memo),
                        key_index: i,
                    });
                }
            }
            None
        })
        .collect()
}

pub(crate) fn recover_outgoing_orchard<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> {
    let ovks: Vec<&orchard::keys::OutgoingViewingKey> = keys
        .orchard
        .iter()
        .filter_map(|k| k.ovk.as_ref())
        .collect();

    if ovks.is_empty() {
        return (0..actions.len()).map(|_| None).collect();
    }

    actions
        .iter()
        .map(|action| {
            let domain = OrchardDomain::for_action(action);
            for (i, ovk) in ovks.iter().enumerate() {
                if let Some((note, recipient, memo)) = try_output_recovery_with_ovk(
                    &domain,
                    ovk,
                    action,
                    action.cv_net(),
                    &action.encrypted_note().out_ciphertext,
                ) {
                    return Some(DecryptResult {
                        note,
                        recipient,
                        memo: Some(memo),
                        key_index: i,
                    });
                }
            }
            None
        })
        .collect()
}

#[cfg(not(feature = "zns-decrypt"))]
pub(crate) fn recover_outgoing_ironwood<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> {
    let ovks: Vec<&orchard::keys::OutgoingViewingKey> = keys
        .orchard
        .iter()
        .filter_map(|k| k.ovk.as_ref())
        .collect();

    if ovks.is_empty() {
        return (0..actions.len()).map(|_| None).collect();
    }

    actions
        .iter()
        .map(|action| {
            let domain = IronwoodDomain::for_action(action);
            for (i, ovk) in ovks.iter().enumerate() {
                if let Some((note, recipient, memo)) = try_output_recovery_with_ovk(
                    &domain,
                    ovk,
                    action,
                    action.cv_net(),
                    &action.encrypted_note().out_ciphertext,
                ) {
                    return Some(DecryptResult {
                        note,
                        recipient,
                        memo: Some(memo),
                        key_index: i,
                    });
                }
            }
            None
        })
        .collect()
}

// ── Relaxed Ironwood scan (`zns-decrypt`) ──────────────────────────────────
//
// Trial-decrypt with the fork's `ZnsIronwoodDomain` and route each result
// with the rseed guard: self-consistent notes take the ordinary path
// (byte-identical to the standard domain); the rest surface unverified.

/// True when the decrypted note self-consistently produces its published
/// commitment, i.e. it is an ordinary note under the standard rseed rule.
#[cfg(feature = "zns-decrypt")]
fn rseed_guard(candidate: &CandidateNote) -> bool {
    use orchard::note::ExtractedNoteCommitment;

    ExtractedNoteCommitment::from(candidate.note().commitment()).to_bytes()
        == candidate.cmx().to_bytes()
}

/// An Ironwood note the rseed guard could not self-validate: (action index
/// in the bundle, decrypted note + published cmx, action's public nullifier,
/// raw memo, is_sent). Unverified — the caller must check the binding.
#[cfg(feature = "zns-decrypt")]
pub type RelaxedIronwoodOutput = (
    usize,
    CandidateNote,
    orchard::note::Nullifier,
    Option<[u8; 512]>,
    bool,
);

#[cfg(feature = "zns-decrypt")]
pub(crate) fn decrypt_compact_ironwood_relaxed(
    actions: &[CompactOrchardAction],
    keys: &ScanningKeys,
) -> (
    Vec<Option<DecryptResult<orchard::Note, orchard::Address>>>,
    Vec<RelaxedIronwoodOutput>,
) {
    let ivks: Vec<_> = keys.orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return ((0..actions.len()).map(|_| None).collect(), Vec::new());
    }

    let mut parsed = Vec::new();
    for (i, a) in actions.iter().enumerate() {
        if let Some(ca) = parse_compact_orchard(a) {
            parsed.push((i, ca));
        }
    }

    let pairs: Vec<_> = parsed
        .iter()
        .map(|(_, ca)| (ZnsIronwoodDomain::for_compact_action(ca), ca.clone()))
        .collect();

    let raw = try_compact_note_decryption(&ivks, &pairs);

    let mut ordinary: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    let mut relaxed = Vec::new();
    for ((idx, ca), r) in parsed.into_iter().zip(raw.into_iter()) {
        if let Some(((candidate, recipient), key_index)) = r {
            if rseed_guard(&candidate) {
                ordinary[idx] = Some(DecryptResult {
                    note: *candidate.note(),
                    recipient,
                    memo: None,
                    key_index,
                });
            } else {
                relaxed.push((idx, candidate, ca.nullifier(), None, false));
            }
        }
    }
    (ordinary, relaxed)
}

#[cfg(feature = "zns-decrypt")]
pub(crate) fn decrypt_full_ironwood_relaxed<T: Clone>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> (
    Vec<Option<DecryptResult<orchard::Note, orchard::Address>>>,
    Vec<RelaxedIronwoodOutput>,
) {
    let ivks: Vec<_> = keys.orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return ((0..actions.len()).map(|_| None).collect(), Vec::new());
    }

    let pairs: Vec<_> = actions
        .iter()
        .map(|a| (ZnsIronwoodDomain::for_action(a), a.clone()))
        .collect();

    let raw = batch_try_note_decryption(&ivks, &pairs);

    let mut ordinary: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    let mut relaxed = Vec::new();
    for (idx, r) in raw.into_iter().enumerate() {
        if let Some(((candidate, recipient, memo), key_index)) = r {
            if rseed_guard(&candidate) {
                ordinary[idx] = Some(DecryptResult {
                    note: *candidate.note(),
                    recipient,
                    memo: Some(memo),
                    key_index,
                });
            } else {
                relaxed.push((idx, candidate, *actions[idx].nullifier(), Some(memo), false));
            }
        }
    }
    (ordinary, relaxed)
}

#[cfg(feature = "zns-decrypt")]
pub(crate) fn recover_outgoing_ironwood_relaxed<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> (
    Vec<Option<DecryptResult<orchard::Note, orchard::Address>>>,
    Vec<RelaxedIronwoodOutput>,
) {
    let ovks: Vec<&orchard::keys::OutgoingViewingKey> = keys
        .orchard
        .iter()
        .filter_map(|k| k.ovk.as_ref())
        .collect();
    if ovks.is_empty() {
        return ((0..actions.len()).map(|_| None).collect(), Vec::new());
    }

    let mut ordinary: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    let mut relaxed = Vec::new();
    for (idx, action) in actions.iter().enumerate() {
        let domain = ZnsIronwoodDomain::for_action(action);
        let nf = *action.nullifier();
        for (i, ovk) in ovks.iter().enumerate() {
            if let Some((candidate, recipient, memo)) =
                domain.try_decrypt_sent(action, ovk)
            {
                if rseed_guard(&candidate) {
                    ordinary[idx] = Some(DecryptResult {
                        note: *candidate.note(),
                        recipient,
                        memo: Some(memo),
                        key_index: i,
                    });
                } else {
                    relaxed.push((idx, candidate, nf, Some(memo), true));
                }
                break;
            }
        }
    }
    (ordinary, relaxed)
}

fn parse_compact_sapling(o: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    use sapling::note::ExtractedNoteCommitment;

    let cmu_bytes: &[u8; 32] = o.cmu.as_slice().try_into().ok()?;
    let cmu = Option::from(ExtractedNoteCommitment::from_bytes(cmu_bytes))?;
    let ephemeral_key = EphemeralKeyBytes(o.ephemeral_key.as_slice().try_into().ok()?);
    let enc_ciphertext: &[u8; COMPACT_NOTE_SIZE] = o.ciphertext.as_slice().try_into().ok()?;

    Some(CompactOutputDescription {
        ephemeral_key,
        cmu,
        enc_ciphertext: *enc_ciphertext,
    })
}

fn parse_compact_orchard(a: &CompactOrchardAction) -> Option<CompactAction> {
    use orchard::note::{ExtractedNoteCommitment, Nullifier};

    let nf_bytes: &[u8; 32] = a.nullifier.as_slice().try_into().ok()?;
    let nullifier = Option::from(Nullifier::from_bytes(nf_bytes))?;
    let cmx_bytes: &[u8; 32] = a.cmx.as_slice().try_into().ok()?;
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(cmx_bytes))?;
    let ephemeral_key = EphemeralKeyBytes(a.ephemeral_key.as_slice().try_into().ok()?);
    let enc_ciphertext: [u8; COMPACT_NOTE_SIZE] = a.ciphertext.as_slice().try_into().ok()?;

    Some(CompactAction::from_parts(
        nullifier,
        cmx,
        ephemeral_key,
        enc_ciphertext,
    ))
}