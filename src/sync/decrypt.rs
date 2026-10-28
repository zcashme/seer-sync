use orchard::note_encryption::CompactAction;
#[cfg(not(feature = "zns-decrypt"))]
use orchard::note_encryption::IronwoodDomain;
use orchard::note_encryption::OrchardDomain;
use sapling::note_encryption::{
    CompactOutputDescription, SaplingDomain, Zip212Enforcement, COMPACT_NOTE_SIZE,
};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_note_encryption::{batch::try_compact_note_decryption, EphemeralKeyBytes};
use zip32::Scope;
#[cfg(feature = "zns-decrypt")]
use zns_verify::decrypt::{CandidateNote, ZnsIronwoodDomain};

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

// Match upstream batch-decryption payloads, including the matching key index.
pub(crate) type CompactDecryptResult<Note, Recipient> = ((Note, Recipient), usize);

pub(crate) fn decrypt_compact_sapling(
    outputs: &[CompactSaplingOutput],
    keys: &ScanningKeys,
    zip212: Zip212Enforcement,
) -> Vec<Option<CompactDecryptResult<sapling::Note, sapling::PaymentAddress>>> {
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

    let mut results: Vec<Option<CompactDecryptResult<sapling::Note, sapling::PaymentAddress>>> =
        (0..outputs.len()).map(|_| None).collect();
    for (idx, result) in indices.into_iter().zip(raw) {
        results[idx] = result;
    }
    results
}

pub(crate) fn decrypt_compact_orchard(
    actions: &[CompactOrchardAction],
    keys: &ScanningKeys,
) -> Vec<Option<CompactDecryptResult<orchard::Note, orchard::Address>>> {
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

    let mut results: Vec<Option<CompactDecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    for (idx, result) in indices.into_iter().zip(raw) {
        results[idx] = result;
    }
    results
}

#[cfg(not(feature = "zns-decrypt"))]
pub(crate) fn decrypt_compact_ironwood(
    actions: &[CompactOrchardAction],
    keys: &ScanningKeys,
) -> Vec<Option<CompactDecryptResult<orchard::Note, orchard::Address>>> {
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

    let mut results: Vec<Option<CompactDecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    for (idx, result) in indices.into_iter().zip(raw) {
        results[idx] = result;
    }
    results
}

// ── Relaxed Ironwood scan (`zns-decrypt`) ──────────────────────────────────
//
// Trial-decrypt with zns-verify's `ZnsIronwoodDomain` and route each result
// with the rseed guard: self-consistent notes take the ordinary path
// (byte-identical to the standard domain); the rest surface unverified.

/// True when the decrypted note self-consistently produces its published
/// commitment, i.e. it is an ordinary note under the standard rseed rule.
#[cfg(feature = "zns-decrypt")]
pub(crate) fn rseed_guard(candidate: &CandidateNote) -> bool {
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
    Vec<Option<CompactDecryptResult<orchard::Note, orchard::Address>>>,
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

    let mut ordinary: Vec<Option<CompactDecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    let mut relaxed = Vec::new();
    for ((idx, ca), r) in parsed.into_iter().zip(raw) {
        if let Some(((candidate, recipient), key_index)) = r {
            if rseed_guard(&candidate) {
                ordinary[idx] = Some(((*candidate.note(), recipient), key_index));
            } else {
                relaxed.push((idx, candidate, ca.nullifier(), None, false));
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
