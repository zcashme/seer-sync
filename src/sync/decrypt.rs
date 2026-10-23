use orchard::note_encryption::CompactAction;
#[cfg(not(feature = "zns-decrypt"))]
use orchard::note_encryption::IronwoodDomain;
use orchard::note_encryption::OrchardDomain;
use sapling::note_encryption::{
    CompactOutputDescription, SaplingDomain, Zip212Enforcement, COMPACT_NOTE_SIZE,
};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_note_encryption::{
    batch::{try_compact_note_decryption, try_note_decryption as batch_try_note_decryption},
    try_note_decryption, try_output_recovery_with_ovk, EphemeralKeyBytes,
};
use zip32::Scope;
#[cfg(feature = "zns-decrypt")]
use zns_orchard::note_encryption::{CandidateNote, ZnsIronwoodDomain};

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
    /// The `orchard` keys again as `zns-orchard` keys, same order, for the
    /// relaxed Ironwood scan.
    #[cfg(feature = "zns-decrypt")]
    pub(crate) zns_orchard: Vec<ZnsScanningKey>,
}

#[cfg(feature = "zns-decrypt")]
pub(crate) type ZnsScanningKey = ScanningKey<
    zns_orchard::keys::PreparedIncomingViewingKey,
    zns_orchard::keys::FullViewingKey,
    zns_orchard::keys::OutgoingViewingKey,
>;

impl ScanningKeys {
    pub fn from_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        let mut sapling = Vec::new();
        let mut orchard = Vec::new();
        #[cfg(feature = "zns-decrypt")]
        let mut zns_orchard = Vec::new();

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
            #[cfg(feature = "zns-decrypt")]
            {
                let fvk = zns::fvk_to_zns(fvk);
                for scope in [Scope::External, Scope::Internal] {
                    zns_orchard.push(ScanningKey {
                        ivk: fvk.to_ivk(scope).prepare(),
                        nk: Some(fvk.clone()),
                        ovk: Some(fvk.to_ovk(scope)),
                        scope,
                    });
                }
            }
        }

        ScanningKeys {
            sapling,
            orchard,
            #[cfg(feature = "zns-decrypt")]
            zns_orchard,
        }
    }

    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        let mut sapling = Vec::new();
        let mut orchard = Vec::new();
        #[cfg(feature = "zns-decrypt")]
        let mut zns_orchard = Vec::new();

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
            #[cfg(feature = "zns-decrypt")]
            zns_orchard.push(ScanningKey {
                ivk: zns::ivk_to_zns(ivk).prepare(),
                nk: None,
                ovk: None,
                scope: Scope::External,
            });
        }

        ScanningKeys {
            sapling,
            orchard,
            #[cfg(feature = "zns-decrypt")]
            zns_orchard,
        }
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
    for (idx, r) in indices.into_iter().zip(raw) {
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
    for (idx, r) in indices.into_iter().zip(raw) {
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
    for (idx, r) in indices.into_iter().zip(raw) {
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
                if let Some((note, recipient, memo)) = try_note_decryption(&domain, ivk, action) {
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
                if let Some((note, recipient, memo)) = try_note_decryption(&domain, ivk, action) {
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
    let ovks: Vec<&sapling::keys::OutgoingViewingKey> =
        keys.sapling.iter().filter_map(|k| k.ovk.as_ref()).collect();

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
    let ovks: Vec<&orchard::keys::OutgoingViewingKey> =
        keys.orchard.iter().filter_map(|k| k.ovk.as_ref()).collect();

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
    let ovks: Vec<&orchard::keys::OutgoingViewingKey> =
        keys.orchard.iter().filter_map(|k| k.ovk.as_ref()).collect();

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
//
// Everything outside this section is upstream `orchard`. Actions and keys
// enter the fork, and ordinary notes leave it, through `zns`.

/// True when the decrypted note self-consistently produces its published
/// commitment, i.e. it is an ordinary note under the standard rseed rule.
#[cfg(feature = "zns-decrypt")]
fn rseed_guard(candidate: &CandidateNote) -> bool {
    use zns_orchard::note::ExtractedNoteCommitment;

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

/// One relaxed scan's results: ordinary notes by action index, and the
/// relaxed outputs.
#[cfg(feature = "zns-decrypt")]
pub(crate) type RelaxedScan = (
    Vec<Option<DecryptResult<orchard::Note, orchard::Address>>>,
    Vec<RelaxedIronwoodOutput>,
);

/// A guard-passing candidate as an ordinary upstream result.
#[cfg(feature = "zns-decrypt")]
fn ordinary_result(
    candidate: &CandidateNote,
    recipient: &zns_orchard::Address,
    memo: Option<[u8; 512]>,
    key_index: usize,
) -> Result<DecryptResult<orchard::Note, orchard::Address>, zns::EncodingMismatch> {
    Ok(DecryptResult {
        note: zns::note_from_zns(candidate.note())?,
        recipient: zns::address_from_zns(recipient)?,
        memo,
        key_index,
    })
}

#[cfg(feature = "zns-decrypt")]
pub(crate) fn decrypt_compact_ironwood_relaxed(
    actions: &[CompactOrchardAction],
    keys: &ScanningKeys,
) -> Result<RelaxedScan, zns::EncodingMismatch> {
    let ivks: Vec<_> = keys.zns_orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return Ok(((0..actions.len()).map(|_| None).collect(), Vec::new()));
    }

    let mut parsed = Vec::new();
    for (i, a) in actions.iter().enumerate() {
        if let Some(ca) = zns::parse_compact(a) {
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
    for ((idx, ca), r) in parsed.into_iter().zip(raw) {
        if let Some(((candidate, recipient), key_index)) = r {
            if rseed_guard(&candidate) {
                ordinary[idx] = Some(ordinary_result(&candidate, &recipient, None, key_index)?);
            } else {
                let nf = zns::nullifier_from_zns(ca.nullifier());
                relaxed.push((idx, candidate, nf, None, false));
            }
        }
    }
    Ok((ordinary, relaxed))
}

#[cfg(feature = "zns-decrypt")]
pub(crate) fn decrypt_full_ironwood_relaxed<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> Result<RelaxedScan, zns::EncodingMismatch> {
    let ivks: Vec<_> = keys.zns_orchard.iter().map(|k| k.ivk.clone()).collect();
    if ivks.is_empty() {
        return Ok(((0..actions.len()).map(|_| None).collect(), Vec::new()));
    }

    let pairs = actions
        .iter()
        .map(|a| {
            let a = zns::action_to_zns(a)?;
            Ok((ZnsIronwoodDomain::for_action(&a), a))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let raw = batch_try_note_decryption(&ivks, &pairs);

    let mut ordinary: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    let mut relaxed = Vec::new();
    for (idx, r) in raw.into_iter().enumerate() {
        if let Some(((candidate, recipient, memo), key_index)) = r {
            if rseed_guard(&candidate) {
                ordinary[idx] = Some(ordinary_result(
                    &candidate,
                    &recipient,
                    Some(memo),
                    key_index,
                )?);
            } else {
                relaxed.push((idx, candidate, *actions[idx].nullifier(), Some(memo), false));
            }
        }
    }
    Ok((ordinary, relaxed))
}

#[cfg(feature = "zns-decrypt")]
pub(crate) fn recover_outgoing_ironwood_relaxed<T>(
    actions: &[orchard::Action<T>],
    keys: &ScanningKeys,
) -> Result<RelaxedScan, zns::EncodingMismatch> {
    let ovks: Vec<&zns_orchard::keys::OutgoingViewingKey> = keys
        .zns_orchard
        .iter()
        .filter_map(|k| k.ovk.as_ref())
        .collect();
    if ovks.is_empty() {
        return Ok(((0..actions.len()).map(|_| None).collect(), Vec::new()));
    }

    let mut ordinary: Vec<Option<DecryptResult<orchard::Note, orchard::Address>>> =
        (0..actions.len()).map(|_| None).collect();
    let mut relaxed = Vec::new();
    for (idx, action) in actions.iter().enumerate() {
        let zns_action = zns::action_to_zns(action)?;
        let domain = ZnsIronwoodDomain::for_action(&zns_action);
        let nf = *action.nullifier();
        for (i, ovk) in ovks.iter().enumerate() {
            if let Some((candidate, recipient, memo)) = domain.try_decrypt_sent(&zns_action, ovk) {
                if rseed_guard(&candidate) {
                    ordinary[idx] = Some(ordinary_result(&candidate, &recipient, Some(memo), i)?);
                } else {
                    relaxed.push((idx, candidate, nf, Some(memo), true));
                }
                break;
            }
        }
    }
    Ok((ordinary, relaxed))
}

#[cfg(feature = "zns-decrypt")]
pub use zns::EncodingMismatch;

/// Conversions between upstream `orchard` and `zns-orchard`.
///
/// Values cross by their canonical byte encodings. Every input was already
/// parsed or derived by one crate, so the other accepts it unless the two
/// disagree on an encoding — a bug, reported as [`EncodingMismatch`].
#[cfg(feature = "zns-decrypt")]
pub(crate) mod zns {
    use zcash_note_encryption::EphemeralKeyBytes;
    use zns_orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
    use zns_orchard::note_encryption::CompactAction;

    use super::COMPACT_NOTE_SIZE;
    use crate::proto::CompactOrchardAction;

    /// `orchard` and `zns-orchard` disagreed on the encoding of a value.
    #[derive(Debug, thiserror::Error)]
    #[error("orchard and zns-orchard disagree on the encoding of a {0}")]
    pub struct EncodingMismatch(&'static str);

    // Key and nullifier parsing is the same code in both crates (the fork
    // leaves `keys.rs` untouched and only widens `Nullifier::derive`'s
    // visibility), so these conversions cannot fail.

    pub(crate) fn fvk_to_zns(
        fvk: &orchard::keys::FullViewingKey,
    ) -> zns_orchard::keys::FullViewingKey {
        zns_orchard::keys::FullViewingKey::from_bytes(&fvk.to_bytes())
            .expect("both crates parse full viewing keys identically")
    }

    pub(crate) fn ivk_to_zns(
        ivk: &orchard::keys::IncomingViewingKey,
    ) -> zns_orchard::keys::IncomingViewingKey {
        zns_orchard::keys::IncomingViewingKey::from_bytes(&ivk.to_bytes())
            .expect("both crates parse incoming viewing keys identically")
    }

    pub(crate) fn nullifier_from_zns(nf: Nullifier) -> orchard::note::Nullifier {
        orchard::note::Nullifier::from_bytes(&nf.to_bytes())
            .expect("both crates parse nullifiers identically")
    }

    pub(crate) fn action_to_zns<T>(
        action: &orchard::Action<T>,
    ) -> Result<zns_orchard::Action<()>, EncodingMismatch> {
        let enc = action.encrypted_note();
        let rk: [u8; 32] = action.rk().into();
        zns_orchard::Action::from_parts(
            Nullifier::from_bytes(&action.nullifier().to_bytes())
                .into_option()
                .ok_or(EncodingMismatch("nullifier"))?,
            rk.try_into().map_err(|_| EncodingMismatch("rk"))?,
            ExtractedNoteCommitment::from_bytes(&action.cmx().to_bytes())
                .into_option()
                .ok_or(EncodingMismatch("note commitment"))?,
            TransmittedNoteCiphertext {
                epk_bytes: enc.epk_bytes,
                enc_ciphertext: enc.enc_ciphertext,
                out_ciphertext: enc.out_ciphertext,
            },
            zns_orchard::value::ValueCommitment::from_bytes(&action.cv_net().to_bytes())
                .into_option()
                .ok_or(EncodingMismatch("value commitment"))?,
            (),
        )
        .map_err(|_| EncodingMismatch("action"))
    }

    pub(crate) fn address_from_zns(
        address: &zns_orchard::Address,
    ) -> Result<orchard::Address, EncodingMismatch> {
        orchard::Address::from_raw_address_bytes(&address.to_raw_address_bytes())
            .into_option()
            .ok_or(EncodingMismatch("address"))
    }

    pub(crate) fn note_from_zns(
        note: &zns_orchard::Note,
    ) -> Result<orchard::Note, EncodingMismatch> {
        use orchard::note::{NoteVersion, RandomSeed, Rho};

        let rho = Rho::from_bytes(&note.rho().to_bytes())
            .into_option()
            .ok_or(EncodingMismatch("rho"))?;
        let rseed = RandomSeed::from_bytes(*note.rseed().as_bytes(), &rho)
            .into_option()
            .ok_or(EncodingMismatch("rseed"))?;
        let version = match note.version() {
            zns_orchard::note::NoteVersion::V2 => NoteVersion::V2,
            zns_orchard::note::NoteVersion::V3 => NoteVersion::V3,
        };
        orchard::Note::from_parts(
            address_from_zns(&note.recipient())?,
            orchard::value::NoteValue::from_raw(note.value().inner()),
            rho,
            rseed,
            version,
        )
        .into_option()
        .ok_or(EncodingMismatch("note"))
    }

    /// [`super::parse_compact_orchard`], producing the fork's type.
    pub(crate) fn parse_compact(a: &CompactOrchardAction) -> Option<CompactAction> {
        let nf_bytes: &[u8; 32] = a.nullifier.as_slice().try_into().ok()?;
        let nullifier = Nullifier::from_bytes(nf_bytes).into_option()?;
        let cmx_bytes: &[u8; 32] = a.cmx.as_slice().try_into().ok()?;
        let cmx = ExtractedNoteCommitment::from_bytes(cmx_bytes).into_option()?;
        let ephemeral_key = EphemeralKeyBytes(a.ephemeral_key.as_slice().try_into().ok()?);
        let enc_ciphertext: [u8; COMPACT_NOTE_SIZE] = a.ciphertext.as_slice().try_into().ok()?;

        Some(CompactAction::from_parts(
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext,
        ))
    }
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

#[cfg(all(test, feature = "zns-decrypt"))]
mod tests {
    use orchard::keys::{FullViewingKey, SpendingKey};
    use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
    use orchard::note_encryption::ENC_CIPHERTEXT_SIZE;
    use orchard::value::ValueCommitment;
    use zcash_note_encryption::note_bytes::NoteBytesData;
    use zip32::Scope;

    use super::{
        decrypt_full_ironwood_relaxed, recover_outgoing_ironwood_relaxed, zns, ScanningKey,
        ScanningKeys,
    };

    fn fvk() -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).expect("spending key"))
    }

    #[test]
    fn viewing_keys_cross_to_the_same_keys() {
        let fvk = fvk();
        let zns_fvk = zns::fvk_to_zns(&fvk);
        assert_eq!(zns_fvk.to_bytes(), fvk.to_bytes());
        for scope in [Scope::External, Scope::Internal] {
            assert_eq!(
                zns_fvk.to_ivk(scope).to_bytes(),
                fvk.to_ivk(scope).to_bytes()
            );
            assert_eq!(zns_fvk.to_ovk(scope).as_ref(), fvk.to_ovk(scope).as_ref());
            assert_eq!(
                zns::ivk_to_zns(&fvk.to_ivk(scope)).to_bytes(),
                fvk.to_ivk(scope).to_bytes()
            );
        }
    }

    #[test]
    fn a_note_crosses_with_its_commitment_and_nullifier() {
        let fvk = fvk();
        let zns_fvk = zns::fvk_to_zns(&fvk);
        let recipient = zns_fvk.address_at(0u32, Scope::External);
        let mut rho_bytes = [0; 32];
        rho_bytes[0] = 1;
        let rho = zns_orchard::note::Rho::from_bytes(&rho_bytes).expect("rho");
        let rseed = zns_orchard::note::RandomSeed::from_bytes([3; 32], &rho).expect("rseed");

        for version in [
            zns_orchard::note::NoteVersion::V2,
            zns_orchard::note::NoteVersion::V3,
        ] {
            let note = zns_orchard::Note::from_parts(
                recipient,
                zns_orchard::value::NoteValue::from_raw(5),
                rho,
                rseed,
                version,
            )
            .expect("note");
            let crossed = zns::note_from_zns(&note).expect("note crosses");

            assert_eq!(
                ExtractedNoteCommitment::from(crossed.commitment()).to_bytes(),
                zns_orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes()
            );
            assert_eq!(
                crossed.nullifier(&fvk).to_bytes(),
                note.nullifier(&zns_fvk).to_bytes()
            );
            assert_eq!(
                crossed.recipient().to_raw_address_bytes(),
                recipient.to_raw_address_bytes()
            );
            assert_eq!(crossed.value().inner(), 5);
        }
    }

    #[test]
    fn an_action_crosses_field_for_field() {
        let fvk = fvk();
        let fvk_bytes = fvk.to_bytes();
        let ak: [u8; 32] = fvk_bytes[..32].try_into().unwrap();
        // pk_d: a valid, non-identity point, so it also serves as epk and cv_net.
        let pk_d: [u8; 32] = fvk.address_at(0u32, Scope::External).to_raw_address_bytes()[11..]
            .try_into()
            .unwrap();
        let action = orchard::Action::from_parts(
            Nullifier::from_bytes(&[0; 32]).expect("nullifier"),
            ak.try_into().expect("rk"),
            ExtractedNoteCommitment::from_bytes(&[0; 32]).expect("cmx"),
            TransmittedNoteCiphertext {
                epk_bytes: pk_d,
                enc_ciphertext: NoteBytesData([5; ENC_CIPHERTEXT_SIZE]),
                out_ciphertext: [6; 80],
            },
            ValueCommitment::from_bytes(&pk_d).expect("cv_net"),
            (),
        )
        .expect("action");

        let crossed = zns::action_to_zns(&action).expect("action crosses");
        assert_eq!(
            crossed.nullifier().to_bytes(),
            action.nullifier().to_bytes()
        );
        assert_eq!(
            <[u8; 32]>::from(crossed.rk()),
            <[u8; 32]>::from(action.rk())
        );
        assert_eq!(crossed.cmx().to_bytes(), action.cmx().to_bytes());
        assert_eq!(crossed.cv_net().to_bytes(), action.cv_net().to_bytes());
        let (enc, crossed_enc) = (action.encrypted_note(), crossed.encrypted_note());
        assert_eq!(crossed_enc.epk_bytes, enc.epk_bytes);
        assert_eq!(crossed_enc.enc_ciphertext.0, enc.enc_ciphertext.0);
        assert_eq!(crossed_enc.out_ciphertext, enc.out_ciphertext);
    }

    /// A standard Ironwood note, encrypted by upstream `orchard`, comes back
    /// out of the fork's relaxed scan as the same ordinary note.
    #[test]
    fn an_upstream_ironwood_note_round_trips_through_the_relaxed_scan() {
        use orchard::note::{NoteVersion, RandomSeed, Rho};
        use orchard::note_encryption::{IronwoodDomain, IronwoodNoteEncryption};
        use orchard::value::NoteValue;
        use zcash_note_encryption::Domain;

        let fvk = fvk();
        let scope = Scope::External;
        let keys = ScanningKeys {
            sapling: Vec::new(),
            orchard: vec![ScanningKey {
                ivk: fvk.to_ivk(scope).prepare(),
                nk: Some(fvk.clone()),
                ovk: Some(fvk.to_ovk(scope)),
                scope,
            }],
            zns_orchard: {
                let zns_fvk = zns::fvk_to_zns(&fvk);
                vec![ScanningKey {
                    ivk: zns_fvk.to_ivk(scope).prepare(),
                    nk: Some(zns_fvk.clone()),
                    ovk: Some(zns_fvk.to_ovk(scope)),
                    scope,
                }]
            },
        };

        // The note's rho is the action's nullifier.
        let mut nf_bytes = [0; 32];
        nf_bytes[0] = 1;
        let nf = Nullifier::from_bytes(&nf_bytes).expect("nullifier");
        let rho = Rho::from_bytes(&nf_bytes).expect("rho");
        let rseed = RandomSeed::from_bytes([3; 32], &rho).expect("rseed");
        let recipient = fvk.address_at(0u32, scope);
        let note = orchard::Note::from_parts(
            recipient,
            NoteValue::from_raw(5),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .expect("note");
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let memo = [9; 512];

        let pk_d: [u8; 32] = recipient.to_raw_address_bytes()[11..].try_into().unwrap();
        let cv_net = ValueCommitment::from_bytes(&pk_d).expect("cv_net");
        let ak: [u8; 32] = fvk.to_bytes()[..32].try_into().unwrap();
        let encryption = IronwoodNoteEncryption::new(Some(fvk.to_ovk(scope)), note, memo);
        let action = orchard::Action::from_parts(
            nf,
            ak.try_into().expect("rk"),
            cmx,
            TransmittedNoteCiphertext {
                epk_bytes: IronwoodDomain::epk_bytes(encryption.epk()).0,
                enc_ciphertext: encryption.encrypt_note_plaintext(),
                out_ciphertext: encryption.encrypt_outgoing_plaintext(
                    &cv_net,
                    &cmx,
                    &mut rand::rng(),
                ),
            },
            cv_net,
            (),
        )
        .expect("action");

        let check = |hit: &super::DecryptResult<orchard::Note, orchard::Address>| {
            assert_eq!(
                ExtractedNoteCommitment::from(hit.note.commitment()).to_bytes(),
                cmx.to_bytes()
            );
            assert_eq!(hit.note.value().inner(), 5);
            assert_eq!(
                hit.recipient.to_raw_address_bytes(),
                recipient.to_raw_address_bytes()
            );
            assert_eq!(hit.memo, Some(memo));
            assert_eq!(hit.key_index, 0);
        };

        let (received, relaxed) =
            decrypt_full_ironwood_relaxed(std::slice::from_ref(&action), &keys).expect("scan");
        check(received[0].as_ref().expect("the ivk decrypts the note"));
        assert!(relaxed.is_empty());

        let (sent, relaxed) =
            recover_outgoing_ironwood_relaxed(std::slice::from_ref(&action), &keys).expect("scan");
        check(sent[0].as_ref().expect("the ovk recovers the note"));
        assert!(relaxed.is_empty());
    }
}
