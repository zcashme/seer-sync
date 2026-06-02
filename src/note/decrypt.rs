//! Note decryption — recover a note (and, from the full ciphertext, its memo)
//! from its on-chain output.
//!
//! Two entry points to one concern:
//!
//! - **compact** ([`try_compact_sapling`] / [`try_compact_orchard`]) — trial-
//!   decrypt the 52-byte compact ciphertext lightwalletd serves inside blocks.
//!   Recovers value / recipient / rseed; the memo was truncated away upstream,
//!   so there is none to recover here. This is the block-scanning path.
//! - **full** ([`try_decrypt_sapling`] / [`try_decrypt_orchard`]) — trial-
//!   decrypt the complete 580-byte ciphertext from a fetched transaction.
//!   Recovers the same note *plus its 512-byte memo* — the memo is simply the
//!   tail of the same plaintext, so it falls out of the one decryption.
//!
//! Both are sans-IO: ciphertext + key → note. Fetching the full transaction is
//! a separate concern ([`crate::sync::chain`]).

// The compact primitives are exercised only by the `lwd` scanner; without that
// feature they're unused here but remain valid sans-IO building blocks.
#![cfg_attr(not(feature = "lwd"), allow(dead_code))]

use orchard::{
    keys::PreparedIncomingViewingKey as OrchardPreparedIvk,
    note_encryption::{CompactAction, OrchardDomain},
    Action,
};
use sapling::{
    bundle::OutputDescription,
    keys::PreparedIncomingViewingKey as SaplingPreparedIvk,
    note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement},
};
use zcash_note_encryption::{batch, try_note_decryption, EphemeralKeyBytes};

use crate::proto::{CompactOrchardAction, CompactSaplingOutput};

/// ZIP-302 memo size in bytes (same for Sapling and Orchard).
pub const MEMO_SIZE: usize = 512;

// ─── Compact decryption (block-scanning path) ──────────────────────────────────

/// Trial-decrypt a batch of compact Sapling outputs with an IVK.
///
/// Returns one slot per input `desc`, in order: `Some((note, recipient))` where
/// the IVK matched and the note commitment checked out, `None` otherwise. No
/// memo — the compact ciphertext is truncated before it.
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

/// Trial-decrypt a batch of compact Orchard actions with an IVK. See
/// [`try_compact_sapling`].
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

/// Proto → `sapling` compact output. Deserialization glue, not crypto.
pub(crate) fn parse_sapling(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu_bytes: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes))?;
    let ephemeral_key = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let enc_ciphertext = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key, enc_ciphertext })
}

/// Proto → `orchard` compact action. Deserialization glue, not crypto.
pub(crate) fn parse_orchard(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}

// ─── Full decryption (memo-recovery path) ──────────────────────────────────────

/// Trial-decrypt one Orchard [`Action`] with an IVK.
///
/// Returns `Some((note, recipient, memo))` iff the IVK matches the ephemeral key,
/// the AEAD authenticates, and the on-chain `cmx` matches the decrypted note.
/// Requires the full 580-byte `enc_ciphertext` — **not** available from compact blocks.
pub fn try_decrypt_orchard<A>(
    action: &Action<A>,
    ivk: &OrchardPreparedIvk,
) -> Option<(orchard::Note, orchard::Address, Box<[u8; MEMO_SIZE]>)> {
    let (note, recipient, memo) =
        try_note_decryption(&OrchardDomain::for_action(action), ivk, action)?;
    Some((note, recipient, Box::new(memo)))
}

/// Trial-decrypt one Sapling [`OutputDescription`] with an IVK.
///
/// `zip212` must match the block height — use `Zip212Enforcement::On` for
/// blocks after the Canopy activation (height 1_046_400 on mainnet).
pub fn try_decrypt_sapling<Proof>(
    output: &OutputDescription<Proof>,
    ivk: &SaplingPreparedIvk,
    zip212: Zip212Enforcement,
) -> Option<(sapling::Note, sapling::PaymentAddress, Box<[u8; MEMO_SIZE]>)> {
    let (note, recipient, memo) =
        try_note_decryption(&SaplingDomain::new(zip212), ivk, output)?;
    Some((note, recipient, Box::new(memo)))
}
