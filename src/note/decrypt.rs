//! Full note decryption — recovers value, recipient, and memo from a complete transaction.
//!
//! Distinct from compact decryption in [`crate::sync`]: compact blocks carry only
//! the first 52 bytes of `enc_ciphertext` (enough to confirm ownership and recover
//! note value / recipient), while full decryption requires the complete 580-byte
//! `enc_ciphertext` available from a fetched full transaction.

use orchard::{
    keys::PreparedIncomingViewingKey as OrchardPreparedIvk, note_encryption::OrchardDomain, Action,
};
use sapling::{
    bundle::OutputDescription, keys::PreparedIncomingViewingKey as SaplingPreparedIvk,
    note_encryption::{SaplingDomain, Zip212Enforcement},
};
use zcash_note_encryption::try_note_decryption;

/// ZIP-302 memo size in bytes (same for Sapling and Orchard).
pub const MEMO_SIZE: usize = 512;

// ─── IVK full decryption ──────────────────────────────────────────────────────

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
