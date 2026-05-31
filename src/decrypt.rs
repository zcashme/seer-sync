//! Full note decryption — recovers value, recipient, and memo from a complete transaction.
//!
//! Distinct from compact decryption in scan.rs: compact blocks carry only the
//! first 52 bytes of enc_ciphertext (enough to confirm ownership), while full
//! decryption requires the complete 580-byte enc_ciphertext from a fetched tx.

use orchard::{
    keys::PreparedIncomingViewingKey as OrchardPreparedIvk, note_encryption::OrchardDomain, Action,
};
use sapling::{
    bundle::OutputDescription,
    keys::PreparedIncomingViewingKey as SaplingPreparedIvk,
    note_encryption::{SaplingDomain, Zip212Enforcement},
};
use zcash_note_encryption::try_note_decryption;

/// ZIP-302 memo size in bytes. Same for Sapling and Orchard.
pub const MEMO_SIZE: usize = 512;

/// Trial-decrypt one Orchard [`Action`] with one IVK.
///
/// Returns `Some((note, recipient, memo))` iff the IVK matches the ephemeral
/// key, the AEAD authenticates, and the on-chain `cmx` matches. Requires a
/// full action with complete `enc_ciphertext` — not available from compact blocks.
pub fn try_decrypt_orchard<A>(
    action: &Action<A>,
    ivk: &OrchardPreparedIvk,
) -> Option<(orchard::Note, orchard::Address, Box<[u8; MEMO_SIZE]>)> {
    let (note, recipient, memo) = try_note_decryption(&OrchardDomain::for_action(action), ivk, action)?;
    Some((note, recipient, Box::new(memo)))
}

/// Trial-decrypt one Sapling [`OutputDescription`] with one IVK.
///
/// `zip212` must match the block height — derive it via
/// `zcash_primitives::transaction::components::sapling::zip212_enforcement`.
pub fn try_decrypt_sapling<Proof>(
    output: &OutputDescription<Proof>,
    ivk: &SaplingPreparedIvk,
    zip212: Zip212Enforcement,
) -> Option<(sapling::Note, sapling::PaymentAddress, Box<[u8; MEMO_SIZE]>)> {
    let (note, recipient, memo) = try_note_decryption(&SaplingDomain::new(zip212), ivk, output)?;
    Some((note, recipient, Box::new(memo)))
}
