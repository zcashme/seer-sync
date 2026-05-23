//! Layer 1 — trial-decrypt one note with one IVK.
//!

use orchard::{
    keys::PreparedIncomingViewingKey as OrchardPreparedIvk, note_encryption::OrchardDomain, Action,
};
use sapling::{
    bundle::OutputDescription,
    keys::PreparedIncomingViewingKey as SaplingPreparedIvk,
    note_encryption::{SaplingDomain, Zip212Enforcement},
};
use zcash_note_encryption::try_note_decryption;

/// ZIP-302 memo size, bytes. Same for Sapling and Orchard.
pub const MEMO_SIZE: usize = 512;

/// Trial-decrypt one Orchard [`Action`] with one IVK.
pub fn try_decrypt_orchard<A>(
    action: &Action<A>,
    ivk: &OrchardPreparedIvk,
) -> Option<(orchard::Note, orchard::Address, [u8; MEMO_SIZE])> {
    let domain = OrchardDomain::for_action(action);
    try_note_decryption(&domain, ivk, action)
}

/// Trial-decrypt one Sapling [`OutputDescription`] with one IVK.
pub fn try_decrypt_sapling<Proof>(
    output: &OutputDescription<Proof>,
    ivk: &SaplingPreparedIvk,
    zip212: Zip212Enforcement,
) -> Option<(sapling::Note, sapling::PaymentAddress, [u8; MEMO_SIZE])> {
    let domain = SaplingDomain::new(zip212);
    try_note_decryption(&domain, ivk, output)
}
