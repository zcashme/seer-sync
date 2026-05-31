//! Full Viewing Keys — incoming + spend detection + outgoing recovery.

use orchard::keys::{
    FullViewingKey as OrchardFvk, OutgoingViewingKey as OrchardOvk,
    PreparedIncomingViewingKey as OrchardPreparedIvk, Scope as OrchardScope,
};
use sapling::{
    keys::OutgoingViewingKey as SaplingOvk,
    note_encryption::PreparedIncomingViewingKey as SaplingPreparedIvk,
    zip32::DiversifiableFullViewingKey as SaplingDfvk,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_transparent::keys::AccountPubKey;

/// Full Viewing Keys — enables incoming detection, nullifier derivation, and
/// outgoing recovery.
///
/// Use this path when you need accurate balance accounting. The FVK detects
/// when received notes are subsequently spent via nullifier matching in compact
/// spend fields.
pub struct FvkKeys {
    pub(crate) orchard_ivk: Option<OrchardPreparedIvk>,
    pub(crate) sapling_ivk: Option<SaplingPreparedIvk>,
    pub(crate) orchard_fvk: Option<OrchardFvk>,
    pub(crate) sapling_dfvk: Option<SaplingDfvk>,
    pub(crate) orchard_ovk: Option<OrchardOvk>,
    pub(crate) sapling_ovk: Option<SaplingOvk>,
    pub(crate) transparent: Option<AccountPubKey>,
}

impl FvkKeys {
    /// Build from a Unified Full Viewing Key.
    pub fn from_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        let orchard_fvk = ufvk.orchard().cloned();
        let sapling_dfvk = ufvk.sapling().cloned();

        let orchard_ivk = orchard_fvk
            .as_ref()
            .map(|fvk| OrchardPreparedIvk::new(&fvk.to_ivk(OrchardScope::External)));

        let sapling_ivk = sapling_dfvk
            .as_ref()
            .map(|dfvk| SaplingPreparedIvk::new(&dfvk.to_ivk(zip32::Scope::External)));

        let orchard_ovk = orchard_fvk.as_ref().map(|fvk| fvk.to_ovk(OrchardScope::External));
        let sapling_ovk =
            sapling_dfvk.as_ref().map(|dfvk| dfvk.to_ovk(zip32::Scope::External));

        let transparent = ufvk.transparent().cloned();

        Self {
            orchard_ivk,
            sapling_ivk,
            orchard_fvk,
            sapling_dfvk,
            orchard_ovk,
            sapling_ovk,
            transparent,
        }
    }

    /// `true` when no shielded FVKs are present.
    pub fn is_empty(&self) -> bool {
        self.orchard_fvk.is_none() && self.sapling_dfvk.is_none()
    }

    /// Returns a reference to the Orchard FVK if present.
    pub fn orchard_fvk(&self) -> Option<&OrchardFvk> {
        self.orchard_fvk.as_ref()
    }

    /// Returns a reference to the Sapling diversifiable FVK if present.
    pub fn sapling_dfvk(&self) -> Option<&SaplingDfvk> {
        self.sapling_dfvk.as_ref()
    }

    /// Returns the transparent account public key if present.
    pub fn transparent(&self) -> Option<&AccountPubKey> {
        self.transparent.as_ref()
    }
}
