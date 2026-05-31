//! Prepared per-pool viewing keys for trial decryption.
//!
//! Two key paths are supported:
//! - [`IvkKeys`] — incoming only; no spend detection
//! - [`FvkKeys`] — incoming + nullifier derivation; full balance
//!
//! An incoming viewing key is just the external-scope projection of a full
//! viewing key, so [`FvkKeys`] *composes* an [`IvkKeys`] rather than
//! re-deriving the same prepared scalars.

use orchard::keys::{
    FullViewingKey as OrchardFvk, PreparedIncomingViewingKey as OrchardPreparedIvk,
};
use sapling::{
    note_encryption::PreparedIncomingViewingKey as SaplingPreparedIvk,
    zip32::DiversifiableFullViewingKey as SaplingDfvk,
};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_transparent::keys::AccountPubKey;

/// Prepared IVKs built from a [`UnifiedIncomingViewingKey`].
///
/// Scalar precomputation happens once at construction and is amortised across
/// all blocks fed to [`crate::scan::scan_ivk`].
pub struct IvkKeys {
    pub(crate) orchard: Option<OrchardPreparedIvk>,
    pub(crate) sapling: Option<SaplingPreparedIvk>,
}

impl IvkKeys {
    /// Build from a Unified Incoming Viewing Key.
    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            orchard: uivk.orchard().as_ref().map(OrchardPreparedIvk::new),
            sapling: uivk.sapling().as_ref().map(|ivk| ivk.prepare()),
        }
    }

    /// `true` when no IVKs are present — scanning will produce no hits.
    pub fn is_empty(&self) -> bool {
        self.orchard.is_none() && self.sapling.is_none()
    }
}

/// Full Viewing Keys — enables incoming detection and nullifier derivation.
///
/// Use this path when you need accurate balance accounting. The FVK detects
/// when received notes are subsequently spent via nullifier matching in compact
/// spend fields.
pub struct FvkKeys {
    /// Incoming viewing keys, derived from the UFVK's contained UIVK.
    pub(crate) ivk: IvkKeys,
    pub(crate) orchard_fvk: Option<OrchardFvk>,
    pub(crate) sapling_dfvk: Option<SaplingDfvk>,
    pub(crate) transparent: Option<AccountPubKey>,
}

impl FvkKeys {
    /// Build from a Unified Full Viewing Key.
    ///
    /// The incoming viewing keys are obtained via
    /// [`UnifiedFullViewingKey::to_unified_incoming_viewing_key`] rather than
    /// re-derived here — the UIVK *is* the external-scope IVK of this UFVK.
    pub fn from_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        Self {
            ivk: IvkKeys::from_uivk(&ufvk.to_unified_incoming_viewing_key()),
            orchard_fvk: ufvk.orchard().cloned(),
            sapling_dfvk: ufvk.sapling().cloned(),
            transparent: ufvk.transparent().cloned(),
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
