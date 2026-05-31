//! Prepared per-pool viewing keys for trial decryption.
//!
//! Three key paths are supported:
//! - [`IvkKeys`] — incoming only; no spend detection
//! - [`FvkKeys`] — incoming + nullifier derivation + outgoing; full balance
//! - [`OvkKeys`] — outgoing only; reveals sent history (full transactions required)

use orchard::keys::{
    FullViewingKey as OrchardFvk, OutgoingViewingKey as OrchardOvk,
    PreparedIncomingViewingKey as OrchardPreparedIvk, Scope as OrchardScope,
};
use sapling::{
    keys::OutgoingViewingKey as SaplingOvk,
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

/// Backward-compatible type alias.
pub type Keys = IvkKeys;

/// Full Viewing Keys — enables incoming detection, nullifier derivation, and outgoing recovery.
///
/// Use this path when you need accurate balance accounting. The FVK can detect
/// when received notes are subsequently spent (via nullifier matching in compact spends).
pub struct FvkKeys {
    /// Prepared IVKs for compact trial decryption.
    pub(crate) orchard_ivk: Option<OrchardPreparedIvk>,
    pub(crate) sapling_ivk: Option<SaplingPreparedIvk>,
    /// Full FVKs retained for nullifier derivation.
    pub(crate) orchard_fvk: Option<OrchardFvk>,
    pub(crate) sapling_dfvk: Option<SaplingDfvk>,
    /// OVKs for out-ciphertext recovery.
    pub(crate) orchard_ovk: Option<OrchardOvk>,
    pub(crate) sapling_ovk: Option<SaplingOvk>,
    /// Transparent account public key for t-address derivation.
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

        let orchard_ovk = orchard_fvk
            .as_ref()
            .map(|fvk| fvk.to_ovk(OrchardScope::External));

        let sapling_ovk = sapling_dfvk
            .as_ref()
            .map(|dfvk| dfvk.to_ovk(zip32::Scope::External));

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

/// Outgoing Viewing Keys — reveals notes *this wallet sent*.
///
/// Requires full transaction data (not available from compact blocks).
/// Use [`FvkKeys`] if you also need to see received notes.
pub struct OvkKeys {
    pub(crate) orchard: Option<OrchardOvk>,
    pub(crate) sapling: Option<SaplingOvk>,
}

impl OvkKeys {
    /// Build from individual pool OVKs.
    pub fn new(orchard: Option<OrchardOvk>, sapling: Option<SaplingOvk>) -> Self {
        Self { orchard, sapling }
    }

    /// Extract OVKs from an existing [`FvkKeys`] without consuming it.
    pub fn from_fvk_keys(fvk: &FvkKeys) -> Self {
        Self {
            orchard: fvk.orchard_ovk.clone(),
            sapling: fvk.sapling_ovk.clone(),
        }
    }

    /// `true` when no OVKs are present.
    pub fn is_empty(&self) -> bool {
        self.orchard.is_none() && self.sapling.is_none()
    }
}
