//! Incoming Viewing Keys — compact trial decryption, no spend detection.

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use sapling::note_encryption::PreparedIncomingViewingKey as SaplingPreparedIvk;
use zcash_keys::keys::UnifiedIncomingViewingKey;

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
