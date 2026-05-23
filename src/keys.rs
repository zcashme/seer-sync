//! Key derivation — prepare per-pool IVKs from a UIVK.

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use sapling::note_encryption::PreparedIncomingViewingKey as SaplingPreparedIvk;
use zcash_keys::keys::UnifiedIncomingViewingKey;

/// Prepared per-pool IVKs ready to feed into [`crate::scan::sync`].
#[derive(Default)]
pub struct Keys {
    /// Orchard incoming viewing key, if the caller has one.
    pub orchard: Option<OrchardPreparedIvk>,
    /// Sapling incoming viewing key, if the caller has one.
    pub sapling: Option<SaplingPreparedIvk>,
}

impl Keys {
    /// Build [`Keys`] from a Unified Incoming Viewing Key.
    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            orchard: uivk.orchard().as_ref().map(OrchardPreparedIvk::new),
            sapling: uivk.sapling().as_ref().map(|ivk| ivk.prepare()),
        }
    }

    /// `true` when there's nothing to scan with.
    pub fn is_empty(&self) -> bool {
        self.orchard.is_none() && self.sapling.is_none()
    }
}
