//! Prepared per-pool IVKs for trial decryption.

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use sapling::note_encryption::PreparedIncomingViewingKey as SaplingPreparedIvk;
use zcash_keys::keys::UnifiedIncomingViewingKey;

/// Prepared per-pool IVKs ready to feed into [`crate::scan::sync`].
///
/// The expensive scalar precomputation happens once at construction and is
/// amortized across all blocks passed to `sync`.
pub struct Keys {
    pub(crate) orchard: Option<OrchardPreparedIvk>,
    pub(crate) sapling: Option<SaplingPreparedIvk>,
}

impl Keys {
    /// Build from a Unified Incoming Viewing Key.
    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            orchard: uivk.orchard().as_ref().map(OrchardPreparedIvk::new),
            sapling: uivk.sapling().as_ref().map(|ivk| ivk.prepare()),
        }
    }

    /// `true` when no IVKs are present — `sync` will produce no hits.
    pub fn is_empty(&self) -> bool {
        self.orchard.is_none() && self.sapling.is_none()
    }
}
