//! Outgoing Viewing Keys — reveals notes this wallet sent.

use orchard::keys::OutgoingViewingKey as OrchardOvk;
use sapling::keys::OutgoingViewingKey as SaplingOvk;

use super::fvk::FvkKeys;

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
            sapling: fvk.sapling_ovk,
        }
    }

    /// `true` when no OVKs are present.
    pub fn is_empty(&self) -> bool {
        self.orchard.is_none() && self.sapling.is_none()
    }
}
