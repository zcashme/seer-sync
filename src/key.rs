//! The crate's view-key boundary.
//!
//! [`ViewKey`] pre-derives all keys the scan engine needs from a Unified Full
//! Viewing Key and then drops it. `zcash_keys` only appears inside the
//! [`ViewKey::decode`] constructor — it never touches the struct definition or
//! any other public surface.

use orchard::keys::{
    FullViewingKey as OrchardFvk, OutgoingViewingKey as OrchardOvk,
    PreparedIncomingViewingKey as OrchardPreparedIvk,
};
use sapling::keys::{
    OutgoingViewingKey as SaplingOvk, PreparedIncomingViewingKey as SaplingPreparedIvk,
};
use sapling::NullifierDerivingKey;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;
use zip32::Scope;

/// A Zcash view-only key — the only key material the sync engine needs.
///
/// All protocol-specific keys are pre-derived at construction; the UFVK is
/// dropped immediately after. Construct one with [`ViewKey::decode`].
pub struct ViewKey {
    pub(crate) sapling_incoming: Vec<SaplingIncoming>,
    pub(crate) orchard_incoming: Vec<OrchardIncoming>,
    pub(crate) sapling_ovks: Vec<SaplingOvk>,
    pub(crate) orchard_ovks: Vec<OrchardOvk>,
}

/// A Sapling incoming viewing key paired with the nullifier-deriving key that
/// spots the spend of any note it detects. The two always travel together: a
/// nullifier is meaningless without the IVK that found the note.
pub(crate) struct SaplingIncoming {
    pub ivk: SaplingPreparedIvk,
    pub nk: NullifierDerivingKey,
}

/// An Orchard incoming viewing key paired with the full viewing key its detected
/// notes need for nullifier derivation.
pub(crate) struct OrchardIncoming {
    pub ivk: OrchardPreparedIvk,
    pub fvk: OrchardFvk,
}

impl ViewKey {
    /// Decodes a Unified Full Viewing Key from its `uview…` string encoding,
    /// pre-derives all scan keys, and drops the UFVK.
    pub fn decode(network: &Network, encoding: &str) -> Result<Self, String> {
        let ufvk = UnifiedFullViewingKey::decode(network, encoding)?;
        Ok(Self {
            sapling_incoming: per_scope(ufvk.sapling(), |dfvk, scope| SaplingIncoming {
                ivk: SaplingPreparedIvk::new(&dfvk.to_ivk(scope)),
                nk: dfvk.to_nk(scope),
            }),
            orchard_incoming: per_scope(ufvk.orchard(), |fvk, scope| OrchardIncoming {
                ivk: OrchardPreparedIvk::new(&fvk.to_ivk(scope)),
                fvk: fvk.clone(),
            }),
            sapling_ovks: per_scope(ufvk.sapling(), |dfvk, scope| dfvk.to_ovk(scope)),
            orchard_ovks: per_scope(ufvk.orchard(), |fvk, scope| fvk.to_ovk(scope)),
        })
    }
}

/// Derives one value per scope (external, internal) from an optional pool key,
/// returning an empty `Vec` when the pool is absent.
fn per_scope<K, T>(key: Option<&K>, derive: impl Fn(&K, Scope) -> T) -> Vec<T> {
    key.map(|k| [Scope::External, Scope::Internal].into_iter().map(|s| derive(k, s)).collect())
        .unwrap_or_default()
}
