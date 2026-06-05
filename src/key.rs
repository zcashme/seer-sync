//! The crate's view-key boundary.
//!
//! [`ViewKey`] seals a Unified Full Viewing Key behind this crate's own type, so
//! `zcash_keys` never appears in the public API. Callers construct a `ViewKey`
//! from its string encoding; the rest of the crate consumes only the *derived*
//! keys this module produces — it never sees the UFVK itself.

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
/// Wraps a Unified Full Viewing Key so that `zcash_keys` stays an implementation
/// detail. Construct one with [`ViewKey::decode`].
pub struct ViewKey {
    ufvk: UnifiedFullViewingKey,
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
    /// Decodes a Unified Full Viewing Key from its `uview…` string encoding.
    pub fn decode(network: &Network, encoding: &str) -> Result<Self, String> {
        Ok(Self { ufvk: UnifiedFullViewingKey::decode(network, encoding)? })
    }

    /// Sapling incoming keys, one per scope (external, internal). Empty if the
    /// UFVK carries no Sapling key.
    pub(crate) fn sapling_incoming(&self) -> Vec<SaplingIncoming> {
        per_scope(self.ufvk.sapling(), |dfvk, scope| SaplingIncoming {
            ivk: SaplingPreparedIvk::new(&dfvk.to_ivk(scope)),
            nk: dfvk.to_nk(scope),
        })
    }

    /// Orchard incoming keys, one per scope (external, internal). Empty if the
    /// UFVK carries no Orchard key.
    pub(crate) fn orchard_incoming(&self) -> Vec<OrchardIncoming> {
        per_scope(self.ufvk.orchard(), |fvk, scope| OrchardIncoming {
            ivk: OrchardPreparedIvk::new(&fvk.to_ivk(scope)),
            fvk: fvk.clone(),
        })
    }

    /// Sapling outgoing viewing keys, one per scope — for recovering sent notes.
    pub(crate) fn sapling_ovks(&self) -> Vec<SaplingOvk> {
        per_scope(self.ufvk.sapling(), |dfvk, scope| dfvk.to_ovk(scope))
    }

    /// Orchard outgoing viewing keys, one per scope — for recovering sent notes.
    pub(crate) fn orchard_ovks(&self) -> Vec<OrchardOvk> {
        per_scope(self.ufvk.orchard(), |fvk, scope| fvk.to_ovk(scope))
    }
}

/// Derives one value per scope (external, internal) from an optional pool key,
/// returning an empty `Vec` when the pool is absent.
fn per_scope<K, T>(key: Option<&K>, derive: impl Fn(&K, Scope) -> T) -> Vec<T> {
    key.map(|k| [Scope::External, Scope::Internal].into_iter().map(|s| derive(k, s)).collect())
        .unwrap_or_default()
}
