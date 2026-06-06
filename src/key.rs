//! The crate's view-key boundary.
//!
//! [`ViewKey`] pre-derives all keys the scan engine needs from a unified
//! viewing key and then drops it. It accepts either a Unified **Full** Viewing
//! Key (`uview1…`) or a Unified **Incoming** Viewing Key (`uivk1…`):
//!
//! * From a UFVK it derives, per scope, the incoming viewing key, the
//!   nullifier-deriving material (`nk`/`fvk`), and the outgoing viewing key —
//!   so it can detect received notes, compute their nullifiers, and recover
//!   outputs you sent.
//! * From a UIVK it derives only the incoming viewing key. A UIVK carries no
//!   `nk`/`fvk` and no OVK, so notes it finds have no nullifier and sent-output
//!   recovery is unavailable. This is a cryptographic limit of the key, not a
//!   missing feature.
//!
//! `zcash_keys` only appears inside the [`ViewKey::decode`] constructor — it
//! never touches the struct definition or any other public surface.

use orchard::keys::{
    FullViewingKey as OrchardFvk, OutgoingViewingKey as OrchardOvk,
    PreparedIncomingViewingKey as OrchardPreparedIvk,
};
use sapling::keys::{
    OutgoingViewingKey as SaplingOvk, PreparedIncomingViewingKey as SaplingPreparedIvk,
};
use sapling::NullifierDerivingKey;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_protocol::consensus::Network;
use zip32::Scope;

/// A Zcash view-only key — the only key material the sync engine needs.
///
/// All protocol-specific keys are pre-derived at construction; the unified key
/// is dropped immediately after. Construct one with [`ViewKey::decode`]. An
/// empty `Vec` means the pool (or capability) is absent: a sapling-less key has
/// an empty `sapling`, and an incoming-only key has empty `*_ovks`.
pub struct ViewKey {
    pub(crate) sapling: Vec<SaplingIncoming>,
    pub(crate) orchard: Vec<OrchardIncoming>,
    pub(crate) sapling_ovks: Vec<SaplingOvk>,
    pub(crate) orchard_ovks: Vec<OrchardOvk>,
}

/// A Sapling incoming viewing key paired with the nullifier-deriving key that
/// spots the spend of any note it detects. `nk` is `None` for an incoming-only
/// (UIVK) key, which cannot derive nullifiers.
pub(crate) struct SaplingIncoming {
    pub ivk: SaplingPreparedIvk,
    pub nk: Option<NullifierDerivingKey>,
}

/// An Orchard incoming viewing key paired with the full viewing key its detected
/// notes need for nullifier derivation. `fvk` is `None` for an incoming-only
/// (UIVK) key.
pub(crate) struct OrchardIncoming {
    pub ivk: OrchardPreparedIvk,
    pub fvk: Option<OrchardFvk>,
}

impl ViewKey {
    /// Decodes a unified viewing key from its string encoding, pre-derives all
    /// scan keys, and drops the unified key.
    ///
    /// Accepts a UFVK (`uview1…`) or a UIVK (`uivk1…`); the kind is detected
    /// automatically. Returns an error only if the input parses as neither.
    pub fn decode(network: &Network, encoding: &str) -> Result<Self, String> {
        match UnifiedFullViewingKey::decode(network, encoding) {
            Ok(ufvk) => Ok(Self::from_ufvk(&ufvk)),
            Err(ufvk_err) => match UnifiedIncomingViewingKey::decode(network, encoding) {
                Ok(uivk) => Ok(Self::from_uivk(&uivk)),
                Err(uivk_err) => Err(format!(
                    "not a recognized unified viewing key \
                     (as UFVK: {ufvk_err}; as UIVK: {uivk_err})"
                )),
            },
        }
    }

    /// Derives the full set of scan keys (incoming, nullifier, outgoing) from a
    /// Unified Full Viewing Key, one entry per scope (external, internal).
    fn from_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        Self {
            sapling: per_scope(ufvk.sapling(), |dfvk, scope| SaplingIncoming {
                ivk: SaplingPreparedIvk::new(&dfvk.to_ivk(scope)),
                nk: Some(dfvk.to_nk(scope)),
            }),
            orchard: per_scope(ufvk.orchard(), |fvk, scope| OrchardIncoming {
                ivk: OrchardPreparedIvk::new(&fvk.to_ivk(scope)),
                fvk: Some(fvk.clone()),
            }),
            sapling_ovks: per_scope(ufvk.sapling(), |dfvk, scope| dfvk.to_ovk(scope)),
            orchard_ovks: per_scope(ufvk.orchard(), |fvk, scope| fvk.to_ovk(scope)),
        }
    }

    /// Derives the incoming-only scan keys from a Unified Incoming Viewing Key.
    ///
    /// A UIVK carries a single (external) incoming key per pool and no
    /// nullifier or outgoing material, so `nk`/`fvk` are `None` and the OVK
    /// lists are empty.
    fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            sapling: uivk
                .sapling()
                .as_ref()
                .map(|ivk| vec![SaplingIncoming { ivk: ivk.prepare(), nk: None }])
                .unwrap_or_default(),
            orchard: uivk
                .orchard()
                .as_ref()
                .map(|ivk| vec![OrchardIncoming { ivk: OrchardPreparedIvk::new(ivk), fvk: None }])
                .unwrap_or_default(),
            sapling_ovks: Vec::new(),
            orchard_ovks: Vec::new(),
        }
    }
}

/// Derives one value per scope (external, internal) from an optional pool key,
/// returning an empty `Vec` when the pool is absent.
fn per_scope<K, T>(key: Option<&K>, derive: impl Fn(&K, Scope) -> T) -> Vec<T> {
    key.map(|k| [Scope::External, Scope::Internal].into_iter().map(|s| derive(k, s)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mainnet UFVK with both sapling and orchard pools.
    const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

    /// A UFVK has both pools, derives a nullifier key per scope (two scopes),
    /// and carries outgoing keys for sent-output recovery.
    #[test]
    fn ufvk_has_full_capability() {
        let key = ViewKey::decode(&Network::MainNetwork, UFVK).expect("decode UFVK");

        assert_eq!(key.sapling.len(), 2, "external + internal scopes");
        assert_eq!(key.orchard.len(), 2);
        assert!(key.sapling.iter().all(|s| s.nk.is_some()));
        assert!(key.orchard.iter().all(|o| o.fvk.is_some()));
        assert!(!key.sapling_ovks.is_empty());
        assert!(!key.orchard_ovks.is_empty());
    }

    /// The UIVK derived from the same key keeps incoming detection but loses
    /// nullifier derivation and outgoing recovery — one incoming key per pool,
    /// no `nk`/`fvk`, no OVKs.
    #[test]
    fn uivk_is_incoming_only() {
        let ufvk = UnifiedFullViewingKey::decode(&Network::MainNetwork, UFVK).unwrap();
        let uivk = ufvk.to_unified_incoming_viewing_key().encode(&Network::MainNetwork);

        let key = ViewKey::decode(&Network::MainNetwork, &uivk).expect("decode UIVK");

        assert_eq!(key.sapling.len(), 1, "UIVK carries a single incoming key");
        assert_eq!(key.orchard.len(), 1);
        assert!(key.sapling.iter().all(|s| s.nk.is_none()));
        assert!(key.orchard.iter().all(|o| o.fvk.is_none()));
        assert!(key.sapling_ovks.is_empty());
        assert!(key.orchard_ovks.is_empty());
    }

    #[test]
    fn rejects_non_viewing_key() {
        let err = match ViewKey::decode(&Network::MainNetwork, "not-a-key") {
            Ok(_) => panic!("expected a decode error"),
            Err(e) => e,
        };
        assert!(err.contains("UFVK") && err.contains("UIVK"), "got: {err}");
    }
}
