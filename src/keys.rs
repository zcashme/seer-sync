//! Parse unified viewing keys into per-pool scanning keys.
//!
//! This module only *parses* — it turns a [`UnifiedIncomingViewingKey`] or
//! [`UnifiedFullViewingKey`] into the per-pool incoming keys (and, for a full
//! key, the nullifier-deriving material) the [`crate::sync`] engine consumes.

// The parsed keys are read only by the `lwd` scanner; without that feature the
// fields are unused, but the parsing is still valid sans-IO API.
#![cfg_attr(not(feature = "lwd"), allow(dead_code))]

use orchard::keys::{FullViewingKey as OrchardFvk, IncomingViewingKey as OrchardIvk};
use sapling::{zip32::IncomingViewingKey as SaplingIvk, NullifierDerivingKey};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zip32::Scope;

/// An incoming viewing key paired with an optional nullifier-deriving key.
///
/// Mirrors `zcash_client_backend`'s `ScanningKey<Ivk, Nk>` — which we can't
/// import (it lives in the banned crate) — minus its account metadata. `nk`
/// is `Some` for a full key and `None` for an incoming-only key.
pub(crate) struct ScanningKey<Ivk, Nk> {
    pub(crate) ivk: Ivk,
    /// Nullifier-deriving key — `Some` for a full key, `None` for incoming-only.
    /// [`crate::sync::scan`] uses it to derive each note's nullifier (and so
    /// detect spends); without it, only incoming notes are seen.
    pub(crate) nk: Option<Nk>,
}

/// Per-pool scanning keys parsed from one unified viewing key.
///
/// Each pool is `Some` only when the key has that component. Build with
/// [`ScanningKeys::from_uivk`] (incoming-only) or [`ScanningKeys::from_ufvk`]
/// (full — additionally carries each pool's nullifier-deriving key).
pub struct ScanningKeys {
    pub(crate) sapling: Option<ScanningKey<SaplingIvk, NullifierDerivingKey>>,
    pub(crate) orchard: Option<ScanningKey<OrchardIvk, OrchardFvk>>,
}

impl ScanningKeys {
    /// Incoming-only keys from a UIVK: each pool's `ivk`, with `nk = None`.
    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            sapling: uivk.sapling().as_ref().map(|ivk| ScanningKey { ivk: ivk.clone(), nk: None }),
            orchard: uivk.orchard().as_ref().map(|ivk| ScanningKey { ivk: ivk.clone(), nk: None }),
        }
    }

    /// Full keys from a UFVK: each pool's `ivk` plus `nk = Some(..)`. External
    /// scope only — change (internal scope) is the caller's concern.
    ///
    /// The `ivk`s come from the UFVK's contained UIVK (so their type matches the
    /// incoming-only path); the FVKs are used only to derive `nk`.
    pub fn from_ufvk(ufvk: &UnifiedFullViewingKey) -> Self {
        let uivk = ufvk.to_unified_incoming_viewing_key();
        Self {
            sapling: uivk.sapling().as_ref().zip(ufvk.sapling()).map(|(ivk, dfvk)| ScanningKey {
                ivk: ivk.clone(),
                nk: Some(dfvk.to_nk(Scope::External)),
            }),
            orchard: uivk.orchard().as_ref().zip(ufvk.orchard()).map(|(ivk, fvk)| ScanningKey {
                ivk: ivk.clone(),
                nk: Some(fvk.clone()),
            }),
        }
    }
}
