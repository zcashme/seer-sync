use orchard::keys::{
    FullViewingKey as OrchardFvk, OutgoingViewingKey as OrchardOvk,
    PreparedIncomingViewingKey as OrchardPreparedIvk,
};
use sapling::keys::{
    OutgoingViewingKey as SaplingOvk, PreparedIncomingViewingKey as SaplingPreparedIvk,
};
use sapling::NullifierDerivingKey;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_protocol::consensus::Network;
use zcash_transparent::keys::{
    ExternalIvk, IncomingViewingKey, InternalIvk, NonHardenedChildIndex,
};
use zip32::Scope;

pub struct ViewKey {
    pub(crate) sapling: Vec<SaplingIncoming>,
    pub(crate) orchard: Vec<OrchardIncoming>,
    pub(crate) sapling_ovks: Vec<SaplingOvk>,
    pub(crate) orchard_ovks: Vec<OrchardOvk>,
    pub(crate) transparent: Option<TransparentIncoming>,
}

pub(crate) struct TransparentIncoming {
    pub external: ExternalIvk,
    pub internal: Option<InternalIvk>,
}

impl TransparentIncoming {
    /// Encoded P2PKH addresses with their child indices for `0..upto` in one
    /// scope. Indices whose BIP-32 derivation is invalid (cryptographically
    /// negligible) are skipped, hence the explicit index in each pair.
    pub fn scoped_addresses(
        &self,
        network: &Network,
        internal: bool,
        upto: u32,
    ) -> Vec<(String, u32)> {
        let derive = |i: u32| {
            let i_t = NonHardenedChildIndex::from_index(i)?;
            let addr = match (internal, &self.internal) {
                (false, _) => self.external.derive_address(i_t).ok()?,
                (true, Some(ivk)) => ivk.derive_address(i_t).ok()?,
                (true, None) => return None,
            };
            Some((addr.encode(network), i))
        };
        (0..upto).filter_map(derive).collect()
    }
}

pub(crate) struct SaplingIncoming {
    pub ivk: SaplingPreparedIvk,
    pub nk: Option<NullifierDerivingKey>,
}

pub(crate) struct OrchardIncoming {
    pub ivk: OrchardPreparedIvk,
    pub fvk: Option<OrchardFvk>,
}

#[derive(Debug, thiserror::Error)]
#[error("not a recognized unified viewing key (as UFVK: {ufvk}; as UIVK: {uivk})")]
pub struct KeyError {
    ufvk: String,
    uivk: String,
}

impl ViewKey {
    pub fn decode(network: &Network, encoding: &str) -> Result<Self, KeyError> {
        match UnifiedFullViewingKey::decode(network, encoding) {
            Ok(ufvk) => Ok(Self::from_ufvk(&ufvk)),
            Err(ufvk) => match UnifiedIncomingViewingKey::decode(network, encoding) {
                Ok(uivk) => Ok(Self::from_uivk(&uivk)),
                Err(uivk) => Err(KeyError {
                    ufvk: ufvk.to_string(),
                    uivk: uivk.to_string(),
                }),
            },
        }
    }

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
            transparent: ufvk.transparent().and_then(|apk| {
                Some(TransparentIncoming {
                    external: apk.derive_external_ivk().ok()?,
                    internal: apk.derive_internal_ivk().ok(),
                })
            }),
        }
    }

    pub(crate) fn can_derive_nullifiers(&self) -> bool {
        self.sapling.iter().any(|s| s.nk.is_some()) || self.orchard.iter().any(|o| o.fvk.is_some())
    }

    fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            sapling: uivk
                .sapling()
                .as_ref()
                .map(|ivk| {
                    vec![SaplingIncoming {
                        ivk: ivk.prepare(),
                        nk: None,
                    }]
                })
                .unwrap_or_default(),
            orchard: uivk
                .orchard()
                .as_ref()
                .map(|ivk| {
                    vec![OrchardIncoming {
                        ivk: OrchardPreparedIvk::new(ivk),
                        fvk: None,
                    }]
                })
                .unwrap_or_default(),
            sapling_ovks: Vec::new(),
            orchard_ovks: Vec::new(),
            transparent: uivk
                .transparent()
                .clone()
                .map(|external| TransparentIncoming {
                    external,
                    internal: None,
                }),
        }
    }
}

fn per_scope<K, T>(key: Option<&K>, derive: impl Fn(&K, Scope) -> T) -> Vec<T> {
    key.map(|k| {
        [Scope::External, Scope::Internal]
            .into_iter()
            .map(|s| derive(k, s))
            .collect()
    })
    .unwrap_or_default()
}

pub(crate) fn encode_sapling_recipient(
    network: &Network,
    addr: sapling::PaymentAddress,
) -> Option<String> {
    UnifiedAddress::from_receivers(None, Some(addr), None).map(|ua| ua.encode(network))
}

pub(crate) fn encode_orchard_recipient(
    network: &Network,
    addr: orchard::Address,
) -> Option<String> {
    UnifiedAddress::from_receivers(Some(addr), None, None).map(|ua| ua.encode(network))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

    #[test]
    fn ufvk_has_full_capability() {
        let key = ViewKey::decode(&Network::MainNetwork, UFVK).expect("decode UFVK");

        assert_eq!(key.sapling.len(), 2, "external + internal scopes");
        assert_eq!(key.orchard.len(), 2);
        assert!(key.sapling.iter().all(|s| s.nk.is_some()));
        assert!(key.orchard.iter().all(|o| o.fvk.is_some()));
        assert!(!key.sapling_ovks.is_empty());
        assert!(!key.orchard_ovks.is_empty());
        assert!(
            key.transparent.is_none(),
            "this UFVK carries no transparent component"
        );
    }

    #[test]
    fn uivk_is_incoming_only() {
        let ufvk = UnifiedFullViewingKey::decode(&Network::MainNetwork, UFVK).unwrap();
        let uivk = ufvk
            .to_unified_incoming_viewing_key()
            .encode(&Network::MainNetwork);

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
        let err = err.to_string();
        assert!(err.contains("UFVK") && err.contains("UIVK"), "got: {err}");
    }
}
