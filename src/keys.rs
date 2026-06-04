
use orchard::keys::{FullViewingKey as OrchardFvk, IncomingViewingKey as OrchardIvk};
use sapling::{zip32::IncomingViewingKey as SaplingIvk, NullifierDerivingKey};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_protocol::consensus::Network;
use zip32::Scope;

pub(crate) struct ScanningKey<Ivk, Nk> {
    pub(crate) ivk: Ivk,
    pub(crate) nk: Option<Nk>,
}

pub struct ScanningKeys {
    pub(crate) sapling: Option<ScanningKey<SaplingIvk, NullifierDerivingKey>>,
    pub(crate) orchard: Option<ScanningKey<OrchardIvk, OrchardFvk>>,
}

impl ScanningKeys {
    pub fn from_uivk(uivk: &UnifiedIncomingViewingKey) -> Self {
        Self {
            sapling: uivk.sapling().as_ref().map(|ivk| ScanningKey { ivk: ivk.clone(), nk: None }),
            orchard: uivk.orchard().as_ref().map(|ivk| ScanningKey { ivk: ivk.clone(), nk: None }),
        }
    }

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

pub fn from_ufvk_str(encoded: &str, network: &Network) -> Result<ScanningKeys, String> {
    let stripped: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let ufvk = UnifiedFullViewingKey::decode(network, &stripped)?;
    Ok(ScanningKeys::from_ufvk(&ufvk))
}
