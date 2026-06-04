//! Decoding the viewing key that drives a scan.
//!
//! The scanner's key currency is the upstream [`UnifiedFullViewingKey`]: it
//! already holds the Sapling `DiversifiableFullViewingKey` and Orchard
//! `FullViewingKey`, from which the scan loop derives the per-scope incoming
//! viewing keys and nullifier-deriving keys it needs. We don't wrap it — this
//! module only turns an encoded key string into that type.

use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

/// Decode a unified full viewing key (`uview1…`) for `network`.
///
/// Whitespace is stripped first, so a key pasted across line breaks still
/// parses. Decode failures are reported as the plain string from `zcash_keys`.
pub(crate) fn decode(network: &Network, encoded: &str) -> Result<UnifiedFullViewingKey, String> {
    let stripped: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    UnifiedFullViewingKey::decode(network, &stripped)
}
