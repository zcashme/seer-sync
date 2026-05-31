//! Transparent address and script utilities.
//!
//! Provides script pattern recognition and address hash extraction for
//! standard P2PKH and P2SH output scripts. Full Base58Check encoding of
//! transparent addresses is left to the caller (requires network-specific
//! version bytes not known at this layer).

/// Recognized standard transparent output script types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptType {
    /// Pay-to-public-key-hash.
    P2pkh,
    /// Pay-to-script-hash.
    P2sh,
}

/// Parse a standard P2PKH or P2SH locking script.
///
/// Returns `Some((type, 20-byte hash))` on a match, `None` for all other
/// script forms (multisig, OP_RETURN, witness outputs, etc.).
///
/// The 20-byte hash is:
/// - For [`ScriptType::P2pkh`]: HASH160 of the compressed public key.
/// - For [`ScriptType::P2sh`]: HASH160 of the redeem script.
pub fn parse_script(script: &[u8]) -> Option<(ScriptType, [u8; 20])> {
    // P2PKH: OP_DUP OP_HASH160 PUSH20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76   // OP_DUP
        && script[1] == 0xa9   // OP_HASH160
        && script[2] == 0x14   // PUSH 20
        && script[23] == 0x88  // OP_EQUALVERIFY
        && script[24] == 0xac  // OP_CHECKSIG
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        return Some((ScriptType::P2pkh, hash));
    }

    // P2SH: OP_HASH160 PUSH20 <20 bytes> OP_EQUAL
    if script.len() == 23
        && script[0] == 0xa9   // OP_HASH160
        && script[1] == 0x14   // PUSH 20
        && script[22] == 0x87  // OP_EQUAL
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[2..22]);
        return Some((ScriptType::P2sh, hash));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2pkh_round_trip() {
        let hash = [0xABu8; 20];
        let mut script = [0u8; 25];
        script[0] = 0x76;
        script[1] = 0xa9;
        script[2] = 0x14;
        script[3..23].copy_from_slice(&hash);
        script[23] = 0x88;
        script[24] = 0xac;
        assert_eq!(parse_script(&script), Some((ScriptType::P2pkh, hash)));
    }

    #[test]
    fn p2sh_round_trip() {
        let hash = [0xCDu8; 20];
        let mut script = [0u8; 23];
        script[0] = 0xa9;
        script[1] = 0x14;
        script[2..22].copy_from_slice(&hash);
        script[22] = 0x87;
        assert_eq!(parse_script(&script), Some((ScriptType::P2sh, hash)));
    }

    #[test]
    fn unknown_script_returns_none() {
        assert_eq!(parse_script(&[0x51, 0x52]), None); // OP_1 OP_2
        assert_eq!(parse_script(&[]), None);
    }
}
