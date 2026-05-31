//! ZIP-302 memo field interpretation.
//!
//! Every shielded note carries a 512-byte memo field. Three encodings are
//! defined by ZIP 302:
//!
//! | First byte | Meaning |
//! |---|---|
//! | `0xFF` | No memo (all bytes are `0xFF`) |
//! | `0xF4` | Arbitrary binary data (511 data bytes follow) |
//! | anything else | UTF-8 text, null-padded to 512 bytes |
//!
//! Compact blocks do **not** carry the memo; it is only available after
//! fetching the full transaction via [`crate::chain::fetch_raw_transaction`].

/// A decoded ZIP-302 memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Memo {
    /// No memo was set (sentinel: all 512 bytes are `0xFF`).
    Empty,
    /// A UTF-8 text memo with trailing null bytes stripped.
    Text(String),
    /// Arbitrary binary data (first byte was `0xF4`; the 511 payload bytes follow).
    Arbitrary(Box<[u8; 511]>),
}

impl Memo {
    /// Parse 512 raw memo bytes.
    ///
    /// Falls back to [`Memo::Arbitrary`] when the first byte signals text but
    /// the content is not valid UTF-8.
    pub fn from_bytes(bytes: &[u8; 512]) -> Self {
        if bytes[0] == 0xFF {
            return Self::Empty;
        }

        if bytes[0] == 0xF4 {
            let mut data = Box::new([0u8; 511]);
            data.copy_from_slice(&bytes[1..]);
            return Self::Arbitrary(data);
        }

        // Text: strip trailing NUL bytes, then validate UTF-8.
        let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        match std::str::from_utf8(&bytes[..end]) {
            Ok(s) => Self::Text(s.to_owned()),
            Err(_) => {
                // Technically malformed, but preserve the bytes rather than discard.
                let mut data = Box::new([0u8; 511]);
                data.copy_from_slice(&bytes[1..]);
                Self::Arbitrary(data)
            }
        }
    }

    /// Return the text content if this is [`Memo::Text`], otherwise `None`.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return `true` if no memo was attached.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

impl std::fmt::Display for Memo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "<empty memo>"),
            Self::Text(s) => f.write_str(s),
            Self::Arbitrary(data) => write!(f, "<{} bytes binary>", data.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_with(prefix: &[u8]) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[..prefix.len()].copy_from_slice(prefix);
        b
    }

    #[test]
    fn all_ff_is_empty() {
        assert_eq!(Memo::from_bytes(&[0xFF; 512]), Memo::Empty);
    }

    #[test]
    fn text_memo_stripped() {
        let raw = bytes_with(b"hello");
        assert_eq!(Memo::from_bytes(&raw), Memo::Text("hello".into()));
    }

    #[test]
    fn all_zeros_is_empty_string() {
        // All NUL → empty text (not the same as Empty sentinel).
        assert_eq!(Memo::from_bytes(&[0u8; 512]), Memo::Text("".into()));
    }

    #[test]
    fn arbitrary_prefix() {
        let mut raw = [0u8; 512];
        raw[0] = 0xF4;
        raw[1] = 0xDE;
        raw[2] = 0xAD;
        let Memo::Arbitrary(data) = Memo::from_bytes(&raw) else { panic!() };
        assert_eq!(data[0], 0xDE);
        assert_eq!(data[1], 0xAD);
        assert_eq!(data[2], 0x00);
    }

    #[test]
    fn display() {
        assert_eq!(Memo::Empty.to_string(), "<empty memo>");
        assert_eq!(Memo::Text("hi".into()).to_string(), "hi");
    }
}
