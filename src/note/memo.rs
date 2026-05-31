//! ZIP-302 memo decoding.
//!
//! This is intentionally a thin re-export of librustzcash's canonical
//! implementation rather than a hand-rolled parser. `zcash_protocol::memo`
//! already implements ZIP 302 exactly:
//!
//! | First byte | Meaning |
//! |---|---|
//! | `0xF6` followed by all-zero bytes | [`Memo::Empty`] (no memo) |
//! | `0x00..=0xF4` | [`Memo::Text`] — UTF-8 text, trailing NULs stripped |
//! | `0xFF` | [`Memo::Arbitrary`] — 511 bytes of opaque data |
//! | anything else | [`Memo::Future`] — reserved encodings |
//!
//! Compact blocks do **not** carry the memo; it is only available after
//! fetching the full transaction and decrypting via [`crate::note::decrypt`],
//! which yields a raw `[u8; 512]`. Decode it with
//! [`MemoBytes::from_bytes`] followed by `Memo::try_from`.

pub use zcash_protocol::memo::{Error, Memo, MemoBytes, TextMemo};
