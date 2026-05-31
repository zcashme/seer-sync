//! Note-domain logic: full-transaction decryption and ZIP-302 memos.
//!
//! - [`decrypt`] — recover a note's value, recipient, and memo from a complete
//!   transaction (the compact-block path lives in [`crate::scan`]).
//! - [`memo`] — decode the 512-byte memo field, re-exported from `zcash_protocol`.

pub mod decrypt;
pub mod memo;
