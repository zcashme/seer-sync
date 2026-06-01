//! View-key-only Zcash chain sync.
//!
//! Detect the funds a viewing key controls without ever holding spend
//! authority. The flow is three steps:
//!
//! 1. Parse a unified viewing key into [`keys::ScanningKeys`].
//! 2. Fetch compact blocks from a lightwalletd server via [`sync::chain`].
//! 3. Trial-decrypt them with [`sync::sync`] to recover the received notes.
//!
//! The viewing key's strength bounds what can be detected. A UIVK (unified
//! incoming viewing key) yields incoming-only detection — you see notes as
//! they arrive but cannot tell when they are spent. A UFVK (unified full
//! viewing key) additionally carries each pool's nullifier-deriving key, so
//! spends can be recognized as well.

#![warn(missing_docs)]

pub mod keys;
pub mod note;
pub mod sync;

/// Generated lightwalletd compact-format types.
pub(crate) mod proto;

/// The generated proto types that surface in `seer-sync`'s public API:
/// [`sync::sync`] and [`sync::chain`] take and return these.
pub use proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, CompactBlock, RawTransaction,
};

/// SQLite persistence for scanned notes, spends, and the sync cursor
/// (`feature = "db"`). A watch-only store: observe notes, never spend them.
#[cfg(feature = "db")]
pub mod db;
