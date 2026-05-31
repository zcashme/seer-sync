//! View-key-only Zcash chain sync.
//!
//! Parse a unified viewing key into [`keys::ScanningKeys`], then trial-decrypt
//! compact blocks with [`sync::sync`]. A UIVK gives incoming-only detection; a
//! UFVK additionally carries each pool's nullifier-deriving key.
//!
//! # Quick start
//! ```no_run
//! # use seer_sync::{keys::ScanningKeys, sync::{chain, sync}};
//! # use zcash_keys::keys::UnifiedIncomingViewingKey;
//! # use zcash_protocol::consensus::MainNetwork;
//! # tokio_test::block_on(async {
//! let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, "uivk1...").unwrap();
//! let keys = ScanningKeys::from_uivk(&uivk);
//! let mut client = chain::connect_auto().await.unwrap();
//! let tip = chain::tip_height(&mut client).await.unwrap();
//! let blocks = chain::fetch_range(client, tip - 100, tip).await.unwrap();
//! let received = sync(&blocks, &keys);
//! for (height, note, _addr) in &received.sapling {
//!     println!("received {} zat at height {}", note.value().inner(), height);
//! }
//! # });
//! ```

#![warn(missing_docs)]

pub mod keys;
pub mod note;
pub mod sync;

/// Generated lightwalletd compact-format types. Kept crate-private; the few
/// types that appear in this crate's public API are re-exported below.
pub(crate) mod proto;

/// The generated proto types that surface in `seer-sync`'s public API:
/// [`sync::sync`] and [`sync::chain`] take and return these.
pub use proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, CompactBlock, RawTransaction,
};

#[cfg(feature = "db")]
pub mod db;
