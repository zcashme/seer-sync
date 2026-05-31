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
//! let mut client = chain::connect(chain::ZEC_ROCKS).await.unwrap();
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
pub mod proto;
pub mod sync;

#[cfg(feature = "db")]
pub mod db;
