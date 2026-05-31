//! View-key-only Zcash chain sync.
//!
//! Three key paths:
//! - [`keys::IvkKeys`] / [`scan::scan_ivk`] — incoming only (no spend detection)
//! - [`keys::FvkKeys`] / [`scan::scan_fvk`] — incoming + spend detection + balance
//! - [`keys::OvkKeys`] / [`decrypt::try_recover_orchard_outgoing`] — sent notes only
//!
//! # Quick start
//! ```no_run
//! # use seer_sync::{chain, keys::IvkKeys, scan::scan_ivk};
//! # use zcash_keys::keys::UnifiedIncomingViewingKey;
//! # use zcash_protocol::consensus::MainNetwork;
//! # tokio_test::block_on(async {
//! let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, "uivk1...").unwrap();
//! let keys = IvkKeys::from_uivk(&uivk);
//! let mut client = chain::connect(chain::ZEC_ROCKS).await.unwrap();
//! let tip = chain::tip_height(&mut client).await.unwrap();
//! let blocks = chain::fetch_range(&mut client, tip - 100, tip).await.unwrap();
//! for note in scan_ivk(&blocks, &keys) {
//!     println!("received {} zat at height {}", note.value_zat, note.height);
//! }
//! # });
//! ```

#![warn(missing_docs)]

pub mod chain;
pub mod decrypt;
pub mod error;
pub mod keys;
pub mod proto;
pub mod scan;

#[cfg(feature = "db")]
pub mod db;
