//! Seer-Sync: view-key-only Zcash chain sync for the Ironwood era.
//!
//! Takes either a Unified Incoming Viewing Key (UIVK) or Unified Full Viewing Key
//! (UFVK) and accurately tracks every note and spend you can see, using only
//! compact blocks from lightwalletd.

pub mod db;
pub mod proto;
pub mod sync;

pub use db::{Db, DbError};
pub use sync::chain::LwdClient;
pub use sync::decrypt::ScanningKeys;
pub use sync::scan::Nullifiers;
pub use sync::{run, Account, Cursor, Resume, SyncError};

pub use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
pub use zcash_protocol::consensus::{BlockHeight, Network};