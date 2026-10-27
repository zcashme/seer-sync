//! Seer-Sync: view-key-only Zcash chain sync for the Ironwood era.
//!
//! Takes either a Unified Incoming Viewing Key (UIVK) or Unified Full Viewing Key
//! (UFVK) and accurately tracks every note and spend you can see, using only
//! compact blocks from lightwalletd.
//!
//! ## Quick start
//!
//! ```no_run
//! use seer_sync::{run, BlockHeight, Db, Network};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let db = Db::open("seer.db")?;
//!     db.init_account(BlockHeight::from_u32(3_000_000))?;
//!     run("uview1...", &Network::MainNetwork, &db).await?;
//!     println!("{} zat", db.balance()?);
//!     Ok(())
//! }
//! ```

use sync::chain;
use sync::decrypt::ScanningKeys;
use sync::SyncError as SeerSyncError;

pub mod db;
pub mod proto;
pub mod sync;

pub use db::{Db, DbError};
pub use sync::scan::Nullifiers;
pub use sync::{Account, Cursor, SyncError};

pub use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
pub use zcash_protocol::consensus::{BlockHeight, Network, Parameters};

/// Sync a view key from a lightwalletd server into the given account store.
///
/// Parses the view key string (UFVK or UIVK), connects to a server, and runs
/// the sync engine until caught up to the chain tip, then polls for new blocks.
pub async fn run<P: Parameters + Sync, A: Account>(
    view_key: &str,
    params: &P,
    account: &A,
) -> Result<(), SeerSyncError> {
    // Parse the view key — try UFVK first, then UIVK.
    let keys = if let Ok(ufvk) = UnifiedFullViewingKey::decode(params, view_key) {
        ScanningKeys::from_ufvk(&ufvk)
    } else if let Ok(uivk) = UnifiedIncomingViewingKey::decode(params, view_key) {
        ScanningKeys::from_uivk(&uivk)
    } else {
        return Err(SeerSyncError::ViewKey);
    };

    // Connect to a lightwalletd server.
    let client = chain::connect_auto(params).await?;

    // Run the sync engine.
    sync::run(client, &keys, params, account).await
}
