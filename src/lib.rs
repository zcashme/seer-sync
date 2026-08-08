//! Seer-Sync: view-key-only Zcash chain sync for the Ironwood era.
//!
//! Takes either a Unified Incoming Viewing Key (UIVK) or Unified Full Viewing Key
//! (UFVK) and accurately tracks every note and spend you can see, using only
//! compact blocks from lightwalletd.
//!
//! ## Example
//!
//! ```no_run
//! use seer_sync::{sync, BlockHeight, Network, ViewKey};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let key = ViewKey::decode(&Network::MainNetwork, "uivk1...")?;
//! let db = seer_sync::db::Db::open("seer.db")?;
//! let _tip = sync(&key, Network::MainNetwork, BlockHeight::from_u32(1_000_000), &db).await?;
//! # Ok(()) }
//! ```

pub use zcash_primitives::block::BlockHash;
pub use zcash_protocol::consensus::{BlockHeight, Network};
pub use zcash_protocol::TxId;
pub use zcash_transparent::bundle::OutPoint;

mod decrypt;
mod key;
pub mod proto;
mod sync;

pub use key::{KeyError, ViewKey};
pub use sync::chain;
pub use sync::scan::{
    scan_commitments, scan_compact, Commitment, Note, Nullifier, Pool, ShieldedNote, Spend,
    TransparentOutput, TransparentSpend,
};
pub use sync::{run, Account, Batch, Cursor, Resume, SyncError};

/// Parse a compact Orchard action into a decryptable [`orchard`] action —
/// the out-of-band decrypt hook zns-verify builds on.
pub use decrypt::parse_orchard;

#[cfg(feature = "db")]
pub mod db;

/// Sync the bundled database to the current chain tip: seed its birthday,
/// connect to a public lightwalletd, run one pass. The composition any caller
/// could write themselves from [`chain::connect`] and [`run`].
#[cfg(feature = "db")]
pub async fn sync(
    key: &ViewKey,
    network: Network,
    birthday: BlockHeight,
    db: &db::Db,
) -> Result<Option<Cursor>, SyncError<db::DbError>> {
    db.set_birthday(birthday)
        .map_err(|e| SyncError::Account(e.into()))?;
    let client = chain::connect_auto(network).await?;
    run(client, key, network, db).await
}
