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
pub use sync::{run, Account, AccountError, Batch, Cursor, Resume, SyncError};

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
) -> Result<Option<Cursor>, SyncError> {
    db.set_birthday(u32::from(birthday))
        .map_err(|e| SyncError::Account(Box::new(e)))?;
    let client = chain::connect_auto().await?;
    run(client, key, network, db).await
}
