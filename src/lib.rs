// REVIEW [deferred]: crate docs + re-export shape — agreed least concern,
// revisit once the API underneath stops moving.
pub use zcash_primitives::block::BlockHash;
pub use zcash_protocol::consensus::{BlockHeight, Network};
pub use zcash_protocol::TxId;
pub use zcash_transparent::bundle::OutPoint;

mod key;
pub use key::{KeyError, ViewKey};

pub(crate) mod decrypt;
// REVIEW(proto) [agreed, blocked]: privatizing breaks tests/sync_loop.rs (the
// mock lightwalletd implements the generated server trait) and any caller
// assembling blocks; decide in the surface pass.
pub mod proto;
// REVIEW(sync) [partial]: the root re-exports below are the curated surface;
// chain/scan stay public for benches and BYO front doors. Full curation and
// the follow-the-tip entry point land in their own passes.
pub mod sync;

pub use proto::{
    ChainMetadata, CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactSaplingSpend,
    CompactTx, CompactTxIn, RawTransaction, TxOut,
};

// REVIEW [accepted for now]: exists for zns-resolver; ugly but we make do.
pub use decrypt::parse_orchard;

pub use sync::scan::{
    Commitment, Note, Nullifier, Pool, ShieldedNote, Spend, TransparentOutput, TransparentSpend,
};
pub use sync::{Account, AccountError, Batch, Cursor, Resume, SyncError};

#[cfg(feature = "db")]
pub mod db;

/// Sync the bundled database to the current chain tip: seed its birthday,
/// connect to a public lightwalletd, run one pass. The composition any caller
/// could write themselves from [`sync::chain::connect`] and [`sync::run`].
#[cfg(feature = "db")]
pub async fn sync(
    key: &ViewKey,
    network: Network,
    birthday: BlockHeight,
    db: &db::Db,
) -> Result<Option<Cursor>, SyncError> {
    db.set_birthday(u32::from(birthday))
        .map_err(|e| SyncError::Account(Box::new(e)))?;
    let client = sync::chain::connect_auto().await?;
    sync::run(client, key, network, db).await
}
