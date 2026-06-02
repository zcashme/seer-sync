//! Seer-Sync: View-key-only Zcash chain sync.
//
//
#![warn(missing_docs)]

/// A block height — the chain coordinate the sync layer speaks in, and the unit
/// of the sync cursor (the *scanned* watermark). Re-exported from
/// `zcash_protocol`: the canonical newtype, type-distinct from counts/indices
/// and the exact type librustzcash's protocol functions take.
pub use zcash_protocol::consensus::BlockHeight;

pub mod keys;
pub mod note;

/// Syncing. Its [`scan`](sync::scan) submodule is the sans-IO core (always
/// compiled); the rest — `chain`, `enrich`, and the [`run`](sync::run) loop — is
/// the live layer, gated on `lwd`.
pub mod sync;

/// Generated lightwalletd proto types. Messages (e.g. [`CompactBlock`]) are
/// always generated; the gRPC client is generated only under `lwd` (see
/// `build.rs`).
pub(crate) mod proto;

/// Proto *message* types that surface in the public API (e.g. [`scan::scan`]
/// takes `&[CompactBlock]`).
pub use proto::{CompactBlock, RawTransaction};

/// The generated gRPC client, available only when talking to lightwalletd.
#[cfg(feature = "lwd")]
pub use proto::compact_tx_streamer_client::CompactTxStreamerClient;

/// SQLite persistence for scanned notes, spends, and the sync cursor
/// (`feature = "db"`). The reference consumer: it subscribes to what the engine
/// finds and writes it down — a watch-only store that observes, never spends.
#[cfg(feature = "db")]
pub mod db;
