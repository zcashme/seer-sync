//! View-key-only Zcash chain sync.
//!
//! Detect the funds a viewing key controls without ever holding spend
//! authority. seer-sync is layered so you pay only for what you use:
//!
//! - **core** (no features) — a pure, sans-IO decryptor. Parse a viewing key
//!   into [`keys::ScanningKeys`], hand [`sync::scan::scan`] a slice of compact
//!   blocks, and get back the [`Transactions`](sync::scan::Transactions)
//!   relevant to that key. No async runtime, no network, no database.
//! - **`lwd`** (default) — "talk to lightwalletd": the gRPC client
//!   ([`sync::chain`]), memo enrichment ([`sync::enrich`]), and the live
//!   reorg-safe sync loop ([`sync::run`]).
//! - **`db`** — an optional SQLite consumer that persists what the engine finds.
//!
//! The viewing key's strength bounds what can be detected. A UIVK (unified
//! incoming viewing key) yields incoming-only detection — you see notes as they
//! arrive but cannot tell when they are spent. A UFVK (unified full viewing key)
//! additionally carries each pool's nullifier-deriving key, so a note's spend
//! can be recognized as well.

#![warn(missing_docs)]

/// A block height — the chain coordinate the whole sync module speaks in, and
/// the unit of the sync cursor (the *scanned* watermark). A first-class alias so
/// signatures read in chain terms rather than bare `u32`.
pub type BlockHeight = u32;

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
