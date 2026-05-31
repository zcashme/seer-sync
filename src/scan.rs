//! Parallel trial-decrypt loop over compact blocks.
//!
//! Two entry points:
//! - [`scan_ivk`] — incoming only, no spend detection
//! - [`scan_fvk`] — incoming + nullifier derivation + spend detection + transparent
//!
//! # Parallelism
//!
//! Both entry points use two levels of parallelism:
//! 1. **Block-level** — rayon distributes blocks across CPU threads.
//! 2. **Block-wide batch** — within each block, all actions/outputs across *all*
//!    transactions are collected into a single slice, then
//!    `zcash_note_encryption::batch::try_compact_note_decryption` decrypts the full
//!    outputs × keys matrix in one rayon call, amortising key-agreement setup across
//!    the entire block.

mod fvk;
mod ivk;
mod parsers;
mod stream;
mod types;

pub use fvk::{scan_fvk, TreeSize};
pub use ivk::scan_ivk;
pub use stream::{scan_stream_fvk, scan_stream_ivk, StreamFvkResult};
pub use types::{
    FvkScanResult, IncomingNoteView, Recipient, ScanEvent, ShieldedPool, TransparentReceived,
    TransparentSpend,
};
