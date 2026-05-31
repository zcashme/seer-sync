//! Parallel trial-decrypt loop over compact blocks.
//!
//! Three entry points:
//! - [`scan_ivk`] — incoming only, no spend detection
//! - [`scan_fvk`] — incoming + nullifier derivation + spend detection + transparent
//! - [`scan_ovk`] — see [`crate::decrypt`] for OVK recovery (full transactions required)
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
mod types;

pub use fvk::scan_fvk;
pub use ivk::scan_ivk;
pub use types::{
    FvkScanResult, IncomingNoteView, Recipient, ScanEvent, SentNoteView, ShieldedPool,
    TransparentReceived, TransparentSpend,
};
