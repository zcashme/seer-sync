//! Output types produced by the scan entry points.

/// Which shielded pool a note belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedPool {
    /// Sapling shielded pool.
    Sapling,
    /// Orchard shielded pool.
    Orchard,
}

/// Recipient address recovered from a decrypted note plaintext.
#[derive(Debug, Clone)]
pub enum Recipient {
    /// An Orchard diversified address.
    Orchard(orchard::Address),
    /// A Sapling payment address.
    Sapling(sapling::PaymentAddress),
}

/// A successfully trial-decrypted incoming note.
#[derive(Debug, Clone)]
pub struct IncomingNoteView {
    /// Block height containing the action/output.
    pub height: u32,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: [u8; 32],
    /// Index of this output/action within the transaction.
    pub output_index: usize,
    /// Pool the note belongs to.
    pub pool: ShieldedPool,
    /// Value in zatoshis (1 ZEC = 1e8 zatoshis).
    pub value_zat: u64,
    /// Recipient address recovered from the decrypted plaintext.
    pub recipient: Recipient,
    /// Note commitment randomness (rseed), needed for later nullifier / memo recovery.
    pub rseed: [u8; 32],
    /// Rho: the input nullifier of this action (Orchard only).
    pub rho: Option<[u8; 32]>,
    /// Sapling leaf position in the commitment tree — FVK path only.
    pub sapling_leaf_pos: Option<u64>,
    /// Nullifier for this note — FVK path only; `None` on IVK path.
    pub nullifier: Option<[u8; 32]>,
}

/// A sent note recovered via OVK / FVK (full transactions required).
#[derive(Debug, Clone)]
pub struct SentNoteView {
    /// Block height.
    pub height: u32,
    /// Transaction ID.
    pub tx_id: [u8; 32],
    /// Output index within the transaction.
    pub output_index: usize,
    /// Pool.
    pub pool: ShieldedPool,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Bech32m-encoded recipient address.
    pub recipient: String,
    /// Full 512-byte ZIP-302 memo.
    pub memo: Box<[u8; 512]>,
}

/// Events emitted by [`crate::scan::scan_fvk`].
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// A note was received by this wallet.
    Incoming(IncomingNoteView),
    /// A known nullifier was observed as a compact spend.
    Spent {
        /// Nullifier bytes.
        nullifier: [u8; 32],
        /// Height at which the spend was observed.
        height: u32,
    },
}

/// Transparent output detected in a compact block.
#[derive(Debug, Clone)]
pub struct TransparentReceived {
    /// Block height.
    pub height: u32,
    /// Transaction ID.
    pub tx_id: [u8; 32],
    /// Output index in vout.
    pub output_index: u32,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Raw locking script (scriptPubKey).
    pub script: Vec<u8>,
}

/// Transparent input (potential spend of a watched UTXO).
#[derive(Debug, Clone)]
pub struct TransparentSpend {
    /// Height at which the spend was mined.
    pub height: u32,
    /// Spending transaction ID.
    pub tx_id: [u8; 32],
    /// TXID of the output being spent.
    pub prevout_txid: [u8; 32],
    /// Index of the output being spent.
    pub prevout_index: u32,
}

/// Aggregated result of a [`crate::scan::scan_fvk`] call.
pub struct FvkScanResult {
    /// All incoming and spend events from this batch.
    pub events: Vec<ScanEvent>,
    /// Updated Sapling leaf count after processing all blocks.
    pub sapling_leaf_count: u64,
    /// All transparent vout entries encountered (caller filters by address).
    pub transparent_received: Vec<TransparentReceived>,
    /// All transparent vin entries (potential spends of watched UTXOs).
    pub transparent_spends: Vec<TransparentSpend>,
}
