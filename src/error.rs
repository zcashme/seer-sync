//! Typed error surface for seer-sync public APIs.

/// Errors that can occur during scanning or chain operations.
#[derive(Debug, thiserror::Error)]
pub enum SeerError {
    /// A gRPC call to the lightwalletd server failed.
    #[error("gRPC transport error: {0}")]
    Grpc(#[from] tonic::Status),

    /// A block's `prev_hash` did not match the expected value, indicating a reorg.
    #[error("chain reorganization detected at height {height}")]
    Reorg {
        /// The height at which the reorg was detected.
        height: u32,
    },

    /// A required protobuf field was missing or had wrong length.
    #[error("protobuf field is malformed: {0}")]
    Proto(String),

    /// A viewing key string could not be decoded.
    #[error("key decode failed: {0}")]
    Key(String),

    /// An address string could not be decoded.
    #[error("address decode failed: {0}")]
    Address(String),

    /// Wraps any other error via [`anyhow`].
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    /// A SQLite database error (requires the `db` feature).
    #[cfg(feature = "db")]
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

/// Convenience alias used throughout seer-sync.
pub type Result<T> = std::result::Result<T, SeerError>;
