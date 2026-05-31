//! Commitment tree state — tracking Sapling and Orchard tree sizes across sync.
//!
//! The Sapling and Orchard note commitment trees grow monotonically. Knowing
//! the cumulative leaf count is required to:
//! - Assign correct leaf positions to received notes (Sapling nullifier derivation
//!   requires knowing a note's position in the tree).
//! - Supply the `sapling_start_pos` parameter to [`crate::scan::scan_fvk`].
//! - Perform wallet recovery by fetching the current tree frontier from the
//!   lightwalletd server.

use anyhow::{Context, Result};

use crate::chain::LwdClient;
use crate::proto::{BlockId, CompactBlock, Empty};

/// Cumulative note commitment counts at a given chain height.
///
/// Both counts are *inclusive* — they include all commitments up to and
/// including the block at which this value was recorded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeSize {
    /// Number of Sapling note commitments in the tree.
    pub sapling: u64,
    /// Number of Orchard note commitments in the tree.
    pub orchard: u64,
}

impl TreeSize {
    /// Extract tree sizes from a [`CompactBlock`]'s `chain_metadata` field.
    ///
    /// Returns `None` for pre-NU5 compact blocks that carry no metadata.
    pub fn from_block(block: &CompactBlock) -> Option<Self> {
        let meta = block.chain_metadata.as_ref()?;
        Some(Self {
            sapling: meta.sapling_commitment_tree_size as u64,
            orchard: meta.orchard_commitment_tree_size as u64,
        })
    }

    /// Extract tree sizes, falling back to counting block outputs when
    /// `chain_metadata` is absent.
    ///
    /// Pass the [`TreeSize`] **before** this block; the returned value reflects
    /// the state **after** the block. Useful for pre-NU5 range recovery.
    pub fn from_block_or_count(block: &CompactBlock, prior: Self) -> Self {
        if let Some(s) = Self::from_block(block) {
            return s;
        }
        let sapling_delta: u64 = block.vtx.iter().map(|tx| tx.outputs.len() as u64).sum();
        let orchard_delta: u64 = block.vtx.iter().map(|tx| tx.actions.len() as u64).sum();
        Self {
            sapling: prior.sapling + sapling_delta,
            orchard: prior.orchard + orchard_delta,
        }
    }

    /// Compute the [`TreeSize`] before the first output of `block` by
    /// subtracting this block's output counts from its post-block size.
    ///
    /// This is the value to pass as `sapling_start_pos` when scanning a
    /// single block in isolation.
    pub fn before_block(block: &CompactBlock) -> Option<Self> {
        let after = Self::from_block(block)?;
        let sapling_in_block: u64 = block.vtx.iter().map(|tx| tx.outputs.len() as u64).sum();
        let orchard_in_block: u64 = block.vtx.iter().map(|tx| tx.actions.len() as u64).sum();
        Some(Self {
            sapling: after.sapling.saturating_sub(sapling_in_block),
            orchard: after.orchard.saturating_sub(orchard_in_block),
        })
    }
}

/// Commitment tree frontier returned by the lightwalletd `GetTreeState` RPC.
///
/// The `sapling_tree` and `orchard_tree` strings are hex-encoded frontier
/// serializations compatible with the `incrementalmerkletree` crate.
/// For balance-only use cases the counts in [`TreeSize`] are sufficient.
#[derive(Debug, Clone)]
pub struct LwdTreeState {
    /// Block height this state corresponds to.
    pub height: u32,
    /// Hex-encoded block hash.
    pub hash: String,
    /// Hex-encoded Sapling commitment tree frontier.
    pub sapling_tree: String,
    /// Hex-encoded Orchard commitment tree frontier.
    pub orchard_tree: String,
}

/// Fetch the commitment tree state at a specific block height.
pub async fn get_tree_state(client: &mut LwdClient, height: u32) -> Result<LwdTreeState> {
    let state = client
        .get_tree_state(tonic::Request::new(BlockId { height: height as u64, hash: vec![] }))
        .await
        .context("GetTreeState")?
        .into_inner();

    Ok(LwdTreeState {
        height: state.height as u32,
        hash: state.hash,
        sapling_tree: state.sapling_tree,
        orchard_tree: state.orchard_tree,
    })
}

/// Fetch the commitment tree state at the current chain tip.
pub async fn get_latest_tree_state(client: &mut LwdClient) -> Result<LwdTreeState> {
    let state = client
        .get_latest_tree_state(tonic::Request::new(Empty {}))
        .await
        .context("GetLatestTreeState")?
        .into_inner();

    Ok(LwdTreeState {
        height: state.height as u32,
        hash: state.hash,
        sapling_tree: state.sapling_tree,
        orchard_tree: state.orchard_tree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ChainMetadata, CompactBlock, CompactTx};

    fn make_block(sapling_size: u32, orchard_size: u32) -> CompactBlock {
        CompactBlock {
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: sapling_size,
                orchard_commitment_tree_size: orchard_size,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn from_block_reads_metadata() {
        let block = make_block(100, 50);
        let size = TreeSize::from_block(&block).unwrap();
        assert_eq!(size.sapling, 100);
        assert_eq!(size.orchard, 50);
    }

    #[test]
    fn before_block_subtracts_outputs() {
        let mut block = make_block(10, 5);
        let mut tx = CompactTx::default();
        tx.outputs = vec![Default::default(); 3];
        tx.actions = vec![Default::default(); 2];
        block.vtx = vec![tx];

        let before = TreeSize::before_block(&block).unwrap();
        assert_eq!(before.sapling, 7); // 10 − 3
        assert_eq!(before.orchard, 3); // 5 − 2
    }
}
