//! Persistence engine (`feature = "db"`): drive the chain client, scan blocks,
//! and write the results to the database.
//!
//! [`sync_to_tip`] resumes from the stored cursor (or the account birthday),
//! streams the confirmed blocks up to the chain tip, and applies each batch to
//! the database in linear order: block headers first, then received notes, then
//! spends, then the advanced cursor. A `prev_hash` discontinuity — at the seam
//! with our stored chain or mid-stream — is treated as a reorg: the wallet walks
//! back until its stored history reconnects, then resumes.
//!
//! This is the confirmed-block loop. Mempool ingestion is a later feature; the
//! schema already represents unconfirmed transactions (`mined_height IS NULL`).

use anyhow::{Context, Result};
use futures::StreamExt;

use crate::db::{BlockMeta, Db, OrchardNoteInsert, SaplingNoteInsert, SyncState};
use crate::keys::ScanningKeys;
use crate::proto::CompactBlock;
use crate::sync::chain::{self, LwdClient, DEFAULT_CHUNK_OUTPUTS};
use crate::sync::{scan, Pool, Scanned};

/// Transient transport failures to retry before giving up. A dropped stream is
/// retried and resumes from the persisted cursor, so nothing is re-fetched.
const MAX_TRANSPORT_RETRIES: usize = 4;

/// Sync the database forward to the current chain tip.
///
/// Returns the height the wallet is synced to. Resumes from the stored cursor;
/// on the first sync it starts at the account birthday (or genesis if no
/// account is set). The confirmed range streams to the tip in a single pass,
/// with the cursor advanced after every applied batch; a dropped stream is
/// retried and resumes from the cursor.
pub async fn sync_to_tip(
    db: &mut Db,
    mut client: LwdClient,
    keys: &ScanningKeys,
) -> Result<u32> {
    let tip = chain::tip_height(&mut client).await?;
    // How far to walk back on a reorg. Doubles on each consecutive reorg so any
    // fork depth is found in logarithmically many tries, and resets once we make
    // forward progress. It caps nothing — the seam check is the all-clear, so the
    // walk-back terminates on its own when our stored history reconnects.
    let mut rewind = 1u32;

    loop {
        let cursor = db.get_sync_state().context("reading sync cursor")?;
        let before = cursor.height;
        let from = start_height(db, &cursor)?;
        if from > tip {
            return Ok(before);
        }
        match scan_retrying(db, &client, keys, from, tip).await? {
            RangeOutcome::Done => {
                // Reached the tip, or the server ended the stream early; either
                // way, loop to resume from the advanced cursor. No forward
                // progress means an empty range, so stop rather than spin.
                if db.get_sync_state().context("reading sync cursor")?.height <= before {
                    return Ok(before);
                }
                rewind = 1;
            }
            RangeOutcome::Reorg => {
                let cur = db.get_sync_state().context("reading sync cursor")?.height;
                db.rewind_to_height(cur.saturating_sub(rewind))
                    .context("rewinding after reorg")?;
                rewind = rewind.saturating_mul(2);
            }
        }
    }
}

/// Stream `[from, tip]`, retrying transient transport failures. Each retry
/// resumes from the cursor, re-applying any blocks already persisted
/// (idempotently).
async fn scan_retrying(
    db: &Db,
    client: &LwdClient,
    keys: &ScanningKeys,
    from: u32,
    tip: u32,
) -> Result<RangeOutcome> {
    let mut attempt = 0;
    loop {
        match scan_range(db, client.clone(), keys, from, tip).await {
            Ok(outcome) => return Ok(outcome),
            Err(_) if attempt < MAX_TRANSPORT_RETRIES => attempt += 1,
            Err(e) => return Err(e),
        }
    }
}

/// First height to request: one past the cursor, or the birthday on a cold start.
fn start_height(db: &Db, cursor: &SyncState) -> Result<u32> {
    if cursor.height == 0 {
        Ok(db.get_account()?.map_or(0, |a| a.birthday))
    } else {
        Ok(cursor.height + 1)
    }
}

enum RangeOutcome {
    /// The range was streamed and applied; the cursor reflects progress.
    Done,
    /// A reorg was detected — at the DB seam or mid-stream; the caller walks
    /// back and retries.
    Reorg,
}

/// Stream and apply blocks `[start, tip]`. Returns [`RangeOutcome::Reorg`] if
/// continuity breaks — at the seam with our stored chain, or mid-stream — so the
/// caller can walk back. Transport faults bubble up to be retried.
async fn scan_range(
    db: &Db,
    client: LwdClient,
    keys: &ScanningKeys,
    start: u32,
    tip: u32,
) -> Result<RangeOutcome> {
    // Seed the stream with the stored hash of the block before `start`, so its
    // continuity check spans the seam with our chain as well as block-to-block.
    let seam = db.get_block_hash(start.saturating_sub(1))?;
    let mut stream = chain::blocks(client, start, tip, DEFAULT_CHUNK_OUTPUTS, seam);

    while let Some(item) = stream.next().await {
        let batch = match item {
            Ok(batch) => batch,
            // Any discontinuity — at the seam or mid-stream — is a reorg, not a
            // transport fault; route it to the walk-back instead of retrying.
            Err(e) if e.downcast_ref::<chain::Reorg>().is_some() => {
                return Ok(RangeOutcome::Reorg)
            }
            Err(e) => return Err(e).context("streaming blocks"),
        };
        let scanned = scan(&batch, keys);
        apply(db, &batch, &scanned)?;
    }

    Ok(RangeOutcome::Done)
}

/// Apply one batch of blocks to the database, in dependency order.
fn apply(db: &Db, blocks: &[CompactBlock], scanned: &Scanned) -> Result<()> {
    // 1. Block headers.
    for b in blocks {
        db.insert_block(&block_meta_of(b))?;
    }

    // 2. Received notes first — a note must exist before its spend can link to
    //    it, and a note is always received in an earlier (or equal) block.
    for s in &scanned.sapling {
        let tx = db.upsert_transaction(&s.txid, Some(s.height), Some(s.tx_index))?;
        db.insert_sapling_note(&SaplingNoteInsert {
            transaction_id: tx,
            output_index: s.output_index,
            diversifier: &s.recipient.diversifier().0,
            value: s.note.value().inner(),
            rcm: &s.note.rcm().to_bytes(),
            nf: s.nf.as_ref().map(|n| n.as_slice()),
            is_change: false,
            commitment_tree_position: s.position,
        })?;
    }
    for o in &scanned.orchard {
        let tx = db.upsert_transaction(&o.txid, Some(o.height), Some(o.tx_index))?;
        db.insert_orchard_note(&OrchardNoteInsert {
            transaction_id: tx,
            action_index: o.action_index,
            diversifier: o.recipient.diversifier().as_array(),
            value: o.note.value().inner(),
            rho: &o.note.rho().to_bytes(),
            rseed: o.note.rseed().as_bytes(),
            nf: o.nf.as_ref().map(|n| n.as_slice()),
            is_change: false,
            commitment_tree_position: o.position,
        })?;
    }

    // 3. Spends.
    for sp in &scanned.spends {
        let tx = db.upsert_transaction(&sp.txid, Some(sp.height), Some(sp.tx_index))?;
        match sp.pool {
            Pool::Sapling => db.mark_sapling_spent(&sp.nf, tx)?,
            Pool::Orchard => db.mark_orchard_spent(&sp.nf, tx)?,
        };
    }

    // 4. Advance the cursor to the last block, carrying the running tree sizes.
    if let Some(b) = blocks.last() {
        let meta = block_meta_of(b);
        let prior = db.get_sync_state()?;
        db.set_sync_state(&SyncState {
            height: meta.height,
            hash: Some(meta.hash),
            sapling_pos: meta.sapling_tree_size.unwrap_or(prior.sapling_pos),
            orchard_pos: meta.orchard_tree_size.unwrap_or(prior.orchard_pos),
        })?;
    }

    Ok(())
}

/// Build a [`BlockMeta`] from a compact block: tree sizes from `chain_metadata`
/// (when present), output/action counts computed directly.
fn block_meta_of(b: &CompactBlock) -> BlockMeta {
    let hash = b.hash[..].try_into().unwrap_or([0u8; 32]);
    let sapling_output_count: usize = b.vtx.iter().map(|t| t.outputs.len()).sum();
    let orchard_action_count: usize = b.vtx.iter().map(|t| t.actions.len()).sum();
    let (sapling_tree_size, orchard_tree_size) = b
        .chain_metadata
        .as_ref()
        .map(|m| {
            (
                Some(m.sapling_commitment_tree_size as u64),
                Some(m.orchard_commitment_tree_size as u64),
            )
        })
        .unwrap_or((None, None));

    BlockMeta {
        height: b.height as u32,
        hash,
        time: b.time,
        sapling_tree_size,
        orchard_tree_size,
        sapling_output_count: Some(sapling_output_count as u32),
        orchard_action_count: Some(orchard_action_count as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ChainMetadata, CompactTx};

    fn block(height: u64, n_outputs: usize, n_actions: usize, tree: Option<(u32, u32)>) -> CompactBlock {
        let tx = CompactTx {
            index: 0,
            txid: vec![height as u8; 32],
            fee: 0,
            spends: vec![],
            outputs: vec![Default::default(); n_outputs],
            actions: vec![Default::default(); n_actions],
            ..Default::default()
        };
        CompactBlock {
            height,
            hash: vec![height as u8; 32],
            time: 1000 + height as u32,
            vtx: vec![tx],
            chain_metadata: tree.map(|(s, o)| ChainMetadata {
                sapling_commitment_tree_size: s,
                orchard_commitment_tree_size: o,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn block_meta_counts_and_sizes() {
        let m = block_meta_of(&block(100, 3, 2, Some((50, 70))));
        assert_eq!(m.height, 100);
        assert_eq!(m.sapling_output_count, Some(3));
        assert_eq!(m.orchard_action_count, Some(2));
        assert_eq!(m.sapling_tree_size, Some(50));
        assert_eq!(m.orchard_tree_size, Some(70));
    }

    #[test]
    fn block_meta_without_chain_metadata() {
        let m = block_meta_of(&block(100, 1, 0, None));
        assert_eq!(m.sapling_tree_size, None);
        assert_eq!(m.orchard_tree_size, None);
        assert_eq!(m.sapling_output_count, Some(1));
    }

    #[test]
    fn apply_advances_cursor_and_persists_block() {
        let db = Db::open_in_memory().unwrap();
        let blocks = vec![block(200, 0, 0, Some((10, 20))), block(201, 0, 0, Some((12, 23)))];
        apply(&db, &blocks, &Scanned::default()).unwrap();

        let cursor = db.get_sync_state().unwrap();
        assert_eq!(cursor.height, 201);
        assert_eq!(cursor.sapling_pos, 12);
        assert_eq!(cursor.orchard_pos, 23);
        assert_eq!(db.get_block_hash(200).unwrap(), Some([200u8; 32]));
    }
}
