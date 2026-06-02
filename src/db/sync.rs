//! The reference consumer: drive the engine and persist what it finds into the
//! SQLite store (`feature = "lwd"` + `feature = "db"`).
//!
//! This is "consumer zero" — proof the engine's persistence-free seam works. It
//! owns its cursor (the `sync_state` row) and its reorg seam (block hashes), and
//! plugs them into [`crate::sync::run`] as three closures. The engine knows none
//! of it.

use anyhow::{Context, Result};
use zcash_protocol::consensus::Network;

use crate::db::{BlockMeta, Db, OrchardNoteInsert, SaplingNoteInsert, SyncState};
use crate::keys::ScanningKeys;
use crate::sync::chain::LwdClient;
use crate::sync::scan::{Transactions, Tx};
use crate::BlockHeight;

/// Sync the database forward to the current chain tip, returning the height it
/// reached.
///
/// Resumes from the stored cursor; on a cold start it begins at the tracked
/// account's birthday (or genesis if none is set). Reorgs are handled by the
/// engine's walk-back driving this consumer's [`Db::rewind_to_height`].
///
/// Every store op is `&self` (rusqlite mutates through `&self`), so the three
/// closures the engine needs — `resume_point`, `rewind`, `sink` — all just share
/// `&Db`. No `&mut` to juggle, no `RefCell`.
pub async fn sync_to_tip(db: &Db, client: LwdClient, keys: &ScanningKeys) -> Result<u32> {
    let network = network_of(db)?;
    let birthday = db.get_account().context("reading account")?.map_or(0, |a| a.birthday);

    crate::sync::run(
        client,
        keys,
        &network,
        // resume_point: where to start, and the seam hash to check continuity.
        || {
            let st = db.get_sync_state().unwrap_or_default();
            if st.height == 0 {
                (BlockHeight::from_u32(birthday), None)
            } else {
                (BlockHeight::from_u32(st.height + 1), st.hash)
            }
        },
        // rewind: drop everything above the fork; resets the cursor too.
        |to| db.rewind_to_height(u32::from(to)).context("rewinding after reorg"),
        // sink: apply one chunk and advance the cursor.
        |height, hash, txs| apply(db, height, hash, txs),
    )
    .await?;

    Ok(db.get_sync_state().context("reading final cursor")?.height)
}

/// Apply one chunk's findings, then advance the cursor — the consumer's half of
/// the boundary contract.
fn apply(db: &Db, height: BlockHeight, hash: [u8; 32], txs: &Transactions) -> Result<()> {
    // The watermark block header. The compact-block tree sizes / timestamp don't
    // cross the sink (height is the spine, hash is reorg seam material), so they
    // are left unset — note positions ride on the findings themselves.
    db.insert_block(&BlockMeta {
        height: u32::from(height),
        hash,
        time: 0,
        sapling_tree_size: None,
        orchard_tree_size: None,
        sapling_output_count: None,
        orchard_action_count: None,
    })?;

    // Receives first (a note must exist before a spend can link to it), then
    // spends, per pool.
    for tx in &txs.orchard {
        match tx {
            Tx::Receive(r) => {
                let id = db.upsert_transaction(&r.txid, Some(u32::from(r.height)), Some(r.tx_index))?;
                db.insert_orchard_note(&OrchardNoteInsert {
                    transaction_id: id,
                    action_index: r.output_index,
                    diversifier: r.recipient.diversifier().as_array(),
                    value: r.note.value().inner(),
                    rho: &r.note.rho().to_bytes(),
                    rseed: r.note.rseed().as_bytes(),
                    nf: r.nf.as_ref().map(|n| n.as_slice()),
                    is_change: false,
                    memo: r.memo.as_deref().map(|m| m.as_slice()),
                    commitment_tree_position: r.position,
                })?;
            }
            Tx::Spend(s) => {
                let id = db.upsert_transaction(&s.txid, Some(u32::from(s.height)), Some(s.tx_index))?;
                db.mark_orchard_spent(&s.nf, id)?;
            }
        }
    }
    for tx in &txs.sapling {
        match tx {
            Tx::Receive(r) => {
                let id = db.upsert_transaction(&r.txid, Some(u32::from(r.height)), Some(r.tx_index))?;
                db.insert_sapling_note(&SaplingNoteInsert {
                    transaction_id: id,
                    output_index: r.output_index,
                    diversifier: &r.recipient.diversifier().0,
                    value: r.note.value().inner(),
                    rcm: &r.note.rcm().to_bytes(),
                    nf: r.nf.as_ref().map(|n| n.as_slice()),
                    is_change: false,
                    memo: r.memo.as_deref().map(|m| m.as_slice()),
                    commitment_tree_position: r.position,
                })?;
            }
            Tx::Spend(s) => {
                let id = db.upsert_transaction(&s.txid, Some(u32::from(s.height)), Some(s.tx_index))?;
                db.mark_sapling_spent(&s.nf, id)?;
            }
        }
    }

    // Advance the cursor to this chunk's tip, recording the seam hash.
    db.set_sync_state(&SyncState {
        height: u32::from(height),
        hash: Some(hash),
        sapling_pos: 0,
        orchard_pos: 0,
    })?;
    Ok(())
}

/// The network the tracked account is on, for transaction parsing and ZIP-212
/// enforcement. Defaults to mainnet when no account is set.
fn network_of(db: &Db) -> Result<Network> {
    Ok(match db.get_account()?.map(|a| a.network).as_deref() {
        Some("test") => Network::TestNetwork,
        _ => Network::MainNetwork,
    })
}
