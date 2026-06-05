pub use zcash_protocol::consensus::{BlockHeight, Network};

mod key;
pub use key::ViewKey;

pub(crate) mod decrypt;
pub mod sync;
pub(crate) mod proto;

#[cfg(feature = "db")]
pub mod db;

/// Scan the chain for notes belonging to `ufvk` from `birthday` and persist them to `db`.
///
/// Returns the final synced height.
#[cfg(feature = "db")]
pub async fn scan(
    ufvk: &str,
    network: &Network,
    birthday: u32,
    db: &db::Db,
    mut progress: impl FnMut(BlockHeight),
) -> anyhow::Result<u32> {
    use anyhow::Context;
    let key = ViewKey::decode(network, ufvk).map_err(|e| anyhow::anyhow!(e))?;
    let client = sync::chain::connect_auto().await.context("connecting to lightwalletd")?;
    sync::run(
        client,
        &key,
        network,
        || {
            let st = db.get_sync_state().unwrap_or_default();
            if st.height == 0 {
                (BlockHeight::from_u32(birthday), None)
            } else {
                (BlockHeight::from_u32(st.height + 1), st.hash)
            }
        },
        |to| db.rewind_to_height(u32::from(to)).context("rewinding after reorg"),
        |height, hash, notes| {
            apply(db, height, hash, notes)?;
            progress(height);
            Ok(())
        },
    )
    .await?;
    Ok(db.get_sync_state().context("reading final sync height")?.height)
}

#[cfg(feature = "db")]
fn apply(
    db: &db::Db,
    height: BlockHeight,
    hash: [u8; 32],
    notes: &[sync::scan::Note],
) -> anyhow::Result<()> {
    use anyhow::Context;
    use db::{OrchardNoteInsert, SaplingNoteInsert, SyncState};
    use sync::scan::ShieldedNote;

    for note in notes {
        let id = db
            .upsert_transaction(&note.txid, Some(u32::from(note.height)), Some(note.tx_index))
            .context("upserting transaction")?;
        let is_outgoing = note.nullifier.is_none();
        match &note.note {
            ShieldedNote::Orchard(n) => {
                db.insert_orchard_note(&OrchardNoteInsert {
                    transaction_id: id,
                    action_index: note.output_index,
                    diversifier: n.recipient().diversifier().as_array(),
                    value: n.value().inner(),
                    rho: &n.rho().to_bytes(),
                    rseed: n.rseed().as_bytes(),
                    nf: note.nullifier.as_ref().map(|n| n.as_slice()),
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
                    commitment_tree_position: None,
                    is_outgoing,
                })
                .context("inserting orchard note")?;
            }
            ShieldedNote::Sapling(n) => {
                db.insert_sapling_note(&SaplingNoteInsert {
                    transaction_id: id,
                    output_index: note.output_index,
                    diversifier: &n.recipient().diversifier().0,
                    value: n.value().inner(),
                    rcm: &n.rcm().to_bytes(),
                    nf: note.nullifier.as_ref().map(|n| n.as_slice()),
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
                    commitment_tree_position: None,
                    is_outgoing,
                })
                .context("inserting sapling note")?;
            }
        }
    }
    db.set_sync_state(&SyncState { height: u32::from(height), hash: Some(hash) })
        .context("updating sync state")
}
