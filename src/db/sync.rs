use anyhow::{Context, Result};
use zcash_protocol::consensus::Network;

use crate::db::{Db, OrchardNoteInsert, SaplingNoteInsert, SyncState};
use crate::sync::chain::LwdClient;
use crate::sync::scan::{Note, ShieldedNote};
use crate::{BlockHeight, UnifiedFullViewingKey};

pub async fn sync_to_tip(
    db: &Db,
    client: LwdClient,
    keys: &UnifiedFullViewingKey,
    mut progress: impl FnMut(BlockHeight),
) -> Result<u32> {
    // The store fixes the chain and the birthday; the viewing key is a caller
    // input, never persisted, so the DB never touches key material.
    let account = db
        .get_account()
        .context("reading account")?
        .context("no account set; call set_account before syncing")?;
    let network = match account.network.as_str() {
        "test" => Network::TestNetwork,
        _ => Network::MainNetwork,
    };
    let birthday = account.birthday;

    crate::sync::run(
        client,
        keys,
        &network,
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

    Ok(db.get_sync_state().context("reading final cursor")?.height)
}

fn apply(db: &Db, height: BlockHeight, hash: [u8; 32], notes: &[Note]) -> Result<()> {
    for note in notes {
        let id = db.upsert_transaction(&note.txid, Some(u32::from(note.height)), Some(note.tx_index))?;
        match &note.note {
            ShieldedNote::Orchard(n) => {
                db.insert_orchard_note(&OrchardNoteInsert {
                    transaction_id: id,
                    action_index: note.output_index,
                    diversifier: n.recipient().diversifier().as_array(),
                    value: n.value().inner(),
                    rho: &n.rho().to_bytes(),
                    rseed: n.rseed().as_bytes(),
                    nf: Some(&note.nullifier),
                    is_change: note.is_change,
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
                    commitment_tree_position: None,
                })?;
            }
            ShieldedNote::Sapling(n) => {
                db.insert_sapling_note(&SaplingNoteInsert {
                    transaction_id: id,
                    output_index: note.output_index,
                    diversifier: &n.recipient().diversifier().0,
                    value: n.value().inner(),
                    rcm: &n.rcm().to_bytes(),
                    nf: Some(&note.nullifier),
                    is_change: note.is_change,
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
                    commitment_tree_position: None,
                })?;
            }
        }
    }
    db.set_sync_state(&SyncState { height: u32::from(height), hash: Some(hash) })?;
    Ok(())
}
