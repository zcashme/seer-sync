use anyhow::{Context, Result};
use zcash_protocol::consensus::Network;

use crate::db::{Db, OrchardNoteInsert, SaplingNoteInsert, SyncState};
use crate::sync::chain::LwdClient;
use crate::sync::scan::{Transactions, Tx};
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
        |height, hash, txs| {
            apply(db, height, hash, txs)?;
            progress(height);
            Ok(())
        },
    )
    .await?;

    Ok(db.get_sync_state().context("reading final cursor")?.height)
}

fn apply(db: &Db, height: BlockHeight, hash: [u8; 32], txs: &Transactions) -> Result<()> {
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
                    is_change: r.is_change,
                    memo: r.memo.as_deref().map(|m| m.as_slice()),
                    commitment_tree_position: r.position,
                })?;
            }
            Tx::Spend(s) => {
                if db.owns_orchard_nf(&s.nf)? {
                    let id = db.upsert_transaction(&s.txid, Some(u32::from(s.height)), Some(s.tx_index))?;
                    db.mark_orchard_spent(&s.nf, id)?;
                }
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
                    is_change: r.is_change,
                    memo: r.memo.as_deref().map(|m| m.as_slice()),
                    commitment_tree_position: r.position,
                })?;
            }
            Tx::Spend(s) => {
                if db.owns_sapling_nf(&s.nf)? {
                    let id = db.upsert_transaction(&s.txid, Some(u32::from(s.height)), Some(s.tx_index))?;
                    db.mark_sapling_spent(&s.nf, id)?;
                }
            }
        }
    }

    db.set_sync_state(&SyncState { height: u32::from(height), hash: Some(hash) })?;
    Ok(())
}
