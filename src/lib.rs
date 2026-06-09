pub use zcash_protocol::consensus::{BlockHeight, Network};

mod key;
pub use key::{KeyError, ViewKey};

pub(crate) mod decrypt;
pub(crate) mod proto;
pub mod sync;

pub use proto::{
    ChainMetadata, CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactSaplingSpend,
    CompactTx, CompactTxIn, RawTransaction, TxOut,
};

pub use decrypt::parse_orchard;

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use sync::scan::{Note, Pool, ShieldedNote, Spend};
#[cfg(feature = "db")]
use sync::{Account, AccountError, Cursor, SyncError};

#[cfg(feature = "db")]
pub async fn scan(
    key: &ViewKey,
    network: &Network,
    birthday: u32,
    db: &db::Db,
) -> Result<(), SyncError> {
    let mut client = sync::chain::connect_auto().await?;
    sync::run(client.clone(), key, network, birthday, db).await?;
    refresh_transparent(&mut client, key, network, birthday, db).await
}

/// Refresh the transparent UTXO snapshot for `key`'s transparent component (a
/// no-op when it has none). Separate from the shielded loop — see
/// [`sync::transparent::utxos`].
#[cfg(feature = "db")]
pub async fn refresh_transparent(
    client: &mut sync::chain::LwdClient,
    key: &ViewKey,
    network: &Network,
    birthday: u32,
    db: &db::Db,
) -> Result<(), SyncError> {
    if key.transparent.is_none() {
        return Ok(());
    }
    let tip = sync::chain::tip_height(client).await?;
    let utxos = sync::transparent::utxos(client, key, network, birthday).await?;
    db.apply_transparent_snapshot(&utxos, tip)
        .map_err(|e| SyncError::Account(Box::new(e)))
}

#[cfg(feature = "db")]
impl Account for db::Db {
    fn checkpoint(&self) -> Option<Cursor> {
        let st = self.get_sync_state().ok()?;
        (st.height != 0).then(|| Cursor {
            height: BlockHeight::from_u32(st.height),
            hash: st.hash,
        })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError> {
        self.rewind_to_height(u32::from(to))?;
        Ok(())
    }

    fn owns_nf(&self, pool: Pool, nf: &[u8; 32]) -> Result<bool, AccountError> {
        Ok(match pool {
            Pool::Sapling => self.owns_sapling_nf(nf),
            Pool::Orchard => self.owns_orchard_nf(nf),
        }?)
    }

    fn apply(&self, at: Cursor, notes: &[Note], spends: &[Spend]) -> Result<(), AccountError> {
        use db::{OrchardNoteInsert, SaplingNoteInsert, SyncState};

        for spend in spends {
            let h = u32::from(spend.height);
            self.upsert_transaction(&spend.txid, Some(h), None)?;
            match spend.pool {
                Pool::Sapling => self.mark_sapling_spent(&spend.nf, h, &spend.txid),
                Pool::Orchard => self.mark_orchard_spent(&spend.nf, h, &spend.txid),
            }?;
        }

        for note in notes {
            let id = self.upsert_transaction(
                &note.txid,
                Some(u32::from(note.height)),
                Some(note.tx_index),
            )?;
            let is_sent = note.is_sent;
            match &note.note {
                ShieldedNote::Orchard(n) => {
                    self.insert_orchard_note(&OrchardNoteInsert {
                        transaction_id: id,
                        action_index: note.output_index,
                        diversifier: n.recipient().diversifier().as_array(),
                        value: n.value().inner(),
                        rho: &n.rho().to_bytes(),
                        rseed: n.rseed().as_bytes(),
                        nf: note.nullifier.as_ref().map(|n| n.as_slice()),
                        memo: note.memo.as_ref().map(|m| m.as_slice()),
                        commitment_tree_position: None,
                        is_sent,
                        recipient_address: note.recipient.as_deref(),
                    })?;
                }
                ShieldedNote::Sapling(n) => {
                    self.insert_sapling_note(&SaplingNoteInsert {
                        transaction_id: id,
                        output_index: note.output_index,
                        diversifier: &n.recipient().diversifier().0,
                        value: n.value().inner(),
                        rcm: &n.rcm().to_bytes(),
                        nf: note.nullifier.as_ref().map(|n| n.as_slice()),
                        memo: note.memo.as_ref().map(|m| m.as_slice()),
                        commitment_tree_position: None,
                        is_sent,
                        recipient_address: note.recipient.as_deref(),
                    })?;
                }
            }
        }

        self.set_sync_state(&SyncState {
            height: u32::from(at.height),
            hash: at.hash,
        })?;
        Ok(())
    }
}
