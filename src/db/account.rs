use std::collections::HashMap;

use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::TxId;

use crate::db::{Db, OrchardNoteInsert, SaplingNoteInsert, SyncState};
use crate::sync::scan::ShieldedNote;
use crate::sync::{Account, AccountError, Batch, Cursor, Resume};

impl Account for Db {
    fn resume(&self) -> Result<Resume, AccountError> {
        let birthday = self
            .birthday()?
            .ok_or("account birthday is not set; call Db::set_birthday or use seer_sync::sync")?;
        let checkpoint = self.get_sync_state()?.map(|st| Cursor {
            height: BlockHeight::from_u32(st.height),
            hash: st.hash.map(BlockHash),
        });
        Ok(Resume {
            birthday: BlockHeight::from_u32(birthday),
            checkpoint,
            nullifiers: self.unspent_nullifiers()?,
            outpoints: self.unspent_outpoints()?,
        })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError> {
        self.rewind_to_height(u32::from(to))?;
        Ok(())
    }

    fn apply(&self, at: Cursor, batch: &Batch) -> Result<(), AccountError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut ids: HashMap<TxId, i64> = HashMap::new();
        let mut id_for =
            |txid: &TxId, height: u32, index: Option<u32>| -> rusqlite::Result<i64> {
                if let Some(id) = ids.get(txid) {
                    return Ok(*id);
                }
                let id = self.upsert_transaction(txid.as_ref(), Some(height), index)?;
                ids.insert(*txid, id);
                Ok(id)
            };

        // Notes before spends: a note received and spent in the same batch
        // must exist before its spend mark lands.
        for note in &batch.notes {
            let id = id_for(&note.txid, u32::from(note.height), Some(note.tx_index))?;
            // REVIEW: twin eight-field arms diverging in three pool-specific
            // fields — same disease the twin-pool SQL collapse (0c646ef)
            // cured in db; wants a single insert path in the db-module pass.
            match &note.note {
                ShieldedNote::Orchard(n) => self.insert_orchard_note(&OrchardNoteInsert {
                    transaction_id: id,
                    action_index: note.output_index,
                    diversifier: n.recipient().diversifier().as_array(),
                    value: n.value().inner(),
                    rho: &n.rho().to_bytes(),
                    rseed: n.rseed().as_bytes(),
                    nf: note.nullifier.as_ref().map(|nf| nf.0.as_slice()),
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
                    // REVIEW: dead column for this impl — it never opts into
                    // commitments; drop it from the schema or wire
                    // wants_commitments in the db-module pass.
                    commitment_tree_position: None,
                    is_sent: note.is_sent,
                    recipient_address: note.recipient.as_deref(),
                })?,
                ShieldedNote::Sapling(n) => self.insert_sapling_note(&SaplingNoteInsert {
                    transaction_id: id,
                    output_index: note.output_index,
                    diversifier: &n.recipient().diversifier().0,
                    value: n.value().inner(),
                    rcm: &n.rcm().to_bytes(),
                    nf: note.nullifier.as_ref().map(|nf| nf.0.as_slice()),
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
                    commitment_tree_position: None,
                    is_sent: note.is_sent,
                    recipient_address: note.recipient.as_deref(),
                })?,
            }
        }

        for spend in &batch.spends {
            let height = u32::from(spend.height);
            id_for(&spend.txid, height, None)?;
            self.mark_spent(spend.pool, &spend.nf.0, height, spend.txid.as_ref())?;
        }

        for o in &batch.transparent_outputs {
            let id = id_for(&o.txid, u32::from(o.height), None)?;
            self.insert_transparent_output(id, o.output_index, &o.address, &o.script, o.value_zat)?;
        }

        for s in &batch.transparent_spends {
            let height = u32::from(s.height);
            id_for(&s.txid, height, None)?;
            self.mark_transparent_spent(
                s.outpoint.txid().as_ref(),
                s.outpoint.n(),
                height,
                s.txid.as_ref(),
            )?;
        }

        self.set_sync_state(&SyncState {
            height: u32::from(at.height),
            hash: at.hash.map(|h| h.0),
        })?;
        tx.commit()?;
        Ok(())
    }
}
