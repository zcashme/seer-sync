pub use zcash_primitives::block::BlockHash;
pub use zcash_protocol::consensus::{BlockHeight, Network};
pub use zcash_protocol::TxId;

mod key;
pub use key::{KeyError, ViewKey};

pub(crate) mod decrypt;
pub mod proto;
pub mod sync;

pub use proto::{
    ChainMetadata, CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactSaplingSpend,
    CompactTx, CompactTxIn, RawTransaction, TxOut,
};

pub use decrypt::parse_orchard;

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use sync::scan::{Note, Pool, ShieldedNote, Spend, TransparentOutput, TransparentSpend};
#[cfg(feature = "db")]
use sync::{Account, AccountError, Cursor, SyncError};
#[cfg(feature = "db")]
use zcash_transparent::bundle::OutPoint;

#[cfg(feature = "db")]
pub async fn scan(
    key: &ViewKey,
    network: &Network,
    birthday: u32,
    db: &db::Db,
) -> Result<(), SyncError> {
    let client = sync::chain::connect_auto().await?;
    sync::run(client, key, network, birthday, db).await
}

#[cfg(feature = "db")]
impl Account for db::Db {
    fn checkpoint(&self) -> Option<Cursor> {
        let st = self.get_sync_state().ok()?;
        (st.height != 0).then(|| Cursor {
            height: BlockHeight::from_u32(st.height),
            hash: st.hash.map(BlockHash),
        })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError> {
        self.rewind_to_height(u32::from(to))?;
        Ok(())
    }

    fn owns_nf(&self, pool: Pool, nf: &[u8; 32]) -> Result<bool, AccountError> {
        Ok(db::Db::owns_nf(self, pool, nf)?)
    }

    fn apply(&self, at: Cursor, notes: &[Note], spends: &[Spend]) -> Result<(), AccountError> {
        use db::{OrchardNoteInsert, SaplingNoteInsert, SyncState};

        for spend in spends {
            let h = u32::from(spend.height);
            self.upsert_transaction(spend.txid.as_ref(), Some(h), None)?;
            self.mark_spent(spend.pool, &spend.nf, h, spend.txid.as_ref())?;
        }

        for note in notes {
            let id = self.upsert_transaction(
                note.txid.as_ref(),
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
            hash: at.hash.map(|h| h.0),
        })?;
        Ok(())
    }

    fn wants_transparent(&self) -> bool {
        true
    }

    fn owns_outpoint(&self, outpoint: &OutPoint) -> Result<bool, AccountError> {
        Ok(db::Db::owns_outpoint(self, outpoint.txid().as_ref(), outpoint.n())?)
    }

    fn apply_transparent(
        &self,
        _at: Cursor,
        outputs: &[TransparentOutput],
        spends: &[TransparentSpend],
    ) -> Result<(), AccountError> {
        for o in outputs {
            let id =
                self.upsert_transaction(o.txid.as_ref(), Some(u32::from(o.height)), None)?;
            self.insert_transparent_output(
                id,
                o.output_index,
                &o.address,
                &o.script,
                o.value_zat,
            )?;
        }
        for s in spends {
            let h = u32::from(s.height);
            self.upsert_transaction(s.txid.as_ref(), Some(h), None)?;
            self.mark_transparent_spent(
                s.outpoint.txid().as_ref(),
                s.outpoint.n(),
                h,
                s.txid.as_ref(),
            )?;
        }
        Ok(())
    }
}
