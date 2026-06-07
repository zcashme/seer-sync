pub use zcash_protocol::consensus::{BlockHeight, Network};

mod key;
pub use key::ViewKey;

pub(crate) mod decrypt;
pub mod sync;
pub(crate) mod proto;

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use anyhow::Context;
#[cfg(feature = "db")]
use sync::scan::{Note, Pool, ShieldedNote, Spend};
#[cfg(feature = "db")]
use sync::{Account, Cursor};

#[cfg(feature = "db")]
pub async fn scan(
    view_key: &str,
    network: &Network,
    birthday: u32,
    db: &db::Db,
) -> anyhow::Result<u32> {
    let key = ViewKey::decode(network, view_key).map_err(|e| anyhow::anyhow!(e))?;
    let client = sync::chain::connect_auto().await.context("connecting to lightwalletd")?;
    sync::run(client, &key, network, birthday, db).await?;
    Ok(db.get_sync_state().context("reading final sync height")?.height)
}

#[cfg(feature = "db")]
impl Account for db::Db {
    fn checkpoint(&self) -> Option<Cursor> {
        let st = self.get_sync_state().ok()?;
        (st.height != 0).then(|| Cursor { height: BlockHeight::from_u32(st.height), hash: st.hash })
    }

    fn rewind(&self, to: BlockHeight) -> anyhow::Result<()> {
        self.rewind_to_height(u32::from(to)).context("rewinding after reorg")
    }

    fn owns_nf(&self, pool: Pool, nf: &[u8; 32]) -> anyhow::Result<bool> {
        match pool {
            Pool::Sapling => self.owns_sapling_nf(nf),
            Pool::Orchard => self.owns_orchard_nf(nf),
        }
        .context("querying owned nullifier")
    }

    fn apply(&self, at: Cursor, notes: &[Note], spends: &[Spend]) -> anyhow::Result<()> {
        use db::{OrchardNoteInsert, SaplingNoteInsert, SyncState};

        for spend in spends {
            let h = u32::from(spend.height);
            match spend.pool {
                Pool::Sapling => self.mark_sapling_spent(&spend.nf, h),
                Pool::Orchard => self.mark_orchard_spent(&spend.nf, h),
            }
            .context("marking note spent")?;
        }

        for note in notes {
            let id = self
                .upsert_transaction(&note.txid, Some(u32::from(note.height)), Some(note.tx_index))
                .context("upserting transaction")?;
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
                    })
                    .context("inserting orchard note")?;
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
                    })
                    .context("inserting sapling note")?;
                }
            }
        }

        self.set_sync_state(&SyncState { height: u32::from(at.height), hash: at.hash })
            .context("updating sync state")
    }
}
