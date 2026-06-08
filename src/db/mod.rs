mod schema;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use zcash_protocol::value::Zatoshis;

pub use schema::init;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub height: u32,
    pub hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolBalance {
    pub orchard: Zatoshis,
    pub sapling: Zatoshis,
}

impl Default for PoolBalance {
    fn default() -> Self {
        PoolBalance {
            orchard: Zatoshis::ZERO,
            sapling: Zatoshis::ZERO,
        }
    }
}

impl PoolBalance {
    pub fn total(&self) -> Zatoshis {
        (self.orchard + self.sapling)
            .expect("summed pool balances exceed MAX_MONEY")
    }
}

#[derive(Debug, Clone)]
pub struct SaplingNoteInsert<'a> {
    pub transaction_id: i64,
    pub output_index: u32,
    pub diversifier: &'a [u8],
    pub value: u64,
    pub rcm: &'a [u8],
    pub nf: Option<&'a [u8]>,
    pub memo: Option<&'a [u8]>,
    pub commitment_tree_position: Option<u64>,
    pub is_sent: bool,
    pub recipient_address: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct OrchardNoteInsert<'a> {
    pub transaction_id: i64,
    pub action_index: u32,
    pub diversifier: &'a [u8],
    pub value: u64,
    pub rho: &'a [u8],
    pub rseed: &'a [u8],
    pub nf: Option<&'a [u8]>,
    pub memo: Option<&'a [u8]>,
    pub commitment_tree_position: Option<u64>,
    pub is_sent: bool,
    pub recipient_address: Option<&'a str>,
}

pub struct Db {
    pub(crate) conn: Connection,
}

impl Db {
    pub fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        init(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init(&conn)?;
        Ok(Self { conn })
    }
}

impl Db {
    pub fn set_sync_state(&self, state: &SyncState) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state(id, height, hash)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                height = excluded.height,
                hash = excluded.hash",
            params![
                state.height,
                state.hash.as_ref().map(|h| h.as_slice()),
            ],
        )?;
        Ok(())
    }

    pub fn get_sync_state(&self) -> rusqlite::Result<SyncState> {
        self.conn
            .query_row(
                "SELECT height, hash FROM sync_state WHERE id = 1",
                [],
                |row| {
                    let hash: Option<Vec<u8>> = row.get(1)?;
                    Ok(SyncState {
                        height: row.get(0)?,
                        hash: hash.and_then(|v| v.try_into().ok()),
                    })
                },
            )
            .optional()
            .map(Option::unwrap_or_default)
    }
}

impl Db {
    pub fn upsert_transaction(
        &self,
        txid: &[u8],
        height: Option<u32>,
        tx_index: Option<u32>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO transactions(txid, mined_height, tx_index)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(txid) DO UPDATE SET
                mined_height = excluded.mined_height,
                tx_index = excluded.tx_index",
            params![txid, height, tx_index],
        )?;
        self.conn.query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            params![txid],
            |row| row.get(0),
        )
    }
}

impl Db {
    pub fn insert_sapling_note(&self, n: &SaplingNoteInsert<'_>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO sapling_received_notes(
                transaction_id, output_index, diversifier, value, rcm, nf,
                memo, commitment_tree_position, is_sent, recipient_address)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(transaction_id, output_index) DO NOTHING",
            params![
                n.transaction_id,
                n.output_index,
                n.diversifier,
                n.value as i64,
                n.rcm,
                n.nf,
                n.memo,
                n.commitment_tree_position.map(|p| p as i64),
                n.is_sent,
                n.recipient_address,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_orchard_note(&self, n: &OrchardNoteInsert<'_>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO orchard_received_notes(
                transaction_id, action_index, diversifier, value, rho, rseed, nf,
                memo, commitment_tree_position, is_sent, recipient_address)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(transaction_id, action_index) DO NOTHING",
            params![
                n.transaction_id,
                n.action_index,
                n.diversifier,
                n.value as i64,
                n.rho,
                n.rseed,
                n.nf,
                n.memo,
                n.commitment_tree_position.map(|p| p as i64),
                n.is_sent,
                n.recipient_address,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn memos(&self) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for table in ["sapling_received_notes", "orchard_received_notes"] {
            let mut stmt = self
                .conn
                .prepare(&format!("SELECT memo FROM {table} WHERE memo IS NOT NULL"))?;
            let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for memo in rows {
                out.push(memo?);
            }
        }
        Ok(out)
    }

    pub fn mark_sapling_spent(&self, nf: &[u8], height: u32) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE sapling_received_notes SET spent_height = ?2 WHERE nf = ?1",
            params![nf, height],
        )
    }

    pub fn mark_orchard_spent(&self, nf: &[u8], height: u32) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE orchard_received_notes SET spent_height = ?2 WHERE nf = ?1",
            params![nf, height],
        )
    }

    pub fn owns_sapling_nf(&self, nf: &[u8]) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sapling_received_notes WHERE nf = ?1)",
            params![nf],
            |row| row.get(0),
        )
    }

    pub fn owns_orchard_nf(&self, nf: &[u8]) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM orchard_received_notes WHERE nf = ?1)",
            params![nf],
            |row| row.get(0),
        )
    }
}

impl Db {
    pub fn balance(&self) -> rusqlite::Result<PoolBalance> {
        let sapling = self.unspent_sum(
            "SELECT COALESCE(SUM(value), 0) FROM sapling_received_notes
             WHERE spent_height IS NULL AND is_sent = 0",
        )?;
        let orchard = self.unspent_sum(
            "SELECT COALESCE(SUM(value), 0) FROM orchard_received_notes
             WHERE spent_height IS NULL AND is_sent = 0",
        )?;
        Ok(PoolBalance { orchard, sapling })
    }

    fn unspent_sum(&self, sql: &str) -> rusqlite::Result<Zatoshis> {
        let v: i64 = self.conn.query_row(sql, [], |row| row.get(0))?;
        Ok(Zatoshis::from_u64(v as u64).expect("pool balance exceeds MAX_MONEY"))
    }
}

impl Db {
    pub fn rewind_to_height(&self, height: u32) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM transactions WHERE mined_height > ?1",
            params![height],
        )?;
        tx.execute(
            "UPDATE sapling_received_notes SET spent_height = NULL WHERE spent_height > ?1",
            params![height],
        )?;
        tx.execute(
            "UPDATE orchard_received_notes SET spent_height = NULL WHERE spent_height > ?1",
            params![height],
        )?;
        tx.execute(
            "INSERT INTO sync_state(id, height, hash)
             VALUES (1, ?1, NULL)
             ON CONFLICT(id) DO UPDATE SET
                height = excluded.height,
                hash = excluded.hash",
            params![height],
        )?;
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mined_tx(db: &Db, txid: &[u8; 32], height: u32) -> i64 {
        db.upsert_transaction(txid, Some(height), Some(0)).unwrap()
    }

    #[test]
    fn schema_init_is_idempotent() {

        let db = Db::open_in_memory().unwrap();
        schema::init(&db.conn).unwrap();
        let tables: u32 = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = 'transactions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
    }

    #[test]
    fn sync_state_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.get_sync_state().unwrap(), SyncState::default());
        let state = SyncState {
            height: 42,
            hash: Some([7u8; 32]),
        };
        db.set_sync_state(&state).unwrap();
        let got = db.get_sync_state().unwrap();
        assert_eq!(got.height, 42);
        assert_eq!(got.hash, Some([7u8; 32]));
    }

    #[test]
    fn balance_empty() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.balance().unwrap(), PoolBalance::default());
    }

    #[test]
    fn orchard_note_received_then_spent() {
        let db = Db::open_in_memory().unwrap();
        let tx = mined_tx(&db, &[1u8; 32], 100);
        db.insert_orchard_note(&OrchardNoteInsert {
            transaction_id: tx,
            action_index: 0,
            diversifier: &[0u8; 11],
            value: 5_000_000,
            rho: &[1u8; 32],
            rseed: &[2u8; 32],
            nf: Some(&[9u8; 32]),
            memo: None,
            commitment_tree_position: Some(7),
            is_sent: false,
            recipient_address: None,
        })
        .unwrap();
        assert_eq!(
            db.balance().unwrap().orchard,
            Zatoshis::const_from_u64(5_000_000)
        );

        assert_eq!(db.mark_orchard_spent(&[9u8; 32], 101).unwrap(), 1);
        assert_eq!(db.balance().unwrap().orchard, Zatoshis::ZERO);
    }

    #[test]
    fn sent_note_persists_recipient_and_is_excluded_from_balance() {
        let db = Db::open_in_memory().unwrap();
        let tx = mined_tx(&db, &[2u8; 32], 200);
        db.insert_sapling_note(&SaplingNoteInsert {
            transaction_id: tx,
            output_index: 0,
            diversifier: &[0u8; 11],
            value: 3_000_000,
            rcm: &[3u8; 32],
            nf: None,
            memo: None,
            commitment_tree_position: None,
            is_sent: true,
            recipient_address: Some("u1recipientaddress"),
        })
        .unwrap();

        assert_eq!(db.balance().unwrap().sapling, Zatoshis::ZERO);

        let recipient: Option<String> = db
            .conn
            .query_row(
                "SELECT recipient_address FROM sapling_received_notes WHERE is_sent = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recipient.as_deref(), Some("u1recipientaddress"));
    }

    #[test]
    fn received_note_has_null_recipient() {
        let db = Db::open_in_memory().unwrap();
        let tx = mined_tx(&db, &[3u8; 32], 300);
        db.insert_orchard_note(&OrchardNoteInsert {
            transaction_id: tx,
            action_index: 0,
            diversifier: &[0u8; 11],
            value: 1_000_000,
            rho: &[1u8; 32],
            rseed: &[2u8; 32],
            nf: Some(&[8u8; 32]),
            memo: None,
            commitment_tree_position: Some(1),
            is_sent: false,
            recipient_address: None,
        })
        .unwrap();
        let recipient: Option<String> = db
            .conn
            .query_row(
                "SELECT recipient_address FROM orchard_received_notes WHERE is_sent = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recipient, None);
    }

    #[test]
    fn rewind_undoes_notes_and_spends() {
        let db = Db::open_in_memory().unwrap();
        let tx = mined_tx(&db, &[1u8; 32], 100);
        db.insert_orchard_note(&OrchardNoteInsert {
            transaction_id: tx,
            action_index: 0,
            diversifier: &[0u8; 11],
            value: 9_000_000,
            rho: &[1u8; 32],
            rseed: &[2u8; 32],
            nf: Some(&[9u8; 32]),
            memo: None,
            commitment_tree_position: Some(0),
            is_sent: false,
            recipient_address: None,
        })
        .unwrap();
        db.mark_orchard_spent(&[9u8; 32], 105).unwrap();
        assert_eq!(db.balance().unwrap().orchard, Zatoshis::ZERO);

        db.rewind_to_height(104).unwrap();
        assert_eq!(
            db.balance().unwrap().orchard,
            Zatoshis::const_from_u64(9_000_000)
        );
        assert_eq!(db.get_sync_state().unwrap().height, 104);

        db.rewind_to_height(99).unwrap();
        assert_eq!(db.balance().unwrap().orchard, Zatoshis::ZERO);
    }
}
