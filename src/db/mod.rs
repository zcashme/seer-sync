mod schema;

pub mod sync;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use zcash_protocol::value::Zatoshis;

pub use schema::init;

#[derive(Debug, Clone)]
pub struct Account {
    pub network: String,
    pub birthday: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub height: u32,
    pub hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolBalance {
    pub orchard: Zatoshis,
    pub sapling: Zatoshis,
    pub transparent: Zatoshis,
}

impl Default for PoolBalance {
    fn default() -> Self {
        PoolBalance {
            orchard: Zatoshis::ZERO,
            sapling: Zatoshis::ZERO,
            transparent: Zatoshis::ZERO,
        }
    }
}

impl PoolBalance {
    pub fn total(&self) -> Zatoshis {

        (self.orchard + self.sapling + self.transparent)
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
    pub is_change: bool,
    pub memo: Option<&'a [u8]>,
    pub commitment_tree_position: Option<u64>,
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
    pub is_change: bool,
    pub memo: Option<&'a [u8]>,
    pub commitment_tree_position: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TransparentOutputInsert<'a> {
    pub transaction_id: i64,
    pub output_index: u32,
    pub address: &'a str,
    pub script: &'a [u8],
    pub value_zat: u64,
    pub max_observed_unspent_height: Option<u32>,
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
    pub fn set_account(&self, account: &Account) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO account(id, network, birthday)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                network = excluded.network,
                birthday = excluded.birthday",
            params![account.network, account.birthday],
        )?;
        Ok(())
    }

    pub fn get_account(&self) -> rusqlite::Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT network, birthday FROM account WHERE id = 1",
                [],
                |row| {
                    Ok(Account {
                        network: row.get(0)?,
                        birthday: row.get(1)?,
                    })
                },
            )
            .optional()
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
                is_change, memo, commitment_tree_position)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(transaction_id, output_index) DO NOTHING",
            params![
                n.transaction_id,
                n.output_index,
                n.diversifier,
                n.value as i64,
                n.rcm,
                n.nf,
                n.is_change as i64,
                n.memo,
                n.commitment_tree_position.map(|p| p as i64),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_orchard_note(&self, n: &OrchardNoteInsert<'_>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO orchard_received_notes(
                transaction_id, action_index, diversifier, value, rho, rseed, nf,
                is_change, memo, commitment_tree_position)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(transaction_id, action_index) DO NOTHING",
            params![
                n.transaction_id,
                n.action_index,
                n.diversifier,
                n.value as i64,
                n.rho,
                n.rseed,
                n.nf,
                n.is_change as i64,
                n.memo,
                n.commitment_tree_position.map(|p| p as i64),
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

    pub fn mark_sapling_spent(&self, nf: &[u8], spending_tx: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "INSERT OR IGNORE INTO sapling_received_note_spends(
                sapling_received_note_id, transaction_id)
             SELECT id, ?2 FROM sapling_received_notes WHERE nf = ?1",
            params![nf, spending_tx],
        )
    }

    pub fn mark_orchard_spent(&self, nf: &[u8], spending_tx: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "INSERT OR IGNORE INTO orchard_received_note_spends(
                orchard_received_note_id, transaction_id)
             SELECT id, ?2 FROM orchard_received_notes WHERE nf = ?1",
            params![nf, spending_tx],
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
    pub fn insert_transparent_output(
        &self,
        o: &TransparentOutputInsert<'_>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO transparent_received_outputs(
                transaction_id, output_index, address, script, value_zat,
                max_observed_unspent_height)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(transaction_id, output_index) DO NOTHING",
            params![
                o.transaction_id,
                o.output_index,
                o.address,
                o.script,
                o.value_zat as i64,
                o.max_observed_unspent_height,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn mark_transparent_spent(
        &self,
        prevout_txid: &[u8],
        prevout_index: u32,
        spending_tx: i64,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "INSERT OR IGNORE INTO transparent_spend_map(
                spending_transaction_id, prevout_txid, prevout_output_index)
             VALUES (?1,?2,?3)",
            params![spending_tx, prevout_txid, prevout_index],
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO transparent_received_output_spends(
                transparent_received_output_id, transaction_id)
             SELECT o.id, ?3 FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE t.txid = ?1 AND o.output_index = ?2",
            params![prevout_txid, prevout_index, spending_tx],
        )
    }
}

impl Db {
    pub fn balance(&self) -> rusqlite::Result<PoolBalance> {
        let sapling = self.unspent_sum(
            "SELECT COALESCE(SUM(n.value), 0) FROM sapling_received_notes n
             WHERE NOT EXISTS (
                SELECT 1 FROM sapling_received_note_spends s
                JOIN transactions t ON t.id_tx = s.transaction_id
                WHERE s.sapling_received_note_id = n.id AND t.mined_height IS NOT NULL)",
        )?;
        let orchard = self.unspent_sum(
            "SELECT COALESCE(SUM(n.value), 0) FROM orchard_received_notes n
             WHERE NOT EXISTS (
                SELECT 1 FROM orchard_received_note_spends s
                JOIN transactions t ON t.id_tx = s.transaction_id
                WHERE s.orchard_received_note_id = n.id AND t.mined_height IS NOT NULL)",
        )?;
        let transparent = self.unspent_sum(
            "SELECT COALESCE(SUM(o.value_zat), 0) FROM transparent_received_outputs o
             WHERE NOT EXISTS (
                SELECT 1 FROM transparent_received_output_spends s
                JOIN transactions t ON t.id_tx = s.transaction_id
                WHERE s.transparent_received_output_id = o.id AND t.mined_height IS NOT NULL)",
        )?;
        Ok(PoolBalance {
            orchard,
            sapling,
            transparent,
        })
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
    fn account_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.get_account().unwrap().is_none());
        let acct = Account { network: "main".into(), birthday: 419_200 };
        db.set_account(&acct).unwrap();
        let got = db.get_account().unwrap().unwrap();
        assert_eq!(got.network, "main");
        assert_eq!(got.birthday, 419_200);
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
            is_change: false,
            memo: None,
            commitment_tree_position: Some(7),
        })
        .unwrap();
        assert_eq!(
            db.balance().unwrap().orchard,
            Zatoshis::const_from_u64(5_000_000)
        );

        let spend_tx = mined_tx(&db, &[2u8; 32], 101);
        assert_eq!(db.mark_orchard_spent(&[9u8; 32], spend_tx).unwrap(), 1);
        assert_eq!(db.balance().unwrap().orchard, Zatoshis::ZERO);
    }

    #[test]
    fn unmined_spend_does_not_reduce_balance() {
        let db = Db::open_in_memory().unwrap();
        let tx = mined_tx(&db, &[1u8; 32], 100);
        db.insert_sapling_note(&SaplingNoteInsert {
            transaction_id: tx,
            output_index: 0,
            diversifier: &[0u8; 11],
            value: 3_000_000,
            rcm: &[2u8; 32],
            nf: Some(&[9u8; 32]),
            is_change: false,
            memo: None,
            commitment_tree_position: Some(5),
        })
        .unwrap();

        let mempool_tx = db.upsert_transaction(&[3u8; 32], None, None).unwrap();
        assert_eq!(db.mark_sapling_spent(&[9u8; 32], mempool_tx).unwrap(), 1);
        assert_eq!(
            db.balance().unwrap().sapling,
            Zatoshis::const_from_u64(3_000_000)
        );
    }

    #[test]
    fn transparent_received_then_spent() {
        let db = Db::open_in_memory().unwrap();
        let tx = mined_tx(&db, &[1u8; 32], 200);
        db.insert_transparent_output(&TransparentOutputInsert {
            transaction_id: tx,
            output_index: 0,
            address: "t1abc",
            script: &[0x76, 0xa9],
            value_zat: 1_000_000,
            max_observed_unspent_height: Some(200),
        })
        .unwrap();
        assert_eq!(
            db.balance().unwrap().transparent,
            Zatoshis::const_from_u64(1_000_000)
        );

        let spend_tx = mined_tx(&db, &[2u8; 32], 201);
        assert_eq!(
            db.mark_transparent_spent(&[1u8; 32], 0, spend_tx).unwrap(),
            1
        );
        assert_eq!(db.balance().unwrap().transparent, Zatoshis::ZERO);
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
            is_change: false,
            memo: None,
            commitment_tree_position: Some(0),
        })
        .unwrap();
        let spend_tx = mined_tx(&db, &[2u8; 32], 105);
        db.mark_orchard_spent(&[9u8; 32], spend_tx).unwrap();
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
