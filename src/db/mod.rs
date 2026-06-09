mod schema;
#[cfg(feature = "commitment-tree")]
pub mod commitment_tree;
#[cfg(feature = "commitment-tree")]
mod shardtree_serialization;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use std::collections::HashSet;
use std::path::Path;
use zcash_protocol::value::Zatoshis;

use crate::sync::chain::TransparentUtxo;
use crate::sync::scan::Pool;

use schema::init;

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
        ((self.orchard + self.sapling).and_then(|s| s + self.transparent))
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

const POOLS: [Pool; 2] = [Pool::Sapling, Pool::Orchard];

fn note_table(pool: Pool) -> &'static str {
    match pool {
        Pool::Sapling => "sapling_received_notes",
        Pool::Orchard => "orchard_received_notes",
    }
}

fn index_col(pool: Pool) -> &'static str {
    match pool {
        Pool::Sapling => "output_index",
        Pool::Orchard => "action_index",
    }
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
                mined_height = COALESCE(excluded.mined_height, mined_height),
                tx_index = COALESCE(excluded.tx_index, tx_index)",
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
    pub fn insert_sapling_note(&self, n: &SaplingNoteInsert<'_>) -> rusqlite::Result<()> {
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
        Ok(())
    }

    pub fn insert_orchard_note(&self, n: &OrchardNoteInsert<'_>) -> rusqlite::Result<()> {
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
        Ok(())
    }

    pub fn mark_spent(
        &self,
        pool: Pool,
        nf: &[u8],
        height: u32,
        txid: &[u8],
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            &format!(
                "UPDATE {} SET spent_height = ?2, spent_txid = ?3 WHERE nf = ?1",
                note_table(pool)
            ),
            params![nf, height, txid],
        )
    }

    pub fn owns_nf(&self, pool: Pool, nf: &[u8]) -> rusqlite::Result<bool> {
        self.conn.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {} WHERE nf = ?1)", note_table(pool)),
            params![nf],
            |row| row.get(0),
        )
    }
}

impl Db {
    pub fn balance(&self) -> rusqlite::Result<PoolBalance> {
        let shielded = |pool| {
            self.unspent_sum(&format!(
                "SELECT COALESCE(SUM(value), 0) FROM {}
                 WHERE spent_height IS NULL AND is_sent = 0",
                note_table(pool)
            ))
        };
        Ok(PoolBalance {
            sapling: shielded(Pool::Sapling)?,
            orchard: shielded(Pool::Orchard)?,
            transparent: self.unspent_sum(
                "SELECT COALESCE(SUM(value), 0) FROM transparent_received_outputs
                 WHERE spent_height IS NULL",
            )?,
        })
    }

    fn unspent_sum(&self, sql: &str) -> rusqlite::Result<Zatoshis> {
        self.conn.query_row(sql, [], |row| row.get(0)).map(zatoshis)
    }
}

impl Db {
    /// Reconcile the stored transparent outputs against a fresh
    /// `GetAddressUtxos` snapshot. The snapshot is the *current unspent set*,
    /// so a stored unspent output absent from it was spent; the snapshot
    /// doesn't say by which transaction or at what height, so it is recorded
    /// as spent at `as_of` (the tip at fetch time) — the closest honest bound.
    pub fn apply_transparent_snapshot(
        &self,
        utxos: &[TransparentUtxo],
        as_of: u32,
    ) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for u in utxos {
            let id = self.upsert_transaction(&u.txid, Some(u.height), None)?;
            tx.execute(
                "INSERT INTO transparent_received_outputs(
                    transaction_id, output_index, address, script, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(transaction_id, output_index)
                 DO UPDATE SET spent_height = NULL",
                params![id, u.index, u.address, u.script, u.value_zat as i64],
            )?;
        }
        let seen: HashSet<([u8; 32], u32)> = utxos.iter().map(|u| (u.txid, u.index)).collect();
        let stored: Vec<(i64, [u8; 32], u32)> = {
            let mut stmt = tx.prepare(
                "SELECT o.id, t.txid, o.output_index
                 FROM transparent_received_outputs o
                 JOIN transactions t ON t.id_tx = o.transaction_id
                 WHERE o.spent_height IS NULL",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (id, txid, index) in stored {
            if !seen.contains(&(txid, index)) {
                tx.execute(
                    "UPDATE transparent_received_outputs SET spent_height = ?2 WHERE id = ?1",
                    params![id, as_of],
                )?;
            }
        }
        tx.commit()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRow {
    pub address: String,
    pub txid: [u8; 32],
    pub height: Option<u32>,
    pub output_index: u32,
    pub value: Zatoshis,
    pub spent_height: Option<u32>,
}

impl Db {
    pub fn transparent_outputs(&self) -> rusqlite::Result<Vec<UtxoRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT o.address, t.txid, t.mined_height, o.output_index, o.value, o.spent_height
             FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             ORDER BY t.mined_height IS NULL, t.mined_height, t.txid, o.output_index",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(UtxoRow {
                address: row.get(0)?,
                txid: row.get(1)?,
                height: row.get(2)?,
                output_index: row.get(3)?,
                value: zatoshis(row.get(4)?),
                spent_height: row.get(5)?,
            })
        })?;
        rows.collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRow {
    pub pool: Pool,
    pub txid: [u8; 32],
    pub height: Option<u32>,
    pub output_index: u32,
    pub value: Zatoshis,
    pub memo: Option<Vec<u8>>,
    pub spent_height: Option<u32>,
    pub is_sent: bool,
    pub recipient: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRow {
    pub txid: [u8; 32],
    pub height: Option<u32>,
    pub tx_index: Option<u32>,
    pub received: Zatoshis,
    pub sent: Zatoshis,
    pub spent: Zatoshis,
}

impl Db {
    pub fn notes(&self) -> rusqlite::Result<Vec<NoteRow>> {
        let mut out = Vec::new();
        for pool in POOLS {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT t.txid, t.mined_height, n.{index}, n.value, n.memo,
                        n.spent_height, n.is_sent, n.recipient_address
                 FROM {table} n JOIN transactions t ON t.id_tx = n.transaction_id",
                table = note_table(pool),
                index = index_col(pool),
            ))?;
            let rows = stmt.query_map([], |row| note_row(pool, row))?;
            for row in rows {
                out.push(row?);
            }
        }
        out.sort_by_key(|n| (n.height.is_none(), n.height, n.txid, n.output_index));
        Ok(out)
    }

    pub fn transactions(&self) -> rusqlite::Result<Vec<TxRow>> {
        let shielded_sum = |pred: &str| {
            POOLS
                .map(|pool| {
                    format!(
                        "(SELECT COALESCE(SUM(value), 0) FROM {} WHERE {pred})",
                        note_table(pool)
                    )
                })
                .join(" + ")
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT t.txid, t.mined_height, t.tx_index,
                {received}
              + (SELECT COALESCE(SUM(value), 0) FROM transparent_received_outputs
                 WHERE transaction_id = t.id_tx),
                {sent},
                {spent}
             FROM transactions t
             ORDER BY t.mined_height IS NULL, t.mined_height, t.tx_index",
            received = shielded_sum("transaction_id = t.id_tx AND is_sent = 0"),
            sent = shielded_sum("transaction_id = t.id_tx AND is_sent = 1"),
            spent = shielded_sum("spent_txid = t.txid"),
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(TxRow {
                txid: row.get(0)?,
                height: row.get(1)?,
                tx_index: row.get(2)?,
                received: zatoshis(row.get(3)?),
                sent: zatoshis(row.get(4)?),
                spent: zatoshis(row.get(5)?),
            })
        })?;
        rows.collect()
    }
}

fn note_row(pool: Pool, row: &Row<'_>) -> rusqlite::Result<NoteRow> {
    Ok(NoteRow {
        pool,
        txid: row.get(0)?,
        height: row.get(1)?,
        output_index: row.get(2)?,
        value: zatoshis(row.get(3)?),
        memo: row.get(4)?,
        spent_height: row.get(5)?,
        is_sent: row.get(6)?,
        recipient: row.get(7)?,
    })
}

fn zatoshis(v: i64) -> Zatoshis {
    Zatoshis::from_u64(v as u64).expect("stored value exceeds MAX_MONEY")
}

impl Db {
    pub fn rewind_to_height(&self, height: u32) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM transactions WHERE mined_height > ?1",
            params![height],
        )?;
        for pool in POOLS {
            tx.execute(
                &format!(
                    "UPDATE {} SET spent_height = NULL, spent_txid = NULL
                     WHERE spent_height > ?1",
                    note_table(pool)
                ),
                params![height],
            )?;
        }
        tx.execute(
            "UPDATE transparent_received_outputs SET spent_height = NULL
             WHERE spent_height > ?1",
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

        assert_eq!(db.mark_spent(Pool::Orchard, &[9u8; 32], 101, &[4u8; 32]).unwrap(), 1);
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
    fn notes_and_transactions_read_back() {
        let db = Db::open_in_memory().unwrap();

        let recv = mined_tx(&db, &[1u8; 32], 100);
        db.insert_orchard_note(&OrchardNoteInsert {
            transaction_id: recv,
            action_index: 0,
            diversifier: &[0u8; 11],
            value: 5_000_000,
            rho: &[1u8; 32],
            rseed: &[2u8; 32],
            nf: Some(&[9u8; 32]),
            memo: Some(b"hi"),
            commitment_tree_position: None,
            is_sent: false,
            recipient_address: None,
        })
        .unwrap();

        let spend = mined_tx(&db, &[2u8; 32], 105);
        db.mark_spent(Pool::Orchard, &[9u8; 32], 105, &[2u8; 32]).unwrap();
        db.insert_sapling_note(&SaplingNoteInsert {
            transaction_id: spend,
            output_index: 1,
            diversifier: &[0u8; 11],
            value: 3_000_000,
            rcm: &[3u8; 32],
            nf: None,
            memo: None,
            commitment_tree_position: None,
            is_sent: true,
            recipient_address: Some("u1recipient"),
        })
        .unwrap();

        let notes = db.notes().unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].pool, Pool::Orchard);
        assert_eq!(notes[0].height, Some(100));
        assert_eq!(notes[0].value, Zatoshis::const_from_u64(5_000_000));
        assert_eq!(notes[0].memo.as_deref(), Some(&b"hi"[..]));
        assert_eq!(notes[0].spent_height, Some(105));
        assert!(notes[1].is_sent);
        assert_eq!(notes[1].recipient.as_deref(), Some("u1recipient"));

        let txs = db.transactions().unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].txid, [1u8; 32]);
        assert_eq!(txs[0].received, Zatoshis::const_from_u64(5_000_000));
        assert_eq!(txs[0].spent, Zatoshis::ZERO);
        assert_eq!(txs[1].txid, [2u8; 32]);
        assert_eq!(txs[1].sent, Zatoshis::const_from_u64(3_000_000));
        assert_eq!(txs[1].spent, Zatoshis::const_from_u64(5_000_000));
    }

    #[test]
    fn transparent_snapshot_inserts_spends_revives_and_rewinds() {
        let db = Db::open_in_memory().unwrap();
        let utxo = TransparentUtxo {
            address: "t1example".into(),
            txid: [5u8; 32],
            index: 0,
            script: vec![0x76],
            value_zat: 2_000_000,
            height: 100,
        };

        db.apply_transparent_snapshot(&[utxo.clone()], 110).unwrap();
        let balance = db.balance().unwrap();
        assert_eq!(balance.transparent, Zatoshis::const_from_u64(2_000_000));
        assert_eq!(balance.total(), Zatoshis::const_from_u64(2_000_000));
        let outs = db.transparent_outputs().unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].height, Some(100));
        assert_eq!(outs[0].spent_height, None);
        let txs = db.transactions().unwrap();
        assert_eq!(txs[0].received, Zatoshis::const_from_u64(2_000_000));

        db.apply_transparent_snapshot(&[], 120).unwrap();
        assert_eq!(db.balance().unwrap().transparent, Zatoshis::ZERO);
        assert_eq!(db.transparent_outputs().unwrap()[0].spent_height, Some(120));

        db.rewind_to_height(115).unwrap();
        assert_eq!(
            db.balance().unwrap().transparent,
            Zatoshis::const_from_u64(2_000_000)
        );

        db.apply_transparent_snapshot(&[utxo], 130).unwrap();
        assert_eq!(db.transparent_outputs().unwrap()[0].spent_height, None);
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
        db.mark_spent(Pool::Orchard, &[9u8; 32], 105, &[4u8; 32]).unwrap();
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
