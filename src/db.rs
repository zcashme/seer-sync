#[cfg(feature = "commitment-tree")]
pub mod commitment_tree;
#[cfg(feature = "commitment-tree")]
mod shardtree_serialization;

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;
use zcash_transparent::bundle::OutPoint;

use crate::sync::scan::{Nullifier, Pool, ShieldedNote};
use crate::sync::{Account, Batch, Cursor, Resume};

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("account birthday is not set; call Db::set_birthday or use seer_sync::sync")]
    BirthdayUnset,
}

fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(
        r#"
            CREATE TABLE IF NOT EXISTS account (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                birthday    INTEGER NOT NULL,
                sync_height INTEGER,
                sync_hash   BLOB
            );

            CREATE TABLE IF NOT EXISTS txs (
                id_tx         INTEGER PRIMARY KEY,
                txid          BLOB    NOT NULL UNIQUE,
                mined_height  INTEGER,
                tx_index      INTEGER
            );

            CREATE TABLE IF NOT EXISTS sapling_received_notes (
                id                       INTEGER PRIMARY KEY,
                transaction_id           INTEGER NOT NULL
                    REFERENCES txs(id_tx) ON DELETE CASCADE,
                output_index             INTEGER NOT NULL,
                diversifier              BLOB    NOT NULL,
                value                    INTEGER NOT NULL,
                rcm                      BLOB    NOT NULL,
                nf                       BLOB    UNIQUE,
                memo                     BLOB,
                commitment_tree_position INTEGER,
                spent_tx                 INTEGER
                    REFERENCES txs(id_tx) ON DELETE SET NULL,
                is_sent                  INTEGER NOT NULL DEFAULT 0,
                recipient_address        TEXT,
                UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_sapling_received_notes_tx
                ON sapling_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_sapling_received_notes_nf
                ON sapling_received_notes (nf) WHERE nf IS NOT NULL;

            CREATE TABLE IF NOT EXISTS orchard_received_notes (
                id                       INTEGER PRIMARY KEY,
                transaction_id           INTEGER NOT NULL
                    REFERENCES txs(id_tx) ON DELETE CASCADE,
                action_index             INTEGER NOT NULL,
                diversifier              BLOB    NOT NULL,
                value                    INTEGER NOT NULL,
                rho                      BLOB    NOT NULL,
                rseed                    BLOB    NOT NULL,
                nf                       BLOB    UNIQUE,
                memo                     BLOB,
                commitment_tree_position INTEGER,
                spent_tx                 INTEGER
                    REFERENCES txs(id_tx) ON DELETE SET NULL,
                is_sent                  INTEGER NOT NULL DEFAULT 0,
                recipient_address        TEXT,
                UNIQUE (transaction_id, action_index)
            );
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_tx
                ON orchard_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_nf
                ON orchard_received_notes (nf) WHERE nf IS NOT NULL;

            CREATE TABLE IF NOT EXISTS ironwood_received_notes (
                id                       INTEGER PRIMARY KEY,
                transaction_id           INTEGER NOT NULL
                    REFERENCES txs(id_tx) ON DELETE CASCADE,
                action_index             INTEGER NOT NULL,
                diversifier              BLOB    NOT NULL,
                value                    INTEGER NOT NULL,
                rho                      BLOB    NOT NULL,
                rseed                    BLOB    NOT NULL,
                nf                       BLOB    UNIQUE,
                memo                     BLOB,
                commitment_tree_position INTEGER,
                spent_tx                 INTEGER
                    REFERENCES txs(id_tx) ON DELETE SET NULL,
                is_sent                  INTEGER NOT NULL DEFAULT 0,
                recipient_address        TEXT,
                UNIQUE (transaction_id, action_index)
            );
            CREATE INDEX IF NOT EXISTS idx_ironwood_received_notes_tx
                ON ironwood_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_ironwood_received_notes_nf
                ON ironwood_received_notes (nf) WHERE nf IS NOT NULL;

            CREATE TABLE IF NOT EXISTS transparent_received_outputs (
                id             INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES txs(id_tx) ON DELETE CASCADE,
                output_index   INTEGER NOT NULL,
                address        TEXT    NOT NULL,
                script         BLOB    NOT NULL,
                value          INTEGER NOT NULL,
                spent_tx       INTEGER
                    REFERENCES txs(id_tx) ON DELETE SET NULL,
                UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_transparent_received_outputs_tx
                ON transparent_received_outputs (transaction_id);

            -- The super table: every transaction with its amounts, pools,
            -- shielding direction, memo, and recipients, derived from the
            -- note/output tables so it can never disagree with them. `txs` is
            -- the storage spine; this is what humans and consumers read.
            DROP VIEW IF EXISTS transactions;
            CREATE VIEW transactions AS
            SELECT
                t.txid,
                t.mined_height,
                t.tx_index,
                (SELECT COALESCE(SUM(value), 0) FROM sapling_received_notes
                  WHERE transaction_id = t.id_tx AND is_sent = 0)
              + (SELECT COALESCE(SUM(value), 0) FROM orchard_received_notes
                  WHERE transaction_id = t.id_tx AND is_sent = 0)
              + (SELECT COALESCE(SUM(value), 0) FROM ironwood_received_notes
                  WHERE transaction_id = t.id_tx AND is_sent = 0)
              + (SELECT COALESCE(SUM(value), 0) FROM transparent_received_outputs
                  WHERE transaction_id = t.id_tx)
                    AS received,
                (SELECT COALESCE(SUM(value), 0) FROM sapling_received_notes
                  WHERE transaction_id = t.id_tx AND is_sent = 1)
              + (SELECT COALESCE(SUM(value), 0) FROM orchard_received_notes
                  WHERE transaction_id = t.id_tx AND is_sent = 1)
              + (SELECT COALESCE(SUM(value), 0) FROM ironwood_received_notes
                  WHERE transaction_id = t.id_tx AND is_sent = 1)
                    AS sent,
                (SELECT COALESCE(SUM(value), 0) FROM sapling_received_notes
                  WHERE spent_tx = t.id_tx)
              + (SELECT COALESCE(SUM(value), 0) FROM orchard_received_notes
                  WHERE spent_tx = t.id_tx)
              + (SELECT COALESCE(SUM(value), 0) FROM ironwood_received_notes
                  WHERE spent_tx = t.id_tx)
              + (SELECT COALESCE(SUM(value), 0) FROM transparent_received_outputs
                  WHERE spent_tx = t.id_tx)
                    AS spent,
                EXISTS(SELECT 1 FROM sapling_received_notes
                        WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                    AS sapling,
                EXISTS(SELECT 1 FROM orchard_received_notes
                        WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                    AS orchard,
                EXISTS(SELECT 1 FROM ironwood_received_notes
                        WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                    AS ironwood,
                EXISTS(SELECT 1 FROM transparent_received_outputs
                        WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                    AS transparent,
                CASE
                    WHEN EXISTS(SELECT 1 FROM transparent_received_outputs
                                 WHERE spent_tx = t.id_tx)
                     AND (EXISTS(SELECT 1 FROM sapling_received_notes
                                  WHERE transaction_id = t.id_tx)
                       OR EXISTS(SELECT 1 FROM orchard_received_notes
                                  WHERE transaction_id = t.id_tx)
                       OR EXISTS(SELECT 1 FROM ironwood_received_notes
                                  WHERE transaction_id = t.id_tx))
                        THEN 'shielding'
                    WHEN (EXISTS(SELECT 1 FROM sapling_received_notes
                                  WHERE spent_tx = t.id_tx)
                       OR EXISTS(SELECT 1 FROM orchard_received_notes
                                  WHERE spent_tx = t.id_tx)
                       OR EXISTS(SELECT 1 FROM ironwood_received_notes
                                  WHERE spent_tx = t.id_tx))
                     AND EXISTS(SELECT 1 FROM transparent_received_outputs
                                 WHERE transaction_id = t.id_tx)
                        THEN 'deshielding'
                    WHEN NOT EXISTS(SELECT 1 FROM sapling_received_notes
                                     WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                    AND NOT EXISTS(SELECT 1 FROM orchard_received_notes
                                    WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                    AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes
                                    WHERE transaction_id = t.id_tx OR spent_tx = t.id_tx)
                        THEN 'transparent'
                    ELSE 'shielded'
                END AS kind,
                (SELECT memo FROM (
                    SELECT memo FROM sapling_received_notes
                     WHERE transaction_id = t.id_tx AND memo IS NOT NULL
                    UNION ALL
                    SELECT memo FROM orchard_received_notes
                     WHERE transaction_id = t.id_tx AND memo IS NOT NULL
                    UNION ALL
                    SELECT memo FROM ironwood_received_notes
                     WHERE transaction_id = t.id_tx AND memo IS NOT NULL)
                 LIMIT 1)
                    AS memo,
                (SELECT GROUP_CONCAT(recipient_address, ', ') FROM (
                    SELECT recipient_address FROM sapling_received_notes
                     WHERE transaction_id = t.id_tx AND recipient_address IS NOT NULL
                    UNION ALL
                    SELECT recipient_address FROM orchard_received_notes
                     WHERE transaction_id = t.id_tx AND recipient_address IS NOT NULL
                    UNION ALL
                    SELECT recipient_address FROM ironwood_received_notes
                     WHERE transaction_id = t.id_tx AND recipient_address IS NOT NULL))
                    AS recipients
            FROM txs t;

            "#,
    )?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub height: u32,
    pub hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolBalance {
    pub orchard: Zatoshis,
    pub ironwood: Zatoshis,
    pub sapling: Zatoshis,
    pub transparent: Zatoshis,
}

impl Default for PoolBalance {
    fn default() -> Self {
        PoolBalance {
            orchard: Zatoshis::ZERO,
            ironwood: Zatoshis::ZERO,
            sapling: Zatoshis::ZERO,
            transparent: Zatoshis::ZERO,
        }
    }
}

impl PoolBalance {
    pub fn total(&self) -> Zatoshis {
        (((self.orchard + self.ironwood).and_then(|s| s + self.sapling))
            .and_then(|s| s + self.transparent))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRow {
    pub address: String,
    pub txid: TxId,
    pub height: Option<u32>,
    pub output_index: u32,
    pub value: Zatoshis,
    pub spent_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRow {
    pub pool: Pool,
    pub txid: TxId,
    pub height: Option<u32>,
    pub output_index: u32,
    pub value: Zatoshis,
    pub memo: Option<Vec<u8>>,
    pub spent_height: Option<u32>,
    pub is_sent: bool,
    pub recipient: Option<String>,
}

/// The account's view of a transaction's shielding direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    /// Touches shielded pools only.
    Shielded,
    /// Spends the account's transparent funds into the shielded pools (t→z).
    Shielding,
    /// Spends the account's shielded notes to a transparent output (z→t).
    Deshielding,
    /// Touches the transparent pool only.
    Transparent,
}

/// One row of the `transactions` super table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRow {
    pub txid: TxId,
    pub height: Option<u32>,
    pub tx_index: Option<u32>,
    pub received: Zatoshis,
    pub sent: Zatoshis,
    pub spent: Zatoshis,
    pub sapling: bool,
    pub orchard: bool,
    pub ironwood: bool,
    pub transparent: bool,
    pub kind: TxKind,
    pub memo: Option<Vec<u8>>,
    pub recipients: Option<String>,
}

/// The shielded note tables are twins; every per-pool statement is written
/// once and parameterized by [`Pool`], iterating [`POOLS`].
const POOLS: [Pool; 3] = [Pool::Sapling, Pool::Orchard, Pool::Ironwood];

fn note_table(pool: Pool) -> &'static str {
    match pool {
        Pool::Sapling => "sapling_received_notes",
        Pool::Orchard => "orchard_received_notes",
        Pool::Ironwood => "ironwood_received_notes",
    }
}

fn index_col(pool: Pool) -> &'static str {
    match pool {
        Pool::Sapling => "output_index",
        Pool::Orchard => "action_index",
        Pool::Ironwood => "action_index",
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

    pub fn set_birthday(&self, height: BlockHeight) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO account(id, birthday) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET birthday = excluded.birthday",
            params![u32::from(height)],
        )?;
        Ok(())
    }

    pub fn birthday(&self) -> rusqlite::Result<Option<BlockHeight>> {
        self.conn
            .query_row("SELECT birthday FROM account WHERE id = 1", [], |row| {
                row.get::<_, u32>(0).map(BlockHeight::from_u32)
            })
            .optional()
    }

    /// Requires the account row ([`Db::set_birthday`] first); a no-op without it.
    pub fn set_sync_state(&self, state: &SyncState) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE account SET sync_height = ?1, sync_hash = ?2 WHERE id = 1",
            params![state.height, state.hash.as_ref().map(|h| h.as_slice())],
        )?;
        Ok(())
    }

    /// `None` until the first applied batch: a NULL `sync_height` is the
    /// "never synced" state, no sentinel heights.
    pub fn get_sync_state(&self) -> rusqlite::Result<Option<SyncState>> {
        self.conn
            .query_row(
                "SELECT sync_height, sync_hash FROM account
                 WHERE id = 1 AND sync_height IS NOT NULL",
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
    }

    pub fn unspent_nullifiers(&self) -> rusqlite::Result<Vec<(Pool, Nullifier)>> {
        let mut out = Vec::new();
        for pool in POOLS {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT nf FROM {} WHERE nf IS NOT NULL AND spent_tx IS NULL",
                note_table(pool)
            ))?;
            let rows = stmt.query_map([], |row| row.get::<_, [u8; 32]>(0))?;
            for nf in rows {
                out.push((pool, Nullifier(nf?)));
            }
        }
        Ok(out)
    }

    pub fn unspent_outpoints(&self) -> rusqlite::Result<Vec<OutPoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.txid, o.output_index
             FROM transparent_received_outputs o
             JOIN txs t ON t.id_tx = o.transaction_id
             WHERE o.spent_tx IS NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(OutPoint::new(row.get::<_, [u8; 32]>(0)?, row.get(1)?))
        })?;
        rows.collect()
    }

    pub fn upsert_transaction(
        &self,
        txid: &[u8],
        height: Option<u32>,
        tx_index: Option<u32>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO txs(txid, mined_height, tx_index)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(txid) DO UPDATE SET
                mined_height = COALESCE(excluded.mined_height, mined_height),
                tx_index = COALESCE(excluded.tx_index, tx_index)",
            params![txid, height, tx_index],
        )?;
        self.conn.query_row(
            "SELECT id_tx FROM txs WHERE txid = ?1",
            params![txid],
            |row| row.get(0),
        )
    }

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
        self.insert_orchard_like_note("orchard_received_notes", n)
    }

    pub fn insert_ironwood_note(&self, n: &OrchardNoteInsert<'_>) -> rusqlite::Result<()> {
        self.insert_orchard_like_note("ironwood_received_notes", n)
    }

    fn insert_orchard_like_note(
        &self,
        table: &str,
        n: &OrchardNoteInsert<'_>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            &format!(
                "INSERT INTO {table}(
                transaction_id, action_index, diversifier, value, rho, rseed, nf,
                memo, commitment_tree_position, is_sent, recipient_address)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(transaction_id, action_index) DO NOTHING"
            ),
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

    pub fn mark_spent(&self, pool: Pool, nf: &[u8], spent_tx: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            &format!(
                "UPDATE {} SET spent_tx = ?2 WHERE nf = ?1",
                note_table(pool)
            ),
            params![nf, spent_tx],
        )
    }

    pub fn insert_transparent_output(
        &self,
        transaction_id: i64,
        output_index: u32,
        address: &str,
        script: &[u8],
        value: u64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO transparent_received_outputs(
                transaction_id, output_index, address, script, value)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(transaction_id, output_index) DO NOTHING",
            params![transaction_id, output_index, address, script, value as i64],
        )?;
        Ok(())
    }

    pub fn mark_transparent_spent(
        &self,
        prevout_txid: &[u8],
        prevout_index: u32,
        spent_tx: i64,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE transparent_received_outputs
             SET spent_tx = ?3
             WHERE output_index = ?2 AND transaction_id =
                (SELECT id_tx FROM txs WHERE txid = ?1)",
            params![prevout_txid, prevout_index, spent_tx],
        )
    }

    pub fn balance(&self) -> rusqlite::Result<PoolBalance> {
        let shielded = |pool| {
            self.unspent_sum(&format!(
                "SELECT COALESCE(SUM(value), 0) FROM {}
                 WHERE spent_tx IS NULL AND is_sent = 0",
                note_table(pool)
            ))
        };
        Ok(PoolBalance {
            sapling: shielded(Pool::Sapling)?,
            orchard: shielded(Pool::Orchard)?,
            ironwood: shielded(Pool::Ironwood)?,
            transparent: self.unspent_sum(
                "SELECT COALESCE(SUM(value), 0) FROM transparent_received_outputs
                 WHERE spent_tx IS NULL",
            )?,
        })
    }

    fn unspent_sum(&self, sql: &str) -> rusqlite::Result<Zatoshis> {
        self.conn.query_row(sql, [], |row| row.get(0)).map(zatoshis)
    }

    pub fn transparent_outputs(&self) -> rusqlite::Result<Vec<UtxoRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT o.address, t.txid, t.mined_height, o.output_index, o.value, sp.mined_height
             FROM transparent_received_outputs o
             JOIN txs t ON t.id_tx = o.transaction_id
             LEFT JOIN txs sp ON sp.id_tx = o.spent_tx
             ORDER BY t.mined_height IS NULL, t.mined_height, t.txid, o.output_index",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(UtxoRow {
                address: row.get(0)?,
                txid: txid(row.get(1)?),
                height: row.get(2)?,
                output_index: row.get(3)?,
                value: zatoshis(row.get(4)?),
                spent_height: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn notes(&self) -> rusqlite::Result<Vec<NoteRow>> {
        let mut out = Vec::new();
        for pool in POOLS {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT t.txid, t.mined_height, n.{index}, n.value, n.memo,
                        sp.mined_height, n.is_sent, n.recipient_address
                 FROM {table} n
                 JOIN txs t ON t.id_tx = n.transaction_id
                 LEFT JOIN txs sp ON sp.id_tx = n.spent_tx",
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

    /// The `transactions` super table, oldest first.
    pub fn transactions(&self) -> rusqlite::Result<Vec<TxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT txid, mined_height, tx_index, received, sent, spent,
                    sapling, orchard, ironwood, transparent, kind, memo, recipients
             FROM transactions
             ORDER BY mined_height IS NULL, mined_height, tx_index",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TxRow {
                txid: txid(row.get(0)?),
                height: row.get(1)?,
                tx_index: row.get(2)?,
                received: zatoshis(row.get(3)?),
                sent: zatoshis(row.get(4)?),
                spent: zatoshis(row.get(5)?),
                sapling: row.get(6)?,
                orchard: row.get(7)?,
                ironwood: row.get(8)?,
                transparent: row.get(9)?,
                kind: tx_kind(&row.get::<_, String>(10)?),
                memo: row.get(11)?,
                recipients: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// Deleting the orphaned transactions un-spends every note and output
    /// they consumed via the `spent_tx` foreign key — the database enforces
    /// what used to be three hand-written UPDATEs.
    pub fn rewind_to_height(&self, height: u32) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM txs WHERE mined_height > ?1", params![height])?;
        tx.execute(
            "UPDATE account SET sync_height = ?1, sync_hash = NULL WHERE id = 1",
            params![height],
        )?;
        tx.commit()
    }
}

fn note_row(pool: Pool, row: &Row<'_>) -> rusqlite::Result<NoteRow> {
    Ok(NoteRow {
        pool,
        txid: txid(row.get(0)?),
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

fn tx_kind(s: &str) -> TxKind {
    match s {
        "shielded" => TxKind::Shielded,
        "shielding" => TxKind::Shielding,
        "deshielding" => TxKind::Deshielding,
        "transparent" => TxKind::Transparent,
        other => unreachable!("unknown transaction kind {other:?}"),
    }
}

fn txid(bytes: [u8; 32]) -> TxId {
    TxId::from_bytes(bytes)
}

impl Account for Db {
    type Error = DbError;

    fn resume(&self) -> Result<Resume, Self::Error> {
        let birthday = self.birthday()?.ok_or(DbError::BirthdayUnset)?;
        let checkpoint = self.get_sync_state()?.map(|st| Cursor {
            height: BlockHeight::from_u32(st.height),
            hash: st.hash.map(BlockHash),
        });
        Ok(Resume {
            birthday,
            checkpoint,
            nullifiers: self.unspent_nullifiers()?,
            outpoints: self.unspent_outpoints()?,
        })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), Self::Error> {
        self.rewind_to_height(u32::from(to))?;
        Ok(())
    }

    fn apply(&self, at: Cursor, batch: &Batch) -> Result<(), Self::Error> {
        let tx = self.conn.unchecked_transaction()?;
        let mut ids: HashMap<TxId, i64> = HashMap::new();
        let mut id_for = |txid: &TxId, height: u32, index: Option<u32>| -> rusqlite::Result<i64> {
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
                ShieldedNote::Ironwood(n) => self.insert_ironwood_note(&OrchardNoteInsert {
                    transaction_id: id,
                    action_index: note.output_index,
                    diversifier: n.recipient().diversifier().as_array(),
                    value: n.value().inner(),
                    rho: &n.rho().to_bytes(),
                    rseed: n.rseed().as_bytes(),
                    nf: note.nullifier.as_ref().map(|nf| nf.0.as_slice()),
                    memo: note.memo.as_ref().map(|m| m.as_slice()),
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
            let id = id_for(&spend.txid, u32::from(spend.height), None)?;
            self.mark_spent(spend.pool, &spend.nf.0, id)?;
        }

        for o in &batch.transparent_outputs {
            let id = id_for(&o.txid, u32::from(o.height), None)?;
            self.insert_transparent_output(id, o.output_index, &o.address, &o.script, o.value_zat)?;
        }

        for s in &batch.transparent_spends {
            let id = id_for(&s.txid, u32::from(s.height), None)?;
            self.mark_transparent_spent(s.outpoint.txid().as_ref(), s.outpoint.n(), id)?;
        }

        self.set_sync_state(&SyncState {
            height: u32::from(at.height),
            hash: at.hash.map(|h| h.0),
        })?;
        tx.commit()?;
        Ok(())
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
        init(&db.conn).unwrap();
        let spine: u32 = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = 'txs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(spine, 1);
        let view: u32 = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type = 'view' AND name = 'transactions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(view, 1, "transactions is the super-table view");
    }

    #[test]
    fn sync_state_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            db.get_sync_state().unwrap(),
            None,
            "fresh db: no account row"
        );
        let state = SyncState {
            height: 42,
            hash: Some([7u8; 32]),
        };
        db.set_sync_state(&state).unwrap();
        assert_eq!(
            db.get_sync_state().unwrap(),
            None,
            "sync state needs the account row: birthday first"
        );
        db.set_birthday(BlockHeight::from_u32(40)).unwrap();
        db.set_sync_state(&state).unwrap();
        let got = db.get_sync_state().unwrap().unwrap();
        assert_eq!(got.height, 42);
        assert_eq!(got.hash, Some([7u8; 32]));
    }

    #[test]
    fn birthday_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.birthday().unwrap(), None);
        db.set_birthday(BlockHeight::from_u32(419_200)).unwrap();
        assert_eq!(db.birthday().unwrap(), Some(BlockHeight::from_u32(419_200)));
    }

    #[test]
    fn unspent_watch_sets_track_spends() {
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
            commitment_tree_position: None,
            is_sent: false,
            recipient_address: None,
        })
        .unwrap();
        db.insert_transparent_output(tx, 1, "t1example", &[0x76], 2_000_000)
            .unwrap();

        assert_eq!(
            db.unspent_nullifiers().unwrap(),
            vec![(Pool::Orchard, Nullifier([9u8; 32]))]
        );
        assert_eq!(
            db.unspent_outpoints().unwrap(),
            vec![OutPoint::new([1u8; 32], 1)]
        );

        let spender = mined_tx(&db, &[2u8; 32], 105);
        db.mark_spent(Pool::Orchard, &[9u8; 32], spender).unwrap();
        db.mark_transparent_spent(&[1u8; 32], 1, spender).unwrap();
        assert!(db.unspent_nullifiers().unwrap().is_empty());
        assert!(db.unspent_outpoints().unwrap().is_empty());
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

        let spender = mined_tx(&db, &[4u8; 32], 101);
        assert_eq!(
            db.mark_spent(Pool::Orchard, &[9u8; 32], spender).unwrap(),
            1
        );
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
        db.mark_spent(Pool::Orchard, &[9u8; 32], spend).unwrap();
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
        assert_eq!(txs[0].txid, txid([1u8; 32]));
        assert_eq!(txs[0].received, Zatoshis::const_from_u64(5_000_000));
        assert_eq!(txs[0].spent, Zatoshis::ZERO);
        assert_eq!(txs[0].kind, TxKind::Shielded);
        assert!(txs[0].orchard && !txs[0].sapling && !txs[0].transparent);
        assert_eq!(txs[0].memo.as_deref(), Some(&b"hi"[..]));
        assert_eq!(txs[0].recipients, None);
        assert_eq!(txs[1].txid, txid([2u8; 32]));
        assert_eq!(txs[1].sent, Zatoshis::const_from_u64(3_000_000));
        assert_eq!(txs[1].spent, Zatoshis::const_from_u64(5_000_000));
        assert_eq!(txs[1].kind, TxKind::Shielded);
        assert!(
            txs[1].orchard && txs[1].sapling,
            "spends orchard, sends sapling"
        );
        assert_eq!(txs[1].recipients.as_deref(), Some("u1recipient"));
    }

    #[test]
    fn super_table_classifies_shielding_directions() {
        let db = Db::open_in_memory().unwrap();

        // t-funds arrive, then get spent into an orchard note: shielding.
        let funding = mined_tx(&db, &[1u8; 32], 100);
        db.insert_transparent_output(funding, 0, "t1example", &[0x76], 2_000_000)
            .unwrap();
        let shield = mined_tx(&db, &[2u8; 32], 110);
        db.mark_transparent_spent(&[1u8; 32], 0, shield).unwrap();
        db.insert_orchard_note(&OrchardNoteInsert {
            transaction_id: shield,
            action_index: 0,
            diversifier: &[0u8; 11],
            value: 1_900_000,
            rho: &[1u8; 32],
            rseed: &[2u8; 32],
            nf: Some(&[9u8; 32]),
            memo: None,
            commitment_tree_position: None,
            is_sent: false,
            recipient_address: None,
        })
        .unwrap();

        // The orchard note gets spent back to a transparent output: deshielding.
        let deshield = mined_tx(&db, &[3u8; 32], 120);
        db.mark_spent(Pool::Orchard, &[9u8; 32], deshield).unwrap();
        db.insert_transparent_output(deshield, 0, "t1example", &[0x76], 1_800_000)
            .unwrap();

        let txs = db.transactions().unwrap();
        assert_eq!(txs.len(), 3);
        assert_eq!(txs[0].kind, TxKind::Transparent);
        assert_eq!(txs[1].kind, TxKind::Shielding);
        assert!(txs[1].transparent && txs[1].orchard);
        assert_eq!(txs[2].kind, TxKind::Deshielding);
    }

    #[test]
    fn transparent_output_received_spent_and_rewound() {
        let db = Db::open_in_memory().unwrap();
        let funding = mined_tx(&db, &[5u8; 32], 100);
        db.insert_transparent_output(funding, 0, "t1example", &[0x76], 2_000_000)
            .unwrap();

        let balance = db.balance().unwrap();
        assert_eq!(balance.transparent, Zatoshis::const_from_u64(2_000_000));
        assert_eq!(balance.total(), Zatoshis::const_from_u64(2_000_000));
        let outs = db.transparent_outputs().unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].height, Some(100));
        assert_eq!(outs[0].spent_height, None);
        assert_eq!(
            db.transactions().unwrap()[0].received,
            Zatoshis::const_from_u64(2_000_000)
        );

        let spender = mined_tx(&db, &[6u8; 32], 120);
        assert_eq!(
            db.mark_transparent_spent(&[5u8; 32], 0, spender).unwrap(),
            1
        );
        assert_eq!(db.balance().unwrap().transparent, Zatoshis::ZERO);
        assert_eq!(db.transparent_outputs().unwrap()[0].spent_height, Some(120));

        db.rewind_to_height(115).unwrap();
        assert_eq!(
            db.balance().unwrap().transparent,
            Zatoshis::const_from_u64(2_000_000)
        );
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
        let spender = mined_tx(&db, &[4u8; 32], 105);
        db.mark_spent(Pool::Orchard, &[9u8; 32], spender).unwrap();
        assert_eq!(db.balance().unwrap().orchard, Zatoshis::ZERO);

        db.set_birthday(BlockHeight::from_u32(90)).unwrap();
        db.rewind_to_height(104).unwrap();
        assert_eq!(
            db.balance().unwrap().orchard,
            Zatoshis::const_from_u64(9_000_000),
            "deleting the spender tx must un-spend the note via the FK"
        );
        assert_eq!(db.get_sync_state().unwrap().unwrap().height, 104);

        db.rewind_to_height(99).unwrap();
        assert_eq!(db.balance().unwrap().orchard, Zatoshis::ZERO);
    }
}
