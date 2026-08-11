//! SQLite-backed `Account` implementation for the sync engine.
//!
//! Stores received notes, detected spends, and the sync checkpoint in a single
//! SQLite database.  Implements the [`Account`] trait so it can be passed
//! directly to [`sync::run`](crate::sync::run).
//!
//! ## Schema
//!
//! - **account** (1 row): birthday, sync_height, sync_hash
//! - **txs**: txid, block_height, tx_index, amount, is_outgoing
//! - **sapling_notes**: per output — note data, nullifier, spend state
//! - **orchard_notes**: same shape, orchard types
//! - **ironwood_notes**: same shape, ironwood (reuses orchard types)
//!
//! Spends are columns on the note they consume (`spent`, `spent_height`,
//! `spent_txid`, `spent_index`), not a separate table — every spend matches
//! exactly one of our notes via its nullifier.

use std::error::Error;
use std::path::Path;

use rusqlite::{params, Connection};

use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zip32::Scope;

use crate::sync::scan::{
    Nullifiers, OrchardOutput, SaplingOutput, WalletTx,
};
use crate::sync::{Account, Cursor, Resume};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("corrupted data: {0}")]
    Corrupt(String),
}



// ─── Db handle ───────────────────────────────────────────────────────────────

pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open or create the database at `path`, running migrations if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (for tests).
    pub fn open_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    fn migrate(conn: &Connection) -> Result<(), DbError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS account (
                id          INTEGER PRIMARY KEY DEFAULT 1,
                birthday    INTEGER NOT NULL,
                sync_height INTEGER,
                sync_hash   BLOB
            );

            CREATE TABLE IF NOT EXISTS txs (
                txid        BLOB    NOT NULL,
                block_height INTEGER NOT NULL,
                tx_index    INTEGER NOT NULL,
                amount      INTEGER NOT NULL,
                is_outgoing INTEGER NOT NULL CHECK (is_outgoing IN (0,1)),
                PRIMARY KEY (txid)
            );

            CREATE TABLE IF NOT EXISTS sapling_notes (
                txid         BLOB    NOT NULL,
                output_index INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                nf           BLOB,
                note         BLOB    NOT NULL,
                recipient    BLOB    NOT NULL,
                memo         BLOB,
                scope        INTEGER NOT NULL,
                position     INTEGER NOT NULL,
                is_sent      INTEGER NOT NULL CHECK (is_sent IN (0,1)),
                is_change    INTEGER NOT NULL CHECK (is_change IN (0,1)),
                spent        INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0,1)),
                spent_height INTEGER,
                spent_txid   BLOB,
                spent_index  INTEGER,
                PRIMARY KEY (txid, output_index)
            );

            CREATE TABLE IF NOT EXISTS orchard_notes (
                txid         BLOB    NOT NULL,
                output_index INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                nf           BLOB,
                note         BLOB    NOT NULL,
                recipient    BLOB    NOT NULL,
                memo         BLOB,
                scope        INTEGER NOT NULL,
                position     INTEGER NOT NULL,
                is_sent      INTEGER NOT NULL CHECK (is_sent IN (0,1)),
                is_change    INTEGER NOT NULL CHECK (is_change IN (0,1)),
                spent        INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0,1)),
                spent_height INTEGER,
                spent_txid   BLOB,
                spent_index  INTEGER,
                PRIMARY KEY (txid, output_index)
            );

            CREATE TABLE IF NOT EXISTS ironwood_notes (
                txid         BLOB    NOT NULL,
                output_index INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                nf           BLOB,
                note         BLOB    NOT NULL,
                recipient    BLOB    NOT NULL,
                memo         BLOB,
                scope        INTEGER NOT NULL,
                position     INTEGER NOT NULL,
                is_sent      INTEGER NOT NULL CHECK (is_sent IN (0,1)),
                is_change    INTEGER NOT NULL CHECK (is_change IN (0,1)),
                spent        INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0,1)),
                spent_height INTEGER,
                spent_txid   BLOB,
                spent_index  INTEGER,
                PRIMARY KEY (txid, output_index)
            );

            CREATE INDEX IF NOT EXISTS idx_sapling_nf   ON sapling_notes(nf);
            CREATE INDEX IF NOT EXISTS idx_orchard_nf   ON orchard_notes(nf);
            CREATE INDEX IF NOT EXISTS idx_ironwood_nf  ON ironwood_notes(nf);
            ",
        )?;
        Ok(())
    }

    /// Initialise the account row if it doesn't exist yet.
    pub fn init_account(&self, birthday: BlockHeight) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO account (id, birthday, sync_height, sync_hash)
             VALUES (1, ?, NULL, NULL)",
            params![u32::from(birthday)],
        )?;
        Ok(())
    }

    /// Total unspent balance across all shielded pools, in zatoshis.
    /// Note values are stored in the note blob; this extracts the 8-byte
    /// little-endian value at offset 43 (after the 43-byte recipient).
    pub fn balance(&self) -> Result<u64, DbError> {
        let mut total: u64 = 0;
        for table in NOTES_TABLES {
            let rows: Vec<Vec<u8>> = self.conn
                .prepare(&format!(
                    "SELECT note FROM {table} WHERE spent = 0"
                ))?
                .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            for blob in rows {
                // Value is at bytes 43..51 (after 43-byte recipient).
                if blob.len() >= 51 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&blob[43..51]);
                    total = total.saturating_add(u64::from_le_bytes(arr));
                }
            }
        }
        Ok(total)
    }
}

// ─── Account impl ────────────────────────────────────────────────────────────

impl Account for Db {
    fn resume(&self) -> Result<Resume, Box<dyn Error + Send + Sync>> {
        let (birthday, sync_height, sync_hash): (u32, Option<u32>, Option<Vec<u8>>) = self
            .conn
            .query_row(
                "SELECT birthday, sync_height, sync_hash FROM account WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| DbError::from(e))?;

        let checkpoint = match (sync_height, sync_hash) {
            (Some(h), Some(h_bytes)) => {
                let hash: [u8; 32] = h_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DbError::Corrupt("sync_hash is not 32 bytes".into()))?;
                Some(Cursor {
                    height: BlockHeight::from_u32(h),
                    hash: BlockHash(hash),
                })
            }
            _ => None,
        };

        let nullifiers = self.load_nullifiers()?;

        Ok(Resume {
            birthday: BlockHeight::from_u32(birthday),
            checkpoint,
            nullifiers,
        })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), Box<dyn Error + Send + Sync>> {
        let to = u32::from(to);
        let tx = self.conn.unchecked_transaction()?;

        // 1. Delete notes received on the dead chain (height >= to).
        for table in NOTES_TABLES {
            tx.execute(
                &format!("DELETE FROM {table} WHERE block_height >= ?"),
                params![to],
            )?;
        }

        // 2. Unspend notes that were spent on the dead chain.
        //    (spent_height >= to → set spent=0, clear spend columns)
        for table in NOTES_TABLES {
            tx.execute(
                &format!(
                    "UPDATE {table} SET spent = 0, spent_height = NULL, \
                     spent_txid = NULL, spent_index = NULL \
                     WHERE spent_height IS NOT NULL AND spent_height >= ?"
                ),
                params![to],
            )?;
        }

        // 3. Delete txs on the dead chain.
        tx.execute(
            "DELETE FROM txs WHERE block_height >= ?",
            params![to],
        )?;

        // 4. Update checkpoint (sync_hash will be fixed by the next apply).
        tx.execute(
            "UPDATE account SET sync_height = ? WHERE id = 1",
            params![to],
        )?;

        tx.commit()?;
        Ok(())
    }

    fn apply(
        &self,
        at: Cursor,
        transactions: &[WalletTx],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let tx = self.conn.unchecked_transaction()?;

        for wtx in transactions {
            // Determine if this tx is outgoing (any is_sent output).
            let is_outgoing = wtx.sapling_outputs.iter().any(|o| o.is_sent)
                || wtx.orchard_outputs.iter().any(|o| o.is_sent)
                || wtx.ironwood_outputs.iter().any(|o| o.is_sent);

            // Total value of all our notes in this tx.
            let amount: u64 = wtx.sapling_outputs.iter().map(|o| o.note.value().inner())
                .chain(wtx.orchard_outputs.iter().map(|o| o.note.value().inner()))
                .chain(wtx.ironwood_outputs.iter().map(|o| o.note.value().inner()))
                .sum();

            // Upsert tx row (ON CONFLICT in case we re-scan the same block).
            tx.execute(
                "INSERT INTO txs (txid, block_height, tx_index, amount, is_outgoing)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(txid) DO UPDATE SET
                    block_height = excluded.block_height,
                    tx_index = excluded.tx_index,
                    amount = excluded.amount,
                    is_outgoing = excluded.is_outgoing",
                params![
                    wtx.txid.as_ref(),
                    u32::from(wtx.height),
                    wtx.tx_index,
                    amount as i64,
                    is_outgoing as i64,
                ],
            )?;

            // Insert notes.
            for o in &wtx.sapling_outputs {
                insert_note_sapling(&tx, &wtx.txid, wtx.height, o)?;
            }
            for o in &wtx.orchard_outputs {
                insert_note_orchard(&tx, "orchard_notes", &wtx.txid, wtx.height, o)?;
            }
            for o in &wtx.ironwood_outputs {
                insert_note_orchard(&tx, "ironwood_notes", &wtx.txid, wtx.height, o)?;
            }

            // Mark spent notes.
            for s in &wtx.sapling_spends {
                tx.execute(
                    "UPDATE sapling_notes SET spent = 1, spent_height = ?, spent_txid = ?, spent_index = ?
                     WHERE nf = ? AND spent = 0",
                    params![u32::from(wtx.height), wtx.txid.as_ref(), s.index, s.nf.to_vec()],
                )?;
            }
            for s in &wtx.orchard_spends {
                tx.execute(
                    "UPDATE orchard_notes SET spent = 1, spent_height = ?, spent_txid = ?, spent_index = ?
                     WHERE nf = ? AND spent = 0",
                    params![u32::from(wtx.height), wtx.txid.as_ref(), s.index, s.nf.to_bytes().to_vec()],
                )?;
            }
            for s in &wtx.ironwood_spends {
                tx.execute(
                    "UPDATE ironwood_notes SET spent = 1, spent_height = ?, spent_txid = ?, spent_index = ?
                     WHERE nf = ? AND spent = 0",
                    params![u32::from(wtx.height), wtx.txid.as_ref(), s.index, s.nf.to_bytes().to_vec()],
                )?;
            }
        }

        // Update checkpoint.
        tx.execute(
            "UPDATE account SET sync_height = ?, sync_hash = ? WHERE id = 1",
            params![u32::from(at.height), at.hash.0.as_slice()],
        )?;

        tx.commit()?;
        Ok(())
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

const NOTES_TABLES: &[&str] = &["sapling_notes", "orchard_notes", "ironwood_notes"];

impl Db {
    fn load_nullifiers(&self) -> Result<Nullifiers, DbError> {
        let sapling = self.conn
            .prepare("SELECT nf FROM sapling_notes WHERE nf IS NOT NULL AND spent = 0")?
            .query_map([], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        32,
                        rusqlite::types::Type::Blob,
                        Box::new(DbError::Corrupt("sapling nf not 32 bytes".into())),
                    )
                })?;
                Ok(sapling::Nullifier::from_slice(&arr).unwrap())
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let orchard = self.load_orchard_nullifiers("orchard_notes")?;
        let ironwood = self.load_orchard_nullifiers("ironwood_notes")?;

        Ok(Nullifiers { sapling, orchard, ironwood })
    }

    fn load_orchard_nullifiers(&self, table: &str) -> Result<Vec<orchard::note::Nullifier>, DbError> {
        self.conn
            .prepare(&format!(
                "SELECT nf FROM {table} WHERE nf IS NOT NULL AND spent = 0"
            ))?
            .query_map([], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let arr: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        32,
                        rusqlite::types::Type::Blob,
                        Box::new(DbError::Corrupt("orchard nf not 32 bytes".into())),
                    )
                })?;
                Option::from(orchard::note::Nullifier::from_bytes(arr))
                    .ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            32,
                            rusqlite::types::Type::Blob,
                            Box::new(DbError::Corrupt("invalid orchard nullifier".into())),
                        )
                    })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

// ─── note serialization ──────────────────────────────────────────────────────
//
// Each note is stored as a single BLOB.  The format is pool-specific but
// deterministic — we only ever read what we wrote.

/// Serialize a sapling note into a blob.
fn serialize_sapling_note(note: &sapling::Note) -> Vec<u8> {
    let mut buf = Vec::with_capacity(84);
    buf.extend_from_slice(&note.recipient().to_bytes());     // 43
    buf.extend_from_slice(&note.value().inner().to_le_bytes()); // 8
    match note.rseed() {
        sapling::note::Rseed::BeforeZip212(fr) => {
            buf.push(0);
            buf.extend_from_slice(&fr.to_bytes());            // 32
        }
        sapling::note::Rseed::AfterZip212(seed) => {
            buf.push(1);
            buf.extend_from_slice(seed);                        // 32
        }
    }
    buf
}

/// Serialize an orchard note into a blob.
fn serialize_orchard_note(note: &orchard::Note) -> Vec<u8> {
    use orchard::note::NoteVersion;
    let mut buf = Vec::with_capacity(116);
    buf.extend_from_slice(&note.recipient().to_raw_address_bytes()); // 43
    buf.extend_from_slice(&note.value().inner().to_le_bytes());     // 8
    buf.extend_from_slice(&note.rho().to_bytes());                   // 32
    buf.extend_from_slice(note.rseed().as_bytes());                  // 32
    buf.push(match note.version() {
        NoteVersion::V2 => 0,
        NoteVersion::V3 => 1,
    });
    buf
}

// ─── note insertion ──────────────────────────────────────────────────────────

fn insert_note_orchard(
    tx: &rusqlite::Transaction,
    table: &str,
    txid: &TxId,
    height: BlockHeight,
    output: &OrchardOutput,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let note_blob = serialize_orchard_note(&output.note);
    let recipient_blob = output.recipient.to_raw_address_bytes();
    let nf_blob = output.nf.map(|nf| nf.to_bytes().to_vec());
    let memo_blob = output.memo.map(|m| m.to_vec());

    tx.execute(
        &format!(
            "INSERT OR IGNORE INTO {table}
             (txid, output_index, block_height, nf, note, recipient, memo,
              scope, position, is_sent, is_change, spent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)"
        ),
        params![
            txid.as_ref(),
            output.index,
            u32::from(height),
            nf_blob,
            &note_blob,
            &recipient_blob,
            memo_blob,
            scope_to_u8(output.scope),
            output.position,
            output.is_sent as i64,
            output.is_change as i64,
        ],
    )?;
    Ok(())
}

// Separate function for sapling notes (different note/recipient types).
fn insert_note_sapling(
    tx: &rusqlite::Transaction,
    txid: &TxId,
    height: BlockHeight,
    output: &SaplingOutput,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let note_blob = serialize_sapling_note(&output.note);
    let recipient_blob = output.recipient.to_bytes();
    let nf_blob = output.nf.map(|nf| nf.to_vec());
    let memo_blob = output.memo.map(|m| m.to_vec());

    tx.execute(
        "INSERT OR IGNORE INTO sapling_notes
         (txid, output_index, block_height, nf, note, recipient, memo,
          scope, position, is_sent, is_change, spent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        params![
            txid.as_ref(),
            output.index,
            u32::from(height),
            nf_blob,
            &note_blob,
            &recipient_blob,
            memo_blob,
            scope_to_u8(output.scope),
            output.position,
            output.is_sent as i64,
            output.is_change as i64,
        ],
    )?;
    Ok(())
}

fn scope_to_u8(scope: Scope) -> u8 {
    match scope {
        Scope::External => 0,
        Scope::Internal => 1,
    }
}