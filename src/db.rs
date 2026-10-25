//! SQLite-backed `Account` implementation for the sync engine.
//!
//! Stores received notes, detected spends, and the sync checkpoint in a single
//! SQLite database.  Implements the [`Account`] trait so it can be passed
//! directly to [`run`](crate::run).
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

use crate::sync::scan::{Nullifiers, OrchardOutput, SaplingOutput, WalletTx};
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

    /// Borrow the underlying connection (for read-only queries).
    pub fn conn(&self) -> &Connection {
        &self.conn
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
    ///
    /// Only notes we own count. A sent note is someone else's: recovered with
    /// the outgoing key, it has no nullifier of ours and is never marked spent.
    pub fn balance(&self) -> Result<u64, DbError> {
        let mut total: u64 = 0;
        for table in NOTES_TABLES {
            let values = note_values(
                &self.conn,
                &format!("SELECT note FROM {table} WHERE spent = 0 AND is_sent = 0"),
                [],
            )?;
            total = values.into_iter().fold(total, u64::saturating_add);
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
            .map_err(DbError::from)?;

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

    fn rewind(&self, to: Cursor) -> Result<(), Box<dyn Error + Send + Sync>> {
        let height = u32::from(to.height);
        let tx = self.conn.unchecked_transaction()?;

        // 1. Delete notes received on the dead chain (height > to).
        for table in NOTES_TABLES {
            tx.execute(
                &format!("DELETE FROM {table} WHERE block_height > ?"),
                params![height],
            )?;
        }

        // 2. Unspend notes that were spent on the dead chain.
        //    (spent_height > to → set spent=0, clear spend columns)
        for table in NOTES_TABLES {
            tx.execute(
                &format!(
                    "UPDATE {table} SET spent = 0, spent_height = NULL, \
                     spent_txid = NULL, spent_index = NULL \
                     WHERE spent_height IS NOT NULL AND spent_height > ?"
                ),
                params![height],
            )?;
        }

        // 3. Delete txs on the dead chain.
        tx.execute("DELETE FROM txs WHERE block_height > ?", params![height])?;

        // 4. `to` becomes the checkpoint, hash included, so the seam check
        //    after a crash compares against the block we kept.
        tx.execute(
            "UPDATE account SET sync_height = ?, sync_hash = ? WHERE id = 1",
            params![height, to.hash.0.as_slice()],
        )?;

        tx.commit()?;
        Ok(())
    }

    fn apply_transactions(
        &self,
        at: Cursor,
        transactions: &[WalletTx],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let tx = self.conn.unchecked_transaction()?;

        for wtx in transactions {
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

            // The notes this transaction took from us. Read back after the
            // updates: a watched spend list names every nullifier in a kept
            // transaction, so only a match on our own notes counts.
            let mut spent = Vec::new();
            for table in NOTES_TABLES {
                spent.extend(note_values(
                    &tx,
                    &format!("SELECT note FROM {table} WHERE spent_txid = ?"),
                    [wtx.txid.as_ref()],
                )?);
            }

            // The value of this transaction's outputs: sent to others, or ours.
            let sapling = wtx
                .sapling_outputs
                .iter()
                .map(|o| (o.is_sent, o.note.value().inner()));
            let orchard = wtx
                .orchard_outputs
                .iter()
                .map(|o| (o.is_sent, o.note.value().inner()));
            let ironwood = wtx
                .ironwood_outputs
                .iter()
                .map(|o| (o.is_sent, o.note.value().inner()));
            let (sent, received): (Vec<_>, Vec<_>) = sapling
                .chain(orchard)
                .chain(ironwood)
                .partition(|&(is_sent, _)| is_sent);

            // Outgoing means our money left: one of our notes was spent, or an
            // output was recovered with our outgoing key. The amount is the net
            // change to what we own, so a payment out is negative.
            let is_outgoing = !spent.is_empty() || !sent.is_empty();
            let amount = received.iter().map(|(_, value)| value).sum::<u64>() as i64
                - spent.into_iter().sum::<u64>() as i64;

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
                    amount,
                    is_outgoing as i64,
                ],
            )?;
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

/// The values of the notes `sql` selects. Every pool's note blob carries the
/// 8-byte little-endian value right after the 43-byte recipient.
fn note_values(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<u64>, rusqlite::Error> {
    conn.prepare(sql)?
        .query_map(params, |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob.get(43..51).map_or(0, |value| {
                u64::from_le_bytes(value.try_into().expect("8 bytes"))
            }))
        })?
        .collect()
}

impl Db {
    fn load_nullifiers(&self) -> Result<Nullifiers, DbError> {
        let sapling = self
            .conn
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

        Ok(Nullifiers {
            sapling,
            orchard,
            ironwood,
        })
    }

    fn load_orchard_nullifiers(
        &self,
        table: &str,
    ) -> Result<Vec<orchard::note::Nullifier>, DbError> {
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
                Option::from(orchard::note::Nullifier::from_bytes(arr)).ok_or_else(|| {
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
    buf.extend_from_slice(&note.recipient().to_bytes()); // 43
    buf.extend_from_slice(&note.value().inner().to_le_bytes()); // 8
    match note.rseed() {
        sapling::note::Rseed::BeforeZip212(fr) => {
            buf.push(0);
            buf.extend_from_slice(&fr.to_bytes()); // 32
        }
        sapling::note::Rseed::AfterZip212(seed) => {
            buf.push(1);
            buf.extend_from_slice(seed); // 32
        }
    }
    buf
}

/// Serialize an orchard note into a blob.
fn serialize_orchard_note(note: &orchard::Note) -> Vec<u8> {
    use orchard::note::NoteVersion;
    let mut buf = Vec::with_capacity(116);
    buf.extend_from_slice(&note.recipient().to_raw_address_bytes()); // 43
    buf.extend_from_slice(&note.value().inner().to_le_bytes()); // 8
    buf.extend_from_slice(&note.rho().to_bytes()); // 32
    buf.extend_from_slice(note.rseed().as_bytes()); // 32
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

#[cfg(test)]
mod tests {
    use super::*;

    use orchard::keys::{FullViewingKey, SpendingKey};
    use orchard::note::{RandomSeed, Rho};
    use orchard::value::NoteValue;
    use orchard::NoteVersion;

    use crate::sync::scan::OrchardSpend;

    fn insert_note(db: &Db, txid: u8, height: u32, spent_height: Option<u32>) {
        db.conn
            .execute(
                "INSERT INTO orchard_notes (txid, output_index, block_height, note, recipient,
                 scope, position, is_sent, is_change, spent, spent_height)
                 VALUES (?, 0, ?, x'', x'', 0, 0, 0, 0, ?, ?)",
                params![vec![txid; 32], height, spent_height.is_some(), spent_height],
            )
            .unwrap();
    }

    fn fvk() -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap())
    }

    /// A note of `value`, made distinct by `tag`.
    fn note(tag: u8, value: u64) -> orchard::Note {
        let rho = Rho::from_bytes(&[tag; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([tag; 32], &rho).unwrap();
        let recipient = fvk().address_at(0u32, Scope::External);
        orchard::Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V2,
        )
        .unwrap()
    }

    /// A note we own carries our nullifier; a note we sent has none.
    fn output(index: u32, note: orchard::Note, is_sent: bool) -> OrchardOutput {
        OrchardOutput {
            index,
            recipient: note.recipient(),
            note,
            nf: (!is_sent).then(|| note.nullifier(&fvk())),
            position: 0,
            scope: Scope::External,
            memo: None,
            is_sent,
            is_change: false,
        }
    }

    fn wallet_tx(
        height: u32,
        orchard_outputs: Vec<OrchardOutput>,
        orchard_spends: Vec<OrchardSpend>,
    ) -> WalletTx {
        WalletTx {
            txid: TxId::from_bytes([height as u8; 32]),
            height: BlockHeight::from_u32(height),
            tx_index: 0,
            sapling_outputs: vec![],
            sapling_spends: vec![],
            orchard_outputs,
            orchard_spends,
            ironwood_outputs: vec![],
            ironwood_spends: vec![],
            #[cfg(feature = "zns-decrypt")]
            relaxed_ironwood_outputs: vec![],
            transparent_outputs: vec![],
            transparent_spends: vec![],
        }
    }

    #[test]
    fn a_payment_nets_out_and_the_note_it_sent_is_not_balance() {
        let db = Db::open_memory().unwrap();
        db.init_account(BlockHeight::from_u32(1)).unwrap();

        // Receive 100_000, then pay 30_000 with 69_999 change and a 1 fee.
        let funds = note(1, 100_000);
        let receive = wallet_tx(1, vec![output(0, funds, false)], vec![]);
        let pay = wallet_tx(
            2,
            vec![
                output(0, note(2, 69_999), false),
                output(1, note(3, 30_000), true),
            ],
            vec![OrchardSpend {
                index: 0,
                nf: funds.nullifier(&fvk()),
            }],
        );
        let tip = Cursor {
            height: BlockHeight::from_u32(2),
            hash: BlockHash([0; 32]),
        };
        db.apply_transactions(tip, &[receive, pay]).unwrap();

        let payment: (i64, bool) = db
            .conn
            .query_row(
                "SELECT amount, is_outgoing FROM txs WHERE block_height = 2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(db.balance().unwrap(), 69_999);
        assert_eq!(payment, (-30_001, true));
    }

    #[test]
    fn rewind_keeps_the_cursor_block_and_makes_it_the_checkpoint() {
        let db = Db::open_memory().unwrap();
        db.init_account(BlockHeight::from_u32(1)).unwrap();
        insert_note(&db, 1, 20, Some(30));
        insert_note(&db, 2, 30, None);

        let to = Cursor {
            height: BlockHeight::from_u32(20),
            hash: BlockHash([7; 32]),
        };
        db.rewind(to).unwrap();

        let notes: Vec<(u32, bool)> = db
            .conn
            .prepare("SELECT block_height, spent FROM orchard_notes")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(notes, vec![(20, false)], "20 stays, unspent; 30 is gone");
        assert_eq!(db.resume().unwrap().checkpoint, Some(to));
    }
}
