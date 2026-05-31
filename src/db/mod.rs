//! SQLite persistence layer for seer-sync (feature = "db").
//!
//! Stores accounts, sync progress, received/sent notes, transactions, and
//! transparent UTXOs. No witness tables — seer-sync is view-only.

mod migration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;

pub use migration::migrate;

// ─── Row types ───────────────────────────────────────────────────────────────

/// A registered viewing key account.
#[derive(Debug, Clone)]
pub struct AccountRow {
    /// Row id assigned by SQLite.
    pub id: i64,
    /// Human-readable label for this account.
    pub label: String,
    /// Key type tag: `"ivk"`, `"fvk"`, or `"ovk"`.
    pub key_type: String,
    /// Bech32m-encoded viewing key string.
    pub encoded: String,
    /// Block height at which this account's wallet was created (used to skip earlier blocks).
    pub birthday: u32,
}

/// Saved sync position for one account.
#[derive(Debug, Clone, Default)]
pub struct SyncCursor {
    /// Last fully-processed block height.
    pub height: u32,
    /// Block hash at `height`, used for reorg detection on resume.
    pub hash: Option<[u8; 32]>,
    /// Running count of Sapling note commitments seen — needed for Sapling
    /// nullifier derivation (commitment position in the tree).
    pub sapling_leaf_count: u64,
}

/// A received shielded note (IVK / FVK paths).
#[derive(Debug, Clone)]
pub struct ReceivedNoteRow {
    /// Row id assigned by SQLite.
    pub id: i64,
    /// Foreign key into the `accounts` table.
    pub account: i64,
    /// Shielded pool: `"orchard"` or `"sapling"`.
    pub pool: String,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: Vec<u8>,
    /// Block height at which this note was mined.
    pub height: u32,
    /// Index of this output/action within the transaction.
    pub output_index: u32,
    /// Diversifier bytes (11 bytes for Sapling; Orchard uses recipient directly).
    pub diversifier: Vec<u8>,
    /// Note value in zatoshis.
    pub value_zat: u64,
    /// Note commitment randomness (rseed), needed for nullifier / memo derivation.
    pub rseed: Vec<u8>,
    /// Rho (Orchard only): the input nullifier of the action carrying this note.
    pub rho: Option<Vec<u8>>,
    /// Sapling leaf position in the commitment tree (FVK path only).
    pub leaf_pos: Option<u64>,
    /// Derived nullifier — populated after full-transaction fetch; `None` on IVK path.
    pub nullifier: Option<Vec<u8>>,
    /// Full 512-byte ZIP-302 memo — populated after full-transaction fetch.
    pub memo: Option<Vec<u8>>,
    /// Height at which this note's nullifier was observed as a spend, if any.
    pub spent_height: Option<u32>,
}

/// A sent note recovered via OVK / FVK.
#[derive(Debug, Clone)]
pub struct SentNoteRow {
    /// Row id assigned by SQLite.
    pub id: i64,
    /// Foreign key into the `accounts` table.
    pub account: i64,
    /// Shielded pool: `"orchard"` or `"sapling"`.
    pub pool: String,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: Vec<u8>,
    /// Block height at which the sending transaction was mined.
    pub height: u32,
    /// Index of this output/action within the transaction.
    pub output_index: u32,
    /// Bech32m-encoded recipient address.
    pub recipient: String,
    /// Value sent in zatoshis.
    pub value_zat: u64,
    /// Full 512-byte ZIP-302 memo, if recovered.
    pub memo: Option<Vec<u8>>,
}

/// A transparent UTXO.
#[derive(Debug, Clone)]
pub struct TransparentUtxoRow {
    /// Row id assigned by SQLite.
    pub id: i64,
    /// Foreign key into the `accounts` table.
    pub account: i64,
    /// Base58Check-encoded transparent address that controls this output.
    pub address: String,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: Vec<u8>,
    /// Index within the transaction's `vout` array.
    pub output_index: u32,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Block height at which this output was created.
    pub height: u32,
    /// Raw locking script (`scriptPubKey`).
    pub script: Vec<u8>,
    /// Height at which this UTXO was spent, if known.
    pub spent_height: Option<u32>,
}

/// Balance broken down by pool.
#[derive(Debug, Clone, Default)]
pub struct PoolBalance {
    /// Unspent Orchard notes, in zatoshis.
    pub orchard_zat: u64,
    /// Unspent Sapling notes, in zatoshis.
    pub sapling_zat: u64,
    /// Unspent transparent UTXOs, in zatoshis.
    pub transparent_zat: u64,
}

impl PoolBalance {
    /// Sum of all pools in zatoshis.
    pub fn total_zat(&self) -> u64 {
        self.orchard_zat + self.sapling_zat + self.transparent_zat
    }
}

// ─── Database handle ─────────────────────────────────────────────────────────

/// An open database connection with migrations applied.
pub struct Db {
    pub(crate) conn: Connection,
}

impl Db {
    /// Open (or create) a database at `path` and apply migrations.
    pub fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Open a temporary in-memory database. Useful for testing.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        migrate(&conn)?;
        Ok(Self { conn })
    }
}

// ─── Accounts ────────────────────────────────────────────────────────────────

impl Db {
    /// Insert a new account and return its row id.
    pub fn insert_account(
        &self,
        label: &str,
        key_type: &str,
        encoded: &str,
        birthday: u32,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO accounts(label, key_type, encoded, birthday) VALUES (?1,?2,?3,?4)",
            params![label, key_type, encoded, birthday],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return all accounts.
    pub fn list_accounts(&self) -> rusqlite::Result<Vec<AccountRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, key_type, encoded, birthday FROM accounts ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AccountRow {
                id: row.get(0)?,
                label: row.get(1)?,
                key_type: row.get(2)?,
                encoded: row.get(3)?,
                birthday: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Look up one account by encoded key string.
    pub fn find_account_by_key(&self, encoded: &str) -> rusqlite::Result<Option<AccountRow>> {
        self.conn
            .query_row(
                "SELECT id, label, key_type, encoded, birthday FROM accounts WHERE encoded = ?1",
                params![encoded],
                |row| {
                    Ok(AccountRow {
                        id: row.get(0)?,
                        label: row.get(1)?,
                        key_type: row.get(2)?,
                        encoded: row.get(3)?,
                        birthday: row.get(4)?,
                    })
                },
            )
            .optional()
    }
}

// ─── Sync state ──────────────────────────────────────────────────────────────

impl Db {
    /// Create or replace the sync cursor for `account`.
    pub fn set_sync_cursor(&self, account: i64, cursor: &SyncCursor) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state(account, height, hash, sapling_leaf_count)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(account) DO UPDATE SET
                height = excluded.height,
                hash = excluded.hash,
                sapling_leaf_count = excluded.sapling_leaf_count",
            params![
                account,
                cursor.height,
                cursor.hash.as_ref().map(|h| h.as_slice()),
                cursor.sapling_leaf_count as i64,
            ],
        )?;
        Ok(())
    }

    /// Return the sync cursor for `account`, or a zeroed default.
    pub fn get_sync_cursor(&self, account: i64) -> rusqlite::Result<SyncCursor> {
        self.conn
            .query_row(
                "SELECT height, hash, sapling_leaf_count FROM sync_state WHERE account = ?1",
                params![account],
                |row| {
                    let height: u32 = row.get(0)?;
                    let hash_blob: Option<Vec<u8>> = row.get(1)?;
                    let leaf_count: i64 = row.get(2)?;
                    Ok(SyncCursor {
                        height,
                        hash: hash_blob.and_then(|v| v.try_into().ok()),
                        sapling_leaf_count: leaf_count as u64,
                    })
                },
            )
            .optional()
            .map(|opt| opt.unwrap_or_default())
    }
}

// ─── Blocks ──────────────────────────────────────────────────────────────────

impl Db {
    /// Persist a block header (height, hash, timestamp).
    pub fn insert_block(&self, height: u32, hash: &[u8; 32], timestamp: u32) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO blocks(height, hash, timestamp) VALUES (?1,?2,?3) ON CONFLICT DO NOTHING",
            params![height, hash.as_slice(), timestamp],
        )?;
        Ok(())
    }

    /// Return the block hash at `height`, if synced.
    pub fn get_block_hash(&self, height: u32) -> rusqlite::Result<Option<[u8; 32]>> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT hash FROM blocks WHERE height = ?1",
                params![height],
                |row| row.get(0),
            )
            .optional()?;
        Ok(blob.and_then(|v| v.try_into().ok()))
    }

    /// Delete all data above `height` (reorg rewind).
    pub fn rewind_to_height(&mut self, height: u32) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM blocks WHERE height > ?1", params![height])?;
        tx.execute(
            "DELETE FROM received_notes WHERE height > ?1",
            params![height],
        )?;
        tx.execute("DELETE FROM sent_notes WHERE height > ?1", params![height])?;
        tx.execute(
            "DELETE FROM transactions WHERE height > ?1",
            params![height],
        )?;
        tx.execute(
            "DELETE FROM transparent_utxos WHERE height > ?1",
            params![height],
        )?;
        // Un-mark spends above the rewind point.
        tx.execute(
            "UPDATE received_notes SET spent_height = NULL WHERE spent_height > ?1",
            params![height],
        )?;
        tx.execute(
            "UPDATE transparent_utxos SET spent_height = NULL WHERE spent_height > ?1",
            params![height],
        )?;
        // Reset sync cursors for all accounts beyond the rewind point.
        tx.execute(
            "UPDATE sync_state SET height = MIN(height, ?1) WHERE height > ?1",
            params![height],
        )?;
        tx.commit()
    }
}

// ─── Received notes ──────────────────────────────────────────────────────────

/// Input struct for persisting a received note.
#[derive(Debug, Clone)]
pub struct ReceivedNoteInsert<'a> {
    /// Foreign key into the `accounts` table.
    pub account: i64,
    /// Shielded pool: `"orchard"` or `"sapling"`.
    pub pool: &'a str,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: &'a [u8],
    /// Block height at which this note was mined.
    pub height: u32,
    /// Index of this output/action within the transaction.
    pub output_index: u32,
    /// Diversifier bytes from the decrypted note plaintext.
    pub diversifier: &'a [u8],
    /// Note value in zatoshis.
    pub value_zat: u64,
    /// Note commitment randomness (rseed).
    pub rseed: &'a [u8],
    /// Rho (Orchard only): the input nullifier of this action.
    pub rho: Option<&'a [u8]>,
    /// Sapling commitment tree leaf position (FVK path only).
    pub leaf_pos: Option<u64>,
    /// Derived nullifier, if already known.
    pub nullifier: Option<&'a [u8]>,
}

impl Db {
    /// Insert a received note, returning the row id. Ignores duplicates.
    pub fn insert_received_note(&self, n: &ReceivedNoteInsert<'_>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO received_notes(
                account, pool, tx_id, height, output_index,
                diversifier, value_zat, rseed, rho, leaf_pos, nullifier
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(tx_id, output_index, pool) DO NOTHING",
            params![
                n.account,
                n.pool,
                n.tx_id,
                n.height,
                n.output_index,
                n.diversifier,
                n.value_zat as i64,
                n.rseed,
                n.rho,
                n.leaf_pos.map(|p| p as i64),
                n.nullifier,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Mark a note as spent at `spent_height` by nullifier.
    pub fn mark_note_spent(&self, nullifier: &[u8], spent_height: u32) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE received_notes SET spent_height = ?1 WHERE nullifier = ?2 AND spent_height IS NULL",
            params![spent_height, nullifier],
        )
    }

    /// Store memo bytes for a note identified by (tx_id, output_index, pool).
    pub fn store_memo(
        &self,
        tx_id: &[u8],
        output_index: u32,
        pool: &str,
        memo: &[u8],
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE received_notes SET memo = ?1 WHERE tx_id = ?2 AND output_index = ?3 AND pool = ?4",
            params![memo, tx_id, output_index, pool],
        )
    }

    /// Return all received notes for `account`.
    pub fn get_received_notes(&self, account: i64) -> rusqlite::Result<Vec<ReceivedNoteRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account, pool, tx_id, height, output_index,
                    diversifier, value_zat, rseed, rho, leaf_pos,
                    nullifier, memo, spent_height
             FROM received_notes WHERE account = ?1 ORDER BY height",
        )?;
        let rows = stmt.query_map(params![account], |row| {
            Ok(ReceivedNoteRow {
                id: row.get(0)?,
                account: row.get(1)?,
                pool: row.get(2)?,
                tx_id: row.get(3)?,
                height: row.get(4)?,
                output_index: row.get(5)?,
                diversifier: row.get(6)?,
                value_zat: {
                    let v: i64 = row.get(7)?;
                    v as u64
                },
                rseed: row.get(8)?,
                rho: row.get(9)?,
                leaf_pos: row.get::<_, Option<i64>>(10)?.map(|p| p as u64),
                nullifier: row.get(11)?,
                memo: row.get(12)?,
                spent_height: row.get(13)?,
            })
        })?;
        rows.collect()
    }

    /// Return the nullifiers of all currently unspent notes for `account`.
    pub fn unspent_nullifiers(&self, account: i64) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT nullifier FROM received_notes
             WHERE account = ?1 AND nullifier IS NOT NULL AND spent_height IS NULL",
        )?;
        let rows = stmt.query_map(params![account], |row| row.get(0))?;
        rows.collect()
    }
}

// ─── Sent notes ──────────────────────────────────────────────────────────────

/// Input struct for persisting a sent note.
#[derive(Debug, Clone)]
pub struct SentNoteInsert<'a> {
    /// Foreign key into the `accounts` table.
    pub account: i64,
    /// Shielded pool: `"orchard"` or `"sapling"`.
    pub pool: &'a str,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: &'a [u8],
    /// Block height at which the sending transaction was mined.
    pub height: u32,
    /// Index of this output/action within the transaction.
    pub output_index: u32,
    /// Bech32m-encoded recipient address.
    pub recipient: &'a str,
    /// Value sent in zatoshis.
    pub value_zat: u64,
    /// Full 512-byte ZIP-302 memo, if recovered.
    pub memo: Option<&'a [u8]>,
}

impl Db {
    /// Insert a sent note.  Ignores duplicates.
    pub fn insert_sent_note(&self, n: &SentNoteInsert<'_>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO sent_notes(
                account, pool, tx_id, height, output_index,
                recipient, value_zat, memo
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(tx_id, output_index, pool) DO NOTHING",
            params![
                n.account,
                n.pool,
                n.tx_id,
                n.height,
                n.output_index,
                n.recipient,
                n.value_zat as i64,
                n.memo,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return all sent notes for `account`.
    pub fn get_sent_notes(&self, account: i64) -> rusqlite::Result<Vec<SentNoteRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account, pool, tx_id, height, output_index,
                    recipient, value_zat, memo
             FROM sent_notes WHERE account = ?1 ORDER BY height",
        )?;
        let rows = stmt.query_map(params![account], |row| {
            Ok(SentNoteRow {
                id: row.get(0)?,
                account: row.get(1)?,
                pool: row.get(2)?,
                tx_id: row.get(3)?,
                height: row.get(4)?,
                output_index: row.get(5)?,
                recipient: row.get(6)?,
                value_zat: {
                    let v: i64 = row.get(7)?;
                    v as u64
                },
                memo: row.get(8)?,
            })
        })?;
        rows.collect()
    }
}

// ─── Transactions ─────────────────────────────────────────────────────────────

impl Db {
    /// Insert (or ignore duplicate) transaction header.
    pub fn upsert_transaction(
        &self,
        account: i64,
        tx_id: &[u8],
        height: u32,
        timestamp: u32,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO transactions(account, tx_id, height, timestamp)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(account, tx_id) DO NOTHING",
            params![account, tx_id, height, timestamp],
        )?;
        let rowid: i64 = self.conn.query_row(
            "SELECT id FROM transactions WHERE account = ?1 AND tx_id = ?2",
            params![account, tx_id],
            |row| row.get(0),
        )?;
        Ok(rowid)
    }

    /// Update the net signed value of a transaction (+incoming, −outgoing).
    pub fn add_transaction_value(
        &self,
        id: i64,
        delta: i64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE transactions SET net_value = net_value + ?1 WHERE id = ?2",
            params![delta, id],
        )?;
        Ok(())
    }
}

// ─── Transparent UTXOs ───────────────────────────────────────────────────────

/// Input for persisting a transparent UTXO.
#[derive(Debug, Clone)]
pub struct UtxoInsert<'a> {
    /// Foreign key into the `accounts` table.
    pub account: i64,
    /// Base58Check-encoded transparent address that controls this output.
    pub address: &'a str,
    /// Transaction ID (32 bytes, protocol byte order).
    pub tx_id: &'a [u8],
    /// Index within the transaction's `vout` array.
    pub output_index: u32,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Block height at which this output was created.
    pub height: u32,
    /// Raw locking script (`scriptPubKey`).
    pub script: &'a [u8],
}

impl Db {
    /// Insert a transparent UTXO, ignoring duplicates.
    pub fn insert_utxo(&self, u: &UtxoInsert<'_>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO transparent_utxos(
                account, address, tx_id, output_index, value_zat, height, script
             ) VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(tx_id, output_index) DO NOTHING",
            params![
                u.account,
                u.address,
                u.tx_id,
                u.output_index,
                u.value_zat as i64,
                u.height,
                u.script,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Mark a UTXO as spent (by its (tx_id, output_index) outpoint).
    pub fn mark_utxo_spent(
        &self,
        prevout_txid: &[u8],
        prevout_index: u32,
        spent_height: u32,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE transparent_utxos SET spent_height = ?1
             WHERE tx_id = ?2 AND output_index = ?3 AND spent_height IS NULL",
            params![spent_height, prevout_txid, prevout_index],
        )
    }

    /// Return all unspent UTXOs for an account.
    pub fn unspent_utxos(&self, account: i64) -> rusqlite::Result<Vec<TransparentUtxoRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account, address, tx_id, output_index,
                    value_zat, height, script, spent_height
             FROM transparent_utxos
             WHERE account = ?1 AND spent_height IS NULL
             ORDER BY height",
        )?;
        let rows = stmt.query_map(params![account], |row| {
            Ok(TransparentUtxoRow {
                id: row.get(0)?,
                account: row.get(1)?,
                address: row.get(2)?,
                tx_id: row.get(3)?,
                output_index: row.get(4)?,
                value_zat: {
                    let v: i64 = row.get(5)?;
                    v as u64
                },
                height: row.get(6)?,
                script: row.get(7)?,
                spent_height: row.get(8)?,
            })
        })?;
        rows.collect()
    }
}

// ─── Balance ─────────────────────────────────────────────────────────────────

impl Db {
    /// Compute the confirmed balance for `account` across all pools.
    pub fn balance(&self, account: i64) -> rusqlite::Result<PoolBalance> {
        let orchard_zat: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(value_zat), 0)
             FROM received_notes
             WHERE account = ?1 AND pool = 'orchard' AND spent_height IS NULL",
            params![account],
            |row| row.get(0),
        )?;

        let sapling_zat: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(value_zat), 0)
             FROM received_notes
             WHERE account = ?1 AND pool = 'sapling' AND spent_height IS NULL",
            params![account],
            |row| row.get(0),
        )?;

        let transparent_zat: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(value_zat), 0)
             FROM transparent_utxos
             WHERE account = ?1 AND spent_height IS NULL",
            params![account],
            |row| row.get(0),
        )?;

        Ok(PoolBalance {
            orchard_zat: orchard_zat as u64,
            sapling_zat: sapling_zat as u64,
            transparent_zat: transparent_zat as u64,
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory_and_schema() {
        let db = Db::open_in_memory().expect("in-memory db");
        let v = migration::get_version(&db.conn).expect("schema version");
        assert_eq!(v, 1);
    }

    #[test]
    fn test_account_crud() {
        let db = Db::open_in_memory().unwrap();
        let id = db.insert_account("test", "ivk", "encoded_key_here", 100).unwrap();
        assert!(id > 0);
        let accounts = db.list_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, "test");
        assert_eq!(accounts[0].birthday, 100);
    }

    #[test]
    fn test_sync_cursor_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let acct = db.insert_account("a", "fvk", "key1", 0).unwrap();
        let cursor = SyncCursor { height: 42, hash: Some([7u8; 32]), sapling_leaf_count: 100 };
        db.set_sync_cursor(acct, &cursor).unwrap();
        let loaded = db.get_sync_cursor(acct).unwrap();
        assert_eq!(loaded.height, 42);
        assert_eq!(loaded.hash, Some([7u8; 32]));
        assert_eq!(loaded.sapling_leaf_count, 100);
    }

    #[test]
    fn test_balance_empty() {
        let db = Db::open_in_memory().unwrap();
        let acct = db.insert_account("b", "ivk", "key2", 0).unwrap();
        let bal = db.balance(acct).unwrap();
        assert_eq!(bal.total_zat(), 0);
    }

    #[test]
    fn test_received_note_and_balance() {
        let db = Db::open_in_memory().unwrap();
        let acct = db.insert_account("c", "fvk", "key3", 0).unwrap();
        db.upsert_transaction(acct, &[0u8; 32], 100, 1000).unwrap();
        db.insert_received_note(&ReceivedNoteInsert {
            account: acct,
            pool: "orchard",
            tx_id: &[0u8; 32],
            height: 100,
            output_index: 0,
            diversifier: &[0u8; 11],
            value_zat: 5_000_000,
            rseed: &[0u8; 32],
            rho: Some(&[1u8; 32]),
            leaf_pos: None,
            nullifier: Some(&[2u8; 32]),
        }).unwrap();
        let bal = db.balance(acct).unwrap();
        assert_eq!(bal.orchard_zat, 5_000_000);
        assert_eq!(bal.sapling_zat, 0);

        // Mark as spent
        db.mark_note_spent(&[2u8; 32], 101).unwrap();
        let bal2 = db.balance(acct).unwrap();
        assert_eq!(bal2.orchard_zat, 0);
    }

    #[test]
    fn test_transparent_utxo() {
        let db = Db::open_in_memory().unwrap();
        let acct = db.insert_account("d", "fvk", "key4", 0).unwrap();
        db.insert_utxo(&UtxoInsert {
            account: acct,
            address: "t1abc",
            tx_id: &[0u8; 32],
            output_index: 0,
            value_zat: 1_000_000,
            height: 200,
            script: &[0x76, 0xa9],
        }).unwrap();
        let bal = db.balance(acct).unwrap();
        assert_eq!(bal.transparent_zat, 1_000_000);
        // Mark spent
        db.mark_utxo_spent(&[0u8; 32], 0, 201).unwrap();
        let bal2 = db.balance(acct).unwrap();
        assert_eq!(bal2.transparent_zat, 0);
    }

    #[test]
    fn test_rewind_to_height() {
        let mut db = Db::open_in_memory().unwrap();
        let acct = db.insert_account("e", "fvk", "key5", 0).unwrap();
        db.upsert_transaction(acct, &[0u8; 32], 300, 2000).unwrap();
        db.insert_received_note(&ReceivedNoteInsert {
            account: acct,
            pool: "sapling",
            tx_id: &[0u8; 32],
            height: 300,
            output_index: 0,
            diversifier: &[0u8; 11],
            value_zat: 2_000_000,
            rseed: &[0u8; 32],
            rho: None,
            leaf_pos: Some(5),
            nullifier: None,
        }).unwrap();
        assert_eq!(db.balance(acct).unwrap().sapling_zat, 2_000_000);
        db.rewind_to_height(100).unwrap();
        assert_eq!(db.balance(acct).unwrap().sapling_zat, 0);
    }
}
