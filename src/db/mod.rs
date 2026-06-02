mod schema;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;

pub use schema::init;

// ─── Row types ───────────────────────────────────────────────────────────────

/// The single viewing key this database tracks.
#[derive(Debug, Clone)]
pub struct Account {
    /// Encoded unified viewing key (UIVK or UFVK).
    pub encoded: String,
    /// `"uivk"` (incoming-only) or `"ufvk"` (full).
    pub key_type: String,
    /// `"main"` or `"test"`.
    pub network: String,
    /// Block height the key was created at; blocks before it are skipped.
    pub birthday: u32,
}

/// Saved linear sync position.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    /// Last fully-applied block height.
    pub height: u32,
    /// Block hash at `height`, for reorg detection on resume.
    pub hash: Option<[u8; 32]>,
    /// Running Sapling commitment-tree size (next leaf position).
    pub sapling_pos: u64,
    /// Running Orchard commitment-tree size (next leaf position).
    pub orchard_pos: u64,
}

/// A block header plus the commitment-tree sizes stamped on it.
#[derive(Debug, Clone)]
pub struct BlockMeta {
    /// Block height.
    pub height: u32,
    /// Block hash (32 bytes, display byte order as delivered by lightwalletd).
    pub hash: [u8; 32],
    /// Block timestamp (Unix seconds).
    pub time: u32,
    /// Sapling commitment-tree size as of the end of this block.
    pub sapling_tree_size: Option<u64>,
    /// Orchard commitment-tree size as of the end of this block.
    pub orchard_tree_size: Option<u64>,
    /// Number of Sapling outputs in this block.
    pub sapling_output_count: Option<u32>,
    /// Number of Orchard actions in this block.
    pub orchard_action_count: Option<u32>,
}

/// Balance broken down by pool, in zatoshis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolBalance {
    /// Unspent Orchard notes.
    pub orchard_zat: u64,
    /// Unspent Sapling notes.
    pub sapling_zat: u64,
    /// Unspent transparent UTXOs.
    pub transparent_zat: u64,
}

impl PoolBalance {
    /// Sum of all pools.
    pub fn total_zat(&self) -> u64 {
        self.orchard_zat + self.sapling_zat + self.transparent_zat
    }
}

// ─── Insert structs ──────────────────────────────────────────────────────────

/// A received Sapling note to persist.
#[derive(Debug, Clone)]
pub struct SaplingNoteInsert<'a> {
    /// Row id of the transaction that created this note ([`Db::upsert_transaction`]).
    pub transaction_id: i64,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Diversifier from the note plaintext.
    pub diversifier: &'a [u8],
    /// Note value in zatoshis.
    pub value: u64,
    /// Note commitment randomness (`rcm`).
    pub rcm: &'a [u8],
    /// Derived nullifier; `None` on the incoming-only path or before a position is known.
    pub nf: Option<&'a [u8]>,
    /// Whether this note is change (received in a transaction that also spent ours).
    pub is_change: bool,
    /// Raw 512-byte ZIP-302 memo, if recovered by full-transaction enrichment.
    pub memo: Option<&'a [u8]>,
    /// Leaf position in the Sapling commitment tree.
    pub commitment_tree_position: Option<u64>,
}

/// A received Orchard note to persist.
#[derive(Debug, Clone)]
pub struct OrchardNoteInsert<'a> {
    /// Row id of the transaction that created this note.
    pub transaction_id: i64,
    /// Action index within the transaction.
    pub action_index: u32,
    /// Diversifier from the note plaintext.
    pub diversifier: &'a [u8],
    /// Note value in zatoshis.
    pub value: u64,
    /// Rho (the action's input nullifier) — needed to derive the nullifier.
    pub rho: &'a [u8],
    /// Note seed randomness (`rseed`).
    pub rseed: &'a [u8],
    /// Derived nullifier; `None` on the incoming-only path.
    pub nf: Option<&'a [u8]>,
    /// Whether this note is change.
    pub is_change: bool,
    /// Raw 512-byte ZIP-302 memo, if recovered by full-transaction enrichment.
    pub memo: Option<&'a [u8]>,
    /// Leaf position in the Orchard commitment tree (not needed for the nullifier).
    pub commitment_tree_position: Option<u64>,
}

/// A received transparent output to persist.
#[derive(Debug, Clone)]
pub struct TransparentOutputInsert<'a> {
    /// Row id of the transaction that created this output.
    pub transaction_id: i64,
    /// Index within the transaction's `vout`.
    pub output_index: u32,
    /// Address that controls the output.
    pub address: &'a str,
    /// Locking script (`scriptPubKey`).
    pub script: &'a [u8],
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Height at which the output was last observed unspent.
    pub max_observed_unspent_height: Option<u32>,
}

// ─── Database handle ─────────────────────────────────────────────────────────

/// An open database connection with the schema initialized.
pub struct Db {
    pub(crate) conn: Connection,
}

impl Db {
    /// Open (or create) a database at `path` and initialize the schema.
    pub fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        init(&conn)?;
        Ok(Self { conn })
    }

    /// Open a temporary in-memory database. Useful for testing.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init(&conn)?;
        Ok(Self { conn })
    }
}

// ─── Account ─────────────────────────────────────────────────────────────────

impl Db {
    /// Set (or replace) the viewing key this database tracks.
    pub fn set_account(&self, account: &Account) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO account(id, encoded, key_type, network, birthday)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                encoded = excluded.encoded,
                key_type = excluded.key_type,
                network = excluded.network,
                birthday = excluded.birthday",
            params![
                account.encoded,
                account.key_type,
                account.network,
                account.birthday
            ],
        )?;
        Ok(())
    }

    /// Return the tracked viewing key, if one has been set.
    pub fn get_account(&self) -> rusqlite::Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT encoded, key_type, network, birthday FROM account WHERE id = 1",
                [],
                |row| {
                    Ok(Account {
                        encoded: row.get(0)?,
                        key_type: row.get(1)?,
                        network: row.get(2)?,
                        birthday: row.get(3)?,
                    })
                },
            )
            .optional()
    }
}

// ─── Sync state ──────────────────────────────────────────────────────────────

impl Db {
    /// Persist the sync cursor.
    pub fn set_sync_state(&self, state: &SyncState) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state(id, height, hash, sapling_pos, orchard_pos)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                height = excluded.height,
                hash = excluded.hash,
                sapling_pos = excluded.sapling_pos,
                orchard_pos = excluded.orchard_pos",
            params![
                state.height,
                state.hash.as_ref().map(|h| h.as_slice()),
                state.sapling_pos as i64,
                state.orchard_pos as i64,
            ],
        )?;
        Ok(())
    }

    /// Return the sync cursor, or a zeroed default if none is stored.
    pub fn get_sync_state(&self) -> rusqlite::Result<SyncState> {
        self.conn
            .query_row(
                "SELECT height, hash, sapling_pos, orchard_pos FROM sync_state WHERE id = 1",
                [],
                |row| {
                    let hash: Option<Vec<u8>> = row.get(1)?;
                    Ok(SyncState {
                        height: row.get(0)?,
                        hash: hash.and_then(|v| v.try_into().ok()),
                        sapling_pos: row.get::<_, i64>(2)? as u64,
                        orchard_pos: row.get::<_, i64>(3)? as u64,
                    })
                },
            )
            .optional()
            .map(Option::unwrap_or_default)
    }
}

// ─── Blocks ──────────────────────────────────────────────────────────────────

impl Db {
    /// Persist a block header. Ignores duplicates.
    pub fn insert_block(&self, b: &BlockMeta) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO blocks(
                height, hash, time, sapling_tree_size, orchard_tree_size,
                sapling_output_count, orchard_action_count)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(height) DO NOTHING",
            params![
                b.height,
                b.hash.as_slice(),
                b.time,
                b.sapling_tree_size.map(|v| v as i64),
                b.orchard_tree_size.map(|v| v as i64),
                b.sapling_output_count,
                b.orchard_action_count,
            ],
        )?;
        Ok(())
    }

    /// Return the stored block hash at `height`, if any.
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
}

// ─── Transactions ────────────────────────────────────────────────────────────

impl Db {
    /// Insert or update a transaction, returning its row id (`id_tx`).
    ///
    /// A mined transaction sets both `block` and `mined_height` to `height`; an
    /// unmined (mempool) transaction passes `height = None`.
    pub fn upsert_transaction(
        &self,
        txid: &[u8],
        height: Option<u32>,
        tx_index: Option<u32>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO transactions(txid, block, mined_height, tx_index)
             VALUES (?1, ?2, ?2, ?3)
             ON CONFLICT(txid) DO UPDATE SET
                block = excluded.block,
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

// ─── Shielded notes ──────────────────────────────────────────────────────────

impl Db {
    /// Insert a received Sapling note, returning its row id. Ignores duplicates.
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

    /// Insert a received Orchard note, returning its row id. Ignores duplicates.
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

    /// Raw ZIP-302 memo bytes for every shielded note that has one recovered,
    /// across both pools. Decode with [`crate::note::memo`].
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

    /// Record that the Sapling note with nullifier `nf` was spent by transaction
    /// `spending_tx`. No-op (returns 0) if no owned note has that nullifier.
    pub fn mark_sapling_spent(&self, nf: &[u8], spending_tx: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "INSERT OR IGNORE INTO sapling_received_note_spends(
                sapling_received_note_id, transaction_id)
             SELECT id, ?2 FROM sapling_received_notes WHERE nf = ?1",
            params![nf, spending_tx],
        )
    }

    /// Record that the Orchard note with nullifier `nf` was spent by transaction
    /// `spending_tx`. No-op (returns 0) if no owned note has that nullifier.
    pub fn mark_orchard_spent(&self, nf: &[u8], spending_tx: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "INSERT OR IGNORE INTO orchard_received_note_spends(
                orchard_received_note_id, transaction_id)
             SELECT id, ?2 FROM orchard_received_notes WHERE nf = ?1",
            params![nf, spending_tx],
        )
    }

}

// ─── Transparent outputs ─────────────────────────────────────────────────────

impl Db {
    /// Insert a received transparent output, returning its row id. Ignores duplicates.
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

    /// Record that the transparent outpoint `(prevout_txid, prevout_index)` was
    /// spent by transaction `spending_tx`.
    ///
    /// Always caches the outpoint in `transparent_spend_map`, and additionally
    /// links the spend to a known output if we already hold it. Returns the
    /// number of owned outputs newly marked spent (0 or 1).
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

// ─── Balance ─────────────────────────────────────────────────────────────────

impl Db {
    /// Confirmed balance across all pools.
    ///
    /// A note/output counts as unspent when no *mined* transaction spends it.
    pub fn balance(&self) -> rusqlite::Result<PoolBalance> {
        let sapling_zat = self.unspent_sum(
            "SELECT COALESCE(SUM(n.value), 0) FROM sapling_received_notes n
             WHERE NOT EXISTS (
                SELECT 1 FROM sapling_received_note_spends s
                JOIN transactions t ON t.id_tx = s.transaction_id
                WHERE s.sapling_received_note_id = n.id AND t.mined_height IS NOT NULL)",
        )?;
        let orchard_zat = self.unspent_sum(
            "SELECT COALESCE(SUM(n.value), 0) FROM orchard_received_notes n
             WHERE NOT EXISTS (
                SELECT 1 FROM orchard_received_note_spends s
                JOIN transactions t ON t.id_tx = s.transaction_id
                WHERE s.orchard_received_note_id = n.id AND t.mined_height IS NOT NULL)",
        )?;
        let transparent_zat = self.unspent_sum(
            "SELECT COALESCE(SUM(o.value_zat), 0) FROM transparent_received_outputs o
             WHERE NOT EXISTS (
                SELECT 1 FROM transparent_received_output_spends s
                JOIN transactions t ON t.id_tx = s.transaction_id
                WHERE s.transparent_received_output_id = o.id AND t.mined_height IS NOT NULL)",
        )?;
        Ok(PoolBalance {
            orchard_zat,
            sapling_zat,
            transparent_zat,
        })
    }

    fn unspent_sum(&self, sql: &str) -> rusqlite::Result<u64> {
        let v: i64 = self.conn.query_row(sql, [], |row| row.get(0))?;
        Ok(v as u64)
    }
}

// ─── Reorg rewind ────────────────────────────────────────────────────────────

impl Db {
    /// Roll the wallet back to `height`, discarding everything above it.
    ///
    /// Deleting the mined transactions above `height` cascades to the notes and
    /// outputs they created and to any spend-junction rows that reference them,
    /// so spends recorded in rolled-back blocks are automatically undone. The
    /// cursor is reset to the surviving block at `height`.
    pub fn rewind_to_height(&mut self, height: u32) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM transactions WHERE mined_height > ?1",
            params![height],
        )?;
        tx.execute("DELETE FROM blocks WHERE height > ?1", params![height])?;
        tx.execute(
            "INSERT INTO sync_state(id, height, hash, sapling_pos, orchard_pos)
             VALUES (
                1,
                ?1,
                (SELECT hash FROM blocks WHERE height = ?1),
                COALESCE((SELECT sapling_tree_size FROM blocks WHERE height = ?1), 0),
                COALESCE((SELECT orchard_tree_size FROM blocks WHERE height = ?1), 0))
             ON CONFLICT(id) DO UPDATE SET
                height = excluded.height,
                hash = excluded.hash,
                sapling_pos = excluded.sapling_pos,
                orchard_pos = excluded.orchard_pos",
            params![height],
        )?;
        tx.commit()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mined_tx(db: &Db, txid: &[u8; 32], height: u32) -> i64 {
        db.insert_block(&BlockMeta {
            height,
            hash: [height as u8; 32],
            time: 1_000 + height,
            sapling_tree_size: Some(u64::from(height) * 2),
            orchard_tree_size: Some(u64::from(height) * 3),
            sapling_output_count: Some(0),
            orchard_action_count: Some(0),
        })
        .unwrap();
        db.upsert_transaction(txid, Some(height), Some(0)).unwrap()
    }

    #[test]
    fn schema_initializes_to_v1() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(schema::get_version(&db.conn).unwrap(), 1);
    }

    #[test]
    fn account_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.get_account().unwrap().is_none());
        let acct = Account {
            encoded: "uview1...".into(),
            key_type: "ufvk".into(),
            network: "main".into(),
            birthday: 419_200,
        };
        db.set_account(&acct).unwrap();
        let got = db.get_account().unwrap().unwrap();
        assert_eq!(got.encoded, acct.encoded);
        assert_eq!(got.birthday, 419_200);
    }

    #[test]
    fn sync_state_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.get_sync_state().unwrap(), SyncState::default());
        let state = SyncState {
            height: 42,
            hash: Some([7u8; 32]),
            sapling_pos: 100,
            orchard_pos: 200,
        };
        db.set_sync_state(&state).unwrap();
        let got = db.get_sync_state().unwrap();
        assert_eq!(got.height, 42);
        assert_eq!(got.hash, Some([7u8; 32]));
        assert_eq!(got.sapling_pos, 100);
        assert_eq!(got.orchard_pos, 200);
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
        assert_eq!(db.balance().unwrap().orchard_zat, 5_000_000);

        // Spend it in a later mined transaction.
        let spend_tx = mined_tx(&db, &[2u8; 32], 101);
        assert_eq!(db.mark_orchard_spent(&[9u8; 32], spend_tx).unwrap(), 1);
        assert_eq!(db.balance().unwrap().orchard_zat, 0);
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

        // A mempool (unmined) spend should NOT reduce the confirmed balance.
        let mempool_tx = db.upsert_transaction(&[3u8; 32], None, None).unwrap();
        assert_eq!(db.mark_sapling_spent(&[9u8; 32], mempool_tx).unwrap(), 1);
        assert_eq!(db.balance().unwrap().sapling_zat, 3_000_000);
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
        assert_eq!(db.balance().unwrap().transparent_zat, 1_000_000);

        let spend_tx = mined_tx(&db, &[2u8; 32], 201);
        // Outpoint references the *creating* tx's txid + output index.
        assert_eq!(
            db.mark_transparent_spent(&[1u8; 32], 0, spend_tx).unwrap(),
            1
        );
        assert_eq!(db.balance().unwrap().transparent_zat, 0);
    }

    #[test]
    fn rewind_undoes_notes_and_spends() {
        let mut db = Db::open_in_memory().unwrap();
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
        assert_eq!(db.balance().unwrap().orchard_zat, 0);

        // Roll back past the spend (but not the note): note returns, spend gone.
        db.rewind_to_height(104).unwrap();
        assert_eq!(db.balance().unwrap().orchard_zat, 9_000_000);
        assert_eq!(db.get_sync_state().unwrap().height, 104);

        // Roll back past the note too: balance empty.
        db.rewind_to_height(99).unwrap();
        assert_eq!(db.balance().unwrap().orchard_zat, 0);
    }
}
