//! SQLite schema for seer-sync (feature = "db").
//!
//! One database tracks exactly one viewing key — this is a *watch-only* store:
//! observe notes, never spend them. The schema is a stripped descendant of
//! `zcash_client_sqlite`, with the spend-only machinery removed: no witness /
//! shardtree tables (we never build a Merkle path), no `scan_queue` (we
//! tip-follow linearly), no `nullifier_map` / `tx_locator_map` (linear scan
//! always sees a note before its spend), and no `sent_notes` (we never author
//! transactions).
//!
//! Spentness follows the upstream model: every note references the transaction
//! that created it, and a per-pool junction table links a note to the
//! transaction that spends it. A note is spent iff that spending transaction is
//! mined. "Unconfirmed" therefore falls out for free — a transaction with
//! `mined_height IS NULL` is in the mempool — though mempool ingestion itself
//! is a later feature.

use rusqlite::{params, Connection};

const SCHEMA_VERSION: u32 = 1;

/// Return the stored schema version, or `0` if the database is uninitialized.
pub fn get_version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.query_row("SELECT version FROM schema_version WHERE id = 1", [], |row| {
        row.get(0)
    })
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(0),
        other => Err(other),
    })
}

fn set_version(conn: &Connection, version: u32) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO schema_version(id, version) VALUES (1, ?1) \
         ON CONFLICT(id) DO UPDATE SET version = excluded.version",
        params![version],
    )?;
    Ok(())
}

/// Create the database schema (idempotent).
pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (
            id      INTEGER PRIMARY KEY NOT NULL,
            version INTEGER NOT NULL)",
        [],
    )?;

    let version = get_version(conn)?;

    if version < 1 {
        conn.execute_batch(
            r#"
            -- The single viewing key this database tracks. Exactly one row.
            CREATE TABLE IF NOT EXISTS account (
                id       INTEGER PRIMARY KEY CHECK (id = 1),
                encoded  TEXT    NOT NULL,
                key_type TEXT    NOT NULL CHECK (key_type IN ('uivk','ufvk')),
                network  TEXT    NOT NULL CHECK (network IN ('main','test')),
                birthday INTEGER NOT NULL DEFAULT 0
            );

            -- Linear sync cursor. Exactly one row: the scanned watermark
            -- (`height`) and its block `hash` (the reorg seam checked on resume).
            -- A view-key observer needs nothing more to know where it is.
            CREATE TABLE IF NOT EXISTS sync_state (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                height      INTEGER NOT NULL DEFAULT 0,
                hash        BLOB
            );

            -- The hub. A wallet-touching transaction, keyed by its mined height.
            -- `mined_height IS NULL` means unmined (mempool). There is no `blocks`
            -- table to point at: an observer tracks notes by height, not a block
            -- ledger, so the cursor (sync_state) is the only chain-position state.
            CREATE TABLE IF NOT EXISTS transactions (
                id_tx         INTEGER PRIMARY KEY,
                txid          BLOB    NOT NULL UNIQUE,
                mined_height  INTEGER,
                tx_index      INTEGER,
                expiry_height INTEGER
            );

            -- ── Sapling ──────────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS sapling_received_notes (
                id                       INTEGER PRIMARY KEY,
                transaction_id           INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index             INTEGER NOT NULL,
                diversifier              BLOB    NOT NULL,
                value                    INTEGER NOT NULL,
                rcm                      BLOB    NOT NULL,
                nf                       BLOB    UNIQUE,
                is_change                INTEGER NOT NULL DEFAULT 0,
                memo                     BLOB,
                commitment_tree_position INTEGER,
                UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_sapling_received_notes_tx
                ON sapling_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_sapling_received_notes_nf
                ON sapling_received_notes (nf) WHERE nf IS NOT NULL;

            -- Junction: a Sapling note and the transaction that spends it.
            CREATE TABLE IF NOT EXISTS sapling_received_note_spends (
                sapling_received_note_id INTEGER NOT NULL
                    REFERENCES sapling_received_notes(id) ON DELETE CASCADE,
                transaction_id           INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (sapling_received_note_id, transaction_id)
            );

            -- ── Orchard ──────────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS orchard_received_notes (
                id                       INTEGER PRIMARY KEY,
                transaction_id           INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                action_index             INTEGER NOT NULL,
                diversifier              BLOB    NOT NULL,
                value                    INTEGER NOT NULL,
                rho                      BLOB    NOT NULL,
                rseed                    BLOB    NOT NULL,
                nf                       BLOB    UNIQUE,
                is_change                INTEGER NOT NULL DEFAULT 0,
                memo                     BLOB,
                commitment_tree_position INTEGER,
                UNIQUE (transaction_id, action_index)
            );
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_tx
                ON orchard_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_nf
                ON orchard_received_notes (nf) WHERE nf IS NOT NULL;

            CREATE TABLE IF NOT EXISTS orchard_received_note_spends (
                orchard_received_note_id INTEGER NOT NULL
                    REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
                transaction_id           INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (orchard_received_note_id, transaction_id)
            );

            -- ── Transparent ──────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS transparent_received_outputs (
                id                          INTEGER PRIMARY KEY,
                transaction_id              INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index                INTEGER NOT NULL,
                address                     TEXT    NOT NULL,
                script                      BLOB    NOT NULL,
                value_zat                   INTEGER NOT NULL,
                max_observed_unspent_height INTEGER,
                UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_transparent_received_outputs_tx
                ON transparent_received_outputs (transaction_id);

            CREATE TABLE IF NOT EXISTS transparent_received_output_spends (
                transparent_received_output_id INTEGER NOT NULL
                    REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
                transaction_id                 INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                UNIQUE (transparent_received_output_id, transaction_id)
            );

            -- Cache of (spending tx -> spent outpoint), so a spend can be
            -- recorded even if we discover the output it spends afterwards.
            CREATE TABLE IF NOT EXISTS transparent_spend_map (
                spending_transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                prevout_txid            BLOB    NOT NULL,
                prevout_output_index    INTEGER NOT NULL,
                UNIQUE (spending_transaction_id, prevout_txid, prevout_output_index)
            );

            -- Derived transparent addresses, for gap-limit scanning.
            CREATE TABLE IF NOT EXISTS addresses (
                id                      INTEGER PRIMARY KEY,
                address                 TEXT    NOT NULL UNIQUE,
                transparent_child_index INTEGER,
                key_scope               INTEGER NOT NULL DEFAULT 0
            );
            "#,
        )?;
    }

    if version != SCHEMA_VERSION {
        set_version(conn, SCHEMA_VERSION)?;
    }

    Ok(())
}
