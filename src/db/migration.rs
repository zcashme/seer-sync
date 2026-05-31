//! SQLite schema creation and versioned migrations.

use rusqlite::{params, Connection};

const SCHEMA_VERSION: u32 = 1;

pub fn get_version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.query_row(
        "SELECT version FROM schema_version WHERE id = 1",
        [],
        |row| row.get(0),
    )
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

/// Create or migrate the database schema up to the current version.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
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
        conn.execute_batch("
            -- Key registry
            CREATE TABLE IF NOT EXISTS accounts (
                id        INTEGER PRIMARY KEY,
                label     TEXT    NOT NULL,
                key_type  TEXT    NOT NULL CHECK(key_type IN ('ivk','fvk','ovk')),
                encoded   TEXT    NOT NULL UNIQUE,
                birthday  INTEGER NOT NULL DEFAULT 0
            );

            -- Per-account sync cursor
            CREATE TABLE IF NOT EXISTS sync_state (
                account             INTEGER PRIMARY KEY REFERENCES accounts(id),
                height              INTEGER NOT NULL DEFAULT 0,
                hash                BLOB,
                sapling_leaf_count  INTEGER NOT NULL DEFAULT 0
            );

            -- Block index (reorg detection and timestamp lookup)
            CREATE TABLE IF NOT EXISTS blocks (
                height    INTEGER PRIMARY KEY,
                hash      BLOB    NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);

            -- Received notes (IVK and FVK paths)
            CREATE TABLE IF NOT EXISTS received_notes (
                id           INTEGER PRIMARY KEY,
                account      INTEGER NOT NULL REFERENCES accounts(id),
                pool         TEXT    NOT NULL CHECK(pool IN ('orchard','sapling')),
                tx_id        BLOB    NOT NULL,
                height       INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                diversifier  BLOB    NOT NULL,
                value_zat    INTEGER NOT NULL,
                rseed        BLOB    NOT NULL,
                rho          BLOB,
                leaf_pos     INTEGER,
                nullifier    BLOB,
                memo         BLOB,
                spent_height INTEGER,
                UNIQUE(tx_id, output_index, pool)
            );
            CREATE INDEX IF NOT EXISTS idx_rn_account   ON received_notes(account);
            CREATE INDEX IF NOT EXISTS idx_rn_nullifier ON received_notes(nullifier)
                WHERE nullifier IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_rn_height    ON received_notes(height);

            -- Sent notes (OVK and FVK paths)
            CREATE TABLE IF NOT EXISTS sent_notes (
                id           INTEGER PRIMARY KEY,
                account      INTEGER NOT NULL REFERENCES accounts(id),
                pool         TEXT    NOT NULL CHECK(pool IN ('orchard','sapling')),
                tx_id        BLOB    NOT NULL,
                height       INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                recipient    TEXT    NOT NULL,
                value_zat    INTEGER NOT NULL,
                memo         BLOB,
                UNIQUE(tx_id, output_index, pool)
            );
            CREATE INDEX IF NOT EXISTS idx_sn_account ON sent_notes(account);

            -- Transaction index (de-duplicated, net signed value)
            CREATE TABLE IF NOT EXISTS transactions (
                id        INTEGER PRIMARY KEY,
                account   INTEGER NOT NULL REFERENCES accounts(id),
                tx_id     BLOB    NOT NULL,
                height    INTEGER NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT 0,
                net_value INTEGER NOT NULL DEFAULT 0,
                UNIQUE(account, tx_id)
            );
            CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions(account);
            CREATE INDEX IF NOT EXISTS idx_tx_height  ON transactions(height);

            -- Transparent UTXOs
            CREATE TABLE IF NOT EXISTS transparent_utxos (
                id        INTEGER PRIMARY KEY,
                account   INTEGER NOT NULL REFERENCES accounts(id),
                address   TEXT    NOT NULL,
                tx_id     BLOB    NOT NULL,
                output_index INTEGER NOT NULL,
                value_zat INTEGER NOT NULL,
                height    INTEGER NOT NULL,
                script    BLOB    NOT NULL,
                spent_height INTEGER,
                UNIQUE(tx_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_utxo_account ON transparent_utxos(account);
            CREATE INDEX IF NOT EXISTS idx_utxo_address ON transparent_utxos(address);
        ")?;
    }

    if version != SCHEMA_VERSION {
        set_version(conn, SCHEMA_VERSION)?;
    }

    Ok(())
}
