use rusqlite::Connection;

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(
        r#"
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
                tx_index      INTEGER
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
                memo                     BLOB,
                commitment_tree_position INTEGER,
                spent_height             INTEGER,
                -- 0 = a note you received (spendable, counts toward balance);
                -- 1 = an output you sent, recovered via OVK (display only).
                is_sent                  INTEGER NOT NULL DEFAULT 0,
                -- The destination, encoded as a unified address (`u1…`). Only an
                -- output you sent (is_sent = 1) has one; NULL for received notes,
                -- whose recipient is your own address. Recovered via OVK, so it is
                -- absent for UIVK-only syncs.
                recipient_address        TEXT,
                UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_sapling_received_notes_tx
                ON sapling_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_sapling_received_notes_nf
                ON sapling_received_notes (nf) WHERE nf IS NOT NULL;

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
                memo                     BLOB,
                commitment_tree_position INTEGER,
                spent_height             INTEGER,
                -- 0 = a note you received (spendable, counts toward balance);
                -- 1 = an output you sent, recovered via OVK (display only).
                is_sent                  INTEGER NOT NULL DEFAULT 0,
                -- The destination, encoded as a unified address (`u1…`). Only an
                -- output you sent (is_sent = 1) has one; NULL for received notes,
                -- whose recipient is your own address. Recovered via OVK, so it is
                -- absent for UIVK-only syncs.
                recipient_address        TEXT,
                UNIQUE (transaction_id, action_index)
            );
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_tx
                ON orchard_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_nf
                ON orchard_received_notes (nf) WHERE nf IS NOT NULL;

            "#,
    )?;

    Ok(())
}
