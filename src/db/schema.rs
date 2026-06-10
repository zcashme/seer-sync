use rusqlite::Connection;

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(
        r#"
            CREATE TABLE IF NOT EXISTS account (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                birthday    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                height      INTEGER NOT NULL DEFAULT 0,
                hash        BLOB
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id_tx         INTEGER PRIMARY KEY,
                txid          BLOB    NOT NULL UNIQUE,
                mined_height  INTEGER,
                tx_index      INTEGER
            );

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
                spent_txid               BLOB,
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
                spent_txid               BLOB,
                is_sent                  INTEGER NOT NULL DEFAULT 0,
                recipient_address        TEXT,
                UNIQUE (transaction_id, action_index)
            );
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_tx
                ON orchard_received_notes (transaction_id);
            CREATE INDEX IF NOT EXISTS idx_orchard_received_notes_nf
                ON orchard_received_notes (nf) WHERE nf IS NOT NULL;

            CREATE TABLE IF NOT EXISTS transparent_received_outputs (
                id             INTEGER PRIMARY KEY,
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                output_index   INTEGER NOT NULL,
                address        TEXT    NOT NULL,
                script         BLOB    NOT NULL,
                value          INTEGER NOT NULL,
                spent_height   INTEGER,
                spent_txid     BLOB,
                UNIQUE (transaction_id, output_index)
            );
            CREATE INDEX IF NOT EXISTS idx_transparent_received_outputs_tx
                ON transparent_received_outputs (transaction_id);

            "#,
    )?;

    Ok(())
}
