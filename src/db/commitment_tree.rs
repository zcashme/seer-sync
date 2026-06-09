//! SQLite-backed `shardtree` store for the Orchard note-commitment tree.
//!
//! Ported from librustzcash `zcash_client_sqlite` v0.19.2
//! (`src/wallet/commitment_tree.rs`), MIT/Apache-2.0, trimmed to the single
//! `ShardStore`-over-`&rusqlite::Transaction` implementation we need (the
//! `Connection` variant, subtree-root insertion, and confirmation-depth helpers
//! are dropped). Shard/cap blobs use the vendored
//! [`crate::db::shardtree_serialization`] codec. Keeping the helpers close to
//! upstream preserves on-disk compatibility; do not "improve" the SQL.

use std::collections::BTreeSet;
use std::io::{self, Cursor};
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Arc;

use incrementalmerkletree::{Address, Level, Position};
use rusqlite::{named_params, OptionalExtension};
use shardtree::{
    store::{Checkpoint, ShardStore, TreeState},
    LocatedPrunableTree, PrunableTree, ShardTree,
};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::BlockHeight;

use super::shardtree_serialization::{read_shard, write_shard};

/// Orchard note-commitment tree depth.
pub const ORCHARD_DEPTH: u8 = 32;
/// Shard height librustzcash uses for the Orchard tree.
pub const ORCHARD_SHARD_HEIGHT: u8 = 16;
/// Table prefix for the Orchard tree tables (matches `orchard_tree_*`).
const ORCHARD_TABLE_PREFIX: &str = "orchard";

/// A `shardtree` over the SQLite store, keyed to a single transaction.
pub type OrchardShardTree<'a, 'conn> = ShardTree<
    SqliteShardStore<&'a rusqlite::Transaction<'conn>, orchard::tree::MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>,
    ORCHARD_DEPTH,
    ORCHARD_SHARD_HEIGHT,
>;

/// Open the Orchard note-commitment tree backed by `tx`. `max_checkpoints`
/// bounds reorg-rollback history.
pub fn orchard_tree<'a, 'conn>(
    tx: &'a rusqlite::Transaction<'conn>,
    max_checkpoints: usize,
) -> Result<OrchardShardTree<'a, 'conn>, rusqlite::Error>
where
    'a: 'conn,
{
    Ok(ShardTree::new(
        SqliteShardStore::from_connection(tx, ORCHARD_TABLE_PREFIX)?,
        max_checkpoints,
    ))
}

/// Create the `orchard_tree_*` tables if absent. Call once at setup (only
/// needed when the commitment tree is in use).
pub fn init_tables(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS orchard_tree_shards (
            shard_index        INTEGER PRIMARY KEY,
            subtree_end_height INTEGER,
            root_hash          BLOB,
            shard_data         BLOB,
            contains_marked    INTEGER,
            CONSTRAINT root_unique UNIQUE (root_hash)
        );
        CREATE TABLE IF NOT EXISTS orchard_tree_cap (
            cap_id   INTEGER PRIMARY KEY,
            cap_data BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orchard_tree_checkpoints (
            checkpoint_id INTEGER PRIMARY KEY,
            position      INTEGER
        );
        CREATE TABLE IF NOT EXISTS orchard_tree_checkpoint_marks_removed (
            checkpoint_id         INTEGER NOT NULL,
            mark_removed_position INTEGER NOT NULL,
            FOREIGN KEY (checkpoint_id)
                REFERENCES orchard_tree_checkpoints(checkpoint_id) ON DELETE CASCADE,
            CONSTRAINT mark_removed_unique UNIQUE (checkpoint_id, mark_removed_position)
        );
        "#,
    )
}

/// Errors from the SQLite `ShardStore`.
#[derive(Debug)]
pub enum Error {
    /// Deserializing stored shard data failed.
    Serialization(io::Error),
    /// A SQLite query or update failed.
    Query(rusqlite::Error),
    /// A checkpoint already exists at this height with a conflicting tree state
    /// (the caller should have detected the reorg and truncated first).
    CheckpointConflict {
        checkpoint_id: BlockHeight,
        checkpoint: Checkpoint,
        extant_tree_state: TreeState,
        extant_marks_removed: Option<BTreeSet<Position>>,
    },
    /// Inserting shards would leave a gap in the stored shard range.
    SubtreeDiscontinuity {
        attempted_insertion_range: Range<u64>,
        existing_range: Range<u64>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Serialization(e) => write!(f, "commitment tree serialization error: {e}"),
            Error::Query(e) => write!(f, "commitment tree query/update error: {e}"),
            Error::CheckpointConflict { checkpoint_id, .. } => {
                write!(f, "conflicting checkpoint at height {checkpoint_id}")
            }
            Error::SubtreeDiscontinuity { attempted_insertion_range, existing_range } => write!(
                f,
                "shard insertion {attempted_insertion_range:?} is discontinuous with {existing_range:?}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Serialization(e) => Some(e),
            Error::Query(e) => Some(e),
            _ => None,
        }
    }
}

/// SQLite-backed shardtree store. Construct over a transaction with
/// [`SqliteShardStore::from_connection`].
pub struct SqliteShardStore<C, H, const SHARD_HEIGHT: u8> {
    conn: C,
    table_prefix: &'static str,
    _hash: PhantomData<H>,
}

impl<C, H, const SHARD_HEIGHT: u8> SqliteShardStore<C, H, SHARD_HEIGHT> {
    const SHARD_ROOT_LEVEL: Level = Level::new(SHARD_HEIGHT);

    pub fn from_connection(conn: C, table_prefix: &'static str) -> Result<Self, rusqlite::Error> {
        Ok(SqliteShardStore { conn, table_prefix, _hash: PhantomData })
    }
}

impl<'conn, 'a: 'conn, H: HashSer, const SHARD_HEIGHT: u8> ShardStore
    for SqliteShardStore<&'a rusqlite::Transaction<'conn>, H, SHARD_HEIGHT>
{
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = Error;

    fn get_shard(&self, shard_root: Address) -> Result<Option<LocatedPrunableTree<H>>, Error> {
        get_shard(self.conn, self.table_prefix, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<H>>, Error> {
        last_shard(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<H>) -> Result<(), Error> {
        put_shard(self.conn, self.table_prefix, subtree)
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Error> {
        get_shard_roots(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Error> {
        truncate_shards(self.conn, self.table_prefix, shard_index)
    }

    fn get_cap(&self) -> Result<PrunableTree<H>, Error> {
        get_cap(self.conn, self.table_prefix)
    }

    fn put_cap(&mut self, cap: PrunableTree<H>) -> Result<(), Error> {
        put_cap(self.conn, self.table_prefix, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<BlockHeight>, Error> {
        min_checkpoint_id(self.conn, self.table_prefix)
    }

    fn max_checkpoint_id(&self) -> Result<Option<BlockHeight>, Error> {
        max_checkpoint_id(self.conn, self.table_prefix)
    }

    fn add_checkpoint(&mut self, checkpoint_id: BlockHeight, checkpoint: Checkpoint) -> Result<(), Error> {
        add_checkpoint(self.conn, self.table_prefix, checkpoint_id, checkpoint)
    }

    fn checkpoint_count(&self) -> Result<usize, Error> {
        checkpoint_count(self.conn, self.table_prefix)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(BlockHeight, Checkpoint)>, Error> {
        get_checkpoint_at_depth(self.conn, self.table_prefix, checkpoint_depth).map_err(Error::Query)
    }

    fn get_checkpoint(&self, checkpoint_id: &BlockHeight) -> Result<Option<Checkpoint>, Error> {
        get_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Error>
    where
        F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Error>,
    {
        with_checkpoints(self.conn, self.table_prefix, limit, callback)
    }

    fn for_each_checkpoint<F>(&self, limit: usize, callback: F) -> Result<(), Error>
    where
        F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Error>,
    {
        with_checkpoints(self.conn, self.table_prefix, limit, callback)
    }

    fn update_checkpoint_with<F>(&mut self, checkpoint_id: &BlockHeight, update: F) -> Result<bool, Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Error>,
    {
        update_checkpoint_with(self.conn, self.table_prefix, *checkpoint_id, update)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &BlockHeight) -> Result<(), Error> {
        remove_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn truncate_checkpoints_retaining(&mut self, checkpoint_id: &BlockHeight) -> Result<(), Error> {
        truncate_checkpoints_retaining(self.conn, self.table_prefix, *checkpoint_id)
    }
}

// ---------- helpers (operate on a Connection/Transaction) ----------

fn get_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_addr: Address,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_data, root_hash FROM {table_prefix}_tree_shards WHERE shard_index = :shard_index"
        ),
        named_params![":shard_index": shard_root_addr.index()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
    )
    .optional()
    .map_err(Error::Query)?
    .map(|(shard_data, root_hash)| {
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        let located_tree = LocatedPrunableTree::from_parts(shard_root_addr, shard_tree).map_err(|e| {
            Error::Serialization(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Tree contained invalid data at address {e:?}"),
            ))
        })?;
        if let Some(root_hash_data) = root_hash {
            let root_hash = H::read(Cursor::new(root_hash_data)).map_err(Error::Serialization)?;
            Ok(located_tree.reannotate_root(Some(Arc::new(root_hash))))
        } else {
            Ok(located_tree)
        }
    })
    .transpose()
}

fn last_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_index, shard_data FROM {table_prefix}_tree_shards ORDER BY shard_index DESC LIMIT 1"
        ),
        [],
        |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
    .map_err(Error::Query)?
    .map(|(shard_index, shard_data)| {
        let shard_root = Address::from_parts(shard_root_level, shard_index);
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        LocatedPrunableTree::from_parts(shard_root, shard_tree).map_err(|e| {
            Error::Serialization(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Tree contained invalid data at address {e:?}"),
            ))
        })
    })
    .transpose()
}

fn check_shard_discontinuity(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    proposed_insertion_range: Range<u64>,
) -> Result<(), Error> {
    if let Ok((Some(stored_min), Some(stored_max))) = conn
        .query_row(
            &format!("SELECT MIN(shard_index), MAX(shard_index) FROM {table_prefix}_tree_shards"),
            [],
            |row| Ok((row.get::<_, Option<u64>>(0)?, row.get::<_, Option<u64>>(1)?)),
        )
        .map_err(Error::Query)
    {
        let (cur_start, cur_end) = (stored_min, stored_max + 1);
        let (ins_start, ins_end) = (proposed_insertion_range.start, proposed_insertion_range.end);
        if cur_start > ins_end || ins_start > cur_end {
            return Err(Error::SubtreeDiscontinuity {
                attempted_insertion_range: proposed_insertion_range,
                existing_range: cur_start..cur_end,
            });
        }
    }
    Ok(())
}

fn put_shard<H: HashSer>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    subtree: LocatedPrunableTree<H>,
) -> Result<(), Error> {
    let subtree_root_hash = subtree
        .root()
        .annotation()
        .and_then(|ann| {
            ann.as_ref().map(|rc| {
                let mut root_hash = vec![];
                rc.write(&mut root_hash)?;
                Ok(root_hash)
            })
        })
        .transpose()
        .map_err(Error::Serialization)?;

    let mut subtree_data = vec![];
    write_shard(&mut subtree_data, subtree.root()).map_err(Error::Serialization)?;

    let shard_index = subtree.root_addr().index();
    check_shard_discontinuity(conn, table_prefix, shard_index..shard_index + 1)?;

    let mut stmt_put_shard = conn
        .prepare_cached(&format!(
            "INSERT INTO {table_prefix}_tree_shards (shard_index, root_hash, shard_data)
             VALUES (:shard_index, :root_hash, :shard_data)
             ON CONFLICT (shard_index) DO UPDATE
             SET root_hash = :root_hash, shard_data = :shard_data"
        ))
        .map_err(Error::Query)?;
    stmt_put_shard
        .execute(named_params![
            ":shard_index": shard_index,
            ":root_hash": subtree_root_hash,
            ":shard_data": subtree_data
        ])
        .map_err(Error::Query)?;
    Ok(())
}

fn get_shard_roots(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Vec<Address>, Error> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT shard_index FROM {table_prefix}_tree_shards ORDER BY shard_index"
        ))
        .map_err(Error::Query)?;
    let mut rows = stmt.query([]).map_err(Error::Query)?;
    let mut res = vec![];
    while let Some(row) = rows.next().map_err(Error::Query)? {
        res.push(Address::from_parts(shard_root_level, row.get(0).map_err(Error::Query)?));
    }
    Ok(res)
}

fn truncate_shards(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_index: u64,
) -> Result<(), Error> {
    conn.execute(
        &format!("DELETE FROM {table_prefix}_tree_shards WHERE shard_index >= ?"),
        [shard_index],
    )
    .map_err(Error::Query)
    .map(|_| ())
}

fn get_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<PrunableTree<H>, Error> {
    conn.query_row(
        &format!("SELECT cap_data FROM {table_prefix}_tree_cap"),
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(Error::Query)?
    .map_or_else(
        || Ok(PrunableTree::empty()),
        |cap_data| read_shard(&mut Cursor::new(cap_data)).map_err(Error::Serialization),
    )
}

fn put_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    cap: PrunableTree<H>,
) -> Result<(), Error> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "INSERT INTO {table_prefix}_tree_cap (cap_id, cap_data)
             VALUES (0, :cap_data)
             ON CONFLICT (cap_id) DO UPDATE SET cap_data = :cap_data"
        ))
        .map_err(Error::Query)?;
    let mut cap_data = vec![];
    write_shard(&mut cap_data, &cap).map_err(Error::Serialization)?;
    stmt.execute([cap_data]).map_err(Error::Query)?;
    Ok(())
}

fn min_checkpoint_id(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!("SELECT MIN(checkpoint_id) FROM {table_prefix}_tree_checkpoints"),
        [],
        |row| row.get::<_, Option<u32>>(0).map(|opt| opt.map(BlockHeight::from)),
    )
    .map_err(Error::Query)
}

fn max_checkpoint_id(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!("SELECT MAX(checkpoint_id) FROM {table_prefix}_tree_checkpoints"),
        [],
        |row| row.get::<_, Option<u32>>(0).map(|opt| opt.map(BlockHeight::from)),
    )
    .map_err(Error::Query)
}

fn add_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), Error> {
    let extant_tree_state = conn
        .query_row(
            &format!(
                "SELECT position FROM {table_prefix}_tree_checkpoints WHERE checkpoint_id = :checkpoint_id"
            ),
            named_params![":checkpoint_id": u32::from(checkpoint_id)],
            |row| {
                row.get::<_, Option<u64>>(0).map(|opt| {
                    opt.map_or(TreeState::Empty, |pos| TreeState::AtPosition(Position::from(pos)))
                })
            },
        )
        .optional()
        .map_err(Error::Query)?;

    match extant_tree_state {
        Some(current) => {
            if current != checkpoint.tree_state() {
                Err(Error::CheckpointConflict {
                    checkpoint_id,
                    checkpoint,
                    extant_tree_state: current,
                    extant_marks_removed: None,
                })
            } else {
                let marks_removed = get_marks_removed(conn, table_prefix, checkpoint_id)?;
                if &marks_removed == checkpoint.marks_removed() {
                    Ok(())
                } else {
                    Err(Error::CheckpointConflict {
                        checkpoint_id,
                        checkpoint,
                        extant_tree_state: current,
                        extant_marks_removed: Some(marks_removed),
                    })
                }
            }
        }
        None => {
            let mut stmt_insert_checkpoint = conn
                .prepare_cached(&format!(
                    "INSERT INTO {table_prefix}_tree_checkpoints (checkpoint_id, position)
                     VALUES (:checkpoint_id, :position)"
                ))
                .map_err(Error::Query)?;
            stmt_insert_checkpoint
                .execute(named_params![
                    ":checkpoint_id": u32::from(checkpoint_id),
                    ":position": checkpoint.position().map(u64::from)
                ])
                .map_err(Error::Query)?;

            let mut stmt_insert_mark_removed = conn
                .prepare_cached(&format!(
                    "INSERT INTO {table_prefix}_tree_checkpoint_marks_removed (checkpoint_id, mark_removed_position)
                     VALUES (:checkpoint_id, :position)"
                ))
                .map_err(Error::Query)?;
            for pos in checkpoint.marks_removed() {
                stmt_insert_mark_removed
                    .execute(named_params![
                        ":checkpoint_id": u32::from(checkpoint_id),
                        ":position": u64::from(*pos)
                    ])
                    .map_err(Error::Query)?;
            }
            Ok(())
        }
    }
}

fn checkpoint_count(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<usize, Error> {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table_prefix}_tree_checkpoints"),
        [],
        |row| row.get::<_, usize>(0),
    )
    .map_err(Error::Query)
}

fn get_marks_removed(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<BTreeSet<Position>, Error> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position FROM {table_prefix}_tree_checkpoint_marks_removed WHERE checkpoint_id = ?"
        ))
        .map_err(Error::Query)?;
    let rows = stmt.query([u32::from(checkpoint_id)]).map_err(Error::Query)?;
    rows.mapped(|row| row.get::<_, u64>(0).map(Position::from))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(Error::Query)
}

fn get_checkpoint(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<Option<Checkpoint>, Error> {
    let checkpoint_position = conn
        .query_row(
            &format!(
                "SELECT position FROM {table_prefix}_tree_checkpoints WHERE checkpoint_id = ?"
            ),
            [u32::from(checkpoint_id)],
            |row| row.get::<_, Option<u64>>(0).map(|opt| opt.map(Position::from)),
        )
        .optional()
        .map_err(Error::Query)?;

    checkpoint_position
        .map(|pos_opt| {
            Ok(Checkpoint::from_parts(
                pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                get_marks_removed(conn, table_prefix, checkpoint_id)?,
            ))
        })
        .transpose()
}

fn get_checkpoint_at_depth(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_depth: usize,
) -> Result<Option<(BlockHeight, Checkpoint)>, rusqlite::Error> {
    let checkpoint_parts = conn
        .query_row(
            &format!(
                "SELECT checkpoint_id, position FROM {table_prefix}_tree_checkpoints
                 ORDER BY checkpoint_id DESC LIMIT 1 OFFSET :offset"
            ),
            named_params![":offset": checkpoint_depth],
            |row| {
                let checkpoint_id: u32 = row.get(0)?;
                let position: Option<u64> = row.get(1)?;
                Ok((BlockHeight::from(checkpoint_id), position.map(Position::from)))
            },
        )
        .optional()?;

    checkpoint_parts
        .map(|(checkpoint_id, pos_opt)| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT mark_removed_position FROM {table_prefix}_tree_checkpoint_marks_removed WHERE checkpoint_id = ?"
            ))?;
            let rows = stmt.query([u32::from(checkpoint_id)])?;
            let marks_removed = rows
                .mapped(|row| row.get::<_, u64>(0).map(Position::from))
                .collect::<Result<BTreeSet<_>, _>>()?;
            Ok((
                checkpoint_id,
                Checkpoint::from_parts(
                    pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                    marks_removed,
                ),
            ))
        })
        .transpose()
}

fn with_checkpoints<F>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    limit: usize,
    mut callback: F,
) -> Result<(), Error>
where
    F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Error>,
{
    let mut stmt_get_checkpoints = conn
        .prepare_cached(&format!(
            "SELECT checkpoint_id, position FROM {table_prefix}_tree_checkpoints ORDER BY position LIMIT :limit"
        ))
        .map_err(Error::Query)?;
    let mut stmt_get_checkpoint_marks_removed = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position FROM {table_prefix}_tree_checkpoint_marks_removed WHERE checkpoint_id = :checkpoint_id"
        ))
        .map_err(Error::Query)?;

    let mut rows = stmt_get_checkpoints.query(named_params![":limit": limit]).map_err(Error::Query)?;
    while let Some(row) = rows.next().map_err(Error::Query)? {
        let checkpoint_id = row.get::<_, u32>(0).map_err(Error::Query)?;
        let tree_state = row
            .get::<_, Option<u64>>(1)
            .map(|opt| opt.map_or(TreeState::Empty, |p| TreeState::AtPosition(p.into())))
            .map_err(Error::Query)?;
        let mark_rows = stmt_get_checkpoint_marks_removed
            .query(named_params![":checkpoint_id": checkpoint_id])
            .map_err(Error::Query)?;
        let marks_removed = mark_rows
            .mapped(|row| row.get::<_, u64>(0).map(Position::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Error::Query)?;
        callback(&BlockHeight::from(checkpoint_id), &Checkpoint::from_parts(tree_state, marks_removed))?
    }
    Ok(())
}

fn update_checkpoint_with<F>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    update: F,
) -> Result<bool, Error>
where
    F: Fn(&mut Checkpoint) -> Result<(), Error>,
{
    if let Some(mut c) = get_checkpoint(conn, table_prefix, checkpoint_id)? {
        update(&mut c)?;
        remove_checkpoint(conn, table_prefix, checkpoint_id)?;
        add_checkpoint(conn, table_prefix, checkpoint_id, c)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn remove_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    conn.prepare_cached(&format!(
        "DELETE FROM {table_prefix}_tree_checkpoints WHERE checkpoint_id = :checkpoint_id"
    ))
    .map_err(Error::Query)?
    .execute(named_params![":checkpoint_id": u32::from(checkpoint_id)])
    .map_err(Error::Query)?;
    Ok(())
}

fn truncate_checkpoints_retaining(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        &format!("DELETE FROM {table_prefix}_tree_checkpoints WHERE checkpoint_id > ?"),
        [u32::from(checkpoint_id)],
    )
    .map_err(Error::Query)?;
    conn.execute(
        &format!("DELETE FROM {table_prefix}_tree_checkpoint_marks_removed WHERE checkpoint_id = ?"),
        [u32::from(checkpoint_id)],
    )
    .map_err(Error::Query)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Position, Retention};
    use orchard::note::ExtractedNoteCommitment;
    use orchard::tree::MerkleHashOrchard;

    fn cmx(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn leaf(b: u8) -> MerkleHashOrchard {
        MerkleHashOrchard::from_bytes(&cmx(b)).into_option().unwrap()
    }

    #[test]
    fn sqlite_backed_witness_root_matches_and_survives_reopen() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        init_tables(&conn).unwrap();
        let marked = leaf(3); // position 2

        // Insert 4 leaves, mark position 2, checkpoint at height 100 — committed.
        {
            let tx = conn.transaction().unwrap();
            {
                let mut tree = orchard_tree(&tx, 100).unwrap();
                tree.batch_insert(
                    Position::from(0),
                    (0u8..4).map(|i| {
                        let h = leaf(i + 1);
                        let r = if h == marked { Retention::Marked } else { Retention::Ephemeral };
                        (h, r)
                    }),
                )
                .unwrap();
                tree.checkpoint(100.into()).unwrap();
            }
            tx.commit().unwrap();
        }

        // Re-open over a fresh transaction (state persisted in SQLite): the
        // witness still verifies against the tree root.
        let tx = conn.transaction().unwrap();
        let tree = orchard_tree(&tx, 100).unwrap();
        let path = tree.witness_at_checkpoint_id(Position::from(2), &100.into()).unwrap().unwrap();
        let note_cmx = ExtractedNoteCommitment::from_bytes(&cmx(3)).into_option().unwrap();
        let root = tree.root_at_checkpoint_id(&100.into()).unwrap().unwrap();
        let orchard_path = orchard::tree::MerklePath::from(path);
        assert_eq!(orchard_path.root(note_cmx), orchard::tree::Anchor::from(root));
    }
}
