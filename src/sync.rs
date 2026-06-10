pub mod chain;
pub mod scan;
pub mod transparent;

use crate::sync::chain::{ChainError, LwdClient, DEFAULT_CHUNK_OUTPUTS};
use crate::sync::scan::{
    enrich_memos, parse_transactions, scan_commitments, scan_compact, scan_sent, scan_transparent,
    Commitment, CompactScan, Note, Nullifier, Pool, Spend, TransparentOutput, TransparentSpend,
};
use crate::BlockHeight;
use crate::ViewKey;
use std::collections::{HashMap, HashSet};
use tokio_stream::StreamExt;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::Network;
use zcash_protocol::TxId;
use zcash_transparent::bundle::OutPoint;

const MAX_TRANSPORT_RETRIES: usize = 4;

pub type AccountError = Box<dyn std::error::Error + Send + Sync>;

#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Key(#[from] crate::key::KeyError),
    #[error("account: {0}")]
    Account(#[source] AccountError),
}

/// A position on the chain: a fully applied height and its block hash.
///
/// The hash is the reorg seam — the next pass verifies the chain still builds
/// on it. `None` means unknown (after a rewind, or a server that omitted it),
/// which skips that verification for one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub height: BlockHeight,
    pub hash: Option<BlockHash>,
}

/// Everything the engine needs from an account before scanning: where to
/// start, and what to watch for. Handed over once per pass via
/// [`Account::resume`]; the engine extends the watch-sets in memory as it
/// discovers new notes and outputs, so it never queries the account mid-run.
pub struct Resume {
    /// The height the account's history begins at. The fresh-start scan point,
    /// and always the transparent-discovery window start (gap-limit discovery
    /// must see the account's whole life).
    pub birthday: BlockHeight,
    /// Where the last pass ended, or `None` for an account that has never
    /// applied a batch.
    pub checkpoint: Option<Cursor>,
    /// Nullifiers of the account's unspent notes.
    pub nullifiers: Vec<(Pool, Nullifier)>,
    /// Outpoints of the account's unspent transparent outputs.
    pub outpoints: Vec<OutPoint>,
}

/// Everything the engine discovered in one chunk of blocks, delivered whole:
/// one batch, one cursor, one [`Account::apply`].
#[non_exhaustive]
pub struct Batch {
    /// Notes received by (and, under an OVK, sent from) the account.
    pub notes: Vec<Note>,
    /// Spends of the account's notes.
    pub spends: Vec<Spend>,
    /// Transparent outputs paying the account's addresses.
    pub transparent_outputs: Vec<TransparentOutput>,
    /// Spends of the account's transparent outputs.
    pub transparent_spends: Vec<TransparentSpend>,
    /// Every Orchard commitment in the chunk, in tree order. Empty unless
    /// [`Account::wants_commitments`] opts in.
    pub commitments: Vec<Commitment>,
}

/// An account is a fold over the chain: [`Account::resume`] is the initial
/// state, each [`Account::apply`] folds in one `(Cursor, Batch)` pair, and
/// [`Account::rewind`] is the undo.
pub trait Account {
    /// Where this account stands and what it is watching. Called once per
    /// pass — at engine start and again after every rewind or transport
    /// retry.
    fn resume(&self) -> Result<Resume, AccountError>;

    /// Truncate all state above `to`: notes, spend marks, and the checkpoint.
    /// Called when the chain reorganizes below the cursor.
    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError>;

    /// Fold one batch into the account. The batch and its cursor must be
    /// persisted atomically — together or not at all.
    fn apply(&self, at: Cursor, batch: &Batch) -> Result<(), AccountError>;

    /// Opt into the Orchard commitment firehose ([`Batch::commitments`]).
    /// Off by default: only consumers building note-commitment-tree witnesses
    /// need it, and it has a real cost.
    fn wants_commitments(&self) -> bool {
        false
    }
}

/// Sync `account` from its [`Resume`] point to the current chain tip, one
/// pass over the chain. Returns where the account stands afterwards — `None`
/// only when a fresh account's birthday is beyond the tip.
pub async fn run<A: Account>(
    client: LwdClient,
    keys: &ViewKey,
    network: Network,
    account: &A,
) -> Result<Option<Cursor>, SyncError> {
    let mut fetch_client = client.clone();
    let tip = BlockHeight::from_u32(chain::tip_height(&mut fetch_client).await?);

    let mut rewind_by: u32 = 1;
    let mut transport_attempts: usize = 0;

    loop {
        let Resume {
            birthday,
            checkpoint,
            nullifiers,
            outpoints,
        } = account.resume().map_err(SyncError::Account)?;
        let mut last = checkpoint;
        let (start, seam) = match checkpoint {
            Some(c) => (c.height + 1, c.hash),
            None => (birthday, None),
        };
        if start > tip {
            return Ok(last);
        }

        let mut watched_nfs: HashSet<(Pool, Nullifier)> = nullifiers.into_iter().collect();
        let mut watched_outpoints: HashSet<(TxId, u32)> =
            outpoints.iter().map(|o| (*o.txid(), o.n())).collect();

        // Transparent discovery is per-pass: a reorg rewind re-enters here, and
        // the replacement chain's transparent transactions must be rediscovered.
        // The window is the account's whole life, not [start, tip] — stateless
        // gap-limit discovery misses later addresses if early ones look unused
        // (see `transparent::discover`); targets already below `start` are
        // simply never reached by the stream. No-op for keys without a
        // transparent component.
        let transparent = transparent::discover(
            &mut fetch_client,
            keys,
            &network,
            u32::from(birthday),
            u32::from(tip),
        )
        .await?;

        let mut stream = chain::blocks(
            client.clone(),
            u32::from(start),
            u32::from(tip),
            DEFAULT_CHUNK_OUTPUTS,
            seam,
        );

        loop {
            let Some(item) = stream.next().await else {
                return Ok(last);
            };
            match item {
                Ok(blocks) => {
                    let Some(last_block) = blocks.last() else { continue };
                    let height = BlockHeight::from_u32(last_block.height as u32);
                    let hash = <[u8; 32]>::try_from(&last_block.hash[..]).ok().map(BlockHash);

                    let CompactScan {
                        notes: incoming,
                        spends,
                    } = scan_compact(&blocks, keys);

                    for n in &incoming {
                        if let Some(nf) = n.nullifier {
                            watched_nfs.insert((n.pool(), nf));
                        }
                    }
                    let spends: Vec<Spend> = spends
                        .into_iter()
                        .filter(|s| watched_nfs.contains(&(s.pool, s.nf)))
                        .collect();

                    let first = blocks.first().map_or(u32::from(height), |b| b.height as u32);
                    let batch_targets: HashSet<TxId> = transparent
                        .targets
                        .iter()
                        .filter(|(_, h)| (first..=u32::from(height)).contains(h))
                        .map(|(txid, _)| *txid)
                        .collect();

                    let mut txids: Vec<TxId> = incoming
                        .iter()
                        .map(|n| n.txid)
                        .chain(spends.iter().map(|s| s.txid))
                        .chain(batch_targets.iter().copied())
                        .collect();
                    txids.sort_unstable();
                    txids.dedup();
                    let mut raw_txs = Vec::with_capacity(txids.len());
                    for txid in txids {
                        let raw = chain::fetch_raw_transaction(&mut fetch_client, &txid).await?;
                        raw_txs.push((txid, raw));
                    }

                    let tx_index: HashMap<TxId, u32> = blocks
                        .iter()
                        .flat_map(|b| b.vtx.iter())
                        .filter_map(|tx| {
                            let id: [u8; 32] = tx.txid[..].try_into().ok()?;
                            Some((TxId::from_bytes(id), tx.index as u32))
                        })
                        .collect();

                    let parsed = parse_transactions(&network, &raw_txs);
                    let incoming = enrich_memos(keys, &network, &parsed, incoming);
                    let sent = scan_sent(keys, &network, &parsed, &incoming, &tx_index);
                    let notes: Vec<Note> = incoming.into_iter().chain(sent).collect();

                    let (transparent_outputs, transparent_spends) = if batch_targets.is_empty() {
                        (Vec::new(), Vec::new())
                    } else {
                        let (outputs, candidates) =
                            scan_transparent(&parsed, &batch_targets, &transparent.addresses);
                        for o in &outputs {
                            watched_outpoints.insert((o.txid, o.output_index));
                        }
                        let spends = candidates
                            .into_iter()
                            .filter(|s| {
                                watched_outpoints.contains(&(*s.outpoint.txid(), s.outpoint.n()))
                            })
                            .collect();
                        (outputs, spends)
                    };

                    let commitments = if account.wants_commitments() {
                        scan_commitments(&blocks)
                    } else {
                        Vec::new()
                    };

                    let at = Cursor { height, hash };
                    let batch = Batch {
                        notes,
                        spends,
                        transparent_outputs,
                        transparent_spends,
                        commitments,
                    };
                    account.apply(at, &batch).map_err(SyncError::Account)?;
                    last = Some(at);

                    transport_attempts = 0;
                    rewind_by = 1;
                }
                Err(ChainError::Reorg(at)) => {
                    account
                        .rewind(BlockHeight::from_u32(at.saturating_sub(rewind_by)))
                        .map_err(SyncError::Account)?;
                    rewind_by = rewind_by.saturating_mul(2);
                    break;
                }
                Err(e) => {
                    if transport_attempts < MAX_TRANSPORT_RETRIES {
                        transport_attempts += 1;
                        break;
                    }
                    return Err(SyncError::Chain(e));
                }
            }
        }
    }
}
