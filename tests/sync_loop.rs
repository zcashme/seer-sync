use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use orchard::keys::FullViewingKey;
use orchard::note::{ExtractedNoteCommitment, RandomSeed, Rho};
use orchard::note_encryption::{OrchardDomain, OrchardNoteEncryption};
use orchard::value::NoteValue;
use seer_sync::proto::compact_tx_streamer_server::{CompactTxStreamer, CompactTxStreamerServer};
use seer_sync::proto::{
    Address, AddressList, Balance, BlockId, BlockRange, ChainMetadata, ChainSpec, CompactBlock,
    CompactOrchardAction, CompactTx, Duration, Empty, GetAddressUtxosArg, GetAddressUtxosReply,
    GetAddressUtxosReplyList, GetMempoolTxRequest, GetSubtreeRootsArg, LightdInfo, PingResponse,
    RawTransaction, SendResponse, SubtreeRoot, TransparentAddressBlockFilter, TreeState, TxFilter,
};
use seer_sync::sync::chain::LwdClient;
use seer_sync::sync::scan::{Commitment, Note, Pool, ShieldedNote, Spend};
use seer_sync::sync::{run, Account, AccountError, Cursor, SyncError};
use seer_sync::{BlockHash, BlockHeight, Network, ViewKey};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_note_encryption::Domain;
use zip32::{AccountId, Scope};

const BIRTHDAY: u32 = 100;
const FORK_A: u8 = 0xaa;
const FORK_B: u8 = 0xbb;
struct Wallet {
    keys: ViewKey,
    fvk: FullViewingKey,
    addr: orchard::Address,
}

fn wallet(seed: u8) -> Wallet {
    let usk =
        UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[seed; 32], AccountId::ZERO).unwrap();
    let encoded = usk
        .to_unified_full_viewing_key()
        .encode(&Network::MainNetwork);
    let fvk = FullViewingKey::from(usk.orchard());
    let addr = fvk.address_at(0u32, Scope::External);
    Wallet {
        keys: ViewKey::decode(&Network::MainNetwork, &encoded).unwrap(),
        fvk,
        addr,
    }
}

fn forge_note(addr: orchard::Address, value: u64, spent_nf: [u8; 32]) -> orchard::Note {
    let rho = Option::from(Rho::from_bytes(&spent_nf)).expect("canonical rho");
    (0u8..=255)
        .find_map(|i| {
            let rseed = Option::from(RandomSeed::from_bytes([i; 32], &rho))?;
            Option::from(orchard::Note::from_parts(
                addr,
                NoteValue::from_raw(value),
                rho,
                rseed,
            ))
        })
        .expect("forgeable note")
}

fn cmx_of(note: &orchard::Note) -> [u8; 32] {
    ExtractedNoteCommitment::from(note.commitment()).to_bytes()
}

fn action_for(note: &orchard::Note) -> CompactOrchardAction {
    let enc = OrchardNoteEncryption::new(None, *note, [0u8; 512]);
    CompactOrchardAction {
        nullifier: note.rho().to_bytes().to_vec(),
        cmx: cmx_of(note).to_vec(),
        ephemeral_key: OrchardDomain::epk_bytes(enc.epk()).0.to_vec(),
        ciphertext: enc.encrypt_note_plaintext()[..52].to_vec(),
    }
}

fn txid(label: u8) -> [u8; 32] {
    [label; 32]
}

fn tx(label: u8, actions: Vec<CompactOrchardAction>) -> CompactTx {
    CompactTx {
        txid: txid(label).to_vec(),
        actions,
        ..Default::default()
    }
}

fn block_hash(height: u32, fork: u8) -> [u8; 32] {
    let mut h = [fork; 32];
    h[..4].copy_from_slice(&height.to_le_bytes());
    h
}

fn chain(
    range: RangeInclusive<u32>,
    fork: u8,
    mut txs_at: impl FnMut(u32) -> Vec<CompactTx>,
) -> Vec<CompactBlock> {
    let mut tree = 0u32;
    range
        .map(|h| {
            let vtx: Vec<CompactTx> = txs_at(h)
                .into_iter()
                .enumerate()
                .map(|(i, mut t)| {
                    t.index = i as u64;
                    t
                })
                .collect();
            tree += vtx.iter().map(|t| t.actions.len() as u32).sum::<u32>();
            CompactBlock {
                height: h as u64,
                hash: block_hash(h, fork).to_vec(),
                prev_hash: block_hash(h - 1, fork).to_vec(),
                vtx,
                chain_metadata: Some(ChainMetadata {
                    orchard_commitment_tree_size: tree,
                    ..Default::default()
                }),
                ..Default::default()
            }
        })
        .collect()
}

#[derive(Clone)]
struct Epoch {
    blocks: Vec<CompactBlock>,
    fail_after: Option<usize>,
}

#[derive(Default)]
struct FakeLwd {
    epochs: Mutex<VecDeque<Epoch>>,
    requested_ranges: Mutex<Vec<(u32, u32)>>,
    requested_txs: Mutex<Vec<Vec<u8>>>,
}

impl FakeLwd {
    fn single(blocks: Vec<CompactBlock>) -> Self {
        Self::epochs(vec![Epoch {
            blocks,
            fail_after: None,
        }])
    }

    fn epochs(list: Vec<Epoch>) -> Self {
        FakeLwd {
            epochs: Mutex::new(list.into()),
            ..Default::default()
        }
    }

    fn ranges(&self) -> Vec<(u32, u32)> {
        self.requested_ranges.lock().unwrap().clone()
    }

    fn txs(&self) -> Vec<Vec<u8>> {
        self.requested_txs.lock().unwrap().clone()
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl CompactTxStreamer for FakeLwd {
    async fn get_latest_block(&self, _: Request<ChainSpec>) -> Result<Response<BlockId>, Status> {
        let epochs = self.epochs.lock().unwrap();
        let tip = epochs
            .front()
            .and_then(|e| e.blocks.last())
            .ok_or_else(|| Status::not_found("no chain"))?;
        Ok(Response::new(BlockId {
            height: tip.height,
            hash: tip.hash.clone(),
        }))
    }

    type GetBlockRangeStream = BoxStream<CompactBlock>;

    async fn get_block_range(
        &self,
        req: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let r = req.into_inner();
        let start = r.start.map_or(0, |b| b.height);
        let end = r.end.map_or(0, |b| b.height);
        self.requested_ranges
            .lock()
            .unwrap()
            .push((start as u32, end as u32));
        let epoch = {
            let mut epochs = self.epochs.lock().unwrap();
            if epochs.len() > 1 {
                epochs.pop_front().unwrap()
            } else {
                epochs
                    .front()
                    .cloned()
                    .ok_or_else(|| Status::not_found("no chain"))?
            }
        };
        let mut items: Vec<Result<CompactBlock, Status>> = epoch
            .blocks
            .into_iter()
            .filter(|b| b.height >= start && b.height <= end)
            .map(Ok)
            .collect();
        if let Some(k) = epoch.fail_after {
            items.truncate(k);
            items.push(Err(Status::unavailable("injected fault")));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(items))))
    }

    async fn get_transaction(
        &self,
        req: Request<TxFilter>,
    ) -> Result<Response<RawTransaction>, Status> {
        self.requested_txs
            .lock()
            .unwrap()
            .push(req.into_inner().hash);
        Ok(Response::new(RawTransaction {
            data: vec![0xde, 0xad, 0xbe, 0xef],
            height: 0,
        }))
    }

    async fn get_block(&self, _: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        Err(Status::unimplemented("get_block"))
    }

    async fn get_block_nullifiers(
        &self,
        _: Request<BlockId>,
    ) -> Result<Response<CompactBlock>, Status> {
        Err(Status::unimplemented("get_block_nullifiers"))
    }

    type GetBlockRangeNullifiersStream = BoxStream<CompactBlock>;

    async fn get_block_range_nullifiers(
        &self,
        _: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        Err(Status::unimplemented("get_block_range_nullifiers"))
    }

    async fn send_transaction(
        &self,
        _: Request<RawTransaction>,
    ) -> Result<Response<SendResponse>, Status> {
        Err(Status::unimplemented("send_transaction"))
    }

    type GetTaddressTxidsStream = BoxStream<RawTransaction>;

    async fn get_taddress_txids(
        &self,
        _: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        Err(Status::unimplemented("get_taddress_txids"))
    }

    type GetTaddressTransactionsStream = BoxStream<RawTransaction>;

    async fn get_taddress_transactions(
        &self,
        _: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        Err(Status::unimplemented("get_taddress_transactions"))
    }

    async fn get_taddress_balance(
        &self,
        _: Request<AddressList>,
    ) -> Result<Response<Balance>, Status> {
        Err(Status::unimplemented("get_taddress_balance"))
    }

    async fn get_taddress_balance_stream(
        &self,
        _: Request<tonic::Streaming<Address>>,
    ) -> Result<Response<Balance>, Status> {
        Err(Status::unimplemented("get_taddress_balance_stream"))
    }

    type GetMempoolTxStream = BoxStream<CompactTx>;

    async fn get_mempool_tx(
        &self,
        _: Request<GetMempoolTxRequest>,
    ) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        Err(Status::unimplemented("get_mempool_tx"))
    }

    type GetMempoolStreamStream = BoxStream<RawTransaction>;

    async fn get_mempool_stream(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        Err(Status::unimplemented("get_mempool_stream"))
    }

    async fn get_tree_state(&self, _: Request<BlockId>) -> Result<Response<TreeState>, Status> {
        Err(Status::unimplemented("get_tree_state"))
    }

    async fn get_latest_tree_state(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<TreeState>, Status> {
        Err(Status::unimplemented("get_latest_tree_state"))
    }

    type GetSubtreeRootsStream = BoxStream<SubtreeRoot>;

    async fn get_subtree_roots(
        &self,
        _: Request<GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        Err(Status::unimplemented("get_subtree_roots"))
    }

    async fn get_address_utxos(
        &self,
        _: Request<GetAddressUtxosArg>,
    ) -> Result<Response<GetAddressUtxosReplyList>, Status> {
        Err(Status::unimplemented("get_address_utxos"))
    }

    type GetAddressUtxosStreamStream = BoxStream<GetAddressUtxosReply>;

    async fn get_address_utxos_stream(
        &self,
        _: Request<GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        Err(Status::unimplemented("get_address_utxos_stream"))
    }

    async fn get_lightd_info(&self, _: Request<Empty>) -> Result<Response<LightdInfo>, Status> {
        Err(Status::unimplemented("get_lightd_info"))
    }

    async fn ping(&self, _: Request<Duration>) -> Result<Response<PingResponse>, Status> {
        Err(Status::unimplemented("ping"))
    }
}

async fn serve(fake: FakeLwd) -> (LwdClient, Arc<FakeLwd>) {
    let fake = Arc::new(fake);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(CompactTxStreamerServer::from_arc(fake.clone()))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let channel = Channel::builder(format!("http://{addr}").parse().unwrap())
        .connect()
        .await
        .unwrap();
    (LwdClient::new(channel), fake)
}

#[derive(Debug, Clone, PartialEq)]
struct RecordedNote {
    txid: [u8; 32],
    value: u64,
    nf: Option<[u8; 32]>,
    has_memo: bool,
    is_sent: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Event {
    Apply {
        height: u32,
        hash: Option<[u8; 32]>,
        notes: Vec<RecordedNote>,
        spends: Vec<([u8; 32], [u8; 32])>,
    },
    Commitments {
        height: u32,
        leaves: Vec<(u64, [u8; 32])>,
    },
    Rewind(u32),
}

#[derive(Default)]
struct AccountState {
    checkpoint: Option<(u32, Option<[u8; 32]>)>,
    notes: Vec<(u32, RecordedNote)>,
    events: Vec<Event>,
}

#[derive(Default)]
struct RecordingAccount {
    state: Mutex<AccountState>,
    want_commitments: bool,
    fail_apply: bool,
}

type ApplyRecord = (
    u32,
    Option<[u8; 32]>,
    Vec<RecordedNote>,
    Vec<([u8; 32], [u8; 32])>,
);

impl RecordingAccount {
    fn events(&self) -> Vec<Event> {
        self.state.lock().unwrap().events.clone()
    }

    fn applies(&self) -> Vec<ApplyRecord> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Apply {
                    height,
                    hash,
                    notes,
                    spends,
                } => Some((height, hash, notes, spends)),
                _ => None,
            })
            .collect()
    }

    fn held_notes(&self) -> Vec<(u32, RecordedNote)> {
        self.state.lock().unwrap().notes.clone()
    }

    fn final_checkpoint(&self) -> Option<(u32, Option<[u8; 32]>)> {
        self.state.lock().unwrap().checkpoint
    }
}

impl Account for RecordingAccount {
    fn checkpoint(&self) -> Option<Cursor> {
        self.state
            .lock()
            .unwrap()
            .checkpoint
            .map(|(h, hash)| Cursor {
                height: BlockHeight::from_u32(h),
                hash: hash.map(BlockHash),
            })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError> {
        let to = u32::from(to);
        let mut s = self.state.lock().unwrap();
        s.events.push(Event::Rewind(to));
        s.notes.retain(|(h, _)| *h <= to);
        if let Some((h, _)) = s.checkpoint {
            s.checkpoint = Some((to.min(h), None));
        }
        Ok(())
    }

    fn owns_nf(&self, _pool: Pool, nf: &[u8; 32]) -> Result<bool, AccountError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .notes
            .iter()
            .any(|(_, n)| n.nf.as_ref() == Some(nf)))
    }

    fn apply(&self, at: Cursor, notes: &[Note], spends: &[Spend]) -> Result<(), AccountError> {
        if self.fail_apply {
            return Err("account exploded".into());
        }
        let mut s = self.state.lock().unwrap();
        let height = u32::from(at.height);
        let recorded: Vec<RecordedNote> = notes
            .iter()
            .map(|n| RecordedNote {
                txid: n.txid.into(),
                value: match &n.note {
                    ShieldedNote::Orchard(o) => o.value().inner(),
                    ShieldedNote::Sapling(sap) => sap.value().inner(),
                },
                nf: n.nullifier,
                has_memo: n.memo.is_some(),
                is_sent: n.is_sent,
            })
            .collect();
        for (n, rec) in notes.iter().zip(&recorded) {
            s.notes.push((u32::from(n.height), rec.clone()));
        }
        s.events.push(Event::Apply {
            height,
            hash: at.hash.map(|h| h.0),
            notes: recorded,
            spends: spends.iter().map(|sp| (sp.nf, sp.txid.into())).collect(),
        });
        s.checkpoint = Some((height, at.hash.map(|h| h.0)));
        Ok(())
    }

    fn wants_commitments(&self) -> bool {
        self.want_commitments
    }

    fn apply_commitments(
        &self,
        at: Cursor,
        commitments: &[Commitment],
    ) -> Result<(), AccountError> {
        let mut s = self.state.lock().unwrap();
        s.events.push(Event::Commitments {
            height: u32::from(at.height),
            leaves: commitments.iter().map(|c| (c.position, c.cmx)).collect(),
        });
        Ok(())
    }
}

async fn sync_with(
    fake: FakeLwd,
    account: &RecordingAccount,
    keys: &ViewKey,
    birthday: u32,
) -> (Result<(), SyncError>, Arc<FakeLwd>) {
    let (client, fake) = serve(fake).await;
    let res = run(client, keys, &Network::MainNetwork, birthday, account).await;
    (res, fake)
}

#[tokio::test(flavor = "multi_thread")]
async fn claims_only_notes_encrypted_to_our_key() {
    let us = wallet(0x01);
    let them = wallet(0x02);
    let ours = forge_note(us.addr, 5_000_000, [1u8; 32]);
    let theirs = forge_note(them.addr, 9_000_000, [2u8; 32]);

    let blocks = chain(100..=103, FORK_A, |h| match h {
        101 => vec![tx(0x51, vec![action_for(&theirs)])],
        102 => vec![tx(0x52, vec![action_for(&ours)])],
        _ => vec![],
    });
    let account = RecordingAccount::default();
    let (res, fake) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;
    res.unwrap();

    let applies = account.applies();
    assert_eq!(applies.len(), 1);
    let (height, hash, notes, spends) = &applies[0];
    assert_eq!(*height, 103);
    assert_eq!(*hash, Some(block_hash(103, FORK_A)));
    assert_eq!(
        notes.len(),
        1,
        "stranger's note must not decrypt for us: {notes:?}"
    );
    assert_eq!(notes[0].txid, txid(0x52));
    assert_eq!(notes[0].value, 5_000_000);
    assert_eq!(notes[0].nf, Some(ours.nullifier(&us.fvk).to_bytes()));
    assert!(
        !notes[0].has_memo,
        "garbage raw tx must be skipped, not parsed into a memo"
    );
    assert!(!notes[0].is_sent);
    assert!(spends.is_empty());
    assert_eq!(
        fake.txs(),
        vec![txid(0x52).to_vec()],
        "only our txid warrants a raw-tx fetch"
    );
    assert_eq!(
        account.final_checkpoint(),
        Some((103, Some(block_hash(103, FORK_A))))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_in_same_batch_is_detected_without_account_state() {
    let us = wallet(0x01);
    let them = wallet(0x02);
    let ours = forge_note(us.addr, 5_000_000, [1u8; 32]);
    let nf = ours.nullifier(&us.fvk).to_bytes();
    let change = forge_note(them.addr, 1_000_000, nf);

    let blocks = chain(100..=104, FORK_A, |h| match h {
        101 => vec![tx(0x51, vec![action_for(&ours)])],
        103 => vec![tx(0x53, vec![action_for(&change)])],
        _ => vec![],
    });
    let account = RecordingAccount::default();
    let (res, fake) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;
    res.unwrap();

    let applies = account.applies();
    assert_eq!(applies.len(), 1);
    let (_, _, notes, spends) = &applies[0];
    assert_eq!(notes.len(), 1);
    assert_eq!(*spends, vec![(nf, txid(0x53))]);
    assert_eq!(fake.txs(), vec![txid(0x51).to_vec(), txid(0x53).to_vec()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_nullifier_is_not_reported_as_our_spend() {
    let us = wallet(0x01);
    let them = wallet(0x02);
    let theirs = forge_note(them.addr, 9_000_000, [2u8; 32]);

    let blocks = chain(100..=102, FORK_A, |h| match h {
        101 => vec![tx(0x51, vec![action_for(&theirs)])],
        _ => vec![],
    });
    let account = RecordingAccount::default();
    let (res, fake) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;
    res.unwrap();

    let applies = account.applies();
    assert_eq!(applies.len(), 1);
    let (_, _, notes, spends) = &applies[0];
    assert!(notes.is_empty());
    assert!(spends.is_empty());
    assert!(fake.txs().is_empty(), "no relevant tx, no raw-tx fetch");
}

#[tokio::test(flavor = "multi_thread")]
async fn mid_stream_reorg_rewinds_and_syncs_replacement_chain() {
    let us = wallet(0x01);
    let orphaned = forge_note(us.addr, 7_000_000, [1u8; 32]);
    let replacement = forge_note(us.addr, 4_000_000, [2u8; 32]);

    let mut bad = chain(100..=105, FORK_A, |h| match h {
        102 => vec![tx(0x61, vec![action_for(&orphaned)])],
        _ => vec![],
    });
    bad[5].prev_hash = block_hash(104, FORK_B).to_vec();
    let good = chain(100..=105, FORK_B, |h| match h {
        102 => vec![tx(0x62, vec![action_for(&replacement)])],
        _ => vec![],
    });

    let account = RecordingAccount::default();
    let (res, _) = sync_with(
        FakeLwd::epochs(vec![
            Epoch {
                blocks: bad,
                fail_after: None,
            },
            Epoch {
                blocks: good,
                fail_after: None,
            },
        ]),
        &account,
        &us.keys,
        BIRTHDAY,
    )
    .await;
    res.unwrap();

    let events = account.events();
    assert_eq!(events[0], Event::Rewind(104));
    let held = account.held_notes();
    assert_eq!(
        held.len(),
        1,
        "only the replacement-chain note may survive: {held:?}"
    );
    assert_eq!(held[0].1.txid, txid(0x62));
    assert_eq!(held[0].1.value, 4_000_000);
    assert_eq!(
        account.final_checkpoint(),
        Some((105, Some(block_hash(105, FORK_B))))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn chunked_stream_applies_every_block_exactly_once() {
    let us = wallet(0x01);
    let them = wallet(0x02);
    let ours = forge_note(us.addr, 5_000_000, [1u8; 32]);
    let nf = ours.nullifier(&us.fvk).to_bytes();
    let change = forge_note(them.addr, 1_000_000, nf);

    let note_action = action_for(&ours);
    let spend_action = action_for(&change);
    let blocks = chain(100..=1599, FORK_A, |h| match h {
        150 => vec![tx(0x71, vec![note_action.clone()])],
        1300 => vec![tx(0x72, vec![spend_action.clone()])],
        _ => vec![],
    });

    let account = RecordingAccount::default();
    let (res, _) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;
    res.unwrap();

    let applies = account.applies();
    let heights: Vec<u32> = applies.iter().map(|(h, ..)| *h).collect();
    assert_eq!(heights, vec![1099, 1599]);
    let our_note_applications: usize = applies
        .iter()
        .map(|(_, _, notes, _)| notes.iter().filter(|n| n.txid == txid(0x71)).count())
        .sum();
    assert_eq!(our_note_applications, 1);
    assert!(applies[0].3.is_empty());
    assert_eq!(
        applies[1].3,
        vec![(nf, txid(0x72))],
        "cross-chunk spend must resolve via owns_nf"
    );
    assert_eq!(
        account.final_checkpoint(),
        Some((1599, Some(block_hash(1599, FORK_A))))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_failure_resumes_from_checkpoint_without_replay() {
    let us = wallet(0x01);
    let them = wallet(0x02);
    let ours = forge_note(us.addr, 5_000_000, [1u8; 32]);
    let nf = ours.nullifier(&us.fvk).to_bytes();
    let change = forge_note(them.addr, 1_000_000, nf);

    let note_action = action_for(&ours);
    let spend_action = action_for(&change);
    let blocks = chain(100..=1599, FORK_A, |h| match h {
        150 => vec![tx(0x71, vec![note_action.clone()])],
        1300 => vec![tx(0x72, vec![spend_action.clone()])],
        _ => vec![],
    });

    let account = RecordingAccount::default();
    let (res, fake) = sync_with(
        FakeLwd::epochs(vec![
            Epoch {
                blocks: blocks.clone(),
                fail_after: Some(1005),
            },
            Epoch {
                blocks,
                fail_after: None,
            },
        ]),
        &account,
        &us.keys,
        BIRTHDAY,
    )
    .await;
    res.unwrap();

    assert_eq!(
        fake.ranges(),
        vec![(100, 1599), (1100, 1599)],
        "resume must start at checkpoint + 1"
    );
    let applies = account.applies();
    let heights: Vec<u32> = applies.iter().map(|(h, ..)| *h).collect();
    assert_eq!(heights, vec![1099, 1599]);
    let our_note_applications: usize = applies
        .iter()
        .map(|(_, _, notes, _)| notes.iter().filter(|n| n.txid == txid(0x71)).count())
        .sum();
    assert_eq!(
        our_note_applications, 1,
        "retry must not double-apply the note"
    );
    assert_eq!(applies[1].3, vec![(nf, txid(0x72))]);
    assert_eq!(
        account.final_checkpoint(),
        Some((1599, Some(block_hash(1599, FORK_A))))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn persistent_stream_failure_errors_after_retries_exhaust() {
    let blocks = chain(100..=105, FORK_A, |_| vec![]);
    let epochs = (0..5)
        .map(|_| Epoch {
            blocks: blocks.clone(),
            fail_after: Some(0),
        })
        .collect::<Vec<_>>();

    let us = wallet(0x01);
    let account = RecordingAccount::default();
    let (res, fake) = sync_with(FakeLwd::epochs(epochs), &account, &us.keys, BIRTHDAY).await;

    assert!(matches!(res, Err(SyncError::Chain(_))), "got: {res:?}");
    assert_eq!(fake.ranges().len(), 5, "four retries, then give up");
    assert!(account.applies().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn account_failure_aborts_without_retry() {
    let us = wallet(0x01);
    let ours = forge_note(us.addr, 5_000_000, [1u8; 32]);
    let blocks = chain(100..=102, FORK_A, |h| match h {
        101 => vec![tx(0x51, vec![action_for(&ours)])],
        _ => vec![],
    });

    let account = RecordingAccount {
        fail_apply: true,
        ..Default::default()
    };
    let (res, fake) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;

    assert!(matches!(res, Err(SyncError::Account(_))), "got: {res:?}");
    assert_eq!(
        fake.ranges().len(),
        1,
        "an account error must not be retried as a transport fault"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn commitment_firehose_follows_apply_with_aligned_positions() {
    let us = wallet(0x01);
    let them = wallet(0x02);
    let theirs = forge_note(them.addr, 9_000_000, [2u8; 32]);
    let ours = forge_note(us.addr, 5_000_000, [1u8; 32]);

    let blocks = chain(100..=102, FORK_A, |h| match h {
        100 => vec![tx(0x51, vec![action_for(&theirs)])],
        101 => vec![tx(0x52, vec![action_for(&ours)])],
        _ => vec![],
    });
    let account = RecordingAccount {
        want_commitments: true,
        ..Default::default()
    };
    let (res, _) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;
    res.unwrap();

    let events = account.events();
    assert_eq!(events.len(), 2);
    let Event::Apply {
        height: apply_h, ..
    } = &events[0]
    else {
        panic!("expected Apply first, got {events:?}");
    };
    let Event::Commitments {
        height: commit_h,
        leaves,
    } = &events[1]
    else {
        panic!("expected Commitments second, got {events:?}");
    };
    assert_eq!(
        apply_h, commit_h,
        "both callbacks must carry the same cursor"
    );
    assert_eq!(*leaves, vec![(0, cmx_of(&theirs)), (1, cmx_of(&ours))]);
}

#[tokio::test(flavor = "multi_thread")]
async fn birthday_beyond_tip_is_a_clean_noop() {
    let blocks = chain(100..=105, FORK_A, |_| vec![]);
    let us = wallet(0x01);
    let account = RecordingAccount::default();
    let (res, fake) = sync_with(FakeLwd::single(blocks), &account, &us.keys, 200).await;

    res.unwrap();
    assert!(fake.ranges().is_empty());
    assert!(account.events().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_block_hash_is_not_checkpointed_as_zeros() {
    let mut blocks = chain(100..=102, FORK_A, |_| vec![]);
    blocks[2].hash.truncate(31);

    let us = wallet(0x01);
    let account = RecordingAccount::default();
    let (res, _) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;

    let checkpointed_zeros =
        res.is_ok() && account.final_checkpoint().and_then(|(_, hash)| hash) == Some([0u8; 32]);
    assert!(
        !checkpointed_zeros,
        "a malformed block hash from the server must not be laundered into [0u8; 32]"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "KNOWN GAP: rewind discards the seam hash (Cursor.hash = None), so a fork below the \
            checkpoint is accepted blindly on the next pass — orphaned notes survive and \
            replacement-chain blocks at or below the checkpoint are never rescanned"]
async fn fork_below_checkpoint_evicts_orphaned_notes() {
    let us = wallet(0x01);
    let orphaned = forge_note(us.addr, 7_000_000, [1u8; 32]);
    let orphan_nf = orphaned.nullifier(&us.fvk).to_bytes();
    let replacement = forge_note(us.addr, 4_000_000, [2u8; 32]);

    let account = RecordingAccount::default();
    {
        let mut s = account.state.lock().unwrap();
        s.checkpoint = Some((110, Some(block_hash(110, FORK_A))));
        s.notes.push((
            105,
            RecordedNote {
                txid: txid(0x81),
                value: 7_000_000,
                nf: Some(orphan_nf),
                has_memo: false,
                is_sent: false,
            },
        ));
    }

    let blocks = chain(100..=115, FORK_B, |h| match h {
        105 => vec![tx(0x82, vec![action_for(&replacement)])],
        _ => vec![],
    });
    let (res, _) = sync_with(FakeLwd::single(blocks), &account, &us.keys, BIRTHDAY).await;
    res.unwrap();

    let held = account.held_notes();
    assert!(
        !held.iter().any(|(_, n)| n.nf == Some(orphan_nf)),
        "note from the orphaned chain must not survive a fork below the checkpoint: {held:?}"
    );
    assert!(
        held.iter().any(|(_, n)| n.txid == txid(0x82)),
        "replacement-chain note at height 105 must be picked up: {held:?}"
    );
}
