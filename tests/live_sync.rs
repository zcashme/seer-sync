//! Live integration test: sync a window of mainnet blocks into a real database
//! and exercise the full engine path (fetch → scan → persist → cursor), using a
//! funded full viewing key so received notes — and their spends — are detected.
//!
//! Hits a public lightwalletd, so it's `#[ignore]`d by default. Run with:
//!
//!     cargo test --test live_sync -- --ignored --nocapture
//!
//! Override the range with `TEST_WINDOW` (blocks back from tip) or an absolute
//! `TEST_FROM` height.

#![cfg(feature = "db")]

use seer_sync::db::{Account, Db};
use seer_sync::keys::ScanningKeys;
use seer_sync::note::memo::{Memo, MemoBytes};
use seer_sync::sync::chain::{connect_auto, tip_height};
use seer_sync::sync::engine::sync_to_tip;
use seer_sync::sync::enrich::enrich_memos;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{MainNetwork, Network};

/// A funded mainnet UFVK (receives notes around height ~3,000,000).
const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

/// Decode the UFVK and build full scanning keys (with nullifier derivation).
fn funded_keys() -> (String, ScanningKeys) {
    let encoded: String = UFVK.chars().filter(|c| !c.is_whitespace()).collect();
    let ufvk = UnifiedFullViewingKey::decode(&MainNetwork, &encoded).expect("decode UFVK");
    let keys = ScanningKeys::from_ufvk(&ufvk);
    (encoded, keys)
}

/// Cheap bounded probe to locate where the key receives notes. Scans an absolute
/// `[TEST_FROM, TEST_FROM+TEST_WINDOW]` window (no persist) and reports hits.
///
///     TEST_FROM=2990000 TEST_WINDOW=20000 cargo test --test live_sync probe_range -- --ignored --nocapture
#[ignore = "hits live mainnet lightwalletd"]
#[tokio::test]
async fn probe_range() {
    use seer_sync::sync::chain::fetch_range;
    use seer_sync::sync::scan;

    let from: u32 = std::env::var("TEST_FROM").expect("set TEST_FROM").parse().unwrap();
    let window: u32 = std::env::var("TEST_WINDOW").ok().and_then(|s| s.parse().ok()).unwrap_or(2_000);
    let to = from + window;

    let (_, keys) = funded_keys();
    let client = connect_auto().await.expect("connect");
    eprintln!("[probe] fetching [{from}..{to}]");
    let blocks = fetch_range(client, from, to).await.expect("fetch_range");
    let mut scanned = scan(&blocks, &keys);
    let outputs: usize =
        blocks.iter().flat_map(|b| &b.vtx).map(|t| t.outputs.len() + t.actions.len()).sum();
    eprintln!(
        "[probe] {} blocks, {outputs} shielded outputs -> {} sapling + {} orchard notes, {} spends",
        blocks.len(), scanned.sapling.len(), scanned.orchard.len(), scanned.spends.len()
    );
    if let Some(n) = scanned.sapling.first() {
        eprintln!("[probe] first sapling hit at height {}", n.height);
    }
    if let Some(n) = scanned.orchard.first() {
        eprintln!("[probe] first orchard hit at height {}", n.height);
    }

    // Enrich the found notes with their memos (bounded window — no full sync).
    let total = scanned.sapling.len() + scanned.orchard.len();
    if total > 0 {
        let mut client = connect_auto().await.expect("connect");
        enrich_memos(&mut client, &keys, &Network::MainNetwork, &mut scanned).await;
        let with_memo = scanned.sapling.iter().filter(|n| n.memo.is_some()).count()
            + scanned.orchard.iter().filter(|n| n.memo.is_some()).count();
        eprintln!("[probe] enriched {with_memo}/{total} notes with a memo");
        let memos = scanned
            .sapling
            .iter()
            .filter_map(|n| n.memo.as_deref())
            .chain(scanned.orchard.iter().filter_map(|n| n.memo.as_deref()));
        for raw in memos {
            let Ok(bytes) = MemoBytes::from_bytes(raw) else { continue };
            if let Ok(Memo::Text(text)) = Memo::try_from(&bytes) {
                eprintln!("[probe] sample text memo: {:?}", &*text);
                break;
            }
        }
    }
}

#[ignore = "hits live mainnet lightwalletd"]
#[tokio::test]
async fn sync_window_into_db() {
    let window: u32 = std::env::var("TEST_WINDOW").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000);

    let mut client = connect_auto().await.expect("connect to lightwalletd");
    let tip = tip_height(&mut client).await.expect("tip height");
    let from = std::env::var("TEST_FROM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| tip.saturating_sub(window));

    let (encoded, keys) = funded_keys();
    let mut db = Db::open_in_memory().expect("open db");
    db.set_account(&Account {
        encoded,
        key_type: "ufvk".into(),
        network: "main".into(),
        birthday: from,
    })
    .expect("set account");

    eprintln!("[live] syncing [{from}..{tip}] ({} blocks)", tip - from + 1);
    let synced = sync_to_tip(&mut db, client.clone(), &keys).await.expect("sync_to_tip");

    // Structural invariants that always hold. (The live tip may advance past
    // `tip` while we sync, so assert we reached at least it.)
    assert!(synced >= tip, "synced past the observed tip");
    let cursor = db.get_sync_state().unwrap();
    assert_eq!(cursor.height, synced, "cursor parked at the synced height");
    assert!(db.get_block_hash(synced).unwrap().is_some(), "synced tip block persisted");

    let bal = db.balance().unwrap();
    eprintln!(
        "[live] balance: orchard={} sapling={} transparent={} (total {} zat)",
        bal.orchard_zat, bal.sapling_zat, bal.transparent_zat, bal.total_zat()
    );

    // Memo enrichment: every owned note should have its full transaction fetched
    // and its memo recovered (even an "empty" memo stores its 512-byte encoding).
    let memos = db.memos().unwrap();
    eprintln!("[live] {} notes carry a recovered memo", memos.len());
    for raw in &memos {
        let Ok(bytes) = MemoBytes::from_bytes(raw) else { continue };
        let Ok(memo) = Memo::try_from(&bytes) else { continue };
        if let Memo::Text(text) = memo {
            eprintln!("[live] sample text memo: {:?}", &*text);
            break;
        }
    }

    // Dedup / idempotency on *real* blocks: rewind into already-synced territory
    // and re-sync. Overlapping blocks are re-fetched and re-applied, so a working
    // ON CONFLICT keeps the balance unchanged.
    let rewind_to = synced.saturating_sub(100);
    db.rewind_to_height(rewind_to).expect("rewind");
    assert_eq!(db.get_sync_state().unwrap().height, rewind_to, "cursor rewound");

    let again = sync_to_tip(&mut db, client, &keys).await.expect("resync");
    assert!(again >= synced, "tip only moves forward");
    assert_eq!(db.balance().unwrap(), bal, "re-applying overlapping blocks is idempotent");
}
