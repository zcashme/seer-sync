//! Throwaway live run of the full db consumer — the real unspent-balance path.
//!
//! Drives `sync_to_tip` into an in-memory `Db` over a funded mainnet UFVK, so the
//! engine's findings flow through the store's nullifier→spend join and
//! `db.balance()` reports true *unspent* balance per pool. Syncs `[BIRTHDAY..tip]`,
//! defaulting BIRTHDAY to the funded region (~2.99M) — expect minutes.
//!
//!     cargo run --release --features db --example run_sync_db
//!     BIRTHDAY=3000000 cargo run --release --features db --example run_sync_db

use seer_sync::db::sync::sync_to_tip;
use seer_sync::db::{Account, Db};
use seer_sync::keys::ScanningKeys;
use seer_sync::note::memo::{Memo, MemoBytes};
use seer_sync::sync::chain;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::MainNetwork;

/// A funded mainnet UFVK (receives notes around height ~3,000,000).
const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

#[tokio::main]
async fn main() {
    let birthday: u32 = std::env::var("BIRTHDAY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_990_000);

    let encoded: String = UFVK.chars().filter(|c| !c.is_whitespace()).collect();
    let ufvk = UnifiedFullViewingKey::decode(&MainNetwork, &encoded).expect("decode UFVK");
    let keys = ScanningKeys::from_ufvk(&ufvk);

    let mut client = chain::connect_auto().await.expect("connect");
    let tip = chain::tip_height(&mut client).await.expect("tip height");

    let db = Db::open_in_memory().expect("open db");
    db.set_account(&Account {
        encoded,
        key_type: "ufvk".into(),
        network: "main".into(),
        birthday,
    })
    .expect("set account");

    eprintln!("[db] syncing [{birthday}..{tip}] ({} blocks) into in-memory Db...", tip.saturating_sub(birthday) + 1);
    let synced = sync_to_tip(&db, client, &keys).await.expect("sync_to_tip");

    let bal = db.balance().expect("balance");
    let memos = db.memos().expect("memos");
    let cursor = db.get_sync_state().expect("sync state");

    eprintln!("\n[db] DONE — cursor at height {} (synced through {synced})", cursor.height);
    eprintln!(
        "[db] UNSPENT balance: orchard {} zat + sapling {} zat + transparent {} zat = {} zat",
        bal.orchard_zat,
        bal.sapling_zat,
        bal.transparent_zat,
        bal.total_zat()
    );
    eprintln!("[db] memos recovered: {}", memos.len());
    for raw in &memos {
        if let Ok(bytes) = MemoBytes::from_bytes(raw) {
            if let Ok(Memo::Text(t)) = Memo::try_from(&bytes) {
                eprintln!("[db] text memo: {:?}", &*t);
            }
        }
    }
}
