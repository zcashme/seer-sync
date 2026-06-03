//! Throwaway live run of the persistence-free sync engine — no store.
//!
//! Drives `seer_sync::sync::run` directly with three in-memory closures over a
//! funded mainnet UFVK, tallying received value, spends, and recovered memos as
//! findings stream in. Syncs `[BIRTHDAY..tip]`, defaulting BIRTHDAY to the funded
//! region (~2.99M), so it scans ~370k blocks — expect minutes.
//!
//!     cargo run --release --example run_sync
//!     BIRTHDAY=3000000 cargo run --release --example run_sync

use std::cell::RefCell;

use seer_sync::keys::from_ufvk_str;
use seer_sync::note::memo::{Memo, MemoBytes};
use seer_sync::sync::scan::{Transactions, Tx};
use seer_sync::sync::{self, chain};
use seer_sync::{BlockHeight, Network};

/// A funded mainnet UFVK (receives notes around height ~3,000,000).
const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

/// In-memory consumer state, shared across the three engine closures.
#[derive(Default)]
struct Tally {
    /// Last applied height (0 = nothing yet → start at birthday). Read back by
    /// `resume_point` so a transport reconnect resumes here, not from birthday.
    scanned: u32,
    /// Hash at `scanned` — the seam handed back on resume.
    seam: Option<[u8; 32]>,
    receives: u64,
    sapling_zat: u64,
    orchard_zat: u64,
    spends: u64,
    memos: Vec<Box<[u8; 512]>>,
}

#[tokio::main]
async fn main() {
    let birthday: u32 = std::env::var("BIRTHDAY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_990_000);

    let keys = ScanningKeys::from_ufvk_str(UFVK, &Network::MainNetwork).expect("decode UFVK");

    let mut client = chain::connect_auto().await.expect("connect");
    let tip = chain::tip_height(&mut client).await.expect("tip height");
    eprintln!("[run] syncing [{birthday}..{tip}] ({} blocks)", tip.saturating_sub(birthday) + 1);

    let state = RefCell::new(Tally::default());

    sync::run(
        client,
        &keys,
        &Network::MainNetwork,
        // resume_point: start at birthday on a cold start, else where we left off.
        || {
            let s = state.borrow();
            if s.scanned == 0 {
                (BlockHeight::from_u32(birthday), None)
            } else {
                (BlockHeight::from_u32(s.scanned + 1), s.seam)
            }
        },
        // rewind: this deep in confirmed history a reorg effectively never fires,
        // so just reset the resume point; the running tallies are left as-is.
        |to| {
            let mut s = state.borrow_mut();
            s.scanned = u32::from(to);
            s.seam = None;
            Ok(())
        },
        // sink: fold one chunk's findings into the tally, then advance.
        |height, hash, txs: &Transactions| {
            let mut s = state.borrow_mut();
            for tx in &txs.orchard {
                match tx {
                    Tx::Receive(r) => {
                        s.receives += 1;
                        s.orchard_zat += r.note.value().inner();
                        if let Some(m) = r.memo.as_ref() {
                            s.memos.push(m.clone());
                        }
                    }
                    Tx::Spend(_) => s.spends += 1,
                }
            }
            for tx in &txs.sapling {
                match tx {
                    Tx::Receive(r) => {
                        s.receives += 1;
                        s.sapling_zat += r.note.value().inner();
                        if let Some(m) = r.memo.as_ref() {
                            s.memos.push(m.clone());
                        }
                    }
                    Tx::Spend(_) => s.spends += 1,
                }
            }
            s.scanned = u32::from(height);
            s.seam = Some(hash);
            eprintln!(
                "[run] through {} — {} receives, {} spends, {} memos so far",
                u32::from(height),
                s.receives,
                s.spends,
                s.memos.len()
            );
            Ok(())
        },
    )
    .await
    .expect("sync::run");

    let s = state.into_inner();
    eprintln!("\n[run] DONE through height {}", s.scanned);
    eprintln!(
        "[run] received {} notes: orchard {} zat + sapling {} zat = {} zat (gross, pre-spend)",
        s.receives,
        s.orchard_zat,
        s.sapling_zat,
        s.orchard_zat + s.sapling_zat
    );
    eprintln!("[run] spends observed on chain: {}", s.spends);
    eprintln!("[run] memos recovered: {}", s.memos.len());
    for raw in &s.memos {
        if let Ok(bytes) = MemoBytes::from_bytes(&raw[..]) {
            if let Ok(Memo::Text(t)) = Memo::try_from(&bytes) {
                eprintln!("[run] text memo: {:?}", &*t);
            }
        }
    }
}
