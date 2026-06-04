//! Live mainnet sync into a SQLite store.
//!
//! Run with:
//!     cargo run --release --features db --example live_sync_db
//!
//! Where `live_sync.rs` drives the bare `run()` engine and fakes the scan cursor
//! in memory, this persists into a `seer_sync::db::Db`. The whole sync collapses
//! to a single call — `db::sync::sync_to_tip` — because the *store* owns the
//! stateful parts: the cursor (its `sync_state` row), the reorg rewinds, and the
//! note writes. The caller declares a store and a key; there is no cursor and no
//! closures to wire.
//!
//! Trade-off: `sync_to_tip` runs the entire loop internally, so there is no
//! per-chunk hook to print a heartbeat from — the payoff lands *after*, when the
//! store is queryable. (For a live per-chunk heartbeat, drive `run()` yourself
//! as `live_sync.rs` does.)

use std::io::Write;

use anyhow::Result;
use seer_sync::db::sync::sync_to_tip;
use seer_sync::db::{Account, Db};
use seer_sync::sync::chain;

/// A unified full viewing key (`uview1…`). Swap in your own.
const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

/// Where to start scanning. Stored on the account as its birthday.
const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    // The store owns everything stateful, including the scan cursor. A file DB
    // keeps that cursor on disk, so a crash or Ctrl-C resumes from where it left
    // off instead of restarting at the birthday. (Use `Db::open_in_memory()` for
    // a throwaway run that intentionally keeps nothing.)
    let db = Db::open("wallet.db")?;
    db.set_account(&Account {
        encoded: UFVK.into(),
        key_type: "ufvk".into(),
        network: "main".into(),
        birthday: BIRTHDAY,
    })?;

    // connect_auto() health-checks liveness only and tends to land on
    // zec.rocks, whose block streaming is ~9× slower than na.zec.rocks. Pin the
    // fast one explicitly.
    let mut client = chain::connect("https://na.zec.rocks:443").await?;
    let tip = chain::tip_height(&mut client).await?;

    println!("┌─ seer-sync · view-key wallet sync ────────────────");
    println!("│  network    mainnet");
    println!("│  birthday   {BIRTHDAY}");
    println!("│  tip        {tip}");
    println!("│  store      wallet.db (on disk)");
    println!("├───────────────────────────────────────────────────");

    // The store holds the cursor, so this is the whole sync. It reads the
    // watermark, streams + scans to tip, persists notes/spends, and advances.
    // The progress closure ticks once per chunk with the height just applied.
    let span = tip.saturating_sub(BIRTHDAY).max(1) as f64;
    let final_height = sync_to_tip(&db, client, |h| {
        let done = u32::from(h).saturating_sub(BIRTHDAY) as f64;
        let pct = (done / span * 100.0).min(100.0);
        print!("\r│  scanning … {pct:>5.1}%  (height {})        ", u32::from(h));
        std::io::stdout().flush().ok();
    })
    .await?;
    println!(); // end the in-place progress line

    // Now the store is queryable — this is what persistence buys you.
    let bal = db.balance()?;
    let memos = db.memos()?.len();

    println!("├───────────────────────────────────────────────────");
    println!("│  synced to height {final_height}");
    println!("│");
    println!("│  balance");
    println!("│    orchard      {:>16} zat", bal.orchard.into_u64());
    println!("│    sapling      {:>16} zat", bal.sapling.into_u64());
    println!("│    transparent  {:>16} zat", bal.transparent.into_u64());
    println!("│    ───────────────────────────────");
    println!("│    total        {:>16} zat", bal.total().into_u64());
    println!("│  {memos} memo(s) recovered");
    println!("└───────────────────────────────────────────────────");

    Ok(())
}
