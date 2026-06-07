//! Persist a UFVK sync to SQLite via the high-level `scan()` entry point.
//!
//! `scan()` connects to lightwalletd, decodes the key, and drives the engine
//! into `db`. With a UFVK the sync is full:
//!
//!   * spends are detected, so `balance()` is net (it drops when you spend);
//!   * outputs you sent are recovered and their destination stored in the
//!     `recipient_address` column (a unified address) of each note table.
//!
//! There is no Rust getter for sent payments by design — the SQLite file is the
//! API. Query it directly, e.g.:
//!
//!   SELECT value, recipient_address FROM orchard_received_notes WHERE is_sent = 1;

use anyhow::Result;
use seer_sync::db::Db;
use seer_sync::Network;

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let db = Db::open("wallet.db")?;

    let height = seer_sync::scan(UFVK, &Network::MainNetwork, BIRTHDAY, &db, |h| {
        eprint!("\rsynced to {}", u32::from(h));
    })
    .await?;
    eprintln!();

    let bal = db.balance()?;
    println!("synced to {height}");
    println!(
        "orchard {} zat  sapling {} zat  total {} zat (net of spends)",
        bal.orchard.into_u64(),
        bal.sapling.into_u64(),
        bal.total().into_u64()
    );
    println!("{} memo(s)", db.memos()?.len());

    Ok(())
}
