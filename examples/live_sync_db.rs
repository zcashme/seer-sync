//! The batteries-included path: sync a UFVK into a SQLite `Db` with `scan()`.
//!
//! Decode the key, open a `Db`, call `scan()` — it connects, scans from the
//! birthday (or resumes from the db cursor on a later run), and persists notes
//! and spends. A UFVK is spend-aware, so the printed balance is net of spends.

use seer_sync::db::Db;
use seer_sync::{Network, ViewKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Db::open("seer.sqlite")?;
    let key = ViewKey::decode(&Network::MainNetwork, UFVK)?;

    seer_sync::scan(&key, &Network::MainNetwork, BIRTHDAY, &db).await?;
    println!("synced to height {}", db.get_sync_state()?.height);

    let balance = db.balance()?;
    println!("orchard: {} zat", balance.orchard.into_u64());
    println!("sapling: {} zat", balance.sapling.into_u64());
    println!("total:   {} zat", balance.total().into_u64());
    Ok(())
}
