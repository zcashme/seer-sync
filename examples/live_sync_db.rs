use std::io::Write;

use anyhow::{anyhow, Result};
use seer_sync::db::sync::sync_to_tip;
use seer_sync::db::{Account, Db};
use seer_sync::sync::chain;
use seer_sync::{Network, UnifiedFullViewingKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {

    let db = Db::open("wallet.db")?;
    db.set_account(&Account { network: "main".into(), birthday: BIRTHDAY })?;

    // The viewing key is a scan input, not stored state: decode it and hand it
    // to the sync. The store never sees key material.
    let ufvk = UnifiedFullViewingKey::decode(&Network::MainNetwork, UFVK).map_err(|e| anyhow!(e))?;

    let mut client = chain::connect("https://na.zec.rocks:443").await?;
    let tip = chain::tip_height(&mut client).await?;

    println!("┌─ seer-sync · view-key wallet sync ────────────────");
    println!("│  network    mainnet");
    println!("│  birthday   {BIRTHDAY}");
    println!("│  tip        {tip}");
    println!("│  store      wallet.db (on disk)");
    println!("├───────────────────────────────────────────────────");

    let span = tip.saturating_sub(BIRTHDAY).max(1) as f64;
    let final_height = sync_to_tip(&db, client, &ufvk, |h| {
        let done = u32::from(h).saturating_sub(BIRTHDAY) as f64;
        let pct = (done / span * 100.0).min(100.0);
        print!("\r│  scanning … {pct:>5.1}%  (height {})        ", u32::from(h));
        std::io::stdout().flush().ok();
    })
    .await?;
    println!();

    let bal = db.balance()?;
    let memos = db.memos()?.len();

    println!("├───────────────────────────────────────────────────");
    println!("│  synced to height {final_height}");
    println!("│");
    println!("│  balance");
    println!("│    orchard      {:>16} zat", bal.orchard.into_u64());
    println!("│    sapling      {:>16} zat", bal.sapling.into_u64());
    println!("│    ───────────────────────────────");
    println!("│    total        {:>16} zat", bal.total().into_u64());
    println!("│  {memos} memo(s) recovered");
    println!("└───────────────────────────────────────────────────");

    Ok(())
}
