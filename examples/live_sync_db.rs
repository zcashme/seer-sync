use anyhow::Result;
use seer_sync::db::{Account, Db};
use seer_sync::Network;

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let db = Db::open("wallet.db")?;
    db.set_account(&Account { network: "main".into(), birthday: BIRTHDAY })?;

    seer_sync::scan(UFVK, &Network::MainNetwork, BIRTHDAY, &db, |_| {}).await?;

    let bal = db.balance()?;
    println!("orchard {} zat  sapling {} zat  total {} zat",
        bal.orchard.into_u64(), bal.sapling.into_u64(), bal.total().into_u64());
    println!("{} memo(s)", db.memos()?.len());

    Ok(())
}
