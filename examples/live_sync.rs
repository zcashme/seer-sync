use anyhow::{anyhow, Result};
use seer_sync::sync::chain;
use seer_sync::sync::scan::ShieldedNote;
use seer_sync::{BlockHeight, Network, ViewKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let key = ViewKey::decode(&Network::MainNetwork, UFVK).map_err(|e| anyhow!(e))?;
    let client = chain::connect_auto().await?;

    let mut balance: u64 = 0;

    seer_sync::sync::run(
        client,
        &key,
        &Network::MainNetwork,
        || (BlockHeight::from_u32(BIRTHDAY), None),
        |_| Ok(()),
        |_height, _hash, notes| {
            for note in notes {
                if !note.outgoing {
                    let value = match &note.note {
                        ShieldedNote::Sapling(n) => n.value().inner(),
                        ShieldedNote::Orchard(n) => n.value().inner(),
                    };
                    balance += value;
                }
            }
            Ok(())
        },
    )
    .await?;

    println!("{balance} zat");
    Ok(())
}
