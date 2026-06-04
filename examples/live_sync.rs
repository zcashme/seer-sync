use std::cell::Cell;

use anyhow::{anyhow, Result};
use seer_sync::sync::{self, chain};
use seer_sync::{BlockHeight, Network, UnifiedFullViewingKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::MainNetwork;

    let ufvk = UnifiedFullViewingKey::decode(&network, UFVK).map_err(|e| anyhow!(e))?;

    let client = chain::connect("https://na.zec.rocks:443").await?;
    println!("connected; scanning {BIRTHDAY} → tip…");

    let cursor = Cell::new(BIRTHDAY);
    let total = Cell::new(0usize);

    sync::run(
        client,
        &ufvk,
        &network,

        || (BlockHeight::from_u32(cursor.get()), None),

        |to| {
            cursor.set(u32::from(to));
            Ok(())
        },

        |height, _hash, notes| {
            let n = notes.len();
            if n > 0 {
                total.set(total.get() + n);
                println!(
                    "  height {:>8}: {:>3} notes   (total {})",
                    u32::from(height),
                    n,
                    total.get(),
                );
            }

            cursor.set(u32::from(height) + 1);
            Ok(())
        },
    )
    .await?;

    println!("done — reached tip, {} note events seen", total.get());
    Ok(())
}
