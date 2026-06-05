// No-db example: use sync::run directly with in-memory state.
//
// seer_sync::scan() (the db convenience API) handles connection and key
// decoding internally. sync::run is the raw engine beneath it — you wire
// those yourself and supply three callbacks:
//
//   resume_point  where to start (or resume after a reorg)
//   rewind        called when a reorg is detected; drop state above that height
//   sink          called per batch with the notes found in that batch
//
// This example accumulates gross received balance. It ignores spends — for
// a true balance you would also need to check compact block nullifiers against
// your own and subtract spent notes.

use anyhow::{anyhow, Result};
use seer_sync::sync::chain;
use seer_sync::sync::scan::ShieldedNote;
use seer_sync::{BlockHeight, Network, ViewKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    // sync::run takes a client; seer_sync::scan() calls connect_auto internally.
    // Here we're below that layer so we do it ourselves.
    let key = ViewKey::decode(&Network::MainNetwork, UFVK).map_err(|e| anyhow!(e))?;
    let client = chain::connect_auto().await?;

    let mut balance: u64 = 0;

    seer_sync::sync::run(
        client,
        &key,
        &Network::MainNetwork,
        || (BlockHeight::from_u32(BIRTHDAY), None), // no persisted resume point
        |_| Ok(()),                                  // no state to rewind
        |_height, _hash, notes| {
            for note in notes {
                // A note we own (and can spend) is one we can derive a nullifier
                // for; OVK-recovered outputs we sent have none.
                if note.nullifier.is_some() {
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
