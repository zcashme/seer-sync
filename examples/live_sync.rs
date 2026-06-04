//! Live mainnet sync from a unified full viewing key.
//!
//! Run with: `cargo run --example live_sync`
//!
//! Give it a view key and a birthday height; it connects to a public
//! lightwalletd server, scans from the birthday to the chain tip, and prints
//! note activity as each chunk lands. There is no database here — the scan
//! cursor lives in memory for the duration of the run, which is enough to show
//! the engine's shape. For persistence, point the same `run()` callbacks at a
//! `seer_sync::db::Db` (see the `db` feature) instead of these `Cell`s.

use std::cell::Cell;

use anyhow::{anyhow, Result};
use seer_sync::sync::{self, chain};
use seer_sync::{BlockHeight, Network, UnifiedFullViewingKey};

/// A unified full viewing key (`uview1…`). Swap in your own.
const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

/// Where to start scanning. Lower = more history to cover before reaching tip.
const BIRTHDAY: u32 = 3_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::MainNetwork;

    // 1. Parse the view key. The scanner derives the per-scope IVKs and
    //    nullifier keys it trial-decrypts with from this directly. (`decode`
    //    reports failures as a plain String.)
    let ufvk = UnifiedFullViewingKey::decode(&network, UFVK).map_err(|e| anyhow!(e))?;

    // 2. Pick a working lightwalletd server. This is the one bit the caller
    //    still does by hand — server selection is slated to move inside the
    //    engine, so eventually step 2 disappears and you pass only key+birthday.
    // connect_auto() tends to land on zec.rocks, whose block streaming is ~9×
    // slower than na.zec.rocks; pin the fast one explicitly.
    let client = chain::connect("https://na.zec.rocks:443").await?;
    println!("connected; scanning {BIRTHDAY} → tip…");

    // 3. The scanned watermark. With a DB this would be read/written from
    //    `sync_state`; here it just lives for the run so resume + rewind have
    //    somewhere to point.
    let cursor = Cell::new(BIRTHDAY);
    let total = Cell::new(0usize);

    sync::run(
        client,
        &ufvk,
        &network,
        // resume_point: where to (re)start, plus the previous block's hash as a
        // reorg seam. No persisted hash here, so hand back None and skip the
        // seam check on the first block of each pass.
        || (BlockHeight::from_u32(cursor.get()), None),
        // rewind: a reorg was detected; drop the cursor back to `to` and the
        // next pass re-streams from there.
        |to| {
            cursor.set(u32::from(to));
            Ok(())
        },
        // sink: one scanned chunk. `txs` carries this chunk's note receives and
        // spends across both shielded pools.
        |height, _hash, txs| {
            let n = txs.orchard.len() + txs.sapling.len();
            if n > 0 {
                total.set(total.get() + n);
                println!(
                    "  height {:>8}: {:>3} orchard, {:>3} sapling   (total {})",
                    u32::from(height),
                    txs.orchard.len(),
                    txs.sapling.len(),
                    total.get(),
                );
            }
            // Advance past this chunk so the next resume starts after it.
            cursor.set(u32::from(height) + 1);
            Ok(())
        },
    )
    .await?;

    println!("done — reached tip, {} note events seen", total.get());
    Ok(())
}
