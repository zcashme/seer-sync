//! Fetch recent blocks from zec.rocks and run the trial-decrypt loop.
//!
//! Usage:
//!   cargo run --release --example sync_live
//!   START_HEIGHT=2700000 cargo run --release --example sync_live

use std::env;
use std::time::Instant;

use anyhow::Result;
use seer_sync::chain::{connect, fetch_range, tip_height, ZEC_ROCKS};
use seer_sync::keys::Keys;
use seer_sync::scan::sync;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

/// The bench UIVK — has real hits on mainnet.
const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

#[tokio::main]
async fn main() -> Result<()> {
    let uivk_str: String = UIVK.chars().filter(|c| !c.is_whitespace()).collect();
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, &uivk_str)
        .expect("hardcoded UIVK");
    let keys = Keys::from_uivk(&uivk);

    println!("Connecting to {ZEC_ROCKS} ...");
    let mut client = connect(ZEC_ROCKS).await?;
    let tip = tip_height(&mut client).await?;

    let from = env::var("START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| tip.saturating_sub(1_000));

    println!("Tip: {tip}  scanning [{from}..{tip}] ({} blocks)", tip - from + 1);

    let t_fetch = Instant::now();
    let blocks = fetch_range(&mut client, from, tip).await?;
    println!("Fetched {} blocks in {:.2}s", blocks.len(), t_fetch.elapsed().as_secs_f64());

    let t_sync = Instant::now();
    let mut count = 0u64;
    for note in sync(&blocks, &keys) {
        println!("  height={} pool={:?} value={} zat  recipient={:?}", note.height, note.pool, note.value_zat, note.recipient);
        count += 1;
    }

    println!(
        "Sync done in {:.3}s — {} incoming notes in {} blocks",
        t_sync.elapsed().as_secs_f64(),
        count,
        blocks.len(),
    );
    Ok(())
}
