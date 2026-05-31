//! Fetch recent blocks from zec.rocks and run the trial-decrypt loop.
//!
//! Usage:
//!   cargo run --release --example sync_live
//!   START_HEIGHT=2700000 cargo run --release --example sync_live

use std::env;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use seer_sync::chain::{blocks, connect, tip_height, DEFAULT_CHUNK_OUTPUTS, ZEC_ROCKS};
use seer_sync::keys::IvkKeys;
use seer_sync::scan::scan_stream_ivk;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

/// The bench UIVK — has real hits on mainnet.
const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

#[tokio::main]
async fn main() -> Result<()> {
    let uivk_str: String = UIVK.chars().filter(|c| !c.is_whitespace()).collect();
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, &uivk_str)
        .expect("hardcoded UIVK");
    let keys = Arc::new(IvkKeys::from_uivk(&uivk));

    println!("Connecting to {ZEC_ROCKS} ...");
    let mut client = connect(ZEC_ROCKS).await?;
    let tip = tip_height(&mut client).await?;

    let from = env::var("START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| tip.saturating_sub(1_000));

    println!("Tip: {tip}  scanning [{from}..{tip}] ({} blocks)", tip - from + 1);

    let stream = blocks(client, from, tip, DEFAULT_CHUNK_OUTPUTS);

    let t = Instant::now();
    let notes = scan_stream_ivk(keys, stream).await?;

    for note in &notes {
        println!(
            "  height={} pool={:?} value={} zat",
            note.height, note.pool, note.value_zat
        );
    }
    println!(
        "Done in {:.3}s — {} incoming notes",
        t.elapsed().as_secs_f64(),
        notes.len(),
    );
    Ok(())
}
