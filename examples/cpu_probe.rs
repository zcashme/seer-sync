//! Throwaway CPU probe: fetch a window once, then hammer `scan_compact` in a
//! tight loop for a fixed wall-clock window so an external sampler can read the
//! true average parallelism. Run:
//!
//!     cargo run --release --example cpu_probe
//!
//! Prints iterations/sec; sample its CPU% externally while it runs.

use std::time::{Duration, Instant};

use seer_sync::keys::ScanningKeys;
use seer_sync::sync::chain::{connect_auto, fetch_range, tip_height};
use seer_sync::sync::scan::scan_compact;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";
const WINDOW: u32 = 5_000;
const RUN_SECS: u64 = 12;

#[tokio::main]
async fn main() {
    let blocks = {
        let mut client = connect_auto().await.expect("connect");
        let tip = tip_height(&mut client).await.expect("tip");
        let from = tip.saturating_sub(WINDOW);
        eprintln!("[probe] fetching [{from}..{tip}]");
        fetch_range(client, from, tip).await.expect("fetch")
    };

    let uivk_str: String = UIVK.chars().filter(|c| !c.is_whitespace()).collect();
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, &uivk_str).expect("uivk");
    let keys = ScanningKeys::from_uivk(&uivk);

    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    eprintln!("[probe] {} blocks, {cores} cores, hammering for {RUN_SECS}s...", blocks.len());

    let start = Instant::now();
    let mut iters = 0u64;
    while start.elapsed() < Duration::from_secs(RUN_SECS) {
        std::hint::black_box(scan_compact(std::hint::black_box(&blocks), &keys));
        iters += 1;
    }
    let secs = start.elapsed().as_secs_f64();
    eprintln!("[probe] {iters} iters in {secs:.2}s = {:.1} scans/s", iters as f64 / secs);
}
