//! Bench trial-decrypt against live blocks fetched from zec.rocks.
//!
//! Blocks are fetched once during setup and reused across iterations so
//! network latency is not measured — only the decrypt loop is timed.
//!
//!     cargo bench --bench decrypt

use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use std::time::Duration;
use seer_sync::sync::chain::{connect_auto, fetch_range, tip_height};
use seer_sync::keys::ScanningKeys;
use seer_sync::sync::scan::scan;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";
/// NU6 mainnet activation height — set `BENCH_FROM=2726400` to bench the full post-NU6 range.
#[allow(dead_code)]
const NU6: u32 = 2_726_400;
/// Default window when BENCH_FROM is not set.
const BENCH_WINDOW: u32 = 5_000;

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let blocks = rt.block_on(async {
        let mut client = connect_auto().await.expect("connecting to lightwalletd");
        let tip = tip_height(&mut client).await.expect("tip height");
        let from = std::env::var("BENCH_FROM")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| tip.saturating_sub(BENCH_WINDOW));
        eprintln!("[bench] fetching [{from}..{tip}] ({} blocks)", tip - from + 1);
        fetch_range(client, from, tip).await.expect("fetch_range")
    });

    let uivk_str: String = UIVK.chars().filter(|c| !c.is_whitespace()).collect();
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, &uivk_str)
        .expect("decoding hardcoded UIVK");
    let keys = ScanningKeys::from_uivk(&uivk);

    let total_actions: u64 = blocks
        .iter()
        .flat_map(|b| b.vtx.iter())
        .map(|tx| tx.actions.len() as u64)
        .sum();
    let total_outputs: u64 = blocks
        .iter()
        .flat_map(|b| b.vtx.iter())
        .map(|tx| tx.outputs.len() as u64)
        .sum();

    eprintln!(
        "[bench] {} blocks  {} orchard actions  {} sapling outputs",
        blocks.len(), total_actions, total_outputs,
    );

    let full_range = std::env::var("BENCH_FROM").is_ok();
    let mut g = c.benchmark_group("scan");
    if full_range {
        g.sample_size(10);
        g.sampling_mode(SamplingMode::Flat);
        g.measurement_time(Duration::from_secs(180));
    }
    g.throughput(Throughput::Elements(total_actions + total_outputs));
    g.bench_function("uivk", |b| {
        b.iter(|| {
            black_box(scan(&blocks, &keys));
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
