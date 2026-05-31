//! Bench trial-decrypt against live blocks fetched from zec.rocks.
//!
//! Blocks are fetched once during setup and reused across iterations so
//! network latency is not measured — only the decrypt loop is timed.
//!
//!     cargo bench --bench decrypt

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use seer_sync::chain::{connect, fetch_range, tip_height, ZEC_ROCKS};
use seer_sync::keys::IvkKeys;
use seer_sync::scan::scan_ivk;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";
/// NU6 mainnet activation height.
const NU6: u32 = 2_726_400;

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let blocks = rt.block_on(async {
        let mut client = connect(ZEC_ROCKS).await.expect("connecting to zec.rocks");
        let tip = tip_height(&mut client).await.expect("tip height");
        eprintln!("[bench] fetching NU6→tip [{NU6}..{tip}] from {ZEC_ROCKS}");
        fetch_range(client, NU6, tip).await.expect("fetch_range")
    });

    let uivk_str: String = UIVK.chars().filter(|c| !c.is_whitespace()).collect();
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, &uivk_str)
        .expect("decoding hardcoded UIVK");
    let keys = IvkKeys::from_uivk(&uivk);

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

    let mut g = c.benchmark_group("scan");
    g.sample_size(3);
    g.throughput(Throughput::Elements(total_actions + total_outputs));
    g.bench_function("uivk", |b| {
        b.iter(|| {
            for note in scan_ivk(&blocks, &keys) {
                black_box(note);
            }
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
