use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode, Throughput};
use futures::TryStreamExt;
use seer_sync::chain::{blocks, connect_auto, tip_height};
use seer_sync::scan_compact;
use seer_sync::{Network, ViewKey};
use std::time::Duration;

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";
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
        eprintln!(
            "[bench] fetching [{from}..{tip}] ({} blocks)",
            tip - from + 1
        );
        blocks(client, from, tip, usize::MAX, None)
            .try_concat()
            .await
            .expect("fetch range")
    });

    let view_key = ViewKey::decode(&Network::MainNetwork, UFVK).expect("decoding hardcoded UFVK");

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
        blocks.len(),
        total_actions,
        total_outputs,
    );

    let full_range = std::env::var("BENCH_FROM").is_ok();
    let mut g = c.benchmark_group("scan");
    if full_range {
        g.sample_size(10);
        g.sampling_mode(SamplingMode::Flat);
        g.measurement_time(Duration::from_secs(180));
    }
    g.throughput(Throughput::Elements(total_actions + total_outputs));
    g.bench_function("ufvk", |b| {
        b.iter(|| {
            black_box(scan_compact(&blocks, &view_key));
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
