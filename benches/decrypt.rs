//! Bench `seer_sync::scan::sync` against the local fixtures using a
//! real UIVK (the one the developer scans with day-to-day).
//!
//! Populate fixtures once:
//!     cargo run --release --example download_fixtures
//!
//! Then iterate on `src/scan.rs` and run:
//!     cargo bench

use std::fs::File;
use std::io::Read;
use std::path::Path;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use prost::Message;
use seer_sync::proto::CompactBlock;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

use seer_sync::keys::Keys;
use seer_sync::scan;

const FIXTURES: &str = "bench-data/compact-blocks.bin";

/// Real-world UIVK — produces hits on mainnet, so the bench measures
/// the same hit-bearing workload the developer actually runs against.
const UIVK: &str = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

fn load_blocks(path: impl AsRef<Path>) -> Vec<CompactBlock> {
    let path = path.as_ref();
    let mut f = File::open(path).unwrap_or_else(|_| {
        panic!(
            "missing {} — run `cargo run --release --example download_fixtures` first",
            path.display(),
        )
    });
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).expect("reading fixtures");

    let mut blocks = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let len = u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        let block = CompactBlock::decode(&buf[i..i + len]).expect("decoding CompactBlock");
        i += len;
        blocks.push(block);
    }
    blocks
}

fn bench(c: &mut Criterion) {
    let blocks = load_blocks(FIXTURES);

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

    let uivk_str: String = UIVK.chars().filter(|c| !c.is_whitespace()).collect();
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, &uivk_str)
        .expect("decoding hardcoded UIVK");
    let keys = Keys::from_uivk(&uivk);

    let mut attempts: u64 = 0;
    if keys.orchard.is_some() { attempts += total_actions; }
    if keys.sapling.is_some() { attempts += total_outputs; }

    eprintln!(
        "[bench] {} blocks  {} actions  {} outputs",
        blocks.len(),
        total_actions,
        total_outputs,
    );
    eprintln!(
        "[bench] uivk pools: orchard={} sapling={}",
        keys.orchard.is_some(),
        keys.sapling.is_some(),
    );
    eprintln!("[bench] attempts per iteration: {attempts}");

    let mut g = c.benchmark_group("scan");
    g.sample_size(10);
    g.throughput(Throughput::Elements(attempts));
    g.bench_function("uivk", |b| {
        b.iter(|| {
            for note in scan::sync(&blocks, &keys) {
                black_box(note);
            }
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
