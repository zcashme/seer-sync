//! One-shot fixture downloader for seer-sync benches.
//!

use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use prost::Message;
use seer_sync::chain::{connect, ZEC_ROCKS};
use seer_sync::proto::{BlockId, BlockRange};
use zcash_protocol::consensus::{MainNetwork, NetworkUpgrade, Parameters};

#[tokio::main]
async fn main() -> Result<()> {
    let url = env::var("LWD_URL").unwrap_or_else(|_| ZEC_ROCKS.to_string());

    let nu6_height: u32 = u32::from(
        MainNetwork
            .activation_height(NetworkUpgrade::Nu6)
            .ok_or_else(|| anyhow!("no NU6 activation height on mainnet?"))?,
    );

    println!("Connecting to {url} ...");
    let mut client = connect(&url).await?;
    let tip_height = seer_sync::chain::tip_height(&mut client).await?;

    let start = env::var("START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(nu6_height);
    let end = env::var("END_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(tip_height);

    if start > end {
        return Err(anyhow!("START_HEIGHT ({start}) > END_HEIGHT ({end})"));
    }
    let total = end - start + 1;

    println!("NU6 activation: {nu6_height}");
    println!("Chain tip:      {tip_height}");
    println!(
        "Downloading {total} blocks  [{start} .. {end}]  → bench-data/compact-blocks.bin",
    );
    println!("(ctrl-C anytime; rerun with smaller END_HEIGHT if needed)");

    let out_dir = PathBuf::from("bench-data");
    fs::create_dir_all(&out_dir).context("creating bench-data/")?;
    let mut out = BufWriter::new(File::create(out_dir.join("compact-blocks.bin"))?);

    let req = BlockRange {
        start: Some(BlockId { height: start as u64, hash: vec![] }),
        end:   Some(BlockId { height: end   as u64, hash: vec![] }),
        pool_types: vec![],
    };
    let mut stream = client
        .get_block_range(req)
        .await
        .context("GetBlockRange")?
        .into_inner();

    let t0 = Instant::now();
    let mut written: u32 = 0;
    let mut total_actions: u64 = 0;
    let mut total_outputs: u64 = 0;
    let mut total_bytes:   u64 = 0;

    while let Some(block) = stream.next().await {
        let block = block.context("streaming a CompactBlock")?;
        for tx in &block.vtx {
            total_actions += tx.actions.len() as u64;
            total_outputs += tx.outputs.len() as u64;
        }
        let bytes = block.encode_to_vec();
        out.write_all(&(bytes.len() as u32).to_le_bytes())?;
        out.write_all(&bytes)?;
        total_bytes += 4 + bytes.len() as u64;
        written += 1;

        if written % 1000 == 0 {
            let elapsed = t0.elapsed().as_secs_f64();
            let bps = total_bytes as f64 / elapsed / 1024.0 / 1024.0;
            let pct = 100.0 * written as f64 / total as f64;
            println!(
                "  {written:>7}/{total} ({pct:5.1}%)  {:>5.1} MB  {bps:5.2} MB/s",
                total_bytes as f64 / 1024.0 / 1024.0,
            );
        }
    }

    out.flush()?;
    let elapsed = t0.elapsed().as_secs_f64();
    println!();
    println!("Done in {elapsed:.1}s");
    println!("  blocks  : {written}");
    println!("  actions : {total_actions} Orchard");
    println!("  outputs : {total_outputs} Sapling");
    println!(
        "  size    : {:.2} MB",
        total_bytes as f64 / 1024.0 / 1024.0,
    );
    Ok(())
}
