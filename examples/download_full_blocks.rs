//! Download full Zcash blocks from a Zebra node via JSON-RPC.
//!
//! Open the SSH tunnel first (in another terminal):
//!     ssh -L 8232:127.0.0.1:8232 ubuntu@<your-zebra-host>
//!
//! Then run:
//!     cargo run --release --example download_full_blocks
//!
//! Env overrides:
//!     ZEBRA_URL    default http://127.0.0.1:8232
//!     START_HEIGHT default 2726400 (NU6 activation)
//!     END_HEIGHT   default = current chain tip from `getblockchaininfo`
//!     CONCURRENCY  default 16 (in-flight `getblock` requests)
//!
//! Output: `bench-data/full-blocks.bin`, length-prefixed raw block bytes,
//! in ascending height order.

use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};

const DEFAULT_URL: &str = "http://127.0.0.1:8232";
const NU6_ACTIVATION: u32 = 2_726_400;
const DEFAULT_CONCURRENCY: usize = 16;
const CHUNK_SIZE: u32 = 1024;

async fn jsonrpc(client: &Client, url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({
        "jsonrpc": "1.0",
        "id": "seer-sync",
        "method": method,
        "params": params,
    });

    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url} ({method})"))?
        .error_for_status()
        .with_context(|| format!("non-2xx from {method}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("decoding JSON response from {method}"))?;

    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(anyhow!("RPC error from {method}: {err}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("no `result` in response from {method}"))
}

async fn fetch_block(client: &Client, url: &str, height: u32) -> Result<Vec<u8>> {
    // Zebra/zcashd accept the height as a string of an integer; verbosity 0
    // returns hex-encoded raw block bytes.
    let result = jsonrpc(
        client,
        url,
        "getblock",
        json!([height.to_string(), 0]),
    )
    .await?;
    let hex_str = result
        .as_str()
        .ok_or_else(|| anyhow!("getblock {height}: expected hex string, got {result}"))?;
    hex::decode(hex_str).with_context(|| format!("decoding hex for height {height}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = env::var("ZEBRA_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let concurrency: usize = env::var("CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CONCURRENCY);

    println!("Connecting to Zebra JSON-RPC at {url}");
    println!("(make sure the SSH tunnel is up if URL is localhost)");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(concurrency)
        .build()
        .context("building reqwest client")?;

    let info = jsonrpc(&client, &url, "getblockchaininfo", json!([])).await?;
    let tip = info
        .get("blocks")
        .and_then(|v| v.as_u64())
        .context("no `blocks` field in getblockchaininfo")? as u32;
    println!("Chain tip: {tip}");

    let start = env::var("START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(NU6_ACTIVATION);
    let end = env::var("END_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(tip);

    if start > end {
        return Err(anyhow!("START_HEIGHT ({start}) > END_HEIGHT ({end})"));
    }
    let total = end - start + 1;

    println!(
        "Downloading {total} full blocks  [{start} .. {end}]  with concurrency={concurrency}",
    );
    println!("→ bench-data/full-blocks.bin");

    let out_dir = PathBuf::from("bench-data");
    fs::create_dir_all(&out_dir).context("creating bench-data/")?;
    let out_path = out_dir.join("full-blocks.bin");
    let mut out = BufWriter::new(File::create(&out_path)?);

    let t0 = Instant::now();
    let mut written: u32 = 0;
    let mut total_bytes: u64 = 0;

    // Chunked parallel fetch + in-order write. Bounded memory.
    let mut chunk_start = start;
    while chunk_start <= end {
        let chunk_end = std::cmp::min(chunk_start + CHUNK_SIZE - 1, end);
        let heights: Vec<u32> = (chunk_start..=chunk_end).collect();

        let mut results: Vec<(u32, Result<Vec<u8>>)> = stream::iter(heights.into_iter().map(|h| {
            let client = client.clone();
            let url = url.clone();
            async move { (h, fetch_block(&client, &url, h).await) }
        }))
        .buffer_unordered(concurrency)
        .collect()
        .await;

        results.sort_by_key(|(h, _)| *h);

        for (h, r) in results {
            let bytes = r.with_context(|| format!("fetching block {h}"))?;
            out.write_all(&(bytes.len() as u32).to_le_bytes())?;
            out.write_all(&bytes)?;
            total_bytes += 4 + bytes.len() as u64;
            written += 1;
        }

        let elapsed = t0.elapsed().as_secs_f64();
        let pct = 100.0 * written as f64 / total as f64;
        let mb = total_bytes as f64 / 1024.0 / 1024.0;
        let mbps = mb / elapsed.max(0.001);
        let bps = written as f64 / elapsed.max(0.001);
        println!(
            "  {written:>7}/{total} ({pct:5.1}%)  {mb:>8.1} MB  {mbps:5.2} MB/s  {bps:5.0} blocks/s",
        );

        chunk_start = chunk_end + 1;
    }

    out.flush()?;
    let elapsed = t0.elapsed().as_secs_f64();
    println!();
    println!("Done in {elapsed:.1}s");
    println!(
        "  blocks : {written}\n  size   : {:.2} MB ({:.2} GB)\n  rate   : {:.2} MB/s",
        total_bytes as f64 / 1024.0 / 1024.0,
        total_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
        total_bytes as f64 / 1024.0 / 1024.0 / elapsed.max(0.001),
    );
    Ok(())
}
