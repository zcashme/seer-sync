# seer-sync

[![Crates.io](https://img.shields.io/crates/v/seer-sync.svg)](https://crates.io/crates/seer-sync)
[![docs.rs](https://docs.rs/seer-sync/badge.svg)](https://docs.rs/seer-sync)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/seer-sync.svg)](https://github.com/yourusername/seer-sync#license)
[![MSRV: 1.85.1](https://img.shields.io/badge/rustc-1.85.1+-blue.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.1.html)

View-key-only Zcash chain sync. Streams compact blocks from a lightwalletd gRPC server and trial-decrypts them in parallel — no spending keys, no witness computation, no full node required.

**Supports:** Orchard · Sapling · Transparent (P2PKH / P2SH)

## Features

- **Three key paths** — IVK (incoming), FVK (full balance + spend detection), OVK (sent notes)
- **Parallel trial decryption** via rayon + crossbeam-channel
- **Chunked streaming** for large block ranges with bounded memory
- **Reorg detection** on `prev_hash` during streaming fetches
- **Optional SQLite persistence** (`features = ["db"]`) — accounts, notes, UTXOs, sync cursors, rewind support

## Usage

```toml
[dependencies]
seer-sync = "0.0.1"
```

```rust
use seer_sync::{chain, keys::IvkKeys, scan::scan_ivk};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::MainNetwork;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, "uivk1...")?;
    let keys = IvkKeys::from_uivk(&uivk);

    let mut client = chain::connect(chain::ZEC_ROCKS).await?;
    let tip = chain::tip_height(&mut client).await?;
    let blocks = chain::fetch_range(&mut client, tip - 100, tip).await?;

    for note in scan_ivk(&blocks, &keys) {
        println!("received {} zat at height {}", note.value_zat, note.height);
    }
    Ok(())
}
```

See [docs.rs/seer-sync](https://docs.rs/seer-sync) for the full API — key paths, FVK spend detection, OVK recovery, chunked streaming, and the SQLite `Db` type.

## Feature flags

| Flag | Default | Description |
|---|---|---|
| `db` | **on** | SQLite persistence via `rusqlite` (bundled) |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
