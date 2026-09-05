# seer-sync

```
   _____ ________________     _______  ___   ________
  / ___// ____/ ____/ __ \   / ___/\ \/ / | / / ____/
  \__ \/ __/ / __/ / /_/ /   \__ \  \  /  |/ / /
 ___/ / /___/ /___/ _, _/   ___/ /  / / /|  / /___
/____/_____/_____/_/ |_|   /____/  /_/_/ |_|\____/

  sync a view key, see your ZEC
```

A **view-key-only** Zcash chain sync engine. Give it a UIVK or UFVK, a
lightwalletd endpoint, and a place to store notes — it trial-decrypts compact
blocks, detects spends, recovers memos, and follows reorgs. No spending keys,
no `zcash_client_backend`, no `zcash_client_sqlite`.

## Usage

```toml
[dependencies]
seer-sync = "0.4"
```

```rust
use seer_sync::{run, BlockHeight, Db, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Db::open("seer.db")?;
    db.init_account(BlockHeight::from_u32(3_000_000))?;

    run("uview1...", Network::MainNetwork, &db).await?;

    println!("{} zat", db.balance()?);
    Ok(())
}
```

That's it. `run` parses the view key, connects to a server, syncs from the
birthday to the tip, and keeps polling for new blocks.

```bash
# Try it yourself
cargo run --release --example sync -- '<view-key>' <birthday> [db-path]
cargo run --release --example balance -- [db-path]
```

## How it works

```
  lightwalletd              seer-sync                         SQLite
  ────────────              ─────────                         ──────
  ┌─────────┐  compact    ┌───────────┐   WalletTx[]    ┌──────────┐
  │GetBlock │ ──────────► │ trial     │ ─────────────► │  txs     │
  │  Range  │             │ decrypt   │                 │  notes   │
  └─────────┘             │           │                 │  spends  │
                          │ reorg     │                 └──────────┘
  ┌─────────┐  full tx    │  detect   │
  │GetTx    │ ──────────► │ rewind   │
  └─────────┘             └───────────┘
```

1. **Stream** compact blocks from lightwalletd (`GetBlockRange`)
2. **Detect** reorgs by checking each block's `prev_hash` against local state
3. **Scan** — batch trial-decrypt sapling + orchard + ironwood outputs
4. **Enrich** — fetch full transactions for memos and outgoing note recovery
5. **Apply** — persist to SQLite, update checkpoint

## Reorg handling

When a block's `prev_hash` doesn't match our local state, the chain forked.
We keep a sliding window of the last 100 block hashes in memory, rewind by
`rewind_by` blocks, and re-stream from the network. The anchor block's
`prev_hash` is checked against our **local** hash from the window — a mismatch
means the fork is deeper, so we double `rewind_by` and repeat. Exponential
backoff finds the fork point in O(log n) iterations.

## Schema

```
account       birthday, sync_height, sync_hash
txs           txid, block_height, tx_index, amount, is_outgoing
sapling_notes txid, output_index, block_height, nf, note, recipient, memo,
              scope, position, is_sent, is_change, spent, spent_height, ...
orchard_notes (same)
ironwood_notes (same)
```

Spends are columns on the note they consume (`spent`, `spent_height`,
`spent_txid`, `spent_index`) — no separate spend tables.

## Pools

- **Sapling** — trial decrypt + nullifier spend detection
- **Orchard** — trial decrypt + nullifier spend detection
- **Ironwood** — trial decrypt + nullifier spend detection (ZIP 2005); with the
  opt-in `zns-decrypt` feature, Name Notes (commitments bound to application
  data) are surfaced unverified for the caller to check

## License

MIT

[Repository](https://github.com/zcashme/seer-sync)