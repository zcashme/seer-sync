# seer-sync

View-key-only Zcash chain sync — a **non-spendable wallet** whose job is to
track every note you can see from a viewing key, as accurately as the chain
allows.

Give it a **UIVK** (incoming) or **UFVK** (full), a lightwalletd endpoint, and
either the bundled SQLite store or your own persistence behind the [`Account`](https://docs.rs/seer-sync/latest/seer_sync/trait.Account.html)
trait. It trial-decrypts compact blocks, detects spends, recovers memos and sent
recipients from full transactions, and follows reorgs without pulling in
`zcash_client_backend` or `zcash_client_sqlite`.


## Features

- **Linear tip sync** — one `GetBlockRange` stream, chunked by output cost with
  backpressure so download overlaps decrypt.
- **Crash-safe cursor** — resume from the last applied batch; transport retries
  are bounded.
- **Reorgs** — `prev_hash` continuity from the stored seam; rewind and walk
  back until the chain reconnects.
- **Two-phase scan** — compact trial decrypt, then full-tx fetch for memos and
  outgoing recipients.
- **Transparent tracking** (opt-in) — BIP-44 discovery with gap limit, same
  `run()` loop as shielded.
- **Commitment firehose** (opt-in) — every Orchard `cmx` with leaf position,
  plus shardtree witnesses for inclusion proofs.


```bash
cargo run --release --features db --example balance -- '<ufvk>' <birthday> [db]
```

MIT OR Apache-2.0
