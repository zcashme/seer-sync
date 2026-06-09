# seer-sync architecture

Data flows top to bottom: two inputs (a viewing key, a lightwalletd server),
one engine, one trait boundary, three kinds of consumer.

```
┌─ key.rs ─────────────────────────┐      ┌──────────────────────────────┐
│  ViewKey::decode(UFVK | UIVK)    │      │         lightwalletd         │
│                                  │      │   zec.rocks fleet · TLS ·    │
│  pre-derives everything scanning │      │   auto-failover              │
│  needs, per pool and scope:      │      └───────────────┬──────────────┘
│  · ivks        find notes        │                      │ gRPC
│  · nk / fvk    derive nullifiers │                      │ (vendored protos,
│                (UFVK: spends)    │                      │  client stubs only)
│  · ovks        recover sent txs  │                      ▼
│  · t-addr ivks transparent       │   ┌─ sync/chain.rs ── the only I/O ─────┐
└───────────┬──────────────────────┘   │  blocks() compact-block stream      │
            │                          │   · chunked by output cost          │
            │                          │   · channel(1) backpressure         │
            │                          │     (download overlaps decrypt)     │
            │                          │   · reorg = prev-hash chain break,  │
            │                          │     seeded with the cursor's seam   │
            │                          │  fetch_raw_transaction()  phase 2   │
            │                          │  fetch_address_utxos()  transparent │
            │                          └───┬───────────┬──────────────┬─────┘
            │              Vec<CompactBlock>│  full txs │  unspent     │
            │                               │  phase 2  │  UTXO set    │
            ├───────────────────────────────┼───────────┼──────┐       │
            ▼                               ▼           ▼      ▼       ▼
┌─ sync/scan.rs ── sans-IO core (no async, no network) ──┐ ┌─ sync/transparent ─┐
│  scan_compact()      trial-decrypt every output/action │ │  per-scope BIP-44  │
│                      parallel across CPUs → notes +    │ │  address windows,  │
│                      every spend (nullifier match)     │ │  widen until 20    │
│  enrich_memos()      phase 2: full-tx decrypt → memos  │ │  trailing indices  │
│  scan_sent()         phase 2: ovk recovery → sent txs  │ │  unused            │
│  scan_commitments()  cmx firehose (key-independent)    │ └─────────┬──────────┘
└───────────┬─────────────────────────────────────────────┘          │
            │ notes · spends · commitments                           │
            ▼                                                        │
┌─ sync.rs ── run::<A: Account>() ── persistence-free ───┐           │
│  one stream to tip: fetch → scan → apply, per batch    │           │
│  crash-safe: cursor advances after every batch         │           │
│  reorg: rewind, double the step, re-seek the seam      │           │
│  transport faults: bounded retries, resume from cursor │           │
└───────────┬─────────────────────────────────────────────┘          │
            │  Account trait — the one boundary                      │
            │  checkpoint() rewind() owns_nf() apply()               │
            │  (+ opt-in wants_commitments/apply_commitments)        │
            ▼                                                        ▼
┌─ consumers ────────────────────────────────────────────────────────────────┐
│                                                                            │
│  db::Db — reference SQLite store              [feature `db`]               │
│   · scan() = shielded loop, then transparent snapshot reconcile            │
│   · reads: balance() notes() transactions() transparent_outputs()         │
│   · shardtree witness store for proof-of-inclusion consumers              │
│                                               [feature `commitment-tree`]  │
│                                                                            │
│  your own store — impl Account, call sync::run()                           │
│                                                                            │
│  external scanners (e.g. zns-resolver) — skip the engine entirely:        │
│   drive chain::blocks() themselves, parse_orchard() + scan_commitments(), │
│   bring their own decrypt rules                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

Boundary rules (see AGENTS.md): depend on librustzcash's protocol/keys/crypto
layer, never its wallet framework; the sans-IO core stays network-free; nothing
application-specific (ZNS or otherwise) lives in this crate.
