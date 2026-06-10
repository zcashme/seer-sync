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
            │                          │  fetch_taddress_transactions()      │
            │                          │     t-addr history (discovery)      │
            │                          └───────┬───────────┬────────────────┘
            │                  Vec<CompactBlock>│  full txs │ txs touching
            │                                   │  phase 2  │ our t-addrs
            ├───────────────────────────────────┼───────────┤
            ▼                                   ▼           ▼
┌─ sync/scan.rs ── sans-IO core (no async, no network) ──────────────────────┐
│  scan_compact()       trial-decrypt every output/action, parallel across   │
│                       CPUs → notes + every spend (nullifier match)         │
│  enrich_memos()       phase 2: full-tx decrypt → memos                     │
│  scan_sent()          phase 2: ovk recovery → sent recipients              │
│  scan_transparent()   phase 2: targeted txs → t-outputs + outpoint spends  │
│  scan_commitments()   cmx firehose (key-independent)                       │
└───────────┬─────────────────────────────────────────────────────────────────┘
            │ notes · spends · t-outputs · t-spends · commitments
            ▼
┌─ sync.rs ── run::<A: Account>() ── persistence-free ───────────────────────┐
│  per pass:  transparent::discover() — gap-limit walk of the key's BIP-44   │
│             address chains → txid targets over the account's whole life    │
│  per batch: fetch → scan → apply; targets in range join phase 2            │
│  crash-safe: cursor advances after every batch                             │
│  reorg: rewind, double the step, re-seek the seam (rediscovers targets)    │
│  transport faults: bounded retries, resume from cursor                     │
└───────────┬─────────────────────────────────────────────────────────────────┘
            │  Account trait — the one boundary
            │  checkpoint() rewind() owns_nf() apply()
            │  + opt-in: wants_commitments/apply_commitments
            │  + opt-in: wants_transparent/owns_outpoint/apply_transparent
            ▼
┌─ consumers ────────────────────────────────────────────────────────────────┐
│  db::Db — reference SQLite store              [feature `db`]               │
│   · scan() = connect + run (transparent rides the same loop)               │
│   · reads: balance() notes() transactions() transparent_outputs()         │
│   · shardtree witness store for proof consumers [feature `commitment-tree`]│
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
