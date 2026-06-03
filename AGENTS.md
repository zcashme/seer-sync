# AGENTS.md

Working notes for agents (and humans) on `seer-sync`.

## What this is

A **view-key-only Zcash chain sync** library, targeting crates.io. Think of it
as a **non-spendable wallet** whose one job is to **accurately track every note,
live** — from viewing keys only (IVK/FVK).

What a viewing key buys you bounds detection:
- **UIVK** (incoming) → see notes arrive, can't tell when they're spent.
- **UFVK** (full) → also carries each pool's nullifier-deriving key → spends too.

## The boundary we hold

Depend on librustzcash's **protocol/keys/crypto** layer, never its **wallet
framework**:
- IN: `zcash_protocol`, `zcash_keys` (+ transitive `zcash_address` /
  `zcash_transparent` / `zcash_encoding`), pool crypto `orchard`,
  `sapling-crypto`, `zcash_note_encryption`, `zip32`.
- OUT: `zcash_client_backend`, `zcash_client_sqlite` — they impose a wallet
  framework, DB schema, and sync model. We hand-roll our own equivalents:
  vendored lightwalletd protos (`proto/`, client stubs only), raw-rusqlite
  `src/db/`, our own `src/sync/` engine.

The line is "**know the protocol**" vs "**be a wallet framework**".

`librustzcash/` is checked out at repo root **for reference only** (canonical
schema lives in its `src/wallet/db.rs`). It is not a dependency.

## Layout

- `src/keys.rs` — parse a UVK into `ScanningKeys` (per-pool `ivk`, plus the
  nullifier-deriving `nk` when the key is full).
- `src/note/` — full-transaction decrypt + ZIP-302 memo (`zcash_protocol`).
- `src/sync/scan.rs` — **sans-IO core**. `scan_compact()` runs batch
  trial-decryption over every compact output/action (parallel across CPUs for
  large ranges), returning rich per-note receives + every spend seen. `scan()`
  wraps it with phase 2: fetch each owning full tx and full-decrypt to recover
  memos, so its findings come back complete.
- `src/sync/chain.rs` — the one lightwalletd block producer (`blocks()` streams
  compact blocks; `fetch_raw_transaction` serves phase 2). The only IO.
- `src/sync.rs` — the persistence-free `run()` loop (`feature = "lwd"`). Drives
  fetch → `scan()` → consumer over three closures (`resume_point`, `rewind`,
  `sink`), handling transport faults and reorgs inline. Reads no consumer state.
  See **Sync architecture**.
- `src/db/` — raw rusqlite (`feature = "db"`). `schema.rs` is a stripped
  descendant of `zcash_client_sqlite`. `sync.rs` is **consumer zero**:
  `sync_to_tip()` wires the `Db` into `run()`'s three closures. The sans-IO core
  builds with `--no-default-features`.
- `proto/` — vendored lightwalletd `.proto`; `build.rs` generates client stubs.

## Sync architecture

The confirmed-block loop lives in `src/sync.rs::run` and is **persistence-free**:
it reads no consumer state and writes none. The consumer supplies three closures
over its own store — `resume_point` (start height + seam hash), `rewind` (drop
state above a height), `sink` (apply one chunk) — and `run` drives the sweep.
`src/db/sync.rs::sync_to_tip` is the reference wiring.

- **One stream to the tip.** `run` opens a single `GetBlockRange` for
  `[start, tip]`. `chain::blocks`/`download` chunks it by output-cost into a
  `channel(1)`-backpressured stream; the spawned downloader stays one batch
  ahead, so network fetch overlaps CPU decrypt for free. Memory is bounded by the
  chunk size, not the range.
- **Crash-safe by the cursor.** `sink` advances the consumer's cursor after
  *every* batch. A dropped stream is retried (`MAX_TRANSPORT_RETRIES`) and
  re-resumes from `resume_point`; nothing is re-fetched.
- **Reorgs: one detector, self-terminating walk-back.** Continuity is checked in
  *one* place — `download`'s `prev_hash` chain, seeded with the seam hash the
  consumer returns from `resume_point`, so the same check covers both the resume
  seam and block-to-block. A break is a typed `chain::Reorg`; `run` calls
  `rewind`, doubles the step, and re-resumes until the seam reconnects. No depth
  limit is needed — the seam check is its own all-clear. Rewinding is cheap
  because there are **no witnesses** (over-rewind costs nothing, inserts are
  idempotent); the consumer keeps only the cursor's single seam hash, not a block
  ledger.
- **Two-phase scan.** `scan()` finds notes in compact blocks (phase 1), then
  fetches each owning full tx and full-decrypts it to recover memos (phase 2), so
  what reaches `sink` is already complete — a failed fetch errors the whole chunk.
- **Errors: anyhow inside, no public error enum.** Nothing a caller branches on
  survived (reorgs self-recover; transport/DB just propagate), so the API returns
  `anyhow::Result`. The one typed error, `chain::Reorg`, is matched internally to
  route the walk-back.

## Schema, in one breath

Watch-only keeps ~11 data tables: `account` (single key, id=1), `sync_state`
(linear cursor — just the scanned `height` + its seam `hash`), `transactions`,
the 4 shielded note/spend tables, the 3 transparent tables (incl.
`transparent_spend_map`), `addresses`, `schema_version`. Note positions live as
an int column on each note, not a tree. **Absent by design:** witness/shardtree
tables (witnesses are for *spending*), `sent_notes` (never authors txs),
`scan_queue` (tip-follow is linear), `nullifier_map` / `tx_locator_map` (a linear
scan always sees a note before its spend), `schemer_migrations`, and any `blocks`
table — an observer tracks notes by height, so the cursor is the only
chain-position state.

Spentness: a note references its creating tx; a junction row links it to the
spending tx; "spent" = that spend tx is mined. **Mempool/unconfirmed falls out
for free** as `transactions.mined_height IS NULL` — no overlay tables.

Sapling nullifiers + leaf positions come from the tree *size* lightwalletd stamps
on each block's `chain_metadata` (positions live as an int column, not a tree).
Orchard nullifiers derive from the key + the action's `rho` directly.

## Scope

Implemented: the `src/db/` store + schema; the `run()` / `sync_to_tip()`
confirmed-block loop; memo recovery (phase 2 of `scan()` full-decrypts each owning
tx into the `memo` columns).

**Scaffolded but not wired** (intentionally present; not dead code):
- **Transparent balance** — schema/db/`balance()` and `chain.rs`'s UTXO fetchers
  model it, but `db/sync.rs::apply` persists only shielded receives/spends, so
  `balance().transparent_zat` stays 0 until the consumer wires the transparent
  path. See `docs/transparent-balances.md`.
- **Live mempool** (`GetMempoolStream`) — the differentiator vs batch wallets.

## Testing & benches

- **Unit tests** live in `src/db/mod.rs` (`cargo test --features db`): account /
  sync-state round-trips, received-then-spent and rewind on synthetic rows,
  unmined-spend-doesn't-reduce-balance. No network.
- **Live integration coverage** — none in-tree. If you add it, mind the trap: a
  window defined as "N blocks back from tip" trails the funded key by ~360k
  blocks, so it scans an empty range and exercises only structural invariants
  (cursor parked, idempotent re-sync), never the received-note / spend / memo
  paths. Either pin the window to the funded range and assert `balance > 0`, or —
  better, and network-free — go **deterministic + offline**: gen a UFVK, encrypt
  a note into a synthetic `CompactBlock`, assert `scan` finds it → `apply`
  persists it → a later block's nullifier marks it spent.
- **Bench** (`benches/decrypt.rs`, `cargo bench --bench decrypt`): fetches a live
  block window *once* in setup, then times `scan_compact` only (no network in the
  measured loop). Window defaults to 5,000 blocks back from tip; set
  `BENCH_FROM=2726400` to sweep the full post-NU6 range. Uses a UIVK with **zero
  mainnet notes** (confirmed across recent + 4 post-NU6 windows — don't re-hunt),
  so it measures the decrypt hot path itself, not hit-handling.

## Conventions

- Don't reach for module hierarchy to express "A uses B" — reach for a
  trait/type at the boundary.
- Keep the sans-IO core free of async/network deps so it stays trivially
  testable (feed it `vec![]` of blocks) and embeddable.
- Discuss structure in prose and converge; don't over-formalize.
