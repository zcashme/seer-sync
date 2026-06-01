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
- `src/sync.rs` — **sans-IO core**. `scan()` runs batch trial-decryption over
  every compact output/action, returns rich per-note records + every spend seen.
  `sync()` is a thin in-memory projection (received notes + `Balance`).
- `src/sync/chain.rs` — the one lightwalletd block producer (streams compact
  blocks). The only IO.
- `src/sync/engine.rs` — persistence engine (`feature = "db"`). `sync_to_tip()`:
  resume cursor → stream to tip → `scan()` → `apply()` → advance cursor; a
  `prev_hash` break → walk-back. See **Sync architecture**.
- `src/db/` — raw rusqlite. `schema.rs` is a stripped descendant of
  `zcash_client_sqlite`. `db` is an **optional** Cargo feature; the sans-IO core
  builds with `--no-default-features`.
- `proto/` — vendored lightwalletd `.proto`; `build.rs` generates client stubs.

## Sync architecture

The confirmed-block loop:

- **One stream to the tip.** `sync_to_tip` opens a single `GetBlockRange` for
  `[cursor+1, tip]`. `download` chunks it by output-cost into a
  `channel(1)`-backpressured stream; the spawned downloader stays one batch
  ahead, so network fetch overlaps CPU decrypt for free. Memory is bounded by the
  chunk size, not the range.
- **Crash-safe by the cursor.** `apply()` advances `sync_state` after *every*
  batch. A dropped stream is retried (`MAX_TRANSPORT_RETRIES`) and resumes from
  the cursor; nothing is re-fetched.
- **Reorgs: one detector, self-terminating walk-back.** Continuity is checked in
  *one* place — `download`'s `prev_hash` chain, seeded with the stored hash of the
  block before `from`, so the same check covers both the DB seam and
  block-to-block. A break is a typed `chain::Reorg`; the engine rewinds, doubles
  the step, and retries until the seam reconnects. No depth limit is needed — the
  seam check is its own all-clear. Rewinding is free because there are **no
  witnesses** (over-rewind costs nothing, inserts are idempotent) and we store
  **every** block hash.
- **Errors: anyhow inside, no public error enum.** Nothing a caller branches on
  survived (reorgs self-recover; transport/DB just propagate), so `sync_to_tip`
  returns `anyhow::Result`. The one typed error, `chain::Reorg`, is matched
  internally to route the walk-back.

## Schema, in one breath

Watch-only keeps ~12 data tables: `account` (single key, id=1), `sync_state`
(linear cursor + per-pool tree positions), `blocks`, `transactions`, the 4
shielded note/spend tables, the 3 transparent tables, `addresses`,
`schema_version`. **Cut** all witness/shardtree tables (witnesses are for
*spending*), `sent_notes`, `scan_queue` (we tip-follow linearly), `nullifier_map`
/ `tx_locator_map` (a linear scan always sees a note before its spend),
`schemer_migrations`.

Spentness: a note references its creating tx; a junction row links it to the
spending tx; "spent" = that spend tx is mined. **Mempool/unconfirmed falls out
for free** as `transactions.mined_height IS NULL` — no overlay tables.

Sapling nullifiers + leaf positions come from the tree *size* lightwalletd stamps
on each block's `chain_metadata` (positions live as an int column, not a tree).
Orchard nullifiers derive from the key + the action's `rho` directly.

## Build staging

1. Schema + `src/db/` — **done**.
2. `sync_to_tip()` confirmed-block loop — **done**.
3. **Deferred — scaffolded but not wired** (intentionally kept; not dead code):
   - **Memo enrichment** — `src/note/` full-tx decrypt + the `memo`
     columns/setters. Wire: fetch full tx → decrypt → store memo.
   - **Transparent balance** — schema/db/`balance()` already model it, but the
     engine only scans shielded compact blocks, so `balance().transparent_zat`
     stays 0 until the engine populates transparent outputs.
   - **Live mempool** (`GetMempoolStream`) — the differentiator vs batch wallets.

## Testing

- `tests/live_sync.rs` is `#[ignore]`d (run `--ignored --nocapture`): syncs a
  live mainnet window into an in-memory DB. Covers
  fetch/parse/scan/block-meta/cursor/rewind/dedup on real data.
- Known gap: the bench/live UIVK has **zero mainnet notes** (confirmed across
  recent + 4 post-NU6 windows — don't re-hunt). So insert-on-decrypt-hit and
  spend detection are **not** covered by the live test.
- To close it: a deterministic **offline synthetic-note** test — gen a UFVK,
  encrypt a note into a synthetic `CompactBlock`, assert `scan` finds it →
  `apply` persists it → a later block's nullifier marks it spent.

## Conventions

- Don't reach for module hierarchy to express "A uses B" — reach for a
  trait/type at the boundary.
- Keep the sans-IO core free of async/network deps so it stays trivially
  testable (feed it `vec![]` of blocks) and embeddable.
- Discuss structure in prose and converge; don't over-formalize.
