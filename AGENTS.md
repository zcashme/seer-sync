# AGENTS.md

Working notes for agents (and humans) on `seer-sync`.

## What this is

A **view-key-only Zcash chain sync** library, targeting crates.io. Think of it
as a **non-spendable wallet** whose one job is to **accurately track every note,
live** — from viewing keys only (IVK/FVK).

What a viewing key buys you bounds detection:
- **UIVK** (incoming) → see notes arrive, can't tell when they're spent.
- **UFVK** (full) → also carries each pool's nullifier-deriving key → spends too.

`ViewKey::decode` accepts either encoding and pre-derives the per-pool scanning
keys up front (`src/key.rs`).

## The boundary we hold

Depend on librustzcash's **protocol/keys/crypto** layer, never its **wallet
framework**:
- IN: `zcash_protocol`, `zcash_keys` (+ transitive `zcash_address` /
  `zcash_transparent` / `zcash_encoding`), pool crypto `orchard`,
  `sapling-crypto`, `zcash_note_encryption`, `zip32`. The whole stack is on the
  **0.14 line** (orchard 0.14, zcash_protocol 0.9, zcash_keys 0.14,
  zcash_primitives 0.28).
- OUT: `zcash_client_backend`, `zcash_client_sqlite` — they impose a wallet
  framework, DB schema, and sync model. We hand-roll our own equivalents:
  vendored lightwalletd protos (`src/proto.rs`, client stubs only), raw-rusqlite
  `src/db/`, our own `src/sync/` engine. For the note-commitment tree we use
  `shardtree` directly plus a vendored ~120-line shard codec
  (`src/db/shardtree_serialization.rs`) — **not** `zcash_client_backend`.

The line is "**know the protocol**" vs "**be a wallet framework**".

`librustzcash/` is checked out at repo root **for reference only**. It is not a
dependency.

## General-purpose, and ZNS-blind

seer-sync is **protocol-faithful and application-agnostic**. Orchard/Sapling
decryption applies the full ZIP-212 commitment check, so it surfaces only notes
whose commitment binds. It carries **no application-specific decrypt rules**, no
`observe`/relaxed-decrypt feature, no cipher crates, and no `cmx` field on
`Note`. Keep it that way.

A consumer that needs a **non-standard decrypt rule** — e.g. ZcashName Name
Notes, whose `(rcm, ψ)` are a deterministic hash that fails the standard
`rseed`→`cmx` check and so gets discarded here — does **not** get a hook in this
crate. Instead it **drives its own scan** over seer-sync's toolkit and supplies
its own decrypt:
- `sync::chain::blocks` — the compact-block stream (with reorg detection);
- the re-exported compact-block **data types** (`CompactBlock`, `CompactTx`,
  `CompactOrchardAction`, `RawTransaction`, … — at the crate root, *not* the
  whole `proto` module; the gRPC client and RPC messages stay private);
- `parse_orchard` — proto action → `orchard::CompactAction`;
- `sync::scan::scan_commitments` — the position-tagged commitment firehose.

The relaxed decrypt and commitment verification then live entirely in the
consumer's crates (the ZcashName resolver drives such a loop; the relaxed
trial-decrypt lives behind a feature in `zns-verify`). If you find yourself
wanting to teach seer-sync about names, memos-as-commands, or skipping the
commitment check — stop; that belongs in the consumer.

## Layout

- `src/key.rs` — `ViewKey`: parse a UFVK/UIVK and pre-derive per-pool incoming
  viewing keys (+ the nullifier-deriving `fvk`/`nk` and outgoing keys when the
  key is full).
- `src/decrypt.rs` — per-pool compact + full trial decryption and sender
  recovery (standard, commitment-checked). `parse_orchard`/`parse_sapling` turn
  proto actions/outputs into the pool crates' compact types; `parse_orchard` is
  re-exported as a public building block.
- `src/sync/scan.rs` — **sans-IO core**. `scan_compact()` runs batch
  trial-decryption over every compact output/action (parallel across CPUs for
  large ranges), returning per-note receives + every spend seen; `enrich_memos`
  + `scan_sent` are phase 2; `scan_commitments()` is the viewing-key-independent
  firehose (every `cmx`, tagged with its absolute leaf position). Types: `Note`,
  `ShieldedNote`, `Pool`, `Spend`, `Commitment`, `CompactScan`.
- `src/sync/chain.rs` — the one lightwalletd block producer. `blocks()` streams
  compact blocks; `fetch_raw_transaction` serves phase 2; `tip_height`,
  `connect`/`connect_auto`. The only IO. Errors are typed (`ChainError`).
- `src/sync.rs` — the persistence-free `run::<A: Account>()` loop. Drives
  fetch → scan → `Account` over the chain, handling transport faults and reorgs
  inline. Reads no consumer state. See **Sync architecture**.
- `src/db/` — raw rusqlite. `schema.rs` is a stripped descendant of
  `zcash_client_sqlite`; `mod.rs` impls `Account` for `Db` (consumer zero);
  `commitment_tree.rs` + `shardtree_serialization.rs` back the `commitment-tree`
  feature.
- `src/proto.rs` — generated lightwalletd types (`build.rs` emits client stubs
  only; we call lightwalletd, never serve it).

## Features

- `db` — the reference raw-rusqlite store, the top-level `scan()` /
  `refresh_transparent()` entries, and the read path (`balance()`, `notes()`,
  `transactions()`, `transparent_outputs()`).
- `commitment-tree` — the Orchard note-commitment tree (shardtree) and the
  `scan_commitments` firehose ingestion, persisted via `db`. **Opt-in**: it
  ingests every on-chain commitment and pulls shardtree, which a plain balance
  scanner neither needs nor should pay for. Witnesses are for consumers that
  must *prove* a note's inclusion (e.g. an indexer), not for tracking balance.

## Sync architecture

The confirmed-block loop lives in `src/sync.rs::run` and is **persistence-free**:
it reads no consumer state and writes none. The consumer implements one trait,
**`Account`**, over its own store, and `run` drives the sweep:

```
checkpoint() -> Option<Cursor>            // resume point: height + seam hash
rewind(to)                                // drop state above a height (reorg)
owns_nf(pool, nf) -> bool                 // is this spend ours?
apply(at, notes, spends)                  // persist one batch, advance cursor
wants_commitments() -> bool   (= false)   // opt-in commitment firehose
apply_commitments(at, commitments)        // ingest the firehose (tree consumer)
```

`Cursor` is the named `(BlockHeight, Option<[u8;32]>)` resume point (scanned
height + its seam hash). The engine stays a free function; `impl Account for Db`
is the reference wiring, and `lib.rs::scan()` is the one-call convenience entry.

- **One stream to the tip.** `run` opens a single `GetBlockRange` for
  `[start, tip]`. `chain::blocks`/`download` chunks it by output-cost *or* block
  count (`DEFAULT_CHUNK_OUTPUTS` / `DEFAULT_CHUNK_BLOCKS`, whichever trips first)
  into a `channel(1)`-backpressured stream; the spawned downloader stays one
  batch ahead, so network fetch overlaps CPU decrypt for free. The two caps guard
  different axes: outputs bound scan work + memory per chunk; the block cap keeps
  cursor checkpoints regular in sparse regions. Memory is bounded by the chunk,
  not the range.
- **Crash-safe by the cursor.** `apply` advances the consumer's cursor after
  *every* batch. A dropped stream is retried (`MAX_TRANSPORT_RETRIES`) and
  re-resumes from `checkpoint()`; nothing is re-fetched.
- **Reorgs: one detector, self-terminating walk-back.** Continuity is checked in
  *one* place — `download`'s `prev_hash` chain, seeded with the seam hash from
  `checkpoint()`, so the same check covers both the resume seam and
  block-to-block. A break is a typed `ChainError::Reorg`; `run` calls `rewind`,
  doubles the step, and re-resumes until the seam reconnects. No depth limit —
  the seam check is its own all-clear. Rewinding is cheap (over-rewind costs
  nothing, inserts are idempotent); the consumer keeps only the cursor's seam
  hash. With `commitment-tree`, the consumer truncates the tree to its nearest
  checkpoint in lockstep inside `rewind`.
- **Two-phase scan.** `scan_compact` finds notes in compact blocks (phase 1),
  then `enrich_memos`/`scan_sent` fetch each owning full tx and full-decrypt to
  recover memos + sent recipients (phase 2), so what reaches `apply` is complete;
  a failed fetch errors the whole chunk.
- **Errors: typed.** `ChainError` (transport + `Reorg`), `SyncError` (wraps
  `Chain` / `Key` / `Account`), and `AccountError = Box<dyn Error + Send + Sync>`
  so consumer stores surface their own error type without seer-sync knowing it.

## Schema, in one breath

Watch-only keeps a lean store: `sync_state` (the linear cursor — scanned
`height` + seam `hash`), `transactions`, and the per-pool
`sapling_received_notes` / `orchard_received_notes` tables (each carries the
note, its nullifier, spend status, leaf position, and memo as columns). Spentness
is a nullifier match — a received note whose nf later appears is spent; unmined
spends fall out for free via `transactions.mined_height IS NULL`, no overlay
tables. **Absent by design:** an `account` table (single key — dropped), a
`blocks` table (the cursor is the only chain-position state), `sent_notes`
(never authors txs), `scan_queue` (tip-follow is linear), and
`nullifier_map`/`tx_locator_map` (a linear scan always sees a note before its
spend). Witness/shardtree tables exist **only** under `commitment-tree`.

Sapling leaf positions come from the tree *size* lightwalletd stamps on each
block's `chain_metadata`; positions live as an int column, not a tree. Orchard
nullifiers derive from the key + the action's `rho` directly.

## Scope

Implemented: the `src/db/` store + schema; the `run()` confirmed-block loop and
`Account` trait; memo + sent-recipient recovery (phase 2); the `commitment-tree`
firehose + shardtree witness store; the read path (`notes()`, `transactions()`
with per-tx received/sent/spent rollups via `spent_txid`, `transparent_outputs()`);
transparent balance v1 (`sync::transparent::utxos` gap-limit snapshot over
`GetAddressUtxos`, reconciled by `Db::apply_transparent_snapshot` — spends
detected by absence, so the spender tx and true spend height are unknown until
the `GetTaddressTransactions` history path is built; see
`docs/transparent-balances.md`).

Not implemented in the current store: **live mempool** (`GetMempoolStream`, the
differentiator vs batch wallets) and the transparent **history path**.

## Testing & benches

- **Unit tests** live in `src/db/mod.rs` and the `commitment_tree` module
  (`cargo test --features commitment-tree`): sync-state round-trips,
  received-then-spent and rewind on synthetic rows, unmined-spend-doesn't-reduce-
  balance, and a sqlite-backed witness root that survives reopen. `scan.rs` has
  offline `scan_commitments` position tests. No network.
- **Live integration coverage** — none in-tree. If you add it, mind the trap: a
  window defined as "N blocks back from tip" trails a funded key by hundreds of
  thousands of blocks, so it scans an empty range and exercises only structural
  invariants, never the received-note / spend / memo paths. Prefer
  **deterministic + offline**: gen a UFVK, encrypt a note into a synthetic
  `CompactBlock`, assert `scan_compact` finds it → `apply` persists it → a later
  block's nullifier marks it spent.
- **Bench** (`benches/decrypt.rs`, `cargo bench --bench decrypt`): fetches a live
  block window *once* in setup, then times `scan_compact` only (no network in the
  measured loop). Uses a UIVK with **zero mainnet notes** (confirmed — don't
  re-hunt), so it measures the decrypt hot path, not hit-handling.

## Conventions

- Don't reach for module hierarchy to express "A uses B" — reach for a
  trait/type at the boundary (the `Account` trait is the canonical example).
- Keep the sans-IO core free of async/network deps so it stays trivially
  testable (feed it `vec![]` of blocks) and embeddable.
- **Tight code, comments explain *why* not *what*.** Match the surrounding
  density; don't narrate the obvious. Discuss structure in prose and converge;
  don't over-formalize or sprint ahead of the agreed change.
- Application-specific logic does not belong here — see **General-purpose, and
  ZNS-blind**.
