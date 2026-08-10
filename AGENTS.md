# AGENTS.md

Working notes for agents (and humans) on **seer-sync**.

## What this is

A **view-key-only Zcash chain sync** library for the **Ironwood era**.
Non-spendable wallet: given a viewing key, accurately track every note and
spend you can see from lightwalletd compact blocks.

| Key | Capability |
|-----|------------|
| **UIVK** | Incoming notes only (no nullifiers → no spends) |
| **UFVK** | Notes + spends (nullifier keys) + sent recovery (OVKs) |

The engine accepts either encoding and pre-derives per-pool scanning keys
in `src/sync/decrypt.rs`. `UnifiedFullViewingKey` and
`UnifiedIncomingViewingKey` are the only two supported user key types.

## Sibling crates (this monorepo)

| Path | Role |
|------|------|
| `../zns-orchard` | **Our orchard** (fork of upstream 0.15.5 + `unsafe-zns`). Path + version + `[patch.crates-io]`. |
| `../zns-verify` | ZNS commitment verify + optional relaxed Ironwood decrypt (`zns-decrypt` feature). |
| `../zns-resolver` | App consumer: `impl Account`, enables `zns-decrypt`, also patches orchard → zns-orchard. |

**Always one orchard identity** in the monorepo:

```toml
orchard = { version = "0.15.5", path = "../zns-orchard", default-features = false, features = ["std"] }

[patch.crates-io]
orchard = { path = "../zns-orchard" }
```

`version` is required for crates.io publish (path is stripped); `path` + `patch`
keep local builds on zns-orchard so types unify with zcash_keys/primitives.
Never leave the graph on two orchard versions.

## Dependency boundary

**IN** — protocol / keys / crypto only (Ironwood stack):

| Crate | Pin |
|-------|-----|
| orchard | path `../zns-orchard` (0.15.5) |
| sapling-crypto | 0.7 |
| zcash_note_encryption | 0.4 |
| zcash_protocol | 0.10 |
| zcash_keys | 0.15 |
| zcash_primitives | 0.29 |
| zcash_transparent | 0.9 |
| zip32 | 0.2 |
| tonic / prost / tokio | gRPC + async driver |

MSRV: **1.88**. Errors: **thiserror only** (no anyhow).

**OUT** — never depend on:

- `zcash_client_backend`
- `zcash_client_sqlite`

We hand-roll: vendored lightwalletd protos (client stubs only), raw rusqlite
`Db`, our own `run` engine, and (opt-in) shardtree + a vendored ~120-line shard
codec — not the wallet framework.

Line: **know the protocol** vs **be a wallet framework**.

**Upstream-first for protocol primitives.** The IN crates already provide the
correct abstractions for note encryption (`zcash_note_encryption::Domain` /
`BatchDomain`), key derivation (`zcash_keys`, `zip32`), and protocol types
(`zcash_protocol`, `zcash_primitives`, `sapling-crypto`, `orchard`). Use them.
Only hand-roll the wallet-framework layer that is off-limits (`OUT` crates)
or specific to this engine (sync loop, `Account` trait, raw storage).

## Features

| Feature | What it enables |
|---------|-----------------|
| *(default none)* | Engine + keys + scan; bring your own `Account` |
| `db` | Reference SQLite `Db`, `sync()`, read path |
| `commitment-tree` | Requires `db`. Every Orchard `cmx` + shardtree witnesses |
| `zns-decrypt` | Layers Ironwood Name Note trial-decrypt (via `zns-verify`) **on top of** standard Orchard — does not replace it |

Standard Ironwood shielded outputs (V3 note plaintext) are handled by
`IronwoodDomain` through `zcash_note_encryption`, exactly like Orchard
outputs. The `zns-decrypt` feature adds only the relaxed Ironwood Name
Note trial-decrypt path via `zns-verify`.

### Decrypt order (with `zns-decrypt`)

1. **Standard Orchard** — `OrchardDomain`, ZIP-212 / cmx check (lead byte `0x02`).
2. **Unclaimed actions only** — relaxed Ironwood via `zns-verify` (V3 / Name Notes; no cmx check; caller verifies bindings).

Default (no feature): step 1 only. Application logic (names, memos-as-commands,
`verify_name_note`) stays in the consumer (`zns-resolver`), not here.

## Layout

```
src/
  lib.rs          public re-exports + feature-gated sync()
  decrypt.rs      view-key capability preparation; per-pool compact/full
                  decryption via `zcash_note_encryption`; parse helpers
  proto.rs        include! of build.rs output (client stubs only)
  sync.rs         run(), Account, Batch, Cursor, Resume, SyncError<E>
  sync/
    chain.rs      only I/O — lightwalletd connect/stream/fetch (BlockHeight-typed)
    scan.rs       sans-IO: scan_compact, enrich_memos, scan_sent, scan_commitments, …
    transparent.rs BIP-44 gap-limit discovery
  db.rs           feature `db` — SQLite Account + schema + reads
  db/
    commitment_tree.rs          feature `commitment-tree`
    shardtree_serialization.rs
```

## Public engine API

### `Account`

Fold over the chain. One associated error type (not boxed):

```rust
trait Account {
    type Error: Error + Send + Sync + 'static;

    fn resume(&self) -> Result<Resume, Self::Error>;
    fn rewind(&self, to: BlockHeight) -> Result<(), Self::Error>;
    fn apply(&self, at: Cursor, batch: &Batch) -> Result<(), Self::Error>;
    fn wants_commitments(&self) -> bool { false }  // opt-in cmx firehose
}
```

| Type | Meaning |
|------|---------|
| `Resume` | birthday, optional checkpoint `Cursor`, watched nullifiers + outpoints |
| `Cursor` | fully applied height + optional seam `BlockHash` |
| `Batch` | notes, spends, transparent outs/spends, optional commitments |

`run(client, keys, network, account) -> Result<Option<Cursor>, SyncError<A::Error>>`.

### Errors

```text
SyncError<E>  = Chain(ChainError) | Key(KeyError) | Account(E)
DbError       = Sqlite(...) | BirthdayUnset          // feature db
ChainError    = Reorg(BlockHeight) | Rpc | Connect | …
```

`From<ChainError>` / `From<KeyError>` for `SyncError<E>` are **hand-written** —
`thiserror`'s `#[from]` does not emit them on a generic enum. Do not reintroduce
`AccountError = Box<dyn Error>`.

### Heights

Public chain API uses **`BlockHeight`** / **`BlockHash`**, not raw `u32` /
`[u8; 32]`, at the edges:

- `tip` / `tip_height` / `blocks(from, to, …)` / `fetch_taddress_transactions`
- `ChainError::Reorg(BlockHeight)`
- `Db::set_birthday(BlockHeight)`
- `connect_auto(Network)` picks mainnet vs testnet lightwalletd lists

Proto still speaks `u64` heights internally; convert at the boundary.

## Sync loop (`run`)

Persistence-free: never opens the consumer's store. Only calls `Account`.

```
resume → discover transparent (whole life, gap-limit)
      → stream blocks [start, tip] (chunked, backpressured)
      → scan_compact → fetch full txs → enrich_memos / scan_sent / scan_transparent
      → optional scan_commitments
      → apply(Cursor, Batch)
reorg  → rewind → double step → re-resume
transport fault → bounded retry from checkpoint
```

- **One stream to tip.** Chunk by `DEFAULT_CHUNK_OUTPUTS` or `DEFAULT_CHUNK_BLOCKS`
  (whichever first). `channel(1)` keeps download one batch ahead of decrypt.
- **Crash-safe cursor.** `apply` must persist batch + cursor atomically.
- **Reorgs.** Single detector in `download` (`prev_hash` chain, seeded by seam).
  `Reorg` → rewind with growing step until seam reconnects.
- **Two-phase scan.** Compact trial decrypt, then full-tx for memos / sent / t-addrs.
- **Transparent** rides the same loop (stateless discovery → whole-life window).

## Schema (`db` feature), in one breath

Single-account SQLite (WAL): birthday + sync cursor on `account`; `txs`;
`sapling_received_notes` / `orchard_received_notes` (nullifier, spend, position,
memo); transparent UTXOs. Spentness = nullifier / outpoint match.

**Absent by design:** multi-account table, blocks table, `sent_notes` authoring,
`scan_queue`, `nullifier_map`. Witness tables only under `commitment-tree`.

## Testing & benches

```bash
cargo test --features db
cargo test --features db,zns-decrypt
cargo test --features db,commitment-tree
cargo check --features db,zns-decrypt --tests --examples
```

- **Unit / offline:** `src/db.rs` tests, `scan_commitments` position tests,
  `tests/sync_loop.rs` (mock lightwalletd, synthetic compact blocks).
- **No live mainnet integration** in-tree. Prefer deterministic offline fixtures.
- **Bench** `benches/decrypt.rs`: live fetch once in setup, then time
  `scan_compact` only.

## Conventions

1. **Trait at the boundary**, not deeper module hierarchy (`Account` is the model).
2. **Sans-IO scan stays free of async/network** — feed it `&[CompactBlock]`.
3. **Tight code; comments explain why, not what.** Match surrounding density.
4. **Typed errors end-to-end** — associated `Account::Error`, no `Box<dyn Error>`
   on the engine boundary, no `anyhow`.
5. **Do not teach the engine ZNS protocol** (names, verbs, prev_rcm). The
   `zns-decrypt` feature only supplies the decrypt *path*; verification stays
   in `zns-verify` / the consumer.
6. **Keep orchard unified** — path + patch to `zns-orchard`; never leave
   zcash_* on crates.io orchard 0.14 while this crate is on 0.15.
7. **Upstream-first for protocol primitives.** If a crate in the IN list
   already defines the abstraction, use it. Do not write parallel
   ChaCha20Poly1305, KDF, key-agreement, note-plaintext, or domain-specific
   decrypt code. `zcash_note_encryption` provides generic trial decryption
   for Sapling, Orchard, and Ironwood; use it directly.

## Out of scope (for now)

- Live mempool (`GetMempoolStream`)
- Spend / transaction authoring
- Multi-account wallets
- Being a drop-in `zcash_client_*` replacement
```
