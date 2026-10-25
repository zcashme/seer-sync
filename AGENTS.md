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
| `../zns-verify` | ZNS commitment verify + the relaxed Ironwood domain (`decrypt` feature), which `zns-decrypt` turns on. |
| `../zns-resolver` | App consumer: `impl Account`, enables `zns-decrypt`, patches orchard → the zns-orchard fork in its own build. |

**Always one orchard identity**: this crate depends on crates.io `orchard`,
the same package `zcash_keys` and `zcash_primitives` use. It never depends on
the zns-orchard fork; a binary that needs the fork swaps it in with its own
`[patch.crates-io]`, and this crate builds against it unchanged.

## Dependency boundary

**IN** — protocol / keys / crypto only (Ironwood stack):

| Crate | Pin |
|-------|-----|
| orchard | 0.16 |
| sapling-crypto | 0.9 |
| zcash_note_encryption | 0.5.1 |
| zcash_protocol | 0.11 |
| zcash_keys | 0.17 |
| zcash_primitives | 0.31 |
| zcash_transparent | 0.11 |
| zip32 | 0.3 |
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
| `zns-decrypt` | Turns on `zns-verify/decrypt`: Ironwood actions are trial-decrypted with zns-verify's `ZnsIronwoodDomain`, and each result is routed by the rseed guard — self-consistent notes take the ordinary path; the rest are surfaced unverified (`WalletTx.relaxed_ironwood_outputs`) for the caller to check bindings. |

Standard Ironwood shielded outputs (V3 note plaintext) are handled by
`IronwoodDomain` through `zcash_note_encryption`, exactly like Orchard
outputs.

### Decrypt order (with `zns-decrypt`)

One unified pass: Ironwood actions are trial-decrypted with zns-verify's
`ZnsIronwoodDomain` and each result is routed by the rseed guard —
self-consistent notes take the ordinary path (byte-identical to the standard
domain), the rest surface as unverified candidates for the consumer to check
(`zns_verify::verify_name_note`). Application logic (names, memos-as-commands, binding verification)
stays in the consumer (`zns-resolver`), not here.

Default (no feature): standard `IronwoodDomain` only — Name Notes remain
invisible.

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
    fn rewind(&self, to: Cursor) -> Result<(), Self::Error>;  // keep ≤ to; to is the checkpoint
    fn apply(&self, at: Cursor, batch: &Batch) -> Result<(), Self::Error>;
    fn wants_commitments(&self) -> bool { false }  // opt-in cmx firehose
}
```

| Type | Meaning |
|------|---------|
| `Resume` | birthday, optional checkpoint `Cursor`, watched nullifiers + outpoints |
| `Cursor` | fully applied height + optional seam `BlockHash` |
| `Batch` | notes, spends, transparent outs/spends, optional commitments |

`run(client, keys, params, account) -> Result<(), SyncError>`.

### Errors

```text
SyncError     = Chain(RpcError) | Connect(NoServer) | ViewKey
              | Scan(ScanError) | Transaction { txid, source } | Account { source }
DbError       = Sqlite(...) | Corrupt(String)
```

### Heights

Public chain API uses **`BlockHeight`** / **`BlockHash`**, not raw `u32` /
`[u8; 32]`, at the edges:

- `tip` / `tip_height` / `blocks(from, to, …)` / `fetch_taddress_transactions`
- `ChainError::Reorg(BlockHeight)`
- `Db::set_birthday(BlockHeight)`
- `connect_auto(&params)` picks the lightwalletd list from `params.network_type()`

Proto still speaks `u64` heights internally; convert at the boundary.

## Sync loop (`run`)

Persistence-free: never opens the consumer's store. Only calls `Account`.

```
resume → discover transparent (whole life, gap-limit)
      → stream blocks [start, tip] (chunked, backpressured)
      → scan_compact → fetch full txs → enrich_memos / scan_sent / scan_transparent
      → optional scan_commitments
      → apply(Cursor, Batch)
reorg  → drop buffer → rewind(Cursor) only if fork ≤ checkpoint → re-resume
transport fault → bounded retry from checkpoint
```

- **One stream to tip.** Chunk by `DEFAULT_CHUNK_OUTPUTS` or `DEFAULT_CHUNK_BLOCKS`
  (whichever first). `channel(1)` keeps download one batch ahead of decrypt.
- **Crash-safe cursor.** `apply` must persist batch + cursor atomically.
- **Reorgs.** Single detector in `download` (`prev_hash` chain, seeded by seam).
  Unapplied blocks are a cache: a reorg drops them and restarts from the
  checkpoint. Applied blocks are rewound to a known-applied `Cursor` with a
  growing step until the seam reconnects; with no applied hash in the window,
  rewind `MAX_REORG_DEPTH` (100) below and trust the server's hash.
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

## Conventions

1. **Trait at the boundary**, not deeper module hierarchy (`Account` is the model).
2. **Sans-IO scan stays free of async/network** — feed it `&[CompactBlock]`.
3. **Tight code; comments explain why, not what.** Match surrounding density.
4. **Typed errors end-to-end** — associated `Account::Error`, no `Box<dyn Error>`
   on the engine boundary, no `anyhow`.
5. **Do not teach the engine ZNS protocol** (names, verbs, prev_rcm). The
   `zns-decrypt` feature only supplies the decrypt *path*; verification stays
   in `zns-verify` / the consumer.
6. **Keep orchard unified** — crates.io `orchard` only, never the fork, and
   no `[patch]` here (it is stripped on publish).
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
