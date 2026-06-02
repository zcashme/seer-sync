# seer-sync — Architecture

## Thesis

seer-sync is a **view-key Zcash sync library**: given a viewing key, detect the value moving in and out of what that key controls — without ever holding spend authority. Today a SQLite database is baked into its core, so the valuable sync machinery can't be used without swallowing a schema. The redesign **flips the dependency**: persistence becomes a *consumer* built around a persistence-free engine, and seer-sync's own database is demoted to "consumer zero."

## Master diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║                     seer-sync  —  SYNC LIBRARY                             ║
║                                                                            ║
║  ┌── CORE (no feature · sans-IO · no tokio/tonic/rusqlite) ─────────────┐  ║
║  │                                                                       │  ║
║  │   proto::messages(prost)   keys(ScanningKeys)   note(decrypt, memo)   │  ║
║  │        │                        │                                     │  ║
║  │        ▼                        ▼                                     │  ║
║  │   ┌───────────────────────────────────────────┐                      │  ║
║  │   │  scan   (pure trial-decryption)            │  blocks + keys       │  ║
║  │   │  &[CompactBlock] + ScanningKeys → findings │  → Tx events         │  ║
║  │   └────────────────────┬────────────────────────┘                     │  ║
║  └────────────────────────┼──────────────────────────────────────────────┘ ║
║                           │ uses                                            ║
║  ┌── sync/  #[cfg(lwd)] · "talk to lightwalletd" ──────────────────────┐   ║
║  │   tonic · tokio · zcash_primitives · futures · http                  │   ║
║  │                        │                                              │   ║
║  │   chain (gRPC stream, reorg DETECT) ── enrich (fetch full tx, memos)  │   ║
║  │                        │                                              │   ║
║  │   ┌────────────────────▼─────────────────────────────────────────┐   │   ║
║  │   │  engine   (the apex — persistence-FREE orchestration)         │   │   ║
║  │   │                                                               │   │   ║
║  │   │  run_pass(client, keys, start: BlockHeight, seam, sink)       │   │   ║
║  │   │     • streams [start..=tip] in chunks                         │   │   ║
║  │   │     • scan + enrich each chunk                                │   │   ║
║  │   │     • HANDLES transport faults itself (in-mem resume)         │   │   ║
║  │   │     • ESCALATES reorg (cannot touch consumer state)           │   │   ║
║  │   │                                                               │   │   ║
║  │   │   data plane   ──►  sink(scanned_height, &found)  per chunk   │   │   ║
║  │   │   control plane ─►  returns PassOutcome::{ Done, Reorg{at} }   │   │   ║
║  │   └───────────────────────────┬───────────────────────────────────┘   │   ║
║  └───────────────────────────────┼───────────────────────────────────────┘ ║
╚══════════════════════════════════┼═════════════════════════════════════════╝
       (height, findings) ▼ data    │    ▲ control PassOutcome
        ┌──────────────────────┬────┴───────────────────────┐
        │ depends on            │ depends on                  │ depends on
┌───────┴──────────────┐   ┌────┴───────────────────┐  ┌──────┴───────────────┐
│  seer-sync::db        │   │  any wallet            │  │  any other consumer   │
│  #[cfg(db)] · rusqlite │   │  (own store)           │  │  (own store)          │
│                       │   │                        │  │                       │
│  REFERENCE CONSUMER:  │   │  sink: apply Tx →       │  │  sink: whatever        │
│  sink: apply Tx →     │   │   wallet state         │  │                       │
│   notes/spends/       │   │  owns cursor + seam    │  │  owns cursor + seam    │
│   positions           │   │                        │  │                       │
│  owns cursor + seam   │   │                        │  │                       │
└───────────────────────┘   └────────────────────────┘  └───────────────────────┘
   every consumer owns its outer loop · its store · its cursor · rewinds on Reorg
```

## 1. Crate architecture — the flip

- **Today (broken):** `sync::engine` does `use crate::db::Db` and lives behind `#[cfg(feature = "db")]`. The resume-cursor loop, the reorg walk-back, and transport retry — the genuinely hard, valuable logic — are welded to a concrete SQLite schema and its private `apply()`. A consumer's only choices were: adopt seer-sync's entire note schema, or reimplement the reorg machinery. (The old per-decrypt `ScanCallback`, since removed, didn't fix this — it still made the consumer own the loop.)
- **Fixed:** `db ──▶ engine`. The engine moves into the always-compiled core, drops every `use crate::db`, and *emits* results. The database becomes a consumer like any other — proof the seam works, not the thing the engine serves.

## 2. Module separation

- **`scan` leaves `sync.rs`.** Today the pure scan core shares a module with the async orchestration — which is precisely why they couldn't be feature-gated apart. `scan` becomes a top-level, always-compiled core module. `sync/` retains `chain` + `enrich` + `engine`.
- **`note` is a sibling utility.** `note::decrypt` feeds `enrich`; `note::memo` is a free-standing ZIP-302 decoder for consumers. **`note` does not feed `scan`** — scan performs its own batch trial-decryption inline against the `orchard`/`sapling` crates.

## 3. Feature architecture

```
default = ["lwd"]
lwd = [tonic, tonic-prost, tokio, tokio-stream, http, futures, zcash_primitives]
      → chain, enrich, engine, proto::client
db  = ["dep:rusqlite"]
```

Three states, each gating a real dependency cluster:

- **core** (no feature) — a pure decryptor: `blocks + key → findings`. No async runtime, no network, no SQLite. A test, an offline verifier, or a consumer that already holds blocks pays for none of it.
- **`lwd`** — "talk to lightwalletd" (the only server that serves compact blocks, so name it after the protocol). The gRPC client (`chain`), memo enrichment (`enrich`), and the live orchestration loop (`engine`).
- **`db`** — "remember across runs." Optional persistence; the reference consumer.

**proto gating at build time.** proto is generated by `tonic-prost-build` (a build-dependency) into `OUT_DIR` and `include!`d — one blob carrying both prost *message* structs and the tonic *service client*. To keep the core free of tonic, the build script branches on the feature:

```rust
// build.rs
let lwd = std::env::var_os("CARGO_FEATURE_LWD").is_some();
tonic_prost_build::configure()
    .build_client(lwd)      // emit the tonic client only when `lwd` is on
    .build_server(false)
    .compile_protos(&["proto/service.proto"], &["proto"])?;
```

`CARGO_FEATURE_LWD` is Cargo's own variable — it sets `CARGO_FEATURE_<NAME>=1` for every enabled feature. It's the only channel a build script has (the script runs before compilation, so it can't see `#[cfg]`). Standard, battle-tested pattern. No manual `proto::messages` / `proto::client` source split needed; the generator decides.

## 4. The spine — chain-height

The cursor is **not** a struct; it is a `BlockHeight`. A bundled `BlockLink { height, hash, prev_hash }` would be wrong — it elevates reorg plumbing to spine status. The three answer different questions:

- **`height`** — *"how far am I?"* → THE cursor/spine. A first-class type the whole module speaks in.
- **`hash`** — reorg **seam** material. A consumer keeps a thin `(height → hash)` side-table so it can hand back a seam on resume.
- **`prev_hash`** — **engine-internal only.** Continuity is checked inside a pass (`chain` compares each block's `prev_hash` against the prior block's `hash`). It never crosses the consumer boundary.

### Two watermarks, both in height — only one is the spine

```
  birthday        scanned cursor              download watermark      tip
     ████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░·················
     │   SCANNED          │   in flight (feeder ran ahead)  │  not fetched
     └─ TRUE PROGRESS ────┘                                 └─ FEEDER ONLY
        = spine, persisted, resumed from                       transient

  scanned_height  ≤  download_height  ≤  tip
```

- **`scanned_height`** — blocks actually decrypted *and committed by the consumer*. THE spine: persisted, resumed from. "Watermark" = a monotonic high-water mark — everything ≤ here is done.
- **`download_height`** — how far the feeder pulled off the wire. Runs ahead, pure plumbing, **never persisted.** Blocks are just the feeder; the feeder must never be the spine.

Consequence: `run_pass`'s retry resumes from `scanned_height`, never `download_height`. The feeder may lose its place; the scanner's place is sacred.

## 5. Engine internals — handle vs. escalate

The engine meets exactly two failures, and they are different in kind:

- **Transport fault** (stream drop / timeout) — fixable in place: reconnect and resume from in-memory progress; the consumer never sees it. → **handle.**
- **Reorg** (chain forked) — fixing it means rewinding consumer-owned state the engine can't touch. → **escalate** via `PassOutcome::Reorg`.

```
run_pass(client, keys, start, seam, sink):
  cursor = start, seam = seam            ← in-memory, this call only
  RETRY LOOP (bounded):
    open stream chain::blocks(cursor, tip, seam)
    CHUNK LOOP:
      Ok(blocks)     → scan + enrich → sink(scanned_height, &found)
                       cursor/seam = last block          (advance in-memory)
      Err(Reorg)     → return Ok(PassOutcome::Reorg{ at: cursor })   ESCALATE
      Err(transport) → break to RETRY (reconnect from cursor)        HANDLE
      stream ended   → return Ok(PassOutcome::Done)
```

Two nested resume levels: a dropped stream resumes from the in-memory `scanned_height`; a process crash has the consumer's outer loop restart `run_pass` from its *persisted* cursor. Consistent because the consumer's `sink` commit and the in-memory cursor advance move in lockstep.

## 6. The boundary contract

A **push-based producer/consumer**, single-pass, **synchronous** (no queue between producer and consumer → backpressure is implicit), with a deliberately **split data/control plane**:

- **Data plane:** `sink(scanned_height, &found)`, called once per chunk. Minimal — a height and the findings, nothing else. Decrypted notes/memos ride inside the findings.
- **Control plane:** `PassOutcome::{ Done, Reorg }` as a **return value**, not an event in the stream. If `Reorg` were muxed into the data stream, the consumer would have to rewind its store *while the stream still borrows it* — the borrow tangle. As a return value, the outer loop handles it cleanly.

The consumer owns the outer loop:

```rust
loop {
    let (start, seam) = my_store.resume_point();        // height+1, hash(height)
    match run_pass(client, keys, start, seam, |h, found| my_store.apply(h, found)).await? {
        PassOutcome::Done       => break,
        PassOutcome::Reorg { .. } => my_store.rewind(/* doubling */),
    }
}
```

No store trait — `start`/`seam` are plain inputs; results leave via `sink` + the return value. The consumer's persisted `(height → hash)` *is* the seam source, so **no in-memory `ReorgBuffer` is needed** — each `resume_point()` after a rewind naturally yields the earlier seam.

## 7. The findings model — `Transactions` / `Tx`

The old `Scanned { sapling: Vec<ScannedSapling>, orchard: Vec<ScannedOrchard>, spends }` is rejected as a **god-bag**: three collections fused together; the note shape hand-written twice (pool duplication where a type parameter belonged); fat 9-field records carrying `nf`/`position` that are dead weight for incoming-only consumers.

Two real libraries informed this:

- **zcash-sync** (hhanh00 warp): `DecryptedBlock` keeps the owned raw `CompactBlock` bundled with notes; welded to its own `DbAdapter`.
- **pepper-sync** (zingo): digests blocks to a lean `WalletBlock { height, hash, prev_hash, time, txids, tree_bounds }` and models notes generically as `WalletNote<N, Nf>` with `NoteInterface`/`OutputInterface` — but exposes a multi-trait store (`SyncBlocks`, `SyncNullifiers`, …): the IoC store pattern we reject. Its heavy fields (`tree_bounds`, located/shard trees) exist only to enable spending.

Lessons:

- **Raw-block-vs-digest is dictated by the concurrency model, not taste.** pepper-sync is multi-task over channels → must own → so it digests. zcash-sync is single-threaded-simple → owns the whole block. seer-sync is single-pass with a synchronous sink — but carries neither: height is the spine, notes are findings.
- **Two trait uses, only one is bad:** IoC/store traits (rejected) vs. data-abstraction generics (`WalletNote<N, Nf>` — exactly what `Scanned` lacked). The fix is a generic, not a store trait.
- pepper-sync's witness/tree machinery is spending infrastructure. seer-sync is view-key — it sheds all of it.

**The model:**

- **`Transactions`** — the collection / history: the spends and receives relevant to your key, height-ordered. (Plural dodges `zcash_primitives::Transaction` and names what we actually model — your transactions.)
- **`Tx`** — one member, generic over pool `<N, A>`. Covers both a receive and a spend (one type, two flavors).
- **The nullifier is the through-line.** With a full viewing key, both flavors carry a nullifier: a receive derives its note's `nf` via `nk` (its future spend-tag); a spend is a revealed `nf`. The matching `nf` is the **join key** — a note's lifecycle is born in a receive, consumed in a spend, the same `nf` on both ends. That is why they are one `Tx` type, not two strangers. `nf` is `Option`: `None` for incoming-only (UIVK; spends unmatchable), `Some` with a full key (UFVK; the lifecycle links up).
- A receive flavor additionally carries `note` / `recipient` / `memo`; a spend flavor just closes the lifecycle. Both tagged by height. Not grouped by transaction — that's a wallet/history concern that over-structures a view-key sync.

**Reality check on the full key:** current `scan` only ivk-decrypts (incoming notes) and uses the FVK's `nk` to derive nullifiers for spend detection. There is no `ovk` in the crate (verified) — it does not recover outgoing-note plaintexts. "The full key sees both" means nullifier derivation, not outgoing-note decryption.

## 8. What a consumer is

A consumer is anything that owns a store and drives the outer loop above. It:

1. computes `(start, seam)` from its own persisted cursor (`scanned_height` + the hash at that height),
2. calls `run_pass`, persisting each `(scanned_height, found)` delivery in its `sink` (atomically: findings + cursor advance commit together),
3. on `PassOutcome::Reorg`, rewinds its own store (doubling walk-back) and loops.

seer-sync's `db` is the **reference consumer** — it applies `Tx` events into its SQLite schema (notes, spends, positions, block metadata, cursor). It exists to prove the seam, and stays behind `#[cfg(db)]`.

## 9. Execution order

1. **Extract `scan`** out of `sync.rs` into a top-level core module; move `Scanned`'s replacement types with it.
2. **Feature-gate:** establish core / `lwd` / `db`; add the `build.rs` proto gating off `CARGO_FEATURE_LWD`; flip `default` to `["lwd"]`.
3. **De-weld the engine:** remove `use crate::db::*`; redefine it as `run_pass(... , sink) -> PassOutcome` over `chain`/`enrich`/`scan`; absorb transport retry, escalate reorg.
4. **Replace the `Scanned` god-bag** with `Transactions` / generic `Tx<N, A>` (nullifier as the lifecycle join; receive/spend flavors).
5. **Re-fit `db`** as a `sink` consumer (the reference consumer): own its cursor/seam, apply `Tx`, rewind on reorg. Confirm it builds and round-trips a sync.
6. **Place the walk-back helper** (see open threads) so consumers don't each re-derive the doubling policy.

## 10. Open threads

- **Where the doubling walk-back lives** — duplicated per consumer, or a thin `lwd` helper taking two closures (`resume_point` + `rewind`) so it's written once without a store trait. (Leaning helper.)
- **The findings container** — pool is a type axis, so how do sapling-`Tx` and orchard-`Tx` (different `N, A`) and the receive/spend flavors coexist in one delivered set: two slices, an enum, or per-pool? The per-item `Tx<N, A>` is decided; the container is not.
- **`run_pass` shape** — free async fn + closure sink (current sketch) vs. a stateful `Engine` struct vs. a `Stream`. Leaning free fn.
- **`ScanningKeys` constructors** — should the library support scanning with a single bare pool IVK (not just unified keys)? Fields are currently `pub(crate)`; only `from_uivk`/`from_ufvk` exist. A general capability question, decided on the library's own merits.
- **ovk / outgoing-note recovery** — whether seer-sync ever grows true outgoing-note decryption (would give the spend flavor recovered plaintext).

## Design principles

- **Shape seer-sync from what a view-key sync is** — never reverse-engineered from a particular consumer's wants.
- **No IoC / store traits** (a consumer impersonating a database). Data-abstraction generics are fine and encouraged.
- **No god-bag, no raw blocks in the contract, no spending machinery** (witnesses, shard trees) in a view-key sync.
- **Persistence lives entirely in consumers.** The engine knows only `(start, seam) → events`.
- **Height is the spine.** The cursor is a `BlockHeight`; hashes are reorg plumbing; the feeder watermark is never persisted.

## 11. As-built (implemented)

The §9 execution order is implemented; the crate builds in all three configurations (`--no-default-features` = pure core, default `lwd`, `lwd + db`), `cargo clippy --all-targets` is clean, and the db unit tests pass. Where the build refined the idealized design:

- **Structure — just `sync.rs` + submodules.** No top-level `scan` module and no `engine` module (both were conceptual noise next to `sync`). `src/sync.rs` is the root and holds the `run` loop; `src/sync/{scan,chain,enrich}.rs` are its submodules. `sync::scan` (core, sans-IO) holds `scan`, `Transactions`, `Tx`, `Receive`, `Spend`; `sync::chain` / `sync::enrich` are the `lwd` IO helpers. `src/db/sync.rs` is the reference consumer (gated `lwd` + `db`). `BlockHeight` is a `pub type = u32` alias in `lib.rs` (a real newtype is a later refinement).
- **`scan` vs `sync`.** `scan` is the verb on *data* (decrypt these blocks); the `sync` layer is the verb on *time* (fetch blocks and stay current by repeatedly scanning). `sync::run`'s loop is literally: fetch chunk → `scan` it → enrich → `sink` → advance.
- **Findings container (resolved §10).** `Transactions { orchard: Vec<Tx<orchard::Note, orchard::Address>>, sapling: Vec<Tx<…>> }` — per-pool vecs because pool is a *type* axis. `Tx<N, A>` is an enum: `Receive(Receive<N, A>)` | `Spend(Spend)`. Receives are rich; `Spend` is non-generic (just `nf`/height/txid) and rides its pool's vec. Accessors `Tx::{height, txid, nf}` expose the nullifier join key uniformly.
- **The sink carries the seam hash.** Implemented as `sink(scanned_height: BlockHeight, hash: [u8; 32], &Transactions)`. Height is the spine; `hash` is the reorg seam material the consumer records (per §4); findings are the data. (The idealized `(height, &found)` couldn't give a consumer the hash it needs to resume — the hash rides the watermark, not the findings.)
- **One inline loop — no `PassOutcome` (resolved §10).** Earlier sketches escalated a `PassOutcome { Done, Reorg }` from a `run_pass` and re-entered via a separate `run_to_tip` — ceremony. Replaced by a single `sync::run(client, keys, network, resume_point, rewind, sink)` that handles both faults **inline**: a dropped stream reconnects and resumes from the consumer's cursor; a reorg calls `rewind` (doubling walk-back) and re-resumes. No outcome enum crosses the boundary; `run` returns `Ok(())` once synced. Still persistence-free — consumer state is reached only through the three closures.
- **db consumer.** `db::sync::sync_to_tip(&mut Db, client, keys) -> Result<u32>` wraps `sync::run`, sharing the one `Db` across the three closures via a `RefCell` (they never run concurrently; no borrow is held across an await). Its `apply` writes the block header (hash only — tree sizes/time don't cross the sink), receives, spends, and advances the cursor. Note positions ride on `Receive.position`.

Still open from §10: a true `BlockHeight` newtype; `ScanningKeys::from_orchard_ivk` (bare single-pool IVK); ovk / outgoing-note recovery; per-chunk atomic `apply` (currently individual statements, matching the prior engine).
