# Adding transparent balance tracking to seer-sync

Design notes for wiring the transparent pool, which is **scaffolded but unwired**
today: the schema, db methods, and a UTXO fetch all exist, but nothing derives
transparent addresses or populates the tables, so `balance().transparent_zat` is
always `0`.

## The core asymmetry — transparent is not shielded

Everything about the shielded path leans on one fact: notes are private, so you
find yours by **trial-decrypting compact blocks**. None of that transfers.

- **Compact blocks carry no transparent data.** A `CompactBlock` holds only
  shielded outputs and spends. Transparent inputs/outputs are *not* in the
  compact stream at all — so transparent tracking **cannot ride `scan()`**. It is
  a separate data path.
- **Transparent addresses are public.** You don't decrypt to find your funds; you
  **derive your own addresses** from the key and ask the server's address index
  "what touches these addresses?" via the `GetTaddress*` / `GetAddressUtxos` RPCs.
- **Spends are visible by outpoint, not nullifier.** A transparent output is spent
  when some transaction names it as an input (`prevout_txid:index`) — no
  key-derived nullifier involved.

So this is a bolt-on alongside the shielded loop, not an extension of it.

## What already exists (the scaffold)

- **Schema** (`src/db/schema.rs`):
  - `transparent_received_outputs` — id, transaction_id, output_index, address,
    script, value_zat, `max_observed_unspent_height`.
  - `transparent_received_output_spends` — junction (output ↔ spending tx).
  - `transparent_spend_map` — cache of (spending tx → prevout), so a spend can be
    recorded even if we discover the output it spends *later*.
  - `addresses` — address, `transparent_child_index`, `key_scope` (for gap-limit
    discovery).
- **db methods** (`src/db/mod.rs`): `insert_transparent_output`,
  `mark_transparent_spent`, and `balance()` already sums `transparent_zat`
  (unspent = no *mined* spend). Spentness and mempool fall out of the same model
  as shielded.
- **chain** (`src/sync/chain.rs`): `TransparentUtxo`, `fetch_transparent_utxos`,
  `stream_transparent_utxos` — both over `GetAddressUtxos`. **Zero callers.**

The destination is wired; the producer is missing.

## The RPC tiers (pick fidelity)

The vendored proto exposes three options, in increasing fidelity and cost:

| RPC | Returns | Fits our model? | Cost |
|---|---|---|---|
| `GetTaddressBalance` | one summed number for an `AddressList` | No — opaque, trusts the server's arithmetic, no per-UTXO/spend detail | trivial |
| `GetAddressUtxos` | current **unspent** UTXOs (txid, index, script, value, height) — *already wired* | Partly — a snapshot, not a history | one call per refresh |
| `GetTaddressTransactions` | stream of **full `RawTransaction`s** touching an address in a height range | Yes — parse vout (received) + vin (spends) | a full-tx fetch per touching tx |

(`GetTaddressTxids` is the deprecated alias of `GetTaddressTransactions`.)

## The missing work

### 1. Address derivation + gap-limit discovery (the real new surface)

A UFVK/UIVK with a transparent component carries an extended pubkey. From it,
derive transparent (P2PKH) addresses at child indices using `zcash_keys` /
`zcash_transparent` (we already enable the `transparent-inputs` feature).

- **Gap limit:** derive indices 0, 1, 2, … querying as you go, and stop after
  `gap_limit` consecutive *unused* addresses (BIP-44 style). Store discovered
  addresses in the `addresses` table with their `transparent_child_index` and
  `key_scope`.
- **Scopes:** external vs internal(change) vs refund. A view-only tracker
  realistically wants **external + refund** (where funds *arrive*); internal/change
  is optional. Make it configurable; default conservatively.
- **Question first:** does the tracked key even *have* a transparent component?
  Many UFVKs are shielded-only. If `ufvk.transparent()` is `None`, transparent
  tracking is a no-op — don't derive, don't query, leave `transparent_zat = 0`
  honestly.

### 2. Fetch + reconcile

**Snapshot path (start here — reuses the already-wired `fetch_transparent_utxos`):**
- Call `GetAddressUtxos` for all known addresses → the current unspent set.
- For each UTXO: `upsert_transaction(txid, height)` then `insert_transparent_output(...)`.
- Spend detection by diff: any output previously stored but **absent** from the
  new unspent set was spent. Caveat: this RPC doesn't reveal the *spending* txid,
  so you can mark it spent but not link the spender. `max_observed_unspent_height`
  is the column for tracking how current each output is.

**History path (fuller fidelity, later):**
- `GetTaddressTransactions` over `[birthday, tip]` → each full tx.
- **Reuse the memo machinery:** parse with `zcash_primitives::transaction::Transaction::read`
  (already a dependency from memo enrichment).
- `vout` → `transparent_received_outputs` for our addresses; `vin` → spends, via
  `mark_transparent_spent(prevout_txid, prevout_index, spending_tx)`. This
  populates the spend junction *with the spender*, fits the model exactly, and is
  reorg-safe.

### 3. Integration into the sync loop

Transparent refresh is a **separate step**, not part of `scan()`. Cleanest shape:
a `refresh_transparent(db, client, keys, network)` called from `sync_to_tip`
*after* the shielded loop reaches the tip (transparent has no compact-block
dependency, so order is free).

- **Cursor:** `GetAddressUtxos`/`GetTaddressTransactions` take a `start_height`.
  Track the last transparent-synced height — either a new column in `sync_state`
  or a dedicated marker — so refreshes are incremental, not full-history every
  time.

### 4. Reorgs — mostly free

Transparent outputs link to mined transactions, and `rewind_to_height` already
`DELETE`s transactions above the rewind point, cascading to
`transparent_received_outputs` and the spend junctions. So the existing reorg
walk-back covers transparent **as long as each output is linked to a mined
transaction at the correct height** (which `upsert_transaction(txid, height)`
ensures). One caveat: the transparent cursor must rewind alongside the shielded
one.

## Recommended path

1. **Address derivation + gap-limit** — unavoidable foundation; the rest is inert
   without it. Guard on "does the key have a transparent component."
2. **Snapshot via `GetAddressUtxos`** for a working, honest `transparent_zat` with
   minimal new code (the fetch already exists). Accept lossy spend-linking for v1.
3. **Upgrade to `GetTaddressTransactions` + full-tx parsing** when you want
   complete spend history with the spender recorded — reuses the memo path's
   `Transaction::read`.

## Open decisions

- Which scopes to scan (external / internal / refund)?
- Gap-limit value (10? 20?) and whether it's caller-configurable.
- Snapshot vs full-history fidelity for the first cut.
- Where the transparent cursor lives (`sync_state` column vs separate marker).
- Whether transparent is always-on or gated/conditional on the key carrying a
  transparent component (lean toward: always attempt, no-op when absent).

## Boundary check

Both new dependencies stay inside the "know the protocol, don't be a wallet
framework" line: `zcash_keys`/`zcash_transparent` for address derivation (already
depended on), and the `GetTaddress*`/`GetAddressUtxos` RPCs from the vendored
lightwalletd proto. No `zcash_client_backend`. Consistent with the rest of
seer-sync.
