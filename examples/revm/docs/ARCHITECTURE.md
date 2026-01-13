# REVM Example Architecture

This document walks through the REVM simulation example with a top-down view that emphasizes the domain model (blocks, transactions, QMDB-rooted state) and the runtime components that operate on it. The diagram in `examples/revm/docs/revm_architecture.png` sketches the major flows described below.

## 1. High-Level Workflow

1. **CLI entry point** (`examples/revm/src/main.rs`): Parses `nodes`, `blocks`, and `seed` flags, then calls `simulate(cfg)`.
2. **Simulation harness** (`examples/revm/src/sim/mod.rs`): Runs on a deterministic Tokio executor, sets up the DKG/network, then starts `N` nodes and waits for a finalized head. This is the orchestration layer that keeps the demo deterministic and observable.
3. **Nodes**: Each node wires together:
   - **Consensus (Threshold Simplex)**: Orders block commitments and emits notarization/finalization events.
   - **Marshal**: Delivers blocks over the simulated network and requests ancestors when needed.
   - **Application** (`examples/revm/src/application/app.rs`): Handles proposing/verifying full REVM blocks and maintains local state snapshots.
4. **Reporters**: The `SeedReporter` captures seeds from simplex activity, and the `FinalizedReporter` replays finalized blocks, verifies execution via QMDB, persists snapshots, and notifies the harness when a block is processed.

## 2. Domain Model

| Term | Description | File |
|------|-------------|------|
| **Block** | Parent pointer, height, prevrandao seed, state root, transactions. Blocks are encoded/decoded via `examples/revm/src/types.rs` and committed via the simplex digest. | `examples/revm/src/types.rs` |
| **Tx** | Minimal transaction (from, to, value, gas limit, calldata) with deterministic codec for gossip. | `examples/revm/src/types.rs` |
| **StateChanges & QmdbChanges** | Deterministic encodings of touched accounts/storage used for rolling commitments and QMDB persistence. | `examples/revm/src/commitment.rs`, `examples/revm/src/qmdb/persist.rs` |
| **StateRoot** | Hash combining QMDB partition roots plus a namespace tag, ensuring authenticated state. | `examples/revm/src/qmdb/mod.rs`, `examples/revm/src/types.rs` |

## 3. Core Components

### Ledger View (`examples/revm/src/application/state.rs`)

- Holds the mempool, per-digest snapshots, seed cache, and persisted digest set.
- Stores snapshots as `LedgerSnapshot` (parent digest, `RevmDb`, `StateRoot`, `QmdbChanges`).
- Provides helpers to preview roots (without durably writing) and to persist snapshots via `QmdbState`.

### QMDB Adapter & Persistence

- `QmdbState` opens partitioned stores (`accounts`, `storage`, `code`) and exposes:
  - `database()` → a `CacheDB`/`WrapDatabaseAsync` adapter to satisfy REVM's sync API.
  - `preview_root()` → computes the state commitment that would result from staged changes.
  - `commit_changes()` → applies the batch, updates the in-memory stores, and returns the new root.
- `QmdbChanges`, `AccountUpdate`, and `AccountRecord` translate REVM's `EvmState` into authenticated batches keyed by addresses, storage slots, and code hashes.

### Execution Layer (`examples/revm/src/execution.rs`)

- `execute_txs` uses Alloy/REVM with a custom seed precompile to run each tx in the provided `RevmDb`.
- After each transaction it:
  1. Builds deterministic `StateChanges` for commitment verification.
  2. Applies touched accounts to a `QmdbChanges` batch.
  3. Commits the changes back to `RevmDb`.
- The `ExecutionOutcome` contains both the per-tx `StateChanges` and the aggregated `QmdbChanges`.

### Application (`examples/revm/src/application/app.rs`)

- `RevmApplication` implements `Application`/`VerifyingApplication` for consensus integration.
- On `propose`, it:
  1. Collects mempool transactions while avoiding duplicates via ancestor scanning.
  2. Executes the transactions using the shared `RevmDb`.
  3. Previews the resulting QMDB root and updates the ledger view with the snapshot.
- On `verify`, it replays the block to recompute the root and ensures it matches the declared `state_root`.

### Reporters (`examples/revm/src/application/reporters.rs`)

- `SeedReporter` watches simplex activity and writes hashed seeds into the ledger view so `RevmApplication` can populate future `prevrandao`.
- `FinalizedReporter` reacts to `marshal::Update::Block`:
  1. Replays the block via `execute_txs` if it's not already finalized.
  2. Validates the computed root against the block.
  3. Persists the snapshot through `QmdbState`.
  4. Prunes the mempool, acknowledges Marshal, and emits finalized events to the simulation harness.

### Ledger Aggregates & Services (`examples/revm/src/application/state.rs`)

- **Mempool**: owns pending transactions and exposes insert/build/prune commands so proposals and finalizers work against a consistent queue.
- **SnapshotStore**: maintains `LedgerSnapshot`s plus the persisted digest set, handles ancestor lookups, merges pending `QmdbChanges`, and tracks which digests have been committed.
- **SeedCache**: keeps per-digest seed hashes so the deterministic `prevrandao` values are pulled from a shared source.
- **LedgerService**: domain service that wraps `LedgerView` and exposes high-level commands (`submit_tx`, `build_txs`, `parent_snapshot`, `preview_root`, `insert_snapshot`, `persist_snapshot`, `prune_mempool`, `seed_for_parent`, `set_seed`, `query_state_root`). The application and reporters talk to `LedgerService` instead of mutating the aggregates directly.

## 4. Flows Illustrated

1. **Proposal Flow**:
   - CLI invokes simulation → `LedgerService` ingests submitted transactions and keeps them in the `Mempool`.
   - `RevmApplication` asks the service for the parent snapshot, builds a proposal batch, executes it, previews the root via `SnapshotStore`, and records a new `LedgerSnapshot`.
   - The computed state root travels with the proposed block, while the snapshot remains available for replay and persistence.

2. **Finalization Flow**:
   - Marshal delivers a finalized block to `FinalizedReporter`.
   - The reporter replays the block, validates the root, and commands `LedgerService` to persist the authenticated updates (marking the digest in `SnapshotStore` and committing via `QMDBState`).
   - `LedgerService` prunes the `Mempool`, and the simulation harness observes the `finalized` domain event so other nodes can progress.

3. **Seed Flow**:
   - `SeedReporter` listens to simplex notarizations/finalizations, hashes each seed, and stores it in the `SeedCache` through `LedgerService`.
   - `RevmApplication` reuses the cached seed when computing `prevrandao` for future proposals.

## 5. Diagram

See `examples/revm/docs/revm_architecture.png` for the visual layout of these components. The diagram mirrors the textual flows above (CLI → Simulation → Nodes → Reporters → QMDB).

## 6. Applying DDD to the Example

The architecture description above already hints at a domain-driven mindset. To make the terminology and structure easier to reason about in future refactors, here is the lightweight DDD methodology we can follow for the REVM example:

1. **Ubiquitous language** – Keep using the nouns introduced earlier (`Node`, `LedgerSnapshot`, `LedgerView`, `QmdbLedger`, `BlockBundle`, `SeedReporter`, `FinalizedReporter`) across documentation and code so every contributor thinks in the same terms.
2. **Bounded contexts** – Treat the simulation harness, consensus/marshal delivery, application execution, and QMDB persistence as separate languages. Within each context, group related types and services (`simulate`/`FastRunner`, `node::start_all_nodes` + reporters, `RevmApplication` + `execute_txs`, `QmdbState` + persist helpers) and avoid leaking implementation details between them.
3. **Entities/Aggregates & Value Objects** – Model mutable, identity-bearing state as entities/aggregates such as `LedgerView` (mempool, snapshots, persisted digests) and `LedgerSnapshot` (parent digest, `RevmDb`, state root, `QmdbChanges`). Keep blocks, transactions, and state roots as value objects with deterministic encodings.
4. **Domain services & events** – Capture behaviors that span aggregates in services (e.g., `FinalizedReporter`’s replay-and-persist routine) and surface domain events (`Finalized events` channel) so other contexts (simulation harness) can react without tight coupling.

Following these steps before refactoring helps ensure any future API or module split feels natural, uses shared vocabulary, and keeps the executable flows (proposal/finalization/seed) grounded in the domain model outlined above.
