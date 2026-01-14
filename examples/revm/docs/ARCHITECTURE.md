# REVM Example Architecture

This document walks through the REVM simulation example with a top-down view that emphasizes the domain model (blocks, transactions, QMDB-rooted state) and the runtime components that operate on it. The diagram in `examples/revm/docs/revm_architecture.png` sketches the major flows described below.

## 1. High-Level Workflow

1. **CLI entry point** (`examples/revm/src/main.rs`): Parses `nodes`, `blocks`, and `seed` flags, then calls `simulate(cfg)`.
2. **Simulation harness** (`examples/revm/src/simulation/mod.rs`): Runs on a deterministic Tokio executor, derives threshold schemes, builds the `BootstrapConfig`, sets up the network, then starts `N` nodes and waits for a finalized head. This is the orchestration layer that keeps the demo deterministic and observable.
3. **Nodes**: Each node wires together:
   - **Consensus (Threshold Simplex)**: Orders block commitments and emits notarization/finalization events.
   - **Marshal**: Delivers blocks over the simulated network and requests ancestors when needed.
   - **Application** (`examples/revm/src/application/app.rs`): Handles proposing/verifying full REVM blocks and maintains local state snapshots.
4. **Reporters**: The `SeedReporter` captures seeds from simplex activity, and the `FinalizedReporter` replays finalized blocks, verifies execution via QMDB, persists snapshots, and notifies the harness when a block is processed.

## 2. Domain Model

| Term | Description | File |
|------|-------------|------|
| **Block** | Parent pointer, height, prevrandao seed, state root, transactions. Blocks are encoded/decoded via `examples/revm/src/domain/types.rs` and committed via the simplex digest. | `examples/revm/src/domain/types.rs` |
| **Tx** | Minimal transaction (from, to, value, gas limit, calldata) with deterministic codec for gossip. | `examples/revm/src/domain/types.rs` |
| **BootstrapConfig** | Genesis allocation plus bootstrap transactions applied before consensus starts. | `examples/revm/src/domain/types.rs` |
| **StateChanges & QmdbChanges** | Deterministic encodings of touched accounts/storage used for rolling commitments and QMDB persistence. | `examples/revm/src/domain/commitment.rs`, `examples/revm/src/qmdb/changes.rs` |
| **StateRoot** | Hash combining QMDB partition roots plus a namespace tag, ensuring authenticated state. | `examples/revm/src/qmdb/mod.rs`, `examples/revm/src/domain/types.rs` |

## 3. Core Components

### Ledger View (`examples/revm/src/application/ledger/mod.rs`)

- Holds the mempool, per-digest snapshots, seed cache, and persisted digest set.
- Stores snapshots as `LedgerSnapshot` (parent digest, `RevmDb`, `StateRoot`, `QmdbChanges`) in `examples/revm/src/application/ledger/snapshot_store.rs`.
- Provides helpers to preview roots (without durably writing) and to persist snapshots via `QmdbLedger`.

### QMDB Adapter & Persistence

- `QmdbLedger` (`examples/revm/src/qmdb/service.rs`) orchestrates partitioned stores (`accounts`, `storage`, `code`) through `QmdbState` (`examples/revm/src/qmdb/state.rs`) and exposes:
  - `database()` → a `QmdbRefDb` adapter (`examples/revm/src/qmdb/adapter.rs`) to satisfy REVM's sync API.
  - `preview_root()` → computes the state commitment that would result from staged changes.
  - `commit_changes()` → applies the batch, updates the in-memory stores, and returns the new root.
- `QmdbChanges`, `AccountUpdate`, and `AccountRecord` live in `examples/revm/src/qmdb/changes.rs` and `examples/revm/src/qmdb/model.rs` and translate REVM's `EvmState` into authenticated batches keyed by addresses, storage slots, and code hashes.

### Execution Layer (`examples/revm/src/application/execution.rs`)

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

### Reporters (`examples/revm/src/application/reporters/seed.rs`, `examples/revm/src/application/reporters/finalized.rs`)

- `SeedReporter` watches simplex activity and writes hashed seeds into the ledger view so `RevmApplication` can populate future `prevrandao`.
- `FinalizedReporter` reacts to `marshal::Update::Block`:
  1. Replays the block via `execute_txs` if it's not already finalized.
  2. Validates the computed root against the block.
  3. Persists the snapshot through `QmdbLedger`.
  4. Prunes the mempool, acknowledges Marshal, and emits finalized events to the simulation harness.

### Ledger Aggregates & Services (`examples/revm/src/application/ledger/mod.rs`)

- **Mempool**: owns pending transactions and exposes insert/build/prune commands so proposals and finalizers work against a consistent queue (`examples/revm/src/application/ledger/mempool.rs`).
- **SnapshotStore**: maintains `LedgerSnapshot`s plus the persisted digest set, handles ancestor lookups, merges pending `QmdbChanges`, and tracks which digests have been committed (`examples/revm/src/application/ledger/snapshot_store.rs`).
- **SeedCache**: keeps per-digest seed hashes so the deterministic `prevrandao` values are pulled from a shared source (`examples/revm/src/application/ledger/seed_cache.rs`).
- **LedgerService**: domain service that wraps `LedgerView` and exposes high-level commands (`submit_tx`, `build_txs`, `parent_snapshot`, `preview_root`, `insert_snapshot`, `persist_snapshot`, `prune_mempool`, `seed_for_parent`, `set_seed`, `query_state_root`). The application and reporters talk to `LedgerService` instead of mutating the aggregates directly.


### Domain Events

`LedgerService` publishes `LedgerEvent`s through a broadcast channel whenever meaningful operations occur:
1. `TransactionSubmitted(TxId)` when the mempool accepts a new transaction.
2. `SnapshotPersisted(ConsensusDigest)` when QMDB commits a finalized digest.
3. `SeedUpdated(ConsensusDigest, B256)` when the per-digest seed cache is refreshed.

Consumers can call `LedgerService::subscribe()` to obtain a listener and react to these events (e.g., instrumentation, metrics, or simulation probes) without touching the aggregates directly.

### Ledger Observers (`examples/revm/src/application/observers.rs`)

Ledger observers subscribe to domain events, emit telemetry/log output for seed refreshes and transaction submissions, and keep the observation context decoupled from the aggregates.

## 4. Flows Illustrated

1. **Proposal Flow**:
   - CLI invokes simulation → `LedgerService` ingests submitted transactions and keeps them in the `Mempool`.
   - `RevmApplication` asks the service for the parent snapshot, builds a proposal batch, executes it, previews the root via `SnapshotStore`, and records a new `LedgerSnapshot`.
   - The computed state root travels with the proposed block, while the snapshot remains available for replay and persistence.

2. **Finalization Flow**:
   - Marshal delivers a finalized block to `FinalizedReporter`.
   - The reporter replays the block, validates the root, and commands `LedgerService` to persist the authenticated updates (marking the digest in `SnapshotStore` and committing via `QmdbLedger`).
   - `LedgerService` prunes the `Mempool`, and the simulation harness observes the `finalized` domain event so other nodes can progress.

3. **Seed Flow**:
   - `SeedReporter` listens to simplex notarizations/finalizations, hashes each seed, and stores it in the `SeedCache` through `LedgerService`.
   - `RevmApplication` reuses the cached seed when computing `prevrandao` for future proposals.

## 5. Diagram

See `examples/revm/docs/revm_architecture.png` for the visual layout of these components. The diagram mirrors the textual flows above (CLI → Simulation → Nodes → Reporters → QMDB).

## 6. Related Docs

For the DDD vocabulary, aggregates, and bounded contexts, see `examples/revm/docs/DOMAIN_MODEL.md`.
