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

### Shared State (`examples/revm/src/application/state.rs`)

- Holds the mempool, per-digest snapshots, seed cache, and persisted digest set.
- Stores snapshots as `ExecutionSnapshot` (parent digest, `RevmDb`, `StateRoot`, `QmdbChanges`).
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
  3. Previews the resulting QMDB root and updates the shared state with the snapshot.
- On `verify`, it replays the block to recompute the root and ensures it matches the declared `state_root`.

### Reporters (`examples/revm/src/application/reporters.rs`)

- `SeedReporter` watches simplex activity and writes hashed seeds into the shared state so `RevmApplication` can populate future `prevrandao`.
- `FinalizedReporter` reacts to `marshal::Update::Block`:
  1. Replays the block via `execute_txs` if it's not already finalized.
  2. Validates the computed root against the block.
  3. Persists the snapshot through `QmdbState`.
  4. Prunes the mempool, acknowledges Marshal, and emits finalized events to the simulation harness.

## 4. Flows Illustrated

1. **Proposal Flow**:
   - CLI invokes simulation → nodes propose via `RevmApplication`.
   - Execution hits `execute_txs`, generating `QmdbChanges`.
   - Shared state saves the snapshot and previews the root for the block commitment.

2. **Finalization Flow**:
   - Marshal delivers a finalized block to `FinalizedReporter`.
   - Reporter replays, checks roots, and asks `QmdbState::commit_changes` to persist the authenticated updates.
   - Mempool is pruned and the simulation harness is notified via the `finalized` channel.

3. **Seed Flow**:
   - `SeedReporter` listens to simplex notaries/finalizations, hashes the received seed, and stores it in shared state.
   - The stored seed is reused by `RevmApplication` when building future proposals.

## 5. Diagram

See `examples/revm/docs/revm_architecture.png` for the visual layout of these components. The diagram mirrors the textual flows above (CLI → Simulation → Nodes → Reporters → QMDB).
