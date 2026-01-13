# REVM Domain Model

This document exposes the REVM example through a domain-driven lens so that contributors can reason about the
core entities, aggregates, services, and events before diving into the concrete implementation.

## 1. Ubiquitous Language
- **Node** – a simulated participant that wires consensus, marshal, and application logic (`examples/revm/src/sim/node.rs`).
- **LedgerSnapshot** – a captured execution result (parent digest, `RevmDb`, `StateRoot`, `QmdbChanges`) tied to a digest (`examples/revm/src/application/state.rs`).
- **LedgerView** – the aggregate that owns the mempool, snapshot store, seed cache, and persistence driver.
- **LedgerService** – the domain service that exposes high-level ledger commands and emits `DomainEvent`s (`examples/revm/src/application/state.rs`).
- **Block** – a value object with parent pointer, height, `prevrandao`, `state_root`, and transactions (`examples/revm/src/types.rs`).
- **Transaction (Tx)** – the value object placed in the mempool and executed inside the REVM (`examples/revm/src/types.rs`).
- **StateRoot / ConsensusDigest** – authenticated identifiers derived from `QmdbChanges` and the block commitment.
- **SeedReporter / FinalizedReporter** – services that react to consensus events and interact with the ledger (`examples/revm/src/application/reporters.rs`).
- **Simulation Harness** – the orchestrator that runs deterministic exec/exam loops (`examples/revm/src/sim/mod.rs`).

## 2. Entities
Entities represent mutable objects with identity that survive across commands:

- **LedgerSnapshot** (`examples/revm/src/application/state.rs`): identified by the digest it came from, it tracks the `RevmDb` state, the digest's `parent`, and the `QmdbChanges` needed to rebuild the snapshot.
- **LedgerService** (`examples/revm/src/application/state.rs`): while it wraps the `LedgerView` aggregate, it behaves as a rich entity that carries listeners/subscribers and orchestrates ledger commands.

## 3. Value Objects
While the public API never mutates these, they carry the data that commands and queries operate on:

- **Block / Tx** (`examples/revm/src/types.rs`): deterministic structures consumed and produced by proposals/verifications.
- **ConsensusDigest / StateRoot** (`examples/revm/src/types.rs` / `examples/revm/src/qmdb/mod.rs`): opaque hashes that identify snapshots and prove authentication.
- **SeedHash (`B256`)**: deterministic randomness reused in `prevrandao`.

## 4. Aggregates
Aggregates are self-consistent clusters of entities/value objects that handle consistency and invariants:

- **LedgerView** (`examples/revm/src/application/state.rs`): the root aggregate that owns the mutable state (`LedgerState`) protected by a mutex. Its responsibilities include:
  - `Mempool` – accepts, builds, and prunes transactions while ensuring no duplicates (`examples/revm/src/application/state.rs`, `Mempool`).
  - `SnapshotStore` – stores recorded `LedgerSnapshot`s, tracks which digests were persisted, and can merge cached `QmdbChanges` when replaying ancestors.
  - `SeedCache` – retains the per-digest randomness used to derive `prevrandao`.
  - `QmdbState` – the persistence backend that previews and commits `QmdbChanges` (`examples/revm/src/qmdb/state.rs`).

## 5. Domain Services
Domain services express operations that span aggregates:

- **LedgerService** (`examples/revm/src/application/state.rs`): exposes commands such as `submit_tx`, `parent_snapshot`, `preview_root`, `persist_snapshot`, and `set_seed`. It holds an observer list for domain events, keeping proposals, verifications, and reporters synchronized.
- **RevmApplication** (`examples/revm/src/application/app.rs`): offers the `Application`/`VerifyingApplication` implementation that consensus calls during propose/verify. It relies on `LedgerService` for ledger commands and ensures blocks only advance after `QmdbChanges` are committed.
- **SeedReporter / FinalizedReporter** (`examples/revm/src/application/reporters.rs`): respond to marshal events, update the ledger, persist snapshots, refresh seeds, and emit `finalized` signals to the harness.
- **Simulation Harness** (`examples/revm/src/sim/mod.rs`): while not a domain service in the classic sense, it orchestrates DKG, node startup, and aggregates domain events for observation.

## 6. Domain Events
`LedgerService` emits `DomainEvent`s (`examples/revm/src/application/state.rs`) so other services can react without tightly coupling to the aggregates:

1. `TransactionSubmitted(TxId)` – emitted when the mempool admits a new transaction.
2. `SnapshotPersisted(ConsensusDigest)` – emitted after a snapshot is successfully persisted via `QmdbState`.
3. `SeedUpdated(ConsensusDigest, B256)` – emitted whenever the cached seed hash is refreshed.

Consumers subscribe via `LedgerService::subscribe()` to instrument, log, or drive auxiliary behavior (e.g., the harness noting proposal readiness).

## 7. Bounded Contexts
DDD thrives when contexts are explicit:

- **Consensus & Marshal** (`commonware_consensus`, `examples/revm/src/application/app.rs`): orders blocks, delivers ancestors, and expects the application to prove payloads. This context owns the signing/verification logic.
- **Application Execution** (`RevmApplication`, `execute_txs`, `QmdbChanges`): handles REVM execution, root previewing, and snapshot caching.
- **Persistence / QMDB** (`examples/revm/src/qmdb`): exposes `QmdbState`, `RevmDb`, and atomic commit/preview helpers.
- **Simulation Harness** (`examples/revm/src/sim`): orchestrates nodes, deterministically steps the runtime, and interprets domain events for logging/termination.

## 8. Flows Revisited
Each major flow maps cleanly to the domain model:

1. **Proposal Flow** (`RevmApplication::propose`): collects `Tx`s from `Mempool`, executes them through `execute_txs`, previews the root, and registers a new `LedgerSnapshot`.
2. **Verification Flow** (`RevmApplication::verify`): replays parent snapshots, re-executes `Tx`s, and validates the `StateRoot`.
3. **Finalization Flow** (`FinalizedReporter`): replays finalized blocks, commands `LedgerService` to persist snapshots, and emits `DomainEvent::SnapshotPersisted`.
4. **Seed Flow** (`SeedReporter` + `LedgerService`): observes hashed prevrandao values and writes them via `set_seed`, pushing the cache update into `DomainEvent::SeedUpdated`.

Linking these flows back to the aggregates ensures the application remains understandable and the DDD vocabulary stays consistent across the example.
