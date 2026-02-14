# REVM Domain Model

This document describes the example using domain-driven design (DDD) terms. It is meant to be
read alongside ARCHITECTURE.md. Use it when you want to reason about invariants and how state
changes move through the system.

## Status

This is an example chain. The domain model is intentionally small and optimized for clarity.

## Ubiquitous language

| Term | Meaning | Notes |
| --- | --- | --- |
| Node | A simulated participant that runs consensus, marshal, and the application | One process per node in the simulation |
| Block | Parent pointer, height, prevrandao, state_root, transactions | Deterministic encoding |
| Tx | Minimal transaction (from, to, value, gas_limit, calldata) | Not a signed Ethereum tx |
| ConsensusDigest | `sha256(BlockId)` | The consensus payload |
| StateRoot | Commitment over QMDB partition roots | Pre-commit root |
| LedgerSnapshot | Cached execution state for a digest | Used for replay and persistence |
| LedgerView | Aggregate root for mempool, snapshots, seeds, and QMDB | Mutex protected |
| LedgerService | Domain service that orchestrates ledger commands and emits events | Uses LedgerView |
| QmdbLedger | Persistence service for authenticated state | Owns QMDB partitions |
| Seed | Threshold-simplex randomness hashed into `prevrandao` | Stored per digest |

## Value objects

Value objects are immutable and compared by value:

- `Block`, `Tx`, `BlockId`, `TxId`, `ConsensusDigest`, `StateRoot`
- `BootstrapConfig` (genesis allocation and bootstrap txs)
- `QmdbChangeSet` and `AccountUpdate` (change batches derived from execution)

## Entities

Entities have identity and evolve over time:

- `LedgerSnapshot` is identified by its digest and holds the execution overlay and change set.
- `LedgerView` owns mutable state and is the root entity for local state.
- `LedgerService` is the domain service that carries subscribers and orchestrates commands.

## Aggregates and boundaries

### LedgerView aggregate

`LedgerView` is the main aggregate. It owns:

- `Mempool` (pending txs)
- `SnapshotStore` (cached snapshots and persisted digests)
- `SeedCache` (digest -> seed hash)
- `QmdbLedger` (persistence driver)

The aggregate boundary ensures that proposal, verification, and finalization all operate on a
consistent snapshot of state.

## Commands and queries

Commands mutate state:

- `submit_tx` adds a tx to the mempool.
- `insert_snapshot` stores a new snapshot after successful execution.
- `set_seed` stores seed hashes from consensus activity.
- `persist_snapshot` commits QMDB changes for a digest.
- `prune_mempool` removes txs included in finalized blocks.

Queries read state:

- `parent_snapshot`, `query_state_root`, `query_balance`, `query_seed`.

## Events

`LedgerService` emits `LedgerEvent` for observation without mutating state:

- `TransactionSubmitted(TxId)`
- `SnapshotPersisted(ConsensusDigest)`
- `SeedUpdated(ConsensusDigest, B256)`

Observers can subscribe and emit telemetry or drive simulation control.

## Invariants

The core invariants the model relies on:

- A block is only accepted if re-execution yields the advertised `state_root`.
- `StateRoot` is derived from merkleized QMDB partitions and is treated as the consensus
  commitment (pre-commit).
- A digest is persisted at most once. Repeated persist calls are no-ops.
- Mempool entries are only removed after the corresponding block is finalized and persisted.

## Consistency and concurrency

- `LedgerView` uses a mutex to serialize access to aggregate state.
- Snapshot merges and persistence happen in digest order to preserve causal correctness.
- Errors from mutable QMDB operations are treated as fatal for that database instance.

## Bounded contexts

| Context | Responsibility | Key files |
| --- | --- | --- |
| Consensus and marshal | Orders digests, disseminates blocks, emits finalizations | `commonware_consensus`, `application/node/` |
| Execution | REVM execution and change set extraction | `application/execution.rs` |
| Ledger | Mempool, snapshots, seeds, persistence orchestration | `application/ledger/` |
| Persistence | QMDB partitions and authenticated roots | `qmdb/` |
| Simulation | Orchestrates nodes and checks convergence | `simulation/` |

## Typical scenarios

### Propose

- Mempool provides a batch of txs not present in pending ancestors.
- Execution produces `QmdbChangeSet` and a new `StateRoot`.
- A `LedgerSnapshot` is stored so finalization can reuse it.

### Verify

- The block is re-executed against the parent snapshot.
- The computed root must match the header or the block is rejected.

### Finalize

- If a cached snapshot exists, reuse it. Otherwise re-execute to rebuild it.
- Persist the change set in QMDB.
- Emit `SnapshotPersisted` and prune the mempool.

## Extension guidelines

If you extend the model, keep these rules in mind:

- Update the ubiquitous language to keep terms precise and shared.
- Keep value objects deterministic and bounded in size.
- Prefer explicit invariants over implicit assumptions.
- Treat persistence errors as fatal and avoid partial reuse of state after failure.
