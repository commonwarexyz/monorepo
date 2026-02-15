# REVM Example Architecture

This document explains how the REVM example works end to end. It is written so a reader can choose
between a quick high-level scan and a deeper technical pass.

## Status and scope

- This is an example chain, not a production client.
- It demonstrates how Commonware consensus, marshal, and QMDB persistence can drive REVM execution.
- It intentionally omits signatures, fee markets, Ethereum MPT state roots, and many other features.

## How to read this

- Quick scan: read "System overview" and "Data flow by stage".
- Deep dive: also read "State and persistence semantics" and "Safety and invariants".
- If you want domain vocabulary, see DOMAIN_MODEL.md.

## System overview

At a high level, the example does this:

1. Consensus orders 32-byte digests, not full blocks.
2. Full blocks are disseminated and backfilled by marshal.
3. Each block is verified by re-executing its transactions in REVM.
4. The resulting state changes are translated into a QMDB change set.
5. Finalized blocks are persisted in QMDB in batch order.

The architecture diagram is in `revm_architecture.png` (source: `revm_architecture.dot`).

## Component map (what owns what)

| Component | Responsibility | Key files |
| --- | --- | --- |
| CLI | Parses flags, starts a simulation | `examples/revm/src/main.rs` |
| Simulation | Orchestrates N nodes, waits for finalization | `examples/revm/src/simulation/mod.rs` |
| Node wiring | Connects consensus, marshal, application, and storage | `examples/revm/src/application/node/` |
| Consensus (simplex) | Orders digests and emits notarization and finalization events | `commonware_consensus` |
| Marshal | Disseminates blocks and serves backfill requests | `examples/revm/src/application/node/marshal.rs` |
| Application | Propose and verify full blocks | `examples/revm/src/application/app.rs` |
| Execution | Runs REVM and extracts state changes | `examples/revm/src/application/execution.rs` |
| Ledger view | Mempool, snapshots, seeds, persistence coordination | `examples/revm/src/application/ledger/` |
| QMDB | Authenticated storage for accounts, storage, and code | `examples/revm/src/qmdb/` |
| Reporters | React to consensus and marshal events | `examples/revm/src/application/reporters/` |
| Observers | Log domain events (non-mutating) | `examples/revm/src/application/observers.rs` |

## Data flow by stage

### 1) Propose

- Simplex asks the application to propose a block.
- The application gathers transactions from the mempool, skipping any already included in pending
  ancestors.
- REVM executes the batch using a parent snapshot and a prevrandao seed.
- The application computes a QMDB state root for the change set.
- The block is produced with the advertised `state_root` and cached as a local snapshot.

### 2) Verify

- Validators receive a full block and re-execute it against the parent snapshot.
- The computed `state_root` must match the block header.
- If it matches, the validator caches the snapshot. If it does not match, the block is rejected.

### 3) Finalize and persist

- Marshal delivers finalized blocks to `FinalizedReporter`.
- If the snapshot already exists, we reuse it. If not, we re-execute to rebuild it.
- We recompute the root and ensure it matches the block header.
- We commit the aggregated change set to QMDB and mark the digest as persisted.
- We prune the mempool and acknowledge marshal so delivery can continue.

The block lifecycle diagram is in `revm_block_lifecycle.png`.
The persistence flow diagram is in `revm_persistence_flow.png`.

## State and persistence semantics

### Digest and root definitions

- `BlockId` is `keccak256(Encode(Block))`.
- The consensus digest is `sha256(BlockId)`.
- `StateRoot` is a commitment over QMDB partition roots for accounts, storage, and code.

### Pre-commit vs post-commit root

- The block header uses a pre-commit root computed by merkleizing partition roots.
- QMDB commit operations append authenticated log entries, so the post-commit root can differ.
- Treat the header `state_root` as the consensus commitment.

### Snapshots

- Each executed block produces a `LedgerSnapshot` with:
  - Parent digest
  - REVM overlay database (`RevmDb`)
  - `StateRoot`
  - `QmdbChangeSet`
- Snapshots are cached to avoid re-executing on finalization.

## Runtime and determinism

- The example uses the tokio runtime because REVM requires a tokio runtime to bridge the async QMDB
  adapter into REVM's sync database interface.
- Determinism is achieved by seeded key generation and a simulated network with fixed configuration.
- Runtime scheduling is not guaranteed deterministic. The tests focus on stable outcomes for fixed
  seeds, not on exact message ordering.

## Safety and invariants

These are the main correctness checks and invariants:

- A block is only accepted if re-execution yields the advertised `state_root`.
- QMDB changes for a digest are merged in order, ancestor to child, before persistence.
- Persisting a digest is idempotent. Duplicate persist calls are a no-op.
- The mempool is pruned only after successful persistence of the finalized block.

## Failure handling

- If a finalized block arrives without a cached snapshot, we re-execute it to rebuild the snapshot.
- If re-execution or root computation fails, we log and acknowledge the update to avoid stalling
  marshal delivery.
- Errors returned by mutable QMDB methods are treated as fatal for that database instance.
  Callers must not use the database after such an error.

## Performance considerations

- Executing and committing per block is expensive. This example batches QMDB commits per finalized
  block for simplicity.
- Snapshot caching avoids re-execution for proposers and validators.
- The simulated network uses fixed link latency and message size caps.

## Extension points

This example is intentionally minimal. Common extension points include:

- Adding transaction signatures and nonce validation.
- Implementing a fee market and gas price handling.
- Replacing `StateRoot` with an Ethereum-compatible trie.
- Adding richer transaction generation for the simulation.
- Introducing byzantine behavior in the simulated network to stress consensus.
