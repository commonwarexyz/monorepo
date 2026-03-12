# State Sync Design

**Status: PLANNED** -- Not yet implemented.

This document outlines the work required to integrate QMDB state sync into
the `stateful` module's `Stateful` wrapper.

## Background

A node that is new or recovering from a long outage cannot participate in
consensus until its databases are caught up to the network's finalized tip.
QMDB provides a per-database sync mechanism (see `examples/sync` and
`storage/src/qmdb/sync/`) that transfers operations and MMR proofs in
batches. The `Stateful` wrapper must orchestrate this across all databases
in the `DatabaseSet` and handle the transition to normal consensus
participation.

## Sync Protocol Summary

QMDB's sync engine operates per-database:

1. The syncing node obtains a **sync target**: the MMR root and operation
   range `[inactivity_floor, size)` corresponding to some finalized state.
2. The node fetches operations in batches, each accompanied by an MMR
   **historical proof** pinned to a specific `op_count` snapshot.
3. The sync engine verifies each batch against the target root and applies
   operations incrementally to build up the local journal.
4. The target is a **moving target** -- as the network continues finalizing
   blocks, the sync target is updated and the engine adjusts its goal
   without restarting.
5. Once the local root matches the target, the database is fully usable.

## Startup Sequence

The consensus engine starts immediately alongside `Stateful`. There is no
separate pre-sync phase: the node joins the p2p network and begins
receiving blocks and certificates right away. `Stateful` internally gates
consensus participation until sync completes.

### Phase 1: Consensus Engine Starts, `Stateful` Pends

The consensus engine (marshal, orchestrator, etc.) is initialized and
started normally, exactly as it would be for a fully synced node. The
`Stateful` wrapper is constructed with its `DatabaseSet` and handed to
consensus as the application.

While databases are behind, `Stateful` does NOT return `None` from
`propose` or `false` from `verify` -- those are meaningful signals that
consensus acts on (view changes, votes against). Instead, the `propose`
and `verify` futures simply **pend** (do not resolve). Consensus treats
this as a slow node and times out the view, which is the correct behavior
for a node that is not yet ready.

Implementation: `Stateful` holds a readiness signal. At the top of
`propose` and `verify`, the future awaits this signal. If sync is not
complete, the future pends indefinitely until either the signal fires or
the consensus view timer expires. Once signaled, the `await` returns
instantly on all subsequent calls (zero overhead on the hot path).

### Phase 2: Finalization-Driven Database Sync

While `propose` and `verify` pend, the `Reporter::report` path remains
active. Each `Activity::Finalization` event flows through `Stateful`,
which extracts per-database sync targets from the finalized block and
forwards them to the running sync engines.

Each database in the `DatabaseSet` syncs independently and can run in
parallel:

- Sync tasks are spawned at construction time (or on the first
  finalization event that provides an initial target).
- A `sync::Resolver` implementation fetches operations and proofs from
  peers over the p2p network.
- The sync engine applies batches and verifies proofs against the current
  target root.
- As new finalizations arrive via `report()`, the target is updated
  through the per-engine `mpsc` update channel (new root, expanded
  operation range).

For `current`-layer QMDBs, sync targets the **ops root** (not the
canonical root). The bitmap is reconstructed automatically from the
applied operations.

### Phase 3: Replay Unfinalized Blocks

Once all databases are synced to a finalized tip, `Stateful` fires the
readiness signal. The next `propose` or `verify` call proceeds into the
normal code path.

Replay of unfinalized blocks is handled by the **existing lazy recovery
mechanism** (`rebuild_pending`): when `propose` or `verify` encounters a
parent whose state is missing from the `pending` map, it walks back
through the block DAG via the `BlockProvider` to the finalized tip and
replays forward via `Application::replay`. No new replay logic is needed.

### Phase 4: Join Consensus

After the readiness signal fires and lazy recovery fills the `pending`
map on the first real call, the node has:

- All databases at the finalized tip.
- A populated `pending` map covering any unfinalized chains ahead of the
  tip.

The node begins proposing and voting normally.

## Design Considerations

### Sync Target Discovery

Each finalized block header should embed state roots for every database in
the `DatabaseSet`. The wrapper extracts these roots to construct
per-database sync targets. The exact format is application-specific (the
`Application` trait needs a method to extract sync targets from a
finalized block).

### Resolver Provisioning

Each database needs a `Resolver` that can fetch operations and proofs from
the network. Options:

- The `Application` provides resolver instances (most flexible).
- The wrapper constructs resolvers from the p2p layer automatically
  (simpler for the application developer, but requires the wrapper to know
  about network topology).

### Readiness Signal

The readiness mechanism must satisfy:

- **Pend cheaply**: `propose`/`verify` must await without busy-looping.
- **Fire once**: once all DBs are synced, the signal is permanent.
- **Zero overhead after sync**: on the hot path (post-sync), the check
  must be trivial (e.g., reading an `AtomicBool` or a `watch` channel
  that has already resolved).
- **Cancel-safe**: consensus may drop the `propose`/`verify` future on
  view timeout; the next call must await the same signal cleanly.

### Convergence

Sync is chasing a moving target. The node converges when the sync engine
catches up to the latest finalized tip faster than new blocks finalize.
In practice, bulk operation transfer is much faster than block production,
so convergence is expected. However, the design should handle the case
where the network is producing blocks faster than the node can sync (e.g.,
by syncing to a recent-enough target and accepting a small replay window).

### Error Handling

- If a peer serves invalid proofs, the resolver should try other peers.
- If sync fails for one database, all databases should be re-synced from
  a consistent finalization point (partial sync across databases in a set
  is not useful).
- The wrapper should expose sync progress metrics (per-database progress,
  overall phase) for observability.

### Interaction with `ManagedDb` Trait

The `ManagedDb` trait may need a sync-related extension or a separate
`SyncableDb` trait that exposes:

- A method to run the sync engine given a resolver and initial target.
- A way to update the sync target mid-flight.
- A completion signal with the synced database state.

Alternatively, sync could be handled entirely outside the trait system as
a one-time bootstrap step that produces initialized `ManagedDb` instances,
which are then installed into `Stateful` once ready.

### Interaction with Engine Lifecycle

The engine (e.g., `reshare::Engine`) requires no special sync-aware
startup logic. It initializes archives, marshal, orchestrator, and
`Stateful` in the same order as today, then calls `start()` on all actors
with `try_join_all`. The only difference is that `Stateful` may be
constructed with databases that need sync, and `Config` carries the
additional sync configuration (resolvers, batch sizes, etc.).

The orchestrator starts immediately -- it does not need to be deferred.
`Stateful` handles the gating internally and transparently.

## Dependencies

- **QMDB lifetime removal**: Sync produces an initialized database that
  must be usable with the batch traits. Requires the `'a` lifetime
  removal on batch types (see `stateful/mod.rs` TODO).
- **QMDB parent type erasure**: Same prerequisite as the core batch
  lifecycle (see `stateful/mod.rs` TODO).
- **Pending state recovery**: Phase 3 (replay) relies on the existing
  `rebuild_pending` lazy recovery path, which is already implemented.

## References

- `examples/sync/`: Working example of per-database sync with a TCP
  resolver, covering `any`, `current`, and `immutable` QMDB variants.
- `storage/src/qmdb/sync/`: Core sync engine, `Target` type, `Resolver`
  trait, and proof verification logic.
- `storage/src/qmdb/any/mod.rs`: `historical_proof` API used by the sync
  server to generate verifiable operation batches.
