# Test Harness Plan: `glue/src/stateful`

**Status: PLAN** -- Ready for implementation.

This document describes the design for a mock database and end-to-end test
harness that exercises the `Stateful` wrapper's full lifecycle: batch forking,
merkleization, finalization, lazy recovery, and startup sync gating.

The mock replaces the real QMDB integration (blocked on lifetime removal and
parent type erasure) with an in-memory key-value store that computes
deterministic roots.

## Mock Database

All mock types live in a single `glue/src/stateful/mocks.rs` module
(non-`#[cfg(test)]`, gated behind the existing `mocks` feature flag) so that
downstream crates and integration tests can reuse them.

### `MockDb`

A single in-memory database implementing `ManagedDb` and `SyncableDb`.

```
struct MockDb {
    committed: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}
```

- `new_batch()` returns an `MockUnmerkleized` that snapshots the committed
  state pointer.
- `finalize(batch)` replaces `committed` with the batch's resolved state.
- State is behind `Arc<Mutex<...>>` so `MockDb` is cheaply clonable for
  `Arc<AsyncRwLock<MockDb>>`.

### `MockUnmerkleized`

Implements `Unmerkleized`. Holds:

- A reference to a parent state (either committed `Arc<Mutex<BTreeMap>>` or
  a `MockMerkleized`'s resolved map).
- A local overlay `BTreeMap<Vec<u8>, Option<Vec<u8>>>` for pending writes
  (`Some` = upsert, `None` = delete).

Methods:

- `get(key)`: check overlay first, then parent.
- `write(key, value)`: insert into overlay, return `self`.
- `merkleize()`: resolve overlay against parent into a flat `BTreeMap`,
  compute a SHA-256 hash of the sorted entries as the root, return
  `MockMerkleized`.

### `MockMerkleized`

Implements `Merkleized`. Holds:

- `resolved: BTreeMap<Vec<u8>, Vec<u8>>` (fully resolved state).
- `root: sha256::Digest` (hash of sorted entries).

Methods:

- `root()` returns the digest.
- `new_batch()` returns a `MockUnmerkleized` reading from `self.resolved`.

### Parent state representation

`MockUnmerkleized` needs to read from either committed DB state or a
`MockMerkleized`. Use an enum:

```
enum ParentState {
    Committed(Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>),
    Merkleized(BTreeMap<Vec<u8>, Vec<u8>>),
}
```

This avoids the lifetime/type-erasure problems that block the real QMDB
integration.

### `SyncableDb` implementation

`MockDb` implements `SyncableDb` with:

- `SyncConfig = ()`.
- `SyncResolver = ()`.
- `SyncTarget = sha256::Digest` (a target root to "sync to").
- `SyncError = MockSyncError`.

`spawn_sync` spawns a task that:

1. Waits for a configurable delay (simulating sync work).
2. Listens on `target_updates` and updates the latest target.
3. Replaces `database.write().committed` with an empty map (or a
   preconfigured "synced state").
4. Sends `Ok(())` on the completion oneshot.

For tests that need to control sync completion externally, the mock
exposes a `SyncControl` handle (via `Arc<Mutex>`) that the test can
use to trigger completion or inject errors.

### `DatabaseSet` / `SyncableDatabaseSet`

The blanket `impl<T: ManagedDb + 'static> DatabaseSet for
Arc<AsyncRwLock<T>>` in `db.rs` already covers `Arc<AsyncRwLock<MockDb>>`.
No additional `DatabaseSet` implementation is needed: tests use
`Arc<AsyncRwLock<MockDb>>` directly.

Similarly, the blanket `SyncableDatabaseSet` impl covers
`Arc<AsyncRwLock<MockDb>>`.

## Mock Application

A `MockApp` implementing `stateful::Application<deterministic::Context>`:

```
struct MockApp {
    blocks: Arc<Mutex<HashMap<sha256::Digest, TestBlock>>>,
}
```

Associated types:

- `SigningScheme`: `ed25519::Scheme` (reuse existing simplex ed25519 fixture).
- `Context`: reuse existing `MockContext { epoch, view }` from wrapper tests.
- `Payload`: `sha256::Digest`.
- `Block`: `TestBlock` (extended from existing wrapper tests to carry a
  `payload_data: Vec<u8>` that drives state transitions).
- `Databases`: `Arc<AsyncRwLock<MockDb>>`.
- `InputProvider`: `Arc<Mutex<VecDeque<(Vec<u8>, Vec<u8>)>>>` (queue of
  key-value mutations to apply).

Methods:

- `payload(block)` / `parent_payload(block)`: extract digests.
- `sync_targets(block)`: return `Some(block.state_root)`.
- `genesis()`: return a block with a known digest and empty state root.
- `propose(context, ancestry, batches, input)`:
  1. Drain entries from `InputProvider`.
  2. Call `batches.write(k, Some(v))` for each.
  3. Call `batches.merkleize()`.
  4. Build a `TestBlock` embedding the state root, return `(block, merkleized)`.
- `verify(context, ancestry, batches)`:
  1. Re-execute the block's mutations against batches.
  2. `merkleize()` and check root matches block header.
  3. Return `Some(merkleized)` on match, `None` on mismatch.
- `replay(context, block, batches)`:
  Same as verify but panics on mismatch (block is known-good).

## Mock Block Provider

Extend the existing `StaticBlockProvider` to a `MapBlockProvider`:

```
struct MapBlockProvider {
    blocks: Arc<Mutex<HashMap<sha256::Digest, TestBlock>>>,
}
```

`fetch_block(digest)` returns the block if present in the map, `None`
otherwise. The map is shared with `MockApp` so blocks produced during
propose are immediately fetchable for lazy recovery.

## Test Harness

The harness does *not* spin up a full simplex consensus engine with p2p
networking. The `Stateful` wrapper's interface is the consensus
`Application`, `VerifyingApplication`, and `Reporter` traits, which can be
driven directly in a deterministic runtime without a real consensus engine.

This is the right level of abstraction for several reasons:

1. `Stateful` does not depend on any simplex internals; it only implements
   the consensus trait interfaces.
2. Full-engine tests would add massive complexity (network simulation,
   cryptographic fixture generation, marshal wiring) for no additional
   coverage of `Stateful`-specific logic.
3. The simplex engine already has extensive tests (`test_all_online`,
   `unclean_shutdown`, etc.). What's missing is coverage of the `Stateful`
   layer itself.

Instead, the harness drives `Stateful` directly by calling
`ConsensusApplication::propose`, `ConsensusVerifyingApplication::verify`,
and `Reporter::report` in the correct sequence, simulating what consensus
would do.

### Harness structure

```
struct TestHarness {
    context: deterministic::Context,
    stateful: Stateful<deterministic::Context, MockApp, MapBlockProvider>,
    databases: Arc<AsyncRwLock<MockDb>>,
    input: Arc<Mutex<VecDeque<(Vec<u8>, Vec<u8>)>>>,
    blocks: Arc<Mutex<HashMap<sha256::Digest, TestBlock>>>,
}
```

Helper methods:

- `new(sync_config: Option<sync::Config<...>>)`: construct everything.
- `propose(epoch, view, parent)`: build an `AncestorStream` from the
  `MapBlockProvider`, call `stateful.propose(...)`.
- `verify(epoch, view, block)`: build an `AncestorStream`, call
  `stateful.verify(...)`.
- `finalize(epoch, view, payload)`: construct a `Finalization` activity,
  call `stateful.report(...)`.
- `committed_state()`: read the database's committed `BTreeMap` for
  assertions.

### `AncestorStream` construction

`AncestorStream::new(marshal, initial)` takes a `BlockProvider` and an
initial set of blocks. For propose, the initial set is `[parent_block]`.
For verify, the initial set is `[block_being_verified]`. The harness
constructs these from the shared `blocks` map.

This is exactly what the marshal layer does internally (see
`inline.rs`), so the harness faithfully simulates the real call path.

## Test Plan

### 1. `test_propose_verify_finalize`

Normal happy-path lifecycle:

1. Create harness with no sync config (immediately ready).
2. Call `genesis()`.
3. Enqueue mutations `[("k1", "v1"), ("k2", "v2")]` in the input provider.
4. `propose(epoch=0, view=1, parent=genesis)` -> get block B1.
5. Verify B1's state root is the SHA-256 of `{k1: v1, k2: v2}`.
6. On a second (cloned) `Stateful`, `verify(epoch=0, view=1, B1)` -> true.
7. `finalize(epoch=0, view=1, B1.payload)`.
8. Assert `committed_state()` == `{k1: v1, k2: v2}`.

### 2. `test_fork_and_finalize`

Speculative execution with forks:

1. Propose B1 on top of genesis with mutations `[(k1, v1)]`.
2. Propose B2 on top of genesis with mutations `[(k1, v2)]` (competing fork).
3. Propose B3 on top of B1 with mutations `[(k2, v3)]`.
4. Finalize B1 -> committed state = `{k1: v1}`.
5. Assert B2 is pruned from pending (its round <= finalized round).
6. Assert B3 is still in pending (its round > finalized round).
7. Finalize B3 -> committed state = `{k1: v1, k2: v3}`.

### 3. `test_lazy_recovery`

Pending state rebuild after restart:

1. Propose and finalize blocks B1, B2, B3 (sequential chain).
2. Create a *new* `Stateful` with the same `databases` and
   `MapBlockProvider` but `finalized_payload = B3.payload` and an empty
   pending map (simulating restart).
3. Propose B4 on top of B3. Since B3 is the finalized tip, no replay
   needed; batches come from committed state.
4. Now propose B5 on top of B4. B4 is not in pending (it was proposed on
   the old instance). The wrapper must `rebuild_pending` by walking back
   to B3 (finalized) and replaying B4.
5. Assert B5 is proposed successfully with correct state.

### 4. `test_sync_gating_propose`

Sync readiness gate on propose:

1. Create harness with sync config (no initial targets).
2. Spawn `stateful.propose(...)` in a task.
3. Assert the propose future does not resolve within a timeout (pends).
4. Call `coordinator.update_targets(target)` to start sync.
5. Complete sync (via `SyncControl`).
6. Assert the propose future now resolves.

### 5. `test_sync_gating_verify`

Same as above but for verify.

### 6. `test_finalization_driven_sync_targets`

Sync target forwarding via report:

1. Create harness with sync config (no initial targets).
2. Report a `Finalization` activity.
3. Assert that `sync_targets` was extracted from the finalized block
   and forwarded to the coordinator.
4. Report another `Finalization` with a newer target.
5. Assert the updated target was forwarded.
6. Complete sync.
7. Report yet another `Finalization`.
8. Assert no target forwarding occurs (sync is already ready).

### 7. `test_sync_to_consensus_transition`

Full transition from syncing to normal participation:

1. Create harness with sync config and initial targets.
2. Assert propose pends.
3. Complete sync.
4. Propose and verify a block successfully.
5. Finalize it.
6. Assert committed state is correct.

### 8. `test_delete_operations`

Verify delete semantics in the mock:

1. Propose B1 with `[(k1, v1), (k2, v2)]`, finalize.
2. Propose B2 with a delete of `k1` (write `None`), finalize.
3. Assert committed state = `{k2: v2}`.

### 9. `test_chained_batches`

Verify batch chaining reads through parent:

1. Propose B1 with `[(k1, v1)]` (not finalized).
2. Propose B2 on top of B1 with `[(k2, v2)]`.
3. In B2's execution, `get(k1)` should return `v1` (read-through from
   B1's merkleized state).
4. Verify B2's root includes both `k1` and `k2`.

## File Layout

```
glue/
  src/
    stateful/
      mocks.rs          # MockDb, MockUnmerkleized, MockMerkleized,
                         # MockApp, MapBlockProvider, TestHarness
      mod.rs            # add `pub mod mocks;` gated on `#[cfg(any(test, feature = "mocks"))]`
      wrapper.rs        # existing tests remain; new tests added at bottom
      sync.rs           # existing tests remain
  Cargo.toml            # add dev-dependencies if needed (commonware-cryptography
                         # is already available transitively)
```

The new `mocks.rs` is a single file. If it grows beyond ~500 lines, split
into `mocks/mod.rs`, `mocks/db.rs`, `mocks/app.rs`, `mocks/harness.rs`.

## Dependencies

The mock needs:

- `sha256` from `commonware-cryptography` (already a dependency).
- `BTreeMap` from std (deterministic iteration order for root computation).
- `deterministic::Runner` from `commonware-runtime` (already a dev-dep).
- `AncestorStream` and `BlockProvider` from `commonware-consensus` (already
  a dependency).

No new external crates are required.

## Non-Goals

- Full simplex engine integration tests. The `Stateful` wrapper is tested
  at its trait boundary. Engine-level integration is deferred to when the
  real QMDB integration lands.
- Benchmarks. The mock is not performance-representative.
- Fuzz testing. Deferred to the real QMDB integration.
- Multi-database tuple tests. The blanket impls in `db.rs` already cover
  tuples via the macros. The mock tests a single-database `DatabaseSet`
  (the `Arc<AsyncRwLock<T>>` blanket impl).
