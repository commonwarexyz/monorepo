# Test Harness Plan: `glue/src/stateful`

**Status: PLAN** -- Ready for implementation.

This document describes the design for a mock database and end-to-end test
harness that exercises the `Stateful` wrapper's full lifecycle: batch forking,
merkleization, finalization, lazy recovery, and startup sync gating.

The mock replaces the real QMDB integration (blocked on lifetime removal and
parent type erasure) with an in-memory key-value store that computes
deterministic roots.

The test harness spins up a full simplex consensus engine with marshal
(`Marshaled` wrapper), simulated p2p network, and `Reporters`-composed
reporter (feeding both `Stateful` for finalization handling and a progress
monitor for test assertions).

## Prerequisite: `Payload` Conversion Function

The `stateful::Application` trait currently requires
`Payload: Digest + Into<<Self::Block as Digestible>::Digest>`. This `Into`
bound prevents using `Commitment` as the payload type, because `Commitment`
embeds the block digest but is not directly convertible via `Into`.

Following the `Variant::commitment_to_inner` pattern from
`consensus/src/marshal/core/variant.rs`, replace the `Into` bound with an
explicit conversion function:

```rust
// Before:
type Payload: Digest + Into<<Self::Block as Digestible>::Digest>;

// After:
type Payload: Digest;

/// Extract the block digest from a consensus payload.
///
/// For `Marshaled` applications, this extracts the inner block digest
/// from the `Commitment`. For `Inline` applications, this is typically
/// the identity function.
fn payload_to_block_digest(
    payload: Self::Payload,
) -> <Self::Block as Digestible>::Digest;
```

The single call site in `wrapper.rs` (`forward_sync_target_update`)
changes from `payload.into()` to `A::payload_to_block_digest(payload)`.

This unblocks `Payload = Commitment` for `Marshaled` applications: the
implementation calls `commitment.block::<sha256::Digest>()` to extract
the inner digest.

## Type Alignment with `Marshaled`

With the conversion function in place, the full type chain is:

```
Engine<..., Automaton = Marshaled<..., Stateful<..., MockApp, ...>, ...>,
            Reporter = Reporters<Activity, Stateful, MockReporter>>
```

Key type mappings:

- `Marshaled::Automaton::Digest = Commitment`
- `Marshaled::Automaton::Context = Context<Commitment, PublicKey>`
- Engine produces `Activity<S, Commitment>`
- `Stateful::Reporter::Activity = Activity<A::SigningScheme, A::Payload>`
  where `A::Payload = Commitment` -- types align
- `Stateful`'s pending map is keyed by `Commitment`
- `A::payload(&block)` computes `Commitment` from the block (the mock
  block type embeds its coding commitment)
- `A::payload_to_block_digest(commitment)` extracts the inner
  `sha256::Digest` for block fetching

## Mock Database

All mock types live in `glue/src/stateful/mocks.rs` (gated behind the
existing `mocks` feature flag) so downstream crates can reuse them.

### `MockDb`

A single in-memory database implementing `ManagedDb` and `SyncableDb`.

```
struct MockDb {
    committed: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}
```

- `new_batch()` returns a `MockUnmerkleized` that snapshots the committed
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

### Parent State Representation

`MockUnmerkleized` needs to read from either committed DB state or a
`MockMerkleized`. Use an enum:

```
enum ParentState {
    Committed(Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>),
    Merkleized(BTreeMap<Vec<u8>, Vec<u8>>),
}
```

This sidesteps the lifetime/type-erasure problems that block the real QMDB
integration.

### `SyncableDb` Implementation

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
No additional implementation is needed. Similarly for `SyncableDatabaseSet`.

## Mock Application

A `MockApp` implementing `stateful::Application<deterministic::Context>`:

```
struct MockApp {
    blocks: Arc<Mutex<HashMap<sha256::Digest, TestBlock>>>,
}
```

Associated types:

- `SigningScheme`: ed25519 scheme (reuse existing simplex ed25519 fixture).
- `Context`: `Context<Commitment, PublicKey>` (simplex context type, to
  satisfy `Marshaled`'s constraint).
- `Payload`: `Commitment`.
- `Block`: `TestBlock` implementing `CertifiableBlock<Context = ...>`. The
  block carries enough state to compute its own `Commitment` (embedded
  coding config and context digest). The mock uses fixed coding config
  since actual erasure coding happens in `Marshaled`.
- `Databases`: `Arc<AsyncRwLock<MockDb>>`.
- `InputProvider`: `Arc<Mutex<VecDeque<(Vec<u8>, Vec<u8>)>>>` (queue of
  key-value mutations to apply).

Methods:

- `payload(block)`: compute `Commitment` from the block (block digest,
  coding root, context hash, coding config).
- `parent_payload(block)`: extract parent `Commitment`.
- `payload_to_block_digest(commitment)`: call
  `commitment.block::<sha256::Digest>()`.
- `sync_targets(block)`: return `Some(block.state_root)`.
- `genesis()`: return a block with a known digest and empty state root.
- `propose(context, ancestry, batches, input)`:
  1. Drain entries from `InputProvider`.
  2. Call `batches.write(k, Some(v))` for each.
  3. Call `batches.merkleize()`.
  4. Build a `TestBlock` embedding the state root, return
     `(block, merkleized)`.
- `verify(context, ancestry, batches)`:
  1. Re-execute the block's mutations against batches.
  2. `merkleize()` and check root matches block header.
  3. Return `Some(merkleized)` on match, `None` on mismatch.
- `replay(context, block, batches)`:
  Same as verify but panics on mismatch (block is known-good).

## Full Simplex Engine Wiring

The test harness spins up real simplex consensus engines in a simulated
network using the deterministic runtime, following the `test_all_online`
pattern in `consensus/src/simplex/mod.rs`.

### Architecture

```
                    +-----------+
                    |  Simplex  |
                    |  Engine   |
                    +-----+-----+
                          |
              +-----------+-----------+
              |                       |
     +--------v--------+    +--------v--------+
     | Marshaled        |    | Reporters       |
     | (Automaton+Relay)|    | (Reporter)      |
     +--------+---------+    +---+----------+--+
              |                  |          |
     +--------v--------+   +----v----+ +---v--------+
     | Stateful         |   |Stateful| |MockReporter |
     | (Application)    |   |(report)| |(monitor)    |
     +--------+---------+   +--------+ +-------------+
              |
     +--------v--------+
     | MockApp          |
     +--------+---------+
              |
     +--------v--------+
     | MockDb           |
     +-----------------+
```

- **`Marshaled`** wraps `Stateful` as its `VerifyingApplication`. It handles
  erasure coding, epoch boundaries, and shard dissemination. Its
  `Automaton::Digest = Commitment`.
- **`Reporters`** (from `consensus/src/reporter.rs`) composes `Stateful`
  (for finalization-driven state management) and a mock reporter (for
  test progress monitoring). Both receive the same `Activity<S, Commitment>`.
- **`Stateful`** wraps `MockApp`, managing the pending-tip DAG and sync
  gating. It implements `ConsensusApplication`, `ConsensusVerifyingApplication`,
  and `Reporter`.
- **`MockApp`** drives state transitions against the mock database.

### Per-Validator Wiring

Following the `test_all_online` pattern:

```rust
for (idx, validator) in participants.iter().enumerate() {
    let context = context.with_label(&format!("validator_{idx}"));

    // Inner application
    let mock_app = MockApp::new(databases.clone(), input.clone(), blocks.clone());

    // Stateful wrapper
    let stateful = Stateful::new(context.clone(), stateful::Config {
        app: mock_app,
        databases: databases.clone(),
        input_provider: input.clone(),
        block_provider: block_provider.clone(),
        finalized_payload: None,
        sync: sync_config.clone(),
    });

    // Marshaled wrapper (automaton + relay)
    let marshaled = Marshaled::new(context.clone(), MarshaledConfig {
        application: stateful.clone(),
        marshal: marshal_mailbox.clone(),
        shards: shard_mailbox.clone(),
        scheme_provider: scheme_provider.clone(),
        strategy: Sequential,
        epocher: epocher.clone(),
    });

    // Composite reporter
    let reporter = Reporters::from((stateful.clone(), mock_reporter.clone()));

    // Engine config
    let cfg = config::Config {
        scheme: schemes[idx].clone(),
        elector: elector.clone(),
        blocker: oracle.control(validator.clone()),
        automaton: marshaled.clone(),
        relay: marshaled.clone(),
        reporter,
        strategy: Sequential,
        // ... timeouts, buffers, etc.
    };

    let engine = Engine::new(context.clone(), cfg);
    engine.start(pending, recovered, resolver);
}
```

### Network Setup

Use `commonware_p2p::simulated::Network` with realistic link properties:

```rust
let link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: 1.0,
};
```

### Progress Monitoring

The mock reporter implements `Monitor` (via subscription channels). Tests
wait for finalization progress:

```rust
let (mut latest, mut monitor) = mock_reporter.subscribe().await;
while latest < required_views {
    latest = monitor.recv().await.expect("event missing");
}
```

Then assert database state, fault counts, etc.

## Test Plan

### 1. `test_all_online_stateful`

Full consensus with stateful state management:

1. Spin up N=5 validators with `Stateful`-wrapped `MockApp`.
2. Feed mutations via `InputProvider` across rounds.
3. Wait for 20+ finalizations.
4. Assert all validators converge on the same committed database state.
5. Assert no faults, no invalid signatures.

### 2. `test_fork_and_finalize`

Speculative execution with forks:

1. Spin up validators with injected competing proposals (e.g. two
   validators propose different mutations for the same view).
2. Wait for finalizations.
3. Assert the committed state matches whichever fork was finalized.
4. Assert dead-fork pending entries were pruned.

### 3. `test_lazy_recovery`

Pending state rebuild after restart:

1. Run consensus until 10+ finalizations.
2. Simulate restart: create new `Stateful` instances with the same
   `databases` and `BlockProvider` but empty pending maps and
   `finalized_payload` set to the last finalized block.
3. Continue consensus.
4. Assert that propose/verify succeed (meaning `rebuild_pending`
   correctly replayed the missing chain segment).
5. Assert continued finalization progress.

### 4. `test_sync_gating`

Sync readiness gate on propose/verify:

1. Spin up validators with sync config (no initial targets).
2. Assert no finalization progress within a timeout (propose/verify pend).
3. Trigger sync completion via `SyncControl`.
4. Assert finalization progress resumes.

### 5. `test_finalization_driven_sync_targets`

Sync target forwarding via report:

1. Spin up validators, some with sync enabled.
2. Let consensus run on the ready validators.
3. Syncing validators receive `Activity::Finalization` events via
   `Reporters`, which `Stateful` forwards to the sync coordinator.
4. Assert sync targets were forwarded.
5. Complete sync.
6. Assert the previously-syncing validator joins consensus and
   finalizes blocks.

### 6. `test_sync_to_consensus_transition`

Full lifecycle: sync -> replay -> normal participation:

1. Start one validator with sync config and initial targets.
2. Other validators run normally.
3. Complete sync on the lagging validator.
4. Assert it catches up via lazy recovery and begins finalizing.
5. Assert all validators converge on the same state.

### 7. `test_delete_operations`

Verify delete semantics through consensus:

1. Run consensus with mutations that include deletions
   (`write(key, None)`).
2. Finalize blocks containing deletions.
3. Assert committed state reflects deletions.

### 8. `test_chained_batches`

Verify batch chaining reads through parent:

1. Run consensus so that a block is proposed on top of an unfinalized
   parent.
2. The child block's execution reads keys written by the parent.
3. Assert the child's state root includes both parent and child
   mutations.

### 9. `test_one_offline_stateful`

Validator goes offline, consensus continues:

1. Spin up N=5 validators, disconnect one after a few rounds.
2. Assert remaining 4 validators continue finalizing (BFT threshold
   met).
3. Assert state remains consistent.

## File Layout

```
glue/
  src/
    stateful/
      mocks.rs          # MockDb, MockUnmerkleized, MockMerkleized,
                         # MockApp, MockReporter, TestBlock, harness helpers
      mod.rs            # add `pub mod mocks;` gated on
                         # `#[cfg(any(test, feature = "mocks"))]`
      wrapper.rs        # existing tests remain; new e2e tests added
      sync.rs           # existing tests remain
  Cargo.toml            # add dev-deps: commonware-p2p, commonware-coding,
                         # commonware-parallel
```

The new `mocks.rs` is a single file. If it grows beyond ~500 lines, split
into `mocks/mod.rs`, `mocks/db.rs`, `mocks/app.rs`, `mocks/harness.rs`.

## Dependencies

New dependencies for the test harness:

- `commonware-p2p` (dev-dep): simulated network.
- `commonware-coding` (dev-dep): `CodingScheme` for `Marshaled`.
- `commonware-parallel` (dev-dep): `Sequential` strategy.

Already available:

- `commonware-cryptography` (dep): `sha256`, `ed25519`.
- `commonware-consensus` (dep): `Engine`, `Marshaled`, `Reporters`,
  marshal core, `AncestorStream`, `BlockProvider`.
- `commonware-runtime` (dep): deterministic runtime.
- `commonware-codec` (dev-dep): codec traits for `TestBlock`.

## Implementation Order

1. **Payload conversion function**: Change `stateful::Application::Payload`
   to drop `Into`, add `payload_to_block_digest`. Update
   `forward_sync_target_update` call site.
2. **Mock database**: `MockDb`, `MockUnmerkleized`, `MockMerkleized`,
   `SyncableDb` impl with `SyncControl`.
3. **Mock application**: `TestBlock` (with `CertifiableBlock`), `MockApp`,
   `MockReporter`.
4. **Harness wiring**: helper function that spins up N validators with
   full simplex + marshaled + stateful + simulated network.
5. **Tests**: implement in order listed above, starting with
   `test_all_online_stateful`.

## QMDB Swap-In

The harness and mock application should be generic over the database type
(bounded by `DatabaseSet` / `SyncableDatabaseSet`), not hard-coded to
`MockDb`. When QMDB's API is updated (lifetime removal and parent type
erasure), swapping `MockDb` for the real QMDB wrapper should require only
changing the `Databases` associated type and providing a concrete
`SyncableDb` implementation -- the harness wiring, test scenarios, and
`Stateful` wrapper stay identical.

In practice this means:

- `MockApp` should be generic over `D: SyncableDatabaseSet` (or at least
  over `D: DatabaseSet`), with `MockDb` as the default type parameter.
- The harness helper function should accept the database set as a parameter,
  not construct `MockDb` internally.
- Test assertions should use the `DatabaseSet` / `ManagedDb` trait methods
  (e.g. `new_batch` + `get`) to inspect committed state, not reach into
  `MockDb`-specific internals. A small `committed_state()` helper that
  reads all keys is fine as a `MockDb`-specific convenience, but the core
  test logic should not depend on it.

## Non-Goals

- Benchmarks. The mock is not performance-representative.
- Fuzz testing. Deferred to the real QMDB integration.
- Multi-database tuple tests. The blanket impls in `db.rs` already cover
  tuples via macros. The mock tests a single-database `DatabaseSet`.
- Byzantine fault tests (equivocation, conflicting proposals). Covered
  by existing simplex tests. The `Stateful` layer is transparent to
  Byzantine behavior.
