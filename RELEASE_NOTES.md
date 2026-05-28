# Release Notes

## v2026.5.0

### Actor Mailboxes

The new `commonware-actor` crate provides a bounded mailbox abstraction with
caller-defined overflow handling and is now used by many actor-style
components.

The mailbox has a bounded ready queue and a separate overflow queue. When the
ready queue is full, each message type's `Policy` decides whether to retain,
coalesce, replace, or discard pending work. This makes backpressure behavior an
explicit part of each actor's API instead of being spread across ad hoc channel
wrappers.

Users will see this in `p2p`, `resolver`, `broadcast`, `collector`, `simplex`,
`marshal`, and the examples. Many public handles that previously returned
futures or response oneshots now synchronously enqueue work and return
`Feedback` values:

- `Ok`: accepted within ready capacity.
- `Backoff`: handled through overflow, but the caller is applying pressure.
- `Closed`: the actor is no longer accepting work.

For lossy ingress paths, APIs can return `Unreliable<Feedback>`, where
`Rejected` means the work was not semantically handled and the caller must retry
or treat the submission as failed.

Actor ingress behavior is now uniform, bounded, and inspectable. Application
code that previously assumed fire-and-forget sends should now check whether
submission was accepted.

### Runtime Contexts And Observability

Runtime context identity now exposes the existing supervision tree more directly:

- `Supervisor::child("name")` creates a supervised child context and extends the
  metric name prefix.
- `Supervisor::with_attribute("key", value)` attaches Prometheus labels and
  tracing attributes without creating a new metric-name segment.
- `Tracing::with_span()` opts the next spawned task into a tracing span.
- `Metrics::register()` returns a registered metric handle, and dropping the
  last handle unregisters the metric.
- Metric label derive macros now resolve through `commonware-runtime`, so
  downstream crates can derive metric labels without depending directly on
  `prometheus-client`.

Earlier versions already supervised task hierarchies, but context cloning and
metric label builders could hide when a new child identity was being created.
Static component names should be modeled with `child()`; dynamic dimensions such
as epoch, round, shard, or peer should be modeled with `with_attribute()`.

The runtime trait surface was also split more clearly:

- `Supervisor` owns task identity.
- `Spawner` builds on supervision and controls task placement.
- `Tracing` controls spans.
- `Metrics` controls metric registration and encoding.
- `Observer` groups tracing and metrics when both are required.

This is a user-visible migration point for code that used `with_label`,
`with_scope`, or relied on context cloning to imply a new child task identity.

### Shared Stateful Application Glue

The new `commonware-glue` crate provides default constructions that span
multiple primitives. Its first major component is `glue::stateful`, a wrapper
for stateful applications built on consensus and QMDB.

The wrapper owns the common bookkeeping that every stateful consensus
application otherwise has to reimplement:

- Before propose or verify, fork unmerkleized database batches from the parent
  block's pending state, or from committed database state if the parent is
  finalized.
- Cache merkleized speculative state by block digest.
- Apply the winning fork on finalization and prune pending entries from dead
  forks.
- Lazily rebuild missing pending state after restart by walking the block DAG
  through marshal and replaying certified blocks.
- Coordinate startup between marshal sync and one-time QMDB state sync.

The same module includes database-set traits, QMDB resolver actors, sync plans,
and simulation support for multi-validator stateful tests. This gives
application authors a concrete path for combining consensus, marshal, QMDB, and
state sync without hand-wiring all of the lifecycle edges.

### Consensus And Marshal

Marshal now has a unified core actor shared by the standard full-block path and
the coded shard path. Variant-specific logic is expressed through `Variant` and
`Buffer` abstractions, while the core actor owns ordering finalized blocks,
persisting blocks and certificates, backfilling gaps, managing acknowledgements,
and serving block lookups.

- Marshal can start from a configurable finalized floor instead of always from
  genesis. This is the consensus-side counterpart to state sync: nodes can
  retain and serve only the block history needed above the floor.
- The `Mailbox` implements block-provider behavior for parent walking and lazy
  recovery, so stateful wrappers can fetch ancestors through the same marshal
  surface.
- Backfill and subscription behavior is more explicit around digest-based and
  commitment-based lookup, including local-only wait behavior and peer fetch
  fallbacks.
- Deferred verification now works with the shared marshal core, and the older
  `VerifyingApplication` split has been removed.

Simplex also exposes a clearer startup floor:

- `Floor::Genesis` starts a fresh epoch from the genesis payload.
- `Floor::Finalized` starts from an already-finalized proposal and verifies the
  supplied finalization certificate.

Simplex now also includes a `ForwardingPolicy` for proactively forwarding
certified blocks to silent voters or the next leader. This is a liveness aid
that avoids forwarding blocks before local certification succeeds.

Application-facing Simplex semantics were tightened around startup and recovery.
`propose` may decline work by dropping its response, but `verify` and `certify`
are stable validity decisions rather than backpressure signals. If an
application is waiting for data, those requests should stay pending. Once a
locally proposed payload is notarized, Simplex treats it as certifiable without
calling back into `certify`; `certify` remains the hook for payloads learned
from other validators. Simplex also syncs votes and certificates before
broadcasting them, and journals certification outcomes so restart can replay
them instead of asking the application to re-certify the same view.

### Resolver And P2P Demand Tracking

The resolver API is now subscriber-aware. A single peer-visible fetch key can
serve multiple local subscribers, and the resolver retains a fetch while at
least one subscriber is still wanted by the latest `retain` predicate.

The `Consumer::deliver` call now receives a `Delivery` containing both the
peer-visible key and the retained subscriber set. This separates peer validity
from local demand: the key validates the response, while subscribers determine
which local waiters should observe it.

P2P fetches also support targeted fetch hints. A caller can restrict a fetch to
specific peers when it knows only those peers may eventually have the data.
Targets persist across transient failures and are cleared on successful fetch
or peer blocking.

The new `resolver::opaque` actor brings the same request lifecycle to
application-provided async fetchers that do not need peer-specific routing. It
coalesces duplicate keys, retries transient misses, prunes stale subscribers,
and redelivers accepted responses to subscribers that attached while validation
was still in flight.

Resolver demand is now more composable: duplicate requests can be coalesced,
late subscribers can attach to in-flight validation, and stale subscribers can
be pruned without tearing down unrelated demand for the same key.

### Storage, QMDB, And Merkle Structures

Merkle structures are now family-generic. Shared `Position<F>` and
`Location<F>` types, plus the `Family` trait, allow MMR and MMB implementations
to share batching, proof, pruning, and persistence logic while retaining their
different tree geometry. Bagging policy is separated from family topology.

QMDB now builds on this family abstraction and exposes more of its lifecycle in
the type system and batch API:

- `any`, `current`, `immutable`, and `keyless` variants gained broader support
  for MMR and MMB families.
- Batches can be merkleized and then used as parents for child batches before
  committing, making speculative execution and forked state transitions a
  first-class pattern.
- Commit operations carry inactivity floors. The floor is authenticated in the
  operation log and governs what can be pruned and what must be replayed during
  reconstruction.
- Merkle and QMDB configuration now carries an explicit
  `commonware_parallel::Strategy`. Use `Sequential` for previous serial
  behavior, or a parallel strategy such as `Rayon` to parallelize batch work.
- Storage journals and QMDB variants gained `read_many` and `get_many` paths
  that reduce repeated storage lookups for callers that need multiple positions,
  locations, or keys.
- QMDB metrics were expanded around state, reads, operations, sync, and
  durability behavior.
- Lower-level storage indexes moved to retain-style predicates. The public API
  now uses `retain` and `insert_and_retain`, cursor values no longer require
  `Eq`, and colliding values are exposed newest-first.

`current` QMDB now authenticates current-value status by grafting a status
bitmap into the operations tree. This produces a single canonical root that can
prove both operation inclusion and whether the operation is active, instead of
requiring independent proofs for the operation log and bitmap state. For replay
sync, `current` still verifies operation batches against the ops root; the new
`OpsRootWitness` links that ops root back to a trusted canonical `current` root
when callers need that authentication.

Compact is a new authenticated storage mode for applications that need the
latest committed state and future appendability, but do not need to retain or
serve full operation history.

Instead of persisting every historical Merkle node, `merkle::compact` persists
the compact frontier: the committed leaf count and pinned peaks needed to
recover the current root and continue appending after restart. The compact QMDB
variants, `qmdb::immutable::CompactDb` and `qmdb::keyless::CompactDb`, mirror
the normal batch flow (`new_batch -> merkleize -> apply_batch -> sync`) while
intentionally omitting historical read/proof APIs such as `get`, `proof`, and
`bounds`.

Compact nodes can still participate in authenticated state transfer. On every
durable sync, compact QMDB persists a witness for the final commit operation.
Compact sync uses that witness, the target root, leaf count, frontier pins, and
final commit proof to reconstruct the latest committed compact state directly.
It does not replay the full historical operation log.

Replay sync rebuilds a database from the operation stream when a node must
retain or serve past operations. Compact sync lets a node join at a proven
committed root, materialize only the append frontier, and continue from there
without downloading or storing the full operation history.

### Runtime I/O

- `Blob::write_at_sync` writes bytes at an offset and durably persists that
  specific write. This is not a global durability barrier for earlier unsynced
  operations.
- The io_uring backend was reworked around a single event loop with bounded
  admission, typed waiter slots, a userspace timeout wheel, futex wakeups when
  idle, and eventfd wakeups while blocked in `submit_and_wait`.
- io_uring storage operations are serialized where needed to avoid unsafe
  overlapping filesystem behavior.
- The I/O buffer layer now distinguishes `Bytes`, untracked aligned buffers,
  and pooled aligned buffers. The pool has a lower-overhead freelist and
  exposes system page size and cache-line size helpers.
- Runtime network sinks and streams are poisoned after send/receive errors or
  cancellation of a partially progressed operation. After that point, later
  calls return `Closed` instead of pretending the object is reusable.

Durability, cancellation, and buffer ownership are more explicit at the runtime
boundary.

### Cryptography

The BLS12-381 DKG module now separates the original Feldman-Desmedt construction
from a new Golden DKG implementation:

- `feldman_desmedt` remains the simpler synchronous, two-round construction.
- `golden` adds an asynchronous, one-round DKG and resharing protocol with
  public verification and optional resharing from a previous output.

The Golden path introduces an eVRF setup and carries explicit safety
requirements around log agreement, round-number reuse, reshare dealer
membership, and use of the authenticated output quorum.

The new `cryptography::zk` module adds Bulletproof-related infrastructure and a
Pedersen-to-plain proof that links a transparent commitment and a Pedersen
commitment to the same hidden value. These are ALPHA building blocks for higher
level protocols that need proof composition.

Ed25519 internals are now vendored rather than relying directly on the upstream
crate. The vendored implementation keeps ZIP215 semantics, uses
`curve25519-dalek`, removes unneeded dependencies, zeroizes additional signing
material, and lets the batch verifier reuse pre-decompressed verification keys.

The generic `BatchVerifier` API is now strategy-aware, enabling parallel batch
verification where the chosen `commonware-parallel` strategy supports it.

### Codec, Formatting, And Utilities

- `commonware-formatting` is now a dedicated crate for formatting and parsing
  encoded data, including the hex helpers previously exposed from
  `commonware-utils` and allocation-free hex display wrappers.
- `commonware-codec` gained byte-container specialization hooks so generic
  container implementations can bulk-copy byte-oriented data without abandoning
  generic fallbacks.
- `commonware-utils` includes a Roaring bitmap implementation and channel
  reservation helpers for reserving bounded-channel capacity while retaining
  ownership of the unsent value.
- `commonware-math` exposes synthetic linear combinations for building symbolic
  group expressions that are later evaluated with an MSM strategy.
- Coding APIs were tightened around canonical Reed-Solomon decoding and
  caller-provided ZODA namespaces.
