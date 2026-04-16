# Context Redesign

This document describes a redesign of the runtime `Context` API to make
structured concurrency and metric registration less error-prone. The changes
target compile-time enforcement where possible and deterministic-runtime
detection for the remainder.

## Motivation

The current `Context` type fuses three concerns into one `Clone`-able handle:
capabilities (Clock, Storage, Network), observability identity (metric labels,
attributes, scopes, spans), and supervision (spawn, abort cascade). Because
`Clone` creates an implicit supervision tree edge, and `with_label` creates
both a tree edge and a metric prefix, callers routinely hit issues that are
only caught by manual review:

- `context.clone()` silently creates a tree child when the intent was to share
  a capability handle.
- `context.clone().with_label("x")` creates a redundant intermediate tree
  node.
- `with_label(&format!("cache_{i}"))` produces unbounded metric name
  cardinality.
- Two children with the same label panic at runtime on the second
  `register()` call (deterministic runtime only).
- `shared(true)` / `dedicated()` / `with_span()` configuration is silently
  reset by any subsequent `clone()` or `with_label()`.
- Nothing in the type system distinguishes "I need to spawn tasks" from "I
  just need to read the clock."

This PR (#3544) required 38 commits of manual cleanup across 108 files to
address these issues. The redesign eliminates the classes of bugs that
produced them.

## Related Issues

- [#3601](https://github.com/commonwarexyz/monorepo/issues/3601): Add a
  linter for `context.clone()` -- the Clone removal subsumes this entirely.
- [#1849](https://github.com/commonwarexyz/monorepo/issues/1849): Formalize
  Child vs Sibling -- `child` is the explicit "child" operation; the implicit
  "sibling via clone" is gone.
- [#1833](https://github.com/commonwarexyz/monorepo/issues/1833): Refactor
  Context API -- this is the comprehensive version of that refactor.

## Stability

All affected traits (`Supervisor`, `Spawner`, `Observer`, `Clock`,
`Storage`, `Network`, `BufferPooler`) are at ALPHA or BETA stability. ALPHA permits breaking
changes without migration paths. BETA requires stable wire/storage formats
but permits API changes with migration -- the trait changes here do not
affect wire or storage formats.

## Design Principles

1. The supervision tree is the core abstraction. Every change to the tree
   must be explicit and visible at the call site.
2. Metric registration should be ergonomic but not dangerous. Duplicate
   registrations at the same key return the existing metric instead of
   panicking. Namespace collisions between parent metrics and child labels
   are detected in the deterministic test runtime.
3. Compile-time enforcement is preferred. Where compile-time enforcement is
   not possible (string-based namespace collisions), the deterministic
   runtime catches the issue during testing.
4. No `Clone` on Context. Every new handle is produced by an explicit,
   named operation.

## API Changes

### Supervisor Trait

New trait. Owns the supervision tree and the identity that rides on
it: creating child nodes, attaching attributes, and reading the
current label. Separating these from `Spawner` makes the core
abstraction (Design Principle 1) its own surface; subsystems that need
to construct sub-contexts without the ability to launch tasks can take
`impl Supervisor` instead of `impl Spawner`. Observability modifiers
(`with_scope`, `with_span`) live on `Observer` because they shape how
metrics and spans are recorded, not the tree itself.

```rust
/// The full identity of a `Supervisor` handle: its label prefix and
/// the attributes attached via `with_attribute`. The pair is what
/// `register` hashes into a metric key and what `with_span` emits as a
/// span target.
pub struct Name {
    pub label: String,
    pub attributes: Vec<(String, String)>,
}

pub trait Supervisor: Send + Sync + 'static {
    /// Create a named child context with a new supervision tree node.
    /// Non-consuming: call N times for N children.
    ///
    /// The child's label prefix is `self.name().label + "_" + label`.
    /// The child's tree node is a new child of self's tree node.
    ///
    /// Duplicate sibling labels are allowed. Each call creates an
    /// independent supervision node. Children at the same label path
    /// share metrics via get-or-register semantics.
    ///
    /// ```text
    /// context
    ///   |-- child("voter")    --> tree node X1
    ///   |-- child("voter")    --> tree node X2 (independent of X1)
    ///   |-- child("resolver") --> tree node X3
    ///   |
    ///   +-- spawn(f) --> task aborter at context.tree
    ///                    context exit cascades X1, X2, X3
    /// ```
    #[must_use]
    fn child(&self, label: &str) -> Self;

    /// Add a key-value attribute to this context's identity. Affects
    /// metric label dimensions and tracing span attributes (when
    /// `with_span` is active). Consuming. Does not create a tree edge:
    /// the returned handle shares `self`'s tree node.
    #[must_use]
    fn with_attribute(self, key: &str, value: impl std::fmt::Display) -> Self;

    /// Get the current identity: the label prefix (joined `child`
    /// labels) and the attributes accumulated via `with_attribute`.
    /// `register` and `with_span` derive metric keys and span targets
    /// from this; it is exposed so external integrations can match
    /// the same identity.
    fn name(&self) -> Name;
}
```

### Spawner Trait

Remove `Clone` from the supertrait. Require `Supervisor` as a
supertrait (so `spawn` can register an aborter at the current tree
node). Keep only task-lifecycle methods on `Spawner` itself.

```rust
pub trait Spawner: Supervisor {
    /// Terminal: consume self and run its tree node as a task.
    ///
    /// The task aborter is registered at self.tree. Children created
    /// via child(..) cascade when the task body returns or is aborted.
    /// The closure receives a fresh child context (new tree node under
    /// self.tree) for sub-work inside the task.
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static;

    /// Return a SpawnBuilder that schedules the next spawn onto the
    /// runtime's shared executor. Only .spawn(..) is available after.
    #[must_use]
    fn shared(self, blocking: bool) -> SpawnBuilder<Self>;

    /// Return a SpawnBuilder that runs the next spawn on a dedicated
    /// thread. Only .spawn(..) is available after.
    #[must_use]
    fn dedicated(self) -> SpawnBuilder<Self>;

    /// Signal all tasks to shut down and wait for completion.
    fn stop(
        self,
        value: i32,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Returns a signal that resolves when stop is called.
    fn stopped(&self) -> signal::Signal;
}
```

Changes from current:

- `Clone` removed from supertrait.
- Supertrait is now `Supervisor` (which owns `child`, `with_attribute`,
  `name`).
- `with_label` removed. Replaced by `Supervisor::child`.
- `shared` and `dedicated` now return `SpawnBuilder<Self>`.
- `#[must_use]` on `shared`, `dedicated`.

### SpawnBuilder

New type. Terminal step in the spawn-configuration chain: the only
method is `spawn`. This turns two classes of mistake into compile
errors: `shared` / `dedicated` configuration being silently reset by a
later call, and tree-edge, identity, or observability operations
(`child`, `with_attribute`, `with_scope`, `with_span`) being added
after the executor is chosen. All of those must appear before
`shared` / `dedicated`.

```rust
#[must_use]
pub struct SpawnBuilder<S: Spawner> { /* private */ }

impl<S: Spawner> SpawnBuilder<S> {
    pub fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(S) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static;
}
```

### Observer Trait

Remove `Clone` from the supertrait. Move `with_label`, `with_attribute`,
and `label` to `Supervisor`. `with_label` is renamed to `child` in the
move, and `label` is renamed to `name`; `name` now returns both the
label prefix and the attached attributes (previously only the prefix).
Keep `with_scope` and `with_span` here: both shape how observability
records identity rather than shaping the tree itself. Change `register`
to get-or-register semantics.

```rust
pub trait Observer: Send + Sync + 'static {
    /// Route metrics registered through this handle into a scoped
    /// sub-registry that is removed when all handles to this scope
    /// are dropped. Consuming. Does not create a tree edge.
    #[must_use]
    fn with_scope(self) -> Self;

    /// Wrap the next spawned task in a tracing span derived from the
    /// current label and attributes (read via `Supervisor::name`).
    /// Consuming. Preserved through `with_attribute` and `with_scope`
    /// (which return the same handle). Not inherited by `child`: the
    /// flag is tied to this handle's next `spawn`. `child` produces a
    /// fresh handle with default state, so callers must reapply
    /// `with_span` after `child` if the subtree should also be
    /// spanned.
    #[must_use]
    fn with_span(self) -> Self;

    /// Get or register a metric.
    ///
    /// First call at a given (prefixed_name, attributes): registers
    /// default and returns it. Subsequent calls at the same key: returns
    /// a clone of the existing metric. Panics only on type mismatch
    /// (e.g., Counter registered where a Gauge already exists).
    fn register<M: Metric + Clone + 'static>(
        &self, name: &str, help: &str, default: M,
    ) -> M;

    /// Encode all metrics into a buffer.
    fn encode(&self) -> String;
}
```

Changes from current:

- `Clone` removed from supertrait.
- `with_label`, `with_attribute`, and `label` moved to `Supervisor`.
  `with_label` is renamed to `child`; `label` is renamed to `name` and
  now returns both the label prefix and the attached attributes as a
  `Name` struct. These shape task identity (the tree and its labels),
  not observability.
- `with_scope` and `with_span` stay. Both are now consuming.
- `register` returns `M` with get-or-register semantics. The duplicate
  registration panic is removed. Type-mismatch panic is retained.
- `#[must_use]` on `with_scope`, `with_span`.

### Capability Traits

Remove `Clone` from all supertraits. Method signatures are unchanged (all
`&self`).

```rust
pub trait Clock:
    governor::clock::Clock<Instant = SystemTime>
    + governor::clock::ReasonablyRealtime
    + Send + Sync + 'static
{ /* methods unchanged */ }

pub trait Network: Send + Sync + 'static { /* methods unchanged */ }
pub trait Storage: Send + Sync + 'static { /* methods unchanged */ }
pub trait BufferPooler: Send + Sync + 'static { /* methods unchanged */ }
```

### Runner and ThreadPooler

`Runner` is unchanged. `ThreadPooler: Spawner` inherits the new `Spawner`
definition. Internal usage becomes
`self.child("rayon_thread").dedicated().spawn(...)`.

### Concrete Context

Delete `impl Clone for Context` from both `tokio::Context` and
`deterministic::Context`.

### Cell

Replace all trait-forwarding impls (~200 lines) with a single `Deref`:

```rust
impl<C> Deref for Cell<C> {
    type Target = C;
    fn deref(&self) -> &C { self.as_present() }
}
```

Delete `impl Clone for Cell<C>`.

All `&self` trait methods (Clock, Storage, Network, BufferPooler, `child`,
`register`, `stopped`, `name`, `encode`) work through `Deref`. Consuming
methods (`with_attribute`, `with_scope`, `with_span`, `spawn`) require
`cell.take()` first, which is what `spawn_cell!` already does.

### spawn_cell! Macro

Unchanged:

```rust
#[macro_export]
macro_rules! spawn_cell {
    ($cell:expr, $body:expr $(,)?) => {{
        let __commonware_context = $cell.take();
        __commonware_context.spawn(move |context| async move {
            $cell.restore(context);
            $body
        })
    }};
}
```

## Compile-Time Enforcement

The following patterns become compile errors:

| Pattern | Reason |
|---|---|
| `context.clone()` | No `Clone` impl on Context |
| `context.with_label("x")` | No `with_label` method; use `child("x")` |
| `ctx.shared(true).child("x").spawn(f)` | `SpawnBuilder` has no `child` |
| `ctx.dedicated().with_attribute("k", v)` | `SpawnBuilder` has no `with_attribute`; add attributes before `dedicated()` |
| Spawning the same handle twice | `spawn(self)` consumes |
| Using a context after `with_attribute` | `with_attribute(self)` consumes |
| Using a context after `with_scope` | `with_scope(self)` consumes |
| Using a context after `with_span` | `with_span(self)` consumes |

## Deterministic Runtime Detection

The deterministic runtime adds cross-checks between child labels and metric
names at each context level. These checks fire as panics during test
execution.

### Implementation

Each context level holds an `Arc<Mutex<NamespaceGuard>>` shared across
every handle at that level (the parent and any non-consuming
derivatives from `child`/`with_attribute`/etc. see the same guard).
The mutex is only contended during registration and child creation,
both of which are cold paths:

```rust
struct NamespaceGuard {
    child_labels: HashSet<String>,
    registered_names: HashSet<String>,
}
```

On `child(label)`:

```rust
// No registered metric at this level should be prefixed by this child's namespace
for name in &guard.registered_names {
    assert!(
        !name.starts_with(&format!("{label}_")),
        "child '{label}' collides with registered metric '{name}'"
    );
}
// Duplicate sibling labels are allowed (each produces an independent
// tree node; metrics are shared via get-or-register). We intentionally
// do NOT panic on prefix-related sibling labels: unrelated modules can
// legitimately share a word prefix (e.g. "peer" and "peer_pool"), so
// a preemptive prefix check produces false positives. Any real
// collision surfaces at the metric-registration cross-check below.
guard.child_labels.insert(label.to_string());
```

On `register(name, ...)`:

```rust
// No child namespace should be a prefix of this metric name
for child in &guard.child_labels {
    assert!(
        !name.starts_with(&format!("{child}_")),
        "metric '{name}' collides with child namespace '{child}'"
    );
}
guard.registered_names.insert(name.to_string());
// Then: get-or-register (return existing on duplicate, panic on type mismatch)
```

These checks exist only in the deterministic runtime. The tokio runtime
performs plain get-or-register with no cross-checks.

### What is detected

| Pattern | Message |
|---|---|
| `child("voter")` after `register("voter_count")` | "child 'voter' collides with registered metric 'voter_count'" |
| `register("voter_count")` after `child("voter")` | "metric 'voter_count' collides with child namespace 'voter'" |
| `register` with same key but different type | "metric type mismatch for 'foo'" |

## Method Summary

| Method | Trait | Consumes? | Tree edge? |
|---|---|---|---|
| `child(&self, label)` | Supervisor | No | Yes |
| `with_attribute(self, k, v)` | Supervisor | Yes | No |
| `name(&self)` | Supervisor | No | No |
| `spawn(self, f)` | Spawner | Yes | Terminal |
| `shared(self, b)` | Spawner | Yes | Terminal (builder) |
| `dedicated(self)` | Spawner | Yes | Terminal (builder) |
| `stop(self, ...)` | Spawner | Yes | Terminal |
| `stopped(&self)` | Spawner | No | No |
| `with_scope(self)` | Observer | Yes | No |
| `with_span(self)` | Observer | Yes | No |
| `register(&self, ...)` | Observer | No | No |
| `encode(&self)` | Observer | No | No |
| Clock/Storage/Network/BufferPooler | respective | No (`&self`) | No |

Non-consuming methods: `child`, `name` (Supervisor); `stopped`
(Spawner); `register`, `encode` (Observer); all capability trait
methods.

Consuming methods: `with_attribute` (Supervisor); `spawn`, `shared`,
`dedicated`, `stop` (Spawner); `with_scope`, `with_span` (Observer).

## Chaining Order

```
context
    .child("engine")                  // Supervisor: tree edge + label (non-consuming)
    .with_attribute("epoch", epoch)   // Supervisor: consuming, identity dimension
    .with_scope()                     // Observer: consuming, scoped registry
    .with_span()                      // Observer: consuming, tracing span
    .dedicated()                      // Spawner: consuming, returns SpawnBuilder
    .spawn(f)                         // SpawnBuilder: consuming, terminal
```

`child` is always first (non-consuming, returns an owned handle).
`with_attribute`, `with_scope`, `with_span` can appear in any order after
`child` (all `Self -> Self`). `shared` / `dedicated` must come last before
`spawn` (they produce `SpawnBuilder` which only has `spawn`).

## Migration Guide

### Mechanical Substitutions

| Before | After |
|---|---|
| `context.clone()` | `context.child("label")` |
| `context.with_label("x")` | `context.child("x")` |
| `self.context.with_label("x").into_present()` | `self.context.child("x")` via `Deref` |
| `scope.clone()` for separate retention | Move scope into consumer |
| `let c = Counter::default(); ctx.register("n","h",c.clone());` | `let c = ctx.register("n","h",Counter::default());` |
| `ContextCell::new(x)` | `Cell::new(x)` |
| Cell trait methods (e.g. `self.context.current()`) | Same calls, routed through `Deref` |

### Example: Voter Actor

Before:

```rust
fn new(context: E, cfg: Config) -> (Self, Mailbox) {
    let outbound_messages = Family::<Outbound, Counter>::default();
    context.register("outbound_messages", "...", outbound_messages.clone());
    let notarization_latency = Histogram::new(LATENCY);
    context.register("notarization_latency", "...", notarization_latency.clone());
    let state = State::new(context.with_label("state"), StateConfig { ... });
    (Self { context: ContextCell::new(context), outbound_messages, ... }, mailbox)
}
```

After:

```rust
fn new(context: E, cfg: Config) -> (Self, Mailbox) {
    let outbound_messages = context.register(
        "outbound_messages", "...", Family::<Outbound, Counter>::default(),
    );
    let notarization_latency = context.register(
        "notarization_latency", "...", Histogram::new(LATENCY),
    );
    let state = State::new(context.child("state"), StateConfig { ... });
    (Self { context: Cell::new(context), outbound_messages, ... }, mailbox)
}
```

### Example: Per-Peer Spawn

Before:

```rust
self.context.with_label("peer").spawn(move |context| async move {
    let (peer_actor, ..) = peer::Actor::new(context, peer::Config { ... });
    peer_actor.run().await;
});
```

After:

```rust
self.context
    .child("peer")
    .with_attribute("peer_id", &peer)
    .spawn(move |context| async move {
        let (peer_actor, ..) = peer::Actor::new(context, peer::Config { ... });
        peer_actor.run().await;
    });
```

With get-or-register semantics, a reconnecting peer that produces the same
`("peer_id", pk)` attribute pair safely returns the existing metric handles
instead of panicking. Previously, if any code inside the peer actor called
`register(...)`, the second connection for the same peer would panic on
duplicate registration in the deterministic runtime. This is no longer an
issue -- duplicate keys return the existing metric, and the per-peer
`with_attribute` dimension keeps each peer's metrics queryable in
dashboards.

### Example: Epoch-Scoped Engine

Before:

```rust
let scope = self.context
    .with_label("consensus_engine")
    .with_attribute("epoch", epoch)
    .with_scope();
let engine = simplex::Engine::new(scope.clone(), cfg);
(engine.start(vote, certificate, resolver), scope)
```

After:

```rust
let scope = self.context
    .child("consensus_engine")
    .with_attribute("epoch", epoch)
    .with_scope();
let engine = simplex::Engine::new(scope, cfg);
engine.start(vote, certificate, resolver)
```

In the current code, `scope.clone()` is passed to the engine while the
original scope is returned alongside the handle to keep the scoped registry
alive until epoch exit. With the redesign, there is no `Clone` -- the scope
moves directly into the engine. The engine holds it in its `Cell`, and the
scoped registry stays alive as long as the engine's task runs. When the
epoch exits and the handle is aborted, the engine's task drops, the scope
drops, and the scoped registry is cleaned up.

Whether the caller also needs to retain a separate scope handle depends on
the abort-to-drop timing: if the caller needs to guarantee the scoped
registry outlives the abort signal (e.g., to ensure a final metrics scrape
captures the epoch's data), it should retain a `child` handle separately.
In most cases, letting the engine own the scope is sufficient -- the task
drop and scope cleanup happen synchronously as part of the abort cascade.

### Example: Construct-Then-Run

Before:

```rust
pub async fn new(context: E, config: Config) -> Self {
    let page_cache = CacheRef::from_pooler(context.with_label("cache"), ...);
    let (dkg, mbox) = dkg::Actor::new(context.with_label("dkg"), ...);
    let (buffer, mbox) = buffered::Engine::new(context.with_label("buffer"), ...);
    Self { context: ContextCell::new(context), ... }
}

pub fn start(mut self, ...) -> Handle<()> {
    spawn_cell!(self.context, self.run(...).await)
}
```

After:

```rust
pub async fn new(context: E, config: Config) -> Self {
    let page_cache = CacheRef::from_pooler(context.child("cache"), ...);
    let (dkg, mbox) = dkg::Actor::new(context.child("dkg"), ...);
    let (buffer, mbox) = buffered::Engine::new(context.child("buffer"), ...);
    Self { context: Cell::new(context), ... }
}

pub fn start(mut self, ...) -> Handle<()> {
    spawn_cell!(self.context, self.run(...).await)
}
```

Cascade semantics unchanged: the engine's task aborter lives at
`context.tree`. Children created via `child(..)` cascade on engine exit.

### Example: spawn_cell! and run()

Before:

```rust
async fn run(mut self) {
    let pool = self.context.network_buffer_pool();
    let journal = Journal::init(
        self.context.with_label("journal").into_present(), cfg,
    ).await?;
    let start = self.context.current();
    select_loop! { self.context, ... }
}
```

After:

```rust
async fn run(mut self) {
    let pool = self.context.network_buffer_pool();        // Deref -> &E
    let journal = Journal::init(
        self.context.child("journal"), cfg,               // Deref -> &E -> child -> owned E
    ).await?;
    let start = self.context.current();                   // Deref -> &E
    select_loop! { self.context, ... }                    // stopped() via Deref
}
```

## Decided Behavior

### `child` is audited in the deterministic runtime

The deterministic runtime's `Auditor` records events for determinism
verification (`context.auditor().state()`). `child` creates a tree edge
and is recorded as an audited event, with the label folded into the
audit hash. Without this, two runs that produce different supervision
trees (e.g. due to a nondeterministic ordering bug) would hash
identically, leaving a determinism gap.

### `register` panics on type mismatch

Registering the same metric key with different types (e.g. Counter vs
Gauge) panics. Returning `Result<M, TypeError>` was considered and
rejected: type mismatches are always programming errors (two actors
disagree about what a metric name means), and no caller can
meaningfully recover.

## Open Questions

### Metric key composition

The metric dedup key is `(prefixed_name, attributes)` -- same as today's
`MetricKey` type (`deterministic.rs:372`). The prefix is built by `child`:
each `child("x")` appends `"_x"` to the current prefix. The attributes are
set by `with_attribute`. The key for get-or-register is the combination of
both. Two children at the same label path with the same attributes share
metrics; children with different attributes (e.g., different `peer_id`)
get independent metrics.

### ThreadPooler and duplicate child labels

`ThreadPooler::create_thread_pool` calls
`self.child("rayon_thread").dedicated().spawn(...)` in a loop (one per
rayon thread). This produces multiple children with the label
`"rayon_thread"`. Under the new design, duplicate sibling labels are
allowed -- each call creates an independent tree node. The rayon threads
share metrics via get-or-register, which is correct (thread pool metrics
should aggregate across workers).

### Migration sequencing

The changes can be landed incrementally:

1. Introduce the `Supervisor` trait (initially a blanket impl over
   existing `Observer` bounds so code compiles unchanged) and add
   `child` on it alongside existing `with_label` on `Observer`. Both
   work during the transition.
2. Add `SpawnBuilder` and route `shared` / `dedicated` through it. Keep
   the old direct-return signatures behind `#[deprecated]`.
3. Change `register` to get-or-register semantics. Remove the
   `registered_metrics` HashSet and duplicate-registration panic from
   the deterministic runtime. Add the `NamespaceGuard` cross-checks.
4. Make `with_attribute`, `with_scope`, `with_span` consuming (take
   `self` instead of `&self`). Move `with_attribute` and `label` from
   `Observer` to `Supervisor`, renaming `label` to `name` and
   broadening its return to include attributes (`with_scope` and
   `with_span` stay on `Observer`). The old `label()` is re-exported
   from `Observer` as a `#[deprecated]` shim (delegates to
   `name().label`) so call sites migrate incrementally. After this
   step, `Observer` contains `with_scope`, `with_span`, `register`,
   and `encode`.
5. Migrate call sites from `with_label` to `child` and from
   `context.clone()` to `context.child("label")`.
6. Require `Spawner: Supervisor` (drop the blanket impl) and remove
   `Clone` from all trait supertraits; delete `impl Clone for Context`.
7. Replace Cell trait forwards with `Deref`. Delete `impl Clone for Cell`.
8. Remove deprecated compat paths.

Each step compiles and passes tests independently.

- Steps 1-3 are non-breaking (additive or signature-compatible).
- Step 4 is a soft breaking change. Flipping `with_attribute`,
  `with_scope`, and `with_span` from `&self` to `self` compiles for any
  call site that does not reuse the context after the call (the common
  pattern `ctx.with_scope().spawn(...)` is unaffected). Sites that
  relied on non-consuming behavior (e.g. `ctx.with_scope();
  use_ctx(...)`) must be updated before the flip; audit with a grep
  for each method name.
- Steps 5-7 are the main breaking migration.
- Step 8 is cleanup.
