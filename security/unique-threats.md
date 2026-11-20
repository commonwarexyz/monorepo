# Threats Unique to This Monorepo

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

These threats come from how Commonware is built and shipped. A single-product
blockchain node does not have them, or has them in a much weaker form. Each
entry names the peculiarity, the threat, why it is specific to this
repository, and its source.

1. **The integrator owns half of every security argument.** Each primitive
   states its guarantees for a caller that meets documented obligations, and
   many obligations cannot be checked by types or at run time.
   The threat is a composed system that loses a property every primitive's
   own tests demonstrate, because the caller broke an unchecked precondition.
   It is specific here because every public trait and constructor is an
   external boundary with an unknown caller. In a single-product node one team
   owns both sides of each internal interface.
2. **Security depends on the instantiation the integrator picks.** Primitives
   are generic over the signature scheme, certificate scheme, hasher, cipher,
   translator, elector, and execution strategy. 
   A property shown for one instantiation can fail for another.
   A documented case: SAKE `Version::V0` authenticates the dialer
   only if the signature scheme admits no key substitution, and with a scheme
   "like ECDSA" a dialer can complete the handshake under a key that is not
   its own . The threat is a valid but unsafe
   combination of generic parameters reaching production. It is specific here
   because a single-product node ships one instantiation and tests only that
   one.
3. **Settings that peers must share are configured, not negotiated.** The
   application namespace and the SAKE version are not negotiated
   (`stream/src/sake/mod.rs`, section "Configuration"). The CUPS version and
   cipher are set out of band, and the handshake contract does not
   authenticate them. Decode limits, quorum
   fault model, coding parameters, and timeouts are local configuration as
   well. The threat is two honest nodes that differ in one of these settings:
   each sees the other's valid traffic as invalid and blocks it, or a node
   keeps accepting a weaker version that its peers believe is retired. It is
   specific here because the library defines no network-wide parameter set;
   the integrator must distribute one.
4. **Decode bounds are caller configuration, not part of the wire format.**
   The threats are: a call site at
   an untrusted boundary that passes an unbounded or oversized limit; limits
   for nested values that are swapped, since two limits of the same type
   type-check in either order; limits that do not nest across layers (stream
   message size, p2p channel size, codec maximum of every representation); a
   stored record that no longer decodes after a limit is lowered; and two
   honest nodes with different limits. It is specific here because
   most wire formats fix their limits in the schema, and one team sets them
   once.
5. **One crate holds code at several stability levels, selected by `cfg`.**
   The threats are: an integrator who runs ALPHA code in production and 
   loses stored state or
   peer compatibility on upgrade; a build at a higher level that compiles a
   different set of items than the default build that CI tested; a
   mis-scoped item that lets stable code depend on unstable behavior; and a
   reviewer who rates a format break without checking the item's level. It is
   specific here because stability is a per-item compile-time property, not a
   property of a release.
6. **Tests run on a runtime that does not ship.** Async protocol tests must
   use the deterministic runtime, while production uses the
   `tokio` runtime or, on Linux, the `iouring` runtime.
   The `iouring` cases run only on Linux.
   The `external` feature lets real latency into
   the deterministic runtime and makes it non-deterministic. Primitives are runtime-agnostic,
   so an integrator may also supply its own runtime. The
   threats are: a scheduling, cancellation, or durability bug that exists only
   on a shipped runtime and that no deterministic test can show; a passing
   deterministic test read as evidence about `tokio` or `iouring`; and a
   custom runtime whose clock, `sync`, or cancellation is weaker than the
   primitives assume. It is specific here because the runtime is a
   replaceable parameter of every protocol. See also Runtime threats.
7. **Namespaces are split between the library and the integrator.** Library
   namespaces follow `_COMMONWARE_<CRATE>_<OPERATION>` and changing one is a
   breaking change (`AGENTS.md`); the integrator supplies the application
   namespace that is combined with them. The threats are: two deployments, or
   a test network and a main network, that share a key and an application
   namespace, so a signature from one verifies in the other; a new primitive
   that reuses an existing library namespace; and a renamed namespace that
   silently splits a network during a rolling upgrade. It is specific here
   because no single party sees all the namespaces that share a key.
8. **Glue code is where the assumptions of separate crates meet.** `glue`
   offers "default constructions that span multiple primitives".
   Limits, the order of persist, acknowledge, and broadcast,
   epoch handoff, and pruning floors are only consistent or inconsistent once
   crates are joined. The threat is a composition in which every primitive
   behaves as documented and the whole still violates safety or liveness. It
   is specific here because integrators copy or replace `glue`, so the same
   class of defect recurs in code this repository never sees.
9. **Storage handles are destroyed by failure, by convention.** Mutating
    storage methods take `self` and return it on success, and a failed
    mutable operation is fatal for that instance . The
    threats are: an integrator that keeps using or reopens a failed instance
    without a restart and commits from inconsistent state; and a reviewer who
    reports the inconsistent state of a failed instance as a defect. It is
    specific here because the rule lives in a convention and in ownership,
    not in a process boundary as in a database server.
10. **The Simplex engine is not the Simplex of the paper.**
    `consensus::simplex` extends the published protocol: an
    application `certify` step between notarization and the finalize vote,
    leader and skip timeouts, stable leaders over multi-view terms with
    optimistic validation and pipelined handoff, certificates fetched on
    demand, and votes verified lazily in batches.
    The threats are: a property proven for the paper or checked in the model
    that is taken as shown for the code; an added rule, alone or combined
    with another, that lets two conflicting blocks finalize or stalls every
    view; `certify` verdicts that differ between honest validators, so that
    part of the committee refuses to build on a block the rest builds on and
    consensus halts; and quorum arithmetic of one fault model applied to the
    rules of the other. It is specific here because the deviations are this
    repository's own: the paper's proof does not cover them, and the
    argument for each is the module documentation.
11. **Simplex agrees on digests, and Marshal turns them into the blocks the
    application executes.** `consensus::simplex` votes on payload digests by
    view. `consensus::marshal` collects blocks from the broadcast buffer or
    from coded shards, takes notarizations and finalizations from Simplex,
    fetches what is missing through the resolver, rebuilds the order by
    height, and delivers each finalized block at least once against the
    application's acknowledgement. A restart or a floor installation can
    redeliver blocks that were already reported. The vote journal of
    Simplex, the archives of Marshal, and the application's database are
    separate stores with separate durable points. The threats are: an
    application that executes a block, an order, or a height that no quorum
    finalized although Simplex itself stayed safe; a crash between two of
    the three durable points that leaves a combination no component
    expects, such as an acknowledged block the application did not persist;
    and a redelivered block that the application applies twice. It is
    specific here because Commonware exposes agreement, block delivery, and
    execution as three separately durable components behind public
    boundaries, which an integrator wires together and may replace, and
    because the at-least-once acknowledgement contract of Marshal leaves
    the handling of duplicates to the application.
12. **A QMDB root commits to the log of operations, not to the key-value
    state.** In `storage::qmdb` the state is derived from an append-only
    log, and the root authenticates that log. Commit operations, their
    metadata, and the updates that a `floor::Policy` rewrites at the tip
    when it advances the inactivity floor are log entries as well. The
    threats are: two honest nodes that hold the same keys and values but
    reached them through different batch boundaries, commit metadata, or
    floor policies, so their roots differ and they disagree on every state
    root; a floor policy whose decisions depend on node-local state; and a
    reviewer or integrator who treats equal content, or equal log size, as
    equal roots. It is specific here because in a state trie the root is a
    function of the current content alone, and here it is a function of the
    path taken, including maintenance that the caller configures.
13. **Each QMDB variant proves a different statement under its root.** The
    variants share one batch API. An `any` database proves that a key had a
    value at some point, not that the value is still current. A `current`
    database grafts an activity bitmap onto the same tree to prove that, and
    only its ordered form proves that a key is absent. The threats are: a
    verifier, such as a light client or a bridge, that accepts an `any`
    proof of a superseded or deleted value as the present state; a proof
    checked against the root of another variant; and an integrator who
    picks a variant for speed and loses the statement its verifiers need.
    It is specific here because the meaning of a valid proof depends on the
    database variant and its verification algorithm, with separate proof
    structures and verification interfaces for `any` and `current`, while a
    root is a plain digest that does not identify that choice. A protocol
    that publishes a root must bind it to the variant and the verifier.
