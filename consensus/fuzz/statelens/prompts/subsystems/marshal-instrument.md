### Marshal (`consensus/src/marshal/`)

- Editable code: non-test code in `consensus/src/marshal/`, except `mocks/`. Call the
  runtime from here as `crate::simplex::statelens::...`, as simplex code does.
- Components:
  - the core actor (`core/`): ordering, the processed floor, caches, archives,
    acknowledgements, subscriptions, and repair and backfill handling;
  - the standard consensus adapters (`standard/`): `Inline` and `Deferred`;
  - the coding mode (`coding/`): the `Marshaled` adapter and the shards engine.

  They exchange messages through mailboxes. They use the backfill resolver (`resolver/`),
  the application gates and validation (`application/`), `ancestry.rs` and `store.rs`.
- Replica index: the participant index of the replica's own signing scheme. Marshal holds a
  scheme provider, not a scheme, and a provider lookup is not a read: an application may
  count lookups against the scope it serves and retire it, as the standard tests'
  `RetiringProvider` and the shards engine tests' `ChurningProvider` do, so a lookup of
  yours can turn a later one of the implementation's into `None`. Never look a provider up
  yourself, whether by calling `scoped` or `scheme` or a method of the implementation that
  does, such as `Actor::scoped_for_height`. In marshal `me` has exactly one source,
  `crate::simplex::statelens::provider_me(&provider, epoch)`: for the `ConstantProvider`
  every harness uses it reads the index without an effect, and for any other provider it
  looks nothing up and returns `None`, an unknown index. The scope is not used, so pass any
  epoch in hand, such as `last_processed_round.epoch()` in `Actor::init`, or
  `Epoch::zero()`. Do not read `me()` from a scheme the implementation holds, even where one
  is in hand: under any other provider that site would be checked while its neighbours are
  not, and history one of them writes and another requires would be incomplete.
  - Core actor: call it once in `Actor::init`, keep the result in a `// [statelens] me`
    field of type `Option<Option<crate::simplex::statelens::Participant>>`, and copy it into
    a field of the same type on the mailbox `init` creates, so every holder of a mailbox
    clone can read it. `Mailbox::new` is a `const fn`: initialize the field to `None` there,
    set it by wrapping the `Mailbox::new(..)` expression in `init` in a block, and list that
    wrap under "Edited lines".
  - Standard adapters: read it from the core mailbox they hold.
  - Coding adapter and shards engine: call it in the `Marshaled` or `Engine` method that
    owns the provider. A task the adapter spawns, and the shards sub-states, hold no
    provider: call it in the method before the spawn, so the task captures the `Copy`
    result, or put the site in the `Engine` method that calls the sub-state. Never add a
    parameter to pass it down.
  - `Some(me)` is the index to pass, including `Some(None)` for a scheme with no signer: the
    replica is known not to be a participant. `None` is not an index. Guard the site with
    `if let Some(me) = ...`, so that under any other provider it stays uninstrumented at run
    time, as rule 3 requires for an index you could not obtain. Where the site yields a
    value, such as a `with_ghost` read whose result you keep, write
    `me.and_then(|me| crate::simplex::statelens::with_ghost(me, ...))`: it yields `None`, as
    a skipped replica does. Never pass `None` in its place, and never convert it with
    `.flatten()`, `.unwrap_or(None)` or `.and_then(|me| me)`: each turns an unknown index
    into "not a participant", and the Byzantine guard off. A type error at a macro,
    `with_ghost`, `with_global` or a helper that takes `me` means the guard is missing.
  - Say in each plan section that its sites take `me` from `provider_me`.
  - The backfill resolver, the application gates and validation, `ancestry.rs` and
    `store.rs` have no identity of their own. Instrument them at their call sites in the
    components above, never inside them.
- Asynchrony worth probing:
  - a finalization arrives before its block;
  - the floor moves while backfill is in flight;
  - a block arrives after its height was passed or pruned;
  - dispatch runs ahead of acknowledgements;
  - certification is requested before the block is available;
  - shards arrive out of order or after reconstruction;
  - state is rebuilt from the archives after a restart.
- Decision and commit are different sites here too: a request to the application, to the
  backfill resolver or to another component is issued in one place and its answer handled
  in another, a mailbox hop later. Before binding an invariant about an act -- delivering
  a block, acknowledging a height, certifying, repairing -- find the handler that performs
  the act and assert there. The dispatching site has not learned what arrived in between.
- Heights: record them relative to the processed floor, the last delivered height or the
  finalized tip, never raw. Never feed commitments or shard indices to a probe.
- Tests: marshal's tests seed archives and metadata directly to stand for an earlier run
  (`seed_inconsistent_restart_state`, `seed_processed_height`, `seed_cache_block`), and
  enqueue resolver deliveries whose local annotations no request of the actor created.
  Treat what the actor restores at startup as its own history, and an annotation on a
  delivery, such as `Annotation::Finalized`, as the actor's own request.
