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
  scheme provider, not a scheme, and a provider lookup is not a read: `Provider::scheme`
  calls `Provider::scoped`, and an application may count lookups against the scope it
  serves and then retire it (the standard tests' `RetiringProvider` allows exactly one), so
  a lookup of yours can turn one of the implementation's into `None`. Never call the
  provider, or anything that calls it, to learn `me`. Read it from a scheme the
  implementation has already obtained, where it obtained it: `scheme.me()`, or for a
  `Scoped`, `scoped.clone().into_scheme()` and then `me()` (a clone of a `Scoped` is a
  read).
  - Coding adapter and shards engine: every site that needs a scheme already looks one up
    for the round in hand; read `me` from that one.
  - Core actor: it looks a scheme up only while it works, never when it is created. Give it
    a `// [statelens] me` cell of type
    `Arc<std::sync::OnceLock<Option<crate::simplex::statelens::Participant>>>`, shared with
    every clone of its mailbox, and set it from the first scheme the actor obtains. It is
    StateLens state, so setting it later is allowed, and the standard adapters, which never
    look a scheme up, read it through the mailbox they hold. It keeps the first epoch's
    index, which the harnesses' `ConstantProvider` never changes.
  - Until the cell is set the index is not obtained, so guard a site that needs it with
    `if let Some(&me) = cell.get()` instead of passing `None`, which means "not a
    participant" and turns the Byzantine guard off.
  - The backfill resolver, the application gates and validation, `ancestry.rs` and
    `store.rs` have no identity of their own. Instrument them at their call sites in the
    components above, never inside them.
  - When the scheme has no signer (it is a verifier), `me` is `None`: the replica is not a
    participant.
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
