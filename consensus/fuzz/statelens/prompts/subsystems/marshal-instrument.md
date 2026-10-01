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
- Replica index: the participant index of the replica's own signing scheme, which marshal
  gets from its scheme provider.
  - Core actor: derive it once when the actor is created, from the scheme its provider
    returns for the epoch it starts in. Keep it in a `// [statelens] me` field of type
    `Option<crate::simplex::statelens::Participant>`. When the actor creates its mailbox,
    copy it into a `// [statelens] me` field of the mailbox, so that every holder of a
    mailbox clone can read it.
  - Standard adapters: read it from the core mailbox they hold.
  - Coding adapter and shards engine: take it from the scheme their scheme provider
    returns for the epoch of the round in hand.
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
