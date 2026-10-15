- `consensus/src/marshal` turns the certificates of the Simplex consensus protocol
  (`consensus/src/simplex`), and the blocks disseminated for its proposals, into an
  ordered stream of finalized blocks for the application. Each replica runs a marshal
  actor. It caches blocks and certificates, persists finalized blocks and their
  finalizations, and keeps a processed floor; it may start from a finalized floor instead
  of genesis. It delivers finalized blocks to the application in height order and at
  least once, waits for the application to acknowledge them, prunes what it no longer
  needs, and fetches missing blocks and certificates from peers (backfill). Between
  Simplex and marshal, a consensus adapter proposes, verifies and certifies blocks:
  `Inline` or `Deferred` in standard mode, or `Marshaled` in coding mode. In coding
  mode, blocks are erasure coded into shards, which the shards engine disseminates,
  checks and reconstructs. The module docs in `consensus/src/marshal/mod.rs` describe
  the design; read them when a source leaves a concept unclear.
- System: `replica`, one honest replica; for scope `protocol`, `protocol`, all honest
  replicas together.
- Adversary: Byzantine replicas up to the fault threshold (equivocating, mutating
  messages, splitting the network), arbitrary message delay, reordering and loss,
  timeouts, and crashes followed by recovery from persistent state.
- Honest actions: the blocks it delivers to the application and their order, the blocks
  and certificates it persists, prunes or serves to peers, the processed floor it keeps,
  the backfill requests it makes and the responses it accepts, the verification and
  certification results it reports to consensus, and the shards it accepts, forwards or
  uses for reconstruction.
- Protocol terms: finalized blocks, heights, parents, notarizations, finalizations, the
  processed floor, delivery and acknowledgement, backfill, durable storage, pruning,
  epochs, and, in coding mode, commitments, shards and reconstruction.
- Example of a progress property that names its moment: "When the replica learns a
  finalization for a height above every finalized tip it has reported, the replica shall
  report that height to the application as its new finalized tip".
- Kinds of rules in design documents: delivery order and duplication, floor and anchor
  rules, conditions for persisting, pruning and serving blocks and certificates, backfill
  and repair rules, verification and certification rules of the consensus adapters,
  shard validity and reconstruction rules, recovery after a restart, and bounds on
  tracked state.
- Scope values: `protocol`, `replica`, `core`, `resolver` (marshal's backfill resolver),
  `standard`, `coding`, `application`, `cross-component`.
- In scope: marshal behavior, including the consensus adapters and the coding mode.
  Simplex voting, views and the forming of certificates belong to the simplex registry.
