- `consensus/src/simplex` implements a modified Simplex consensus protocol. Leaders
  propose blocks for views. Replicas vote to notarize a proposal, to nullify a view
  (skip it), or to finalize a notarized proposal, and a quorum of votes of one kind
  forms a certificate (notarization, nullification, finalization). Each replica runs
  three actors: the voter (the view state machine), the batcher (vote collection and
  verification) and the resolver (fetching missing certificates). Replicas persist
  their votes in a journal and recover from it after a crash. The module docs in
  `consensus/src/simplex/mod.rs` describe the protocol; read them when a source leaves
  a concept unclear.
- System: `replica`, one honest replica; for scope `protocol`, `protocol`, all honest
  replicas together.
- Adversary: Byzantine replicas up to the fault threshold (equivocating, mutating
  messages, splitting the network), arbitrary message delay, reordering and loss,
  timeouts, and crashes followed by recovery from persistent state.
- Honest actions: votes it signs, messages it sends, certificates it accepts, state it
  persists, views it enters.
- Protocol terms: views, leaders, proposals, parents, votes, certificates, timeouts, the
  finalized tip, the journal.
- Example of a progress property that names its moment: "When the replica times out in a
  view without having signed a finalize vote for it, the replica shall sign a nullify
  vote for that view".
- Kinds of rules in design documents: voting rules, conditions for entering a view,
  timeout and nullification rules, certificate validity and use, parent and ancestry
  rules, persistence and recovery guarantees, and bounds on tracked state.
- Scope values: `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor`.
- In scope: Simplex behavior.
