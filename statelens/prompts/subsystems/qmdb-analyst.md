- `storage/src/qmdb` implements databases inspired by QMDB (Quick Merkle Database, arXiv
  2501.05262). A database's state is derived from an append-only log of operations. In the
  authenticated variants a Merkle structure over the log (an MMR or an MMB) gives the root
  that authenticates it: `any` (keyed; proves any value a key ever had, over an ordered or
  an unordered key space), `current` (an `any` database plus a bitmap of the active
  operations grafted onto the operations tree, so it also proves that a value is the
  current one), `immutable` (keyed values that are set once and never updated or deleted)
  and `keyless` (values appended and read back by location). `store` is a keyed store over
  the same kind of log, without authentication. Every variant changes through batches: a
  batch is created, mutations are staged on it, and it is applied; `commit` and `sync` make
  applied state durable. In the authenticated variants a batch is merkleized against the
  current state before it is applied, which gives the root that applying it would produce.
  A `store` batch is finalized into a changeset instead, and the store has no root and no
  proofs. Each commit carries an inactivity floor below which operations may be pruned.
  `sync` builds a database from an untrusted source up to a trusted target, and `verify`
  checks proofs against a root. The module docs in `storage/src/qmdb/mod.rs` and in the
  `mod.rs` of each variant describe the design; read them when a source leaves a concept
  unclear.
- System: `database`, one database over its whole life, restarts included.
- Adversary: arbitrary sequences of batches, including forks, chains and stale batches;
  crashes at any point, followed by recovery from what reached storage; storage faults;
  and, in sync and in proof verification, a source or a prover that answers with anything.
- Honest actions: the operations it appends, the roots it reports, the batches it accepts
  or rejects, what it makes durable and what it prunes, the state it recovers after a
  restart, the values and proofs it returns, and what a verifier or a sync target accepts.
- Terms: operations, locations, keys and values, active operations, the operation log,
  the root, batches (merkleized, applied, stale; in `store`, finalized changesets), commits,
  the inactivity floor, pruning, durability, recovery, proofs, sync targets.
- Example of a progress property that names its moment: "When a commit returns
  successfully, the database shall have made durable every operation it applied before
  the commit".
- Kinds of rules in design documents: root and proof rules, batch validity (staleness,
  chains, floors), commit and durability rules, recovery after a crash and initialization
  bounds, pruning bounds, activity tracking in `current`, sync rules, and bounds on
  in-memory state.
- Scope values: `database` (one database), `proof` (proofs and their verification),
  `sync` (a database built from a source), and the variant a property is about: `any`,
  `current`, `immutable`, `keyless`, `store`.
- In scope: the databases of `storage/src/qmdb`. The journals and Merkle structures they
  build on (`storage/src/journal`, `storage/src/merkle`) are not, though a qmdb invariant
  may rely on what they guarantee.
