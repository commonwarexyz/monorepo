### QMDB (`storage/src/qmdb/`)

- Editable code: non-test code in `storage/src/qmdb/`, except `benches/`. Call the runtime
  as `crate::qmdb::statelens::...`.
- Components: the variants `any/`, `current/`, `immutable/`, `keyless/` and `store/`, the
  sync engine in `sync/` with the `sync/` module of each variant, and the shared code they
  call: `mod.rs` (initialization and recovery), `chain.rs` (batch-chain validation),
  `bitmap.rs`, `operation.rs`, `verify.rs` and `compact/`. A beacon run for one variant
  may probe the shared code it calls.
- Adversary: the fuzzer drives a database through arbitrary sequences of batches, forks,
  stale batches, commits, pruning, crashes, storage faults and reopens, and feeds sync and
  proof verification with data from an untrusted source.
- No replicas: there is no participant index, so `me` is `None` at every site, and the
  guard checks every site. Use `with_global` for ghost state; `with_ghost` needs an index
  and always returns `None` here.
- Several databases can share one run, such as a sync source and its target, and one
  database can be reopened within a run. Ghost history in `Global` must keep distinct
  databases apart and follow one database across a reopen: key it by an identity the
  database keeps across a reopen, such as the partition its log uses. History that need
  not survive a reopen can live in a `// [statelens] ghost:` field of the database.
- Asynchrony worth probing: a batch merkleized against a state that another batch has
  since changed, a chain applied whole or from its tail, a background sync from
  `start_sync` still running while later batches are applied or the log is pruned,
  recovery from a log that runs past the last commit, a sync target that moves while
  requests are in flight, a proof checked against an older root.
- Decision and commit are different sites here too. In the authenticated variants
  `merkleize` computes the root a batch would give and `apply_batch` makes it the
  database's state; in `store`, `finalize` turns a batch into a changeset that
  `apply_batch` applies, with no root. `commit` or `sync` makes applied state durable
  later still, and another batch may be applied in between. Assert where the state
  changes or becomes durable, not where it was computed.
- Errors: a mutating method that returns an error consumes the database, so nothing can
  use it afterwards. Check on the success path, and read an error as the database
  refusing the act.
- Locations, floors and sizes: record them relative to one another (a location against
  the inactivity floor or the log size, the floor against the pruning boundary), never
  raw. Never feed keys, values, digests or roots to a probe.
- Tests build states by hand: they write logs directly, truncate or corrupt them, and
  reopen databases at chosen bounds. Treat what a database recovers at startup as its own
  history; where a check needs evidence of an earlier event, accept what the database
  holds or recovered.
- Fuzz targets: `storage/fuzz/fuzz_targets/qmdb_*.rs`. Each drives the variant its name
  says. Most run on the deterministic runtime, some reopen the database within a run,
  `qmdb_current_recovery` injects storage faults and restarts from checkpoints, the sync
  targets build a database from a source database, and `qmdb_verify_proof` checks proofs
  decoded from fuzzer bytes.
