# QMDB fuzz coverage plan

## Constraints

- Keep existing targets structurally intact; add surgical operation arms and invariant assertions.
- Keep every target input-driven. Do not embed unit-test scenarios or fixed expected values.
- Generate at least one operation per input.
- Reserve fuzz bytes before parsing operations and seed the deterministic runtime with
  `commonware_utils::FuzzRng`.
- Run targets from empty corpus directories and verify production-line coverage with LLVM coverage.

## Generator work

- Replace unconstrained derived operation vectors in `qmdb_unordered_operations`,
  `qmdb_ordered_batching`, `qmdb_any_variable_sync`, `current_crash_recovery`, and
  `verify_proof`.
- Bound the digest and operation payload vectors in `verify_proof` so variable-length fields cannot
  consume the bytes required to construct an input.
- Reserve a short input prefix for `FuzzRng`, following `cache_operations.rs`, in targets that use
  the deterministic runtime. `verify_proof` is a pure verification target and has no runtime RNG.

## Missing concrete variants

All generated targets use the `qmgb_gen_` prefix.

- `qmgb_gen_any_ordered_variable`: Any ordered-variable, MMR and MMB.
- `qmgb_gen_current_ordered_variable`: Current ordered-variable, MMR and MMB.
- `qmgb_gen_immutable_fixed`: full immutable fixed, MMR and MMB.
- `qmgb_gen_immutable_compact`: compact immutable fixed and variable, MMR and MMB.
- `qmgb_gen_keyless_fixed`: full keyless fixed, MMR and MMB.
- `qmgb_gen_keyless_compact_fixed`: compact keyless fixed, MMR and MMB.
- `qmgb_gen_partitioned`: representative partitioned Any and Current variants.
- `qmgb_gen_stream_sync`: streaming-sync adapters not covered by `qmdb_any_fixed_sync`.

## Existing-target API additions

### Any

- Add `get_many`, a strategy-backed fold oracle, pinned-node proof verification, idempotent rewind,
  sync/reopen, and empty-state invariants across the operation and variable-sync targets.
- Add ordered `get_all`, `stream_range`, and `span_contains` invariants.
- Exercise batch reads, staging/expansion, bounds, child batches, validation, and `to_batch` in the
  existing batching targets.

### Current

- Add metadata, ops-root witness, historical proof, pinned nodes, rewind, sync/reopen, and batch
  validation operations.
- Cross-check lower-level proof verification against database verification wrappers.
- Add ordered range streaming and batch read/staging/to-batch invariants.

### Immutable and keyless

- Add size/bounds, sync boundary, bulk reads, pinned-node proof verification, rewind, sync/reopen,
  validation, `to_batch`, and batch-view operations.
- Exercise operation accessors using operations returned by generated proofs.
- Add compact last-commit, commit/reopen, bounds, and `to_batch` invariants.

### Store and sync

- Add store `is_empty`, `size`, and batch-read invariants.
- Exercise streaming sync for variable Any, Current, immutable, and keyless databases using
  input-driven commit/sync operations and root, bounds, metadata, and ops-root oracles.

## Validation

1. Build every changed and generated fuzz target.
2. Run each target from an empty temporary corpus.
3. Generate per-target LLVM coverage.
4. Merge the profiles and inspect `storage/src/qmdb` with `llvm-cov show`.
5. Iterate until each intended variant is instantiated and every public production method is
   either directly fuzzed with an invariant or documented as transitive-only support code.
