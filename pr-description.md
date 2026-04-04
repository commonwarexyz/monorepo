## Summary

This derives activity bitmap updates at commit time from the snapshot diff set,
instead of computing and threading bitmap push/clear segments through the batch
chain.

- **Removes bitmap diff bookkeeping from the batch chain**:
  `bitmap_pushes` and `bitmap_clears` are removed from
  `UnmerkleizedBatch`, `MerkleizedBatch`, and `Changeset` in
  `current::batch`. `compute_current_layer()` no longer accumulates these
  segments, and `finalize()` / `finalize_from()` no longer flatten them.

- **Reconstructs bitmap updates only when applying the batch**:
  `current::Db::apply_batch` now builds bitmap pushes and clears in one pass
  over the inner changeset's `snapshot_diffs`. This keeps the batch-chain
  representation smaller and avoids carrying bitmap push/clear vectors through
  `merkleize()`, batch chaining, and `finalize()`.

- **Adds a fast path for committed bitmap updates**:
  when the `Arc<BitMap>` has no outstanding clones, `push_changeset` mutates
  the Base bitmap in place. In the common sequential-commit case, this avoids
  layer buildup between prunes and keeps later `get_chunk()` calls O(1).

The `BitmapBatch` layer chain is still maintained in `MerkleizedBatch` for
floor scanning via `BitmapScan` during merkleization. That behavior is
unchanged.

## Changes

- `any/batch.rs`: makes `snapshot_diffs`, `new_last_commit_loc`, and `db_size`
  on `Changeset` `pub(crate)`, and switches snapshot diff iteration in
  `apply_batch` from by-value to by-reference.
- `current/batch.rs`: Removed `base_bitmap_pushes`/`base_bitmap_clears` from
  `UnmerkleizedBatch`, `bitmap_pushes`/`bitmap_clears` from
  `MerkleizedBatch` and `Changeset`, simplifies `finalize`,
  `finalize_from`, `new_batch`, `to_batch`, and `compute_current_layer`,
  adds the direct-Base fast path to `push_changeset`, and reserves bitmap
  push capacity up front for the current segment.
- `current/db.rs`: derives bitmap pushes/clears from inner changeset diffs in
  `apply_batch`, factors that reconstruction into a small helper, and adds an
  early stale-changeset check before building the bitmap updates.
- `current` readability follow-up: splits `BitmapBatch::push_changeset` into
  explicit in-place and COW-layer paths, and adds assertions/comments around
  CommitFloor handling to make the bitmap invariants easier to follow.

## Test plan

- [x] `just test -p commonware-storage` (1779 passed, 30 skipped)
- [x] `cargo clippy -p commonware-storage --all-targets -- -D warnings` (clean)
- [x] Benchmarked `qmdb::generate` variants locally (~5% faster typically)
