//! Apply merkleized batches to the journal, snapshot index, and activity bitmap.

use super::{DiffCursors, DiffEntry, DiffMerge, MerkleizedBatch};
use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::Mutable,
    merkle::{Family, Location},
    qmdb::{
        any::{
            db::Db,
            operation::{Operation, update},
        },
        delete_known_loc,
        operation::Key,
        update_known_loc,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::bitmap;
use std::{iter, sync::Arc};

/// Diff entries that [probe_index] looks up together before any of them is applied, whether they
/// come from the diff itself or from its merge with pending ancestor diffs.
///
/// A chunk is long enough for the probe loop to keep several misses in flight and short enough
/// that the lines the probe pulled in are still cached when the apply loop reaches them.
const PROBE_CHUNK: usize = 64;

/// Look each of `keys` up in a tight loop ahead of applying their diff entries, so the cache
/// misses of their index entries overlap where the apply loop's longer body would wait on each in
/// turn. Each hit's location is folded into a black-boxed checksum, so the probe loads the value
/// line as well as the key. Does nothing for an index whose lookups do not warm its updates (see
/// [`UnorderedIndex::LOOKUP_WARMS_UPDATE`]).
fn probe_index<'a, F: Family, K: Key + 'a, I: UnorderedIndex<Value = Location<F>>>(
    snapshot: &I,
    keys: impl Iterator<Item = &'a K>,
) {
    if !I::LOOKUP_WARMS_UPDATE {
        return;
    }
    let mut probed = 0u64;
    for key in keys {
        probed ^= snapshot.get(key).next().map_or(0, |loc| **loc);
    }
    std::hint::black_box(probed);
}

/// Apply a single diff entry to the snapshot index and activity bitmap in lockstep:
/// install the entry's `Active` location and clear the key's prior location.
fn apply_diff<F: Family, V, I: UnorderedIndex<Value = Location<F>>, const N: usize>(
    snapshot: &mut I,
    bitmap: &mut bitmap::Prunable<N>,
    key: &impl Key,
    entry: &DiffEntry<F, V>,
    old_loc: Option<Location<F>>,
) {
    match entry {
        DiffEntry::Active { loc, .. } => match old_loc {
            Some(old) => update_known_loc::<F, _>(snapshot, key, old, *loc),
            None => snapshot.insert(key, *loc),
        },
        DiffEntry::Deleted { .. } => {
            if let Some(old) = old_loc {
                delete_known_loc::<F, _>(snapshot, key, old);
            }
        }
    }
    if let Some(loc) = entry.loc() {
        bitmap.set_bit(*loc, true);
    }
    if let Some(loc) = old_loc {
        bitmap.set_bit(*loc, false);
    }
}

impl<F: Family, D: Digest, U: update::Update, S: Strategy> MerkleizedBatch<F, D, U, S> {
    /// Publish this batch's key-level changes to the in-memory snapshot index and activity bitmap.
    ///
    /// `snapshot` and `bitmap` must hold the state already applied through the first `db_size`
    /// operations, the last of which is the commit they currently end at. On return they reflect
    /// `self.bounds.tip`.
    fn apply_to_index<I: UnorderedIndex<Value = Location<F>>, const N: usize>(
        &self,
        snapshot: &mut I,
        bitmap: &mut bitmap::Prunable<N>,
        db_size: u64,
    ) {
        let tip = *self.bounds.tip.size;
        bitmap.extend_to(tip);

        if self.ancestor_diffs.is_empty() {
            // With no ancestors there is nothing to merge and no fixups to look up, so each chunk
            // of the diff is probed and then applied.
            for chunk in self.diff.chunks(PROBE_CHUNK) {
                probe_index(snapshot, chunk.iter().map(|(key, _)| key));
                for (key, entry) in chunk {
                    apply_diff(snapshot, bitmap, key, entry, entry.base_old_loc());
                }
            }
        } else {
            // Already-applied ancestors supply prior locations, and unapplied ones merge with this
            // batch's diff. The database applies a chain oldest first and the list is newest first,
            // so the unapplied ancestors are the ones at the front.
            let split = self
                .bounds
                .ancestors
                .partition_point(|ancestor| ancestor.size > db_size);
            let (pending, applied) = self.ancestor_diffs.split_at(split);
            let mut resolver = DiffCursors::new(applied.iter().map(|diff| diff.as_slice()));
            let mut base_locs = self.ancestor_base_locs.iter().peekable();
            let mut merge = DiffMerge::new(
                iter::once(self.diff.as_slice()).chain(pending.iter().map(|diff| diff.as_slice())),
            )
            .map(|(key, entry)| {
                // Merged keys ascend, so the boundary cursor only moves forward.
                while base_locs
                    .peek()
                    .is_some_and(|(candidate, _)| candidate < key)
                {
                    base_locs.next();
                }

                // This entry replaces the key's current location in the index, which is, in order:
                // - the newest write of an ancestor the database has applied, from `resolver`,
                // - else the location saved in `ancestor_base_locs` if that ancestor was dropped,
                // - else `base_old_loc`, where the key was when the chain began.
                let old = resolver
                    .resolve(key)
                    .map(DiffEntry::loc)
                    .or_else(|| {
                        base_locs
                            .next_if(|(candidate, _)| candidate == key)
                            .map(|(_, loc)| *loc)
                    })
                    .unwrap_or_else(|| entry.base_old_loc());
                (key, entry, old)
            });

            // Prior locations come from the diffs alone, so a chunk of merged entries is resolved
            // and probed before any of it is applied, as the diff's chunks are above.
            let mut chunk = Vec::with_capacity(PROBE_CHUNK);
            loop {
                chunk.clear();
                chunk.extend(merge.by_ref().take(PROBE_CHUNK));
                if chunk.is_empty() {
                    break;
                }
                probe_index(snapshot, chunk.iter().map(|(key, _, _)| *key));
                for &(key, entry, old) in &chunk {
                    apply_diff(snapshot, bitmap, key, entry, old);
                }
            }
        }

        // Maintain the invariant that only the most recent CommitFloor operation can be active.
        bitmap.set_bit(db_size - 1, false);
        bitmap.set_bit(tip - 1, true);
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Check that `batch` can be applied to the database in its current state, without
    /// applying it.
    ///
    /// [`Self::apply_batch`] runs the same validation but consumes the database when it
    /// fails; callers that want to reject a bad batch and keep the handle can check first.
    pub fn validate_batch(
        &self,
        batch: &MerkleizedBatch<F, H::Digest, U, S>,
    ) -> Result<(), crate::qmdb::Error<F>> {
        batch.bounds.validate_apply_to(self.commitment())
    }

    /// Apply a batch to the database.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal.
    /// Call [`Db::commit`] or [`Db::sync`], or await the handle returned by [`Db::start_sync`], to
    /// make the applied state durable.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleBatch`] if the database is at neither the batch's
    /// recorded database boundary nor an ancestor's tip.
    #[tracing::instrument(
        name = "qmdb.any.db.apply_batch",
        level = "info",
        skip_all,
        fields(
            batch_total_size = *batch.bounds.tip.size,
            batch_base_size = *batch.bounds.base.size,
            db_size = *self.log.size(),
            ancestor_batches = batch.ancestor_diffs.len() as u64,
        ),
    )]
    pub async fn apply_batch(
        mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, U, S>>,
    ) -> Result<Self, crate::qmdb::Error<F>>
    where
        I: 'static,
    {
        let _timer = self.metrics.apply_batch_timer();
        self.metrics.apply_batch_calls.inc();
        self.validate_batch(&batch)?;
        let db_size = *self.log.size();

        // The journal append and the in-memory index application touch disjoint state (the log vs
        // the snapshot and bitmap), so run them concurrently. The index application is spawned as a
        // job on the strategy while the journal append proceeds on this task. The job owns the
        // snapshot until it returns it, so this method requires `I: 'static`. A journal failure
        // leaves the instance unusable either way (mutable storage failures are fatal and consume
        // the database), so the index job's effects on error do not need to be rolled back.
        let strategy = self.strategy().clone();
        let log = self.log;
        let mut snapshot = self.snapshot;
        let index_batch = Arc::clone(&batch);
        let index_bitmap = Arc::clone(&self.bitmap);

        // The job's size class counts the diff entries it merges or scans. The strategy estimates
        // cost per call site, so databases of different index types that share a strategy blend
        // their per-entry costs into this one inline-or-offload decision.
        let work_hint = batch.diff.len()
            + batch
                .ancestor_diffs
                .iter()
                .map(|diff| diff.len())
                .sum::<usize>();
        let index_job = strategy.spawn(work_hint, move |_| {
            index_batch.apply_to_index(&mut snapshot, &mut index_bitmap.write(), db_size);
            snapshot
        });

        // Apply journal (handles its own partial ancestor skipping) while the index job runs.
        let (log, snapshot) = futures::join!(log.apply_batch(&batch.journal_batch), index_job);
        self.log = log?;
        self.snapshot = snapshot;

        // Update DB metadata.
        self.active_keys = batch.total_active_keys;
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        self.root = batch.root();

        self.update_metrics();
        self.metrics
            .operations_applied
            .inc_by(*batch.bounds.tip.size - db_size);
        Ok(self)
    }
}
