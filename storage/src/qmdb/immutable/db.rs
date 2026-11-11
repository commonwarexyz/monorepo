use super::{Config, Operation, batch};
use crate::{
    Context,
    index::immutable::Index,
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable},
    },
    merkle::{Family, Location, Proof},
    qmdb::{Error, chain, metrics::Metrics, operation::Key, sync::source, value::ValueEncoding},
    translator::Translator,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, ReadOptions};
use core::{
    borrow::Borrow,
    num::{NonZeroU64, NonZeroUsize},
};
use futures::{StreamExt, pin_mut};
use std::{ops::Range, sync::Arc};
use tracing::warn;

/// Build the snapshot by replaying the log from `inactivity_floor_loc`, inserting the location of
/// every retained [Operation::Set]. Assumes the log is not pruned beyond the inactivity floor.
///
/// `init_buffer` sizes the replay read buffer (in bytes).
pub(super) async fn build_snapshot<F, E, K, V, C, T>(
    context: E,
    translator: T,
    inactivity_floor_loc: Location<F>,
    log: &C,
    init_buffer: NonZeroUsize,
) -> Result<Index<T>, Error<F>>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<F, K, V>>,
    T: Translator,
{
    // Size the table for every replayed operation, an upper bound on the sets among them, so the
    // replay neither counts them first nor grows the table as it goes. Commits are not indexed,
    // so a log of tiny batches can leave the table one doubling larger than its entries need.
    let end = log.bounds().end;
    let mut snapshot = Index::new(
        context,
        translator,
        *inactivity_floor_loc,
        usize::try_from(end - *inactivity_floor_loc)
            .expect("operations since the floor must fit in usize"),
    );

    // Init reads every operation once, so the replayed pages are not kept in the OS page cache:
    // the init cache, not the OS cache, decides which probes hit.
    let stream = log
        .replay(
            *inactivity_floor_loc..end,
            init_buffer,
            ReadOptions::DONT_CACHE,
        )
        .await?;
    pin_mut!(stream);
    while let Some(batch) = stream.next().await {
        for (loc, op) in batch? {
            if let Operation::Set(key, _) = op {
                snapshot.insert(&key, loc);
            }
        }
    }
    Ok(snapshot)
}

/// An authenticated database that only supports adding new keyed values (no updates or
/// deletions).
///
/// # Invariant
///
/// A key must be set at most once across the database history.
///
/// Use [super::fixed::Db] or [super::variable::Db] for concrete instantiations.
pub struct Db<
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
> where
    C::Item: EncodeShared,
{
    /// Authenticated journal of operations.
    pub(super) journal: authenticated::Journal<F, E, C, H, S>,

    /// Cached canonical operations root.
    pub(crate) root: H::Digest,

    /// The location of the [Operation::Set] of every key set at or after the inactivity floor
    /// the snapshot was built from, excluding pruned locations.
    pub(crate) snapshot: Index<T>,

    /// The inactivity floor declared by the last committed batch.
    /// Operations before this location are considered inactive by the application.
    pub(crate) inactivity_floor_loc: Location<F>,

    /// Metrics for this database.
    pub(super) metrics: Metrics<E>,
}

impl<F, E, K, V, C, H, T, S> std::fmt::Debug for Db<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    C::Item: EncodeShared,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("bounds", &self.bounds())
            .field("inactivity_floor", &self.inactivity_floor())
            .finish_non_exhaustive()
    }
}

// Shared read-only functionality.
impl<F, E, K, V, C, H, T, S> Db<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    C::Item: EncodeShared,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    /// Initialize from the latest retained commit, discarding every operation after it.
    /// `Some(max_size)` selects the latest retained commit with at most `max_size` operations.
    /// `None` selects the latest retained state.
    #[boxed]
    pub async fn init(
        context: E,
        cfg: Config<T, C::Config, S>,
        max_size: Option<Location<F>>,
    ) -> Result<Self, Error<F>>
    where
        C: authenticated::Backing<E>,
    {
        // Snapshot reconstruction replays from the selected commit's inactivity floor, so that
        // floor must remain in the retained operation prefix.
        let mut journal = crate::qmdb::init_journal::<F, E, C, H, S>(
            context.child("journal"),
            cfg.merkle,
            cfg.log,
            max_size,
            true,
        )
        .await?;
        if journal.size() == 0 {
            warn!("Authenticated log is empty, initialized new db.");
            (journal, _) = journal
                .append(&Operation::Commit(None, Location::new(0)))
                .await?;
            journal = journal.sync().await?;
        }

        // Rebuild the in-memory state the last commit defines. Its inactivity floor is where
        // the snapshot replay starts, so keys set before the floor are not loaded.
        let (last_commit_loc, inactivity_floor_loc, snapshot) = {
            let bounds = journal.journal.bounds();
            let last_commit_loc =
                Location::new(bounds.end.checked_sub(1).expect("commit should exist"));

            // Read the floor from the last commit operation.
            let last_op = journal.journal.read(*last_commit_loc).await?;
            let inactivity_floor_loc = last_op
                .inactivity_floor()
                .expect("last operation should be a commit with floor");

            // Replay the log from the inactivity floor to build the snapshot.
            let snapshot = build_snapshot(
                context.child("snapshot"),
                cfg.translator,
                inactivity_floor_loc,
                &journal.journal,
                cfg.init_buffer,
            )
            .await?;

            (last_commit_loc, inactivity_floor_loc, snapshot)
        };
        let inactive_peaks = F::inactive_peaks(last_commit_loc + 1, inactivity_floor_loc);
        let root = journal.root(inactive_peaks)?;

        let metrics = Metrics::new(context);
        let db = Self {
            journal,
            root,
            snapshot,
            inactivity_floor_loc,
            metrics,
        };
        db.update_metrics();
        Ok(db)
    }

    /// Return the inactivity floor location declared by the last committed batch.
    pub const fn inactivity_floor(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return the retained operation range `[start, end)`.
    ///
    /// Proof generation also requires the necessary Merkle nodes to be retained.
    pub fn bounds(&self) -> Range<Location<F>> {
        let bounds = self.journal.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Update state gauges from the current database state.
    pub(super) fn update_metrics(&self) {
        let bounds = self.journal.bounds();
        self.metrics.update(
            bounds.end,
            bounds.start,
            *self.inactivity_floor_loc,
            bounds.end - 1,
        );
    }

    /// Return the most recent location from which this database can safely be synced, and the
    /// upper bound on [`Self::prune`]'s `loc`. For immutable databases, this equals the
    /// inactivity floor declared by the last committed batch.
    pub const fn sync_boundary(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Get the value of `key` in the db, or None if it has no value or its corresponding operation
    /// has been pruned.
    ///
    /// Unlike batch reads, this may return a value written below the inactivity floor, until the
    /// database prunes that operation or rebuilds its index from the floor on restart or sync.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        self.get_from(key, Location::new(0)).await
    }

    /// Like [`Self::get`], but also ignores operations below `floor`.
    pub(crate) async fn get_from(
        &self,
        key: &K,
        floor: Location<F>,
    ) -> Result<Option<V::Value>, Error<F>> {
        let _timer = self.metrics.get_timer();
        self.metrics.get_calls.inc();
        self.metrics.lookups_requested.inc();
        for loc in self.snapshot.get(key) {
            let loc = Location::new(loc);
            if loc < floor {
                continue;
            }
            if let Some(v) = Self::get_from_loc(&self.journal, key, loc).await? {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys. Like [`Self::get`], this may return
    /// values written below the inactivity floor.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<K> + Sync],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        self.get_many_from(keys, Location::new(0)).await
    }

    /// Like [`Self::get_many`], but also ignores operations below `floor`.
    pub(crate) async fn get_many_from(
        &self,
        keys: &[impl Borrow<K> + Sync],
        floor: Location<F>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let _timer = self.metrics.get_many_timer();
        self.metrics.get_many_calls.inc();
        self.metrics.lookups_requested.inc_by(keys.len() as u64);
        let mut candidates: Vec<(usize, u64)> = Vec::with_capacity(keys.len());
        let mut results: Vec<Option<V::Value>> = vec![None; keys.len()];

        // Every location at or above `floor` whose translated key matches a requested key is a
        // candidate for it, including collisions. They are read in one batch below, each location
        // once, and resolved by comparing full keys.
        for (key_idx, key) in keys.iter().enumerate() {
            for loc in self.snapshot.get(key.borrow()) {
                if loc < *floor {
                    continue;
                }
                candidates.push((key_idx, loc));
            }
        }

        if candidates.is_empty() {
            return Ok(results);
        }

        candidates.sort_unstable_by_key(|&(_, pos)| pos);

        let same_pos = |a: &(usize, u64), b: &(usize, u64)| a.1 == b.1;
        let positions: Vec<u64> = candidates
            .chunk_by(same_pos)
            .map(|group| group[0].1)
            .collect();

        let ops = self.journal.read_many(&positions).await?;
        assert_eq!(
            ops.len(),
            positions.len(),
            "read_many returns one operation per position"
        );

        for (op, group) in ops.into_iter().zip(candidates.chunk_by(same_pos)) {
            let Operation::Set(k, v) = op else {
                unreachable!(
                    "location does not reference set operation. loc={}",
                    group[0].1
                );
            };
            let mut pending = None;
            for &(key_idx, _) in group {
                if results[key_idx].is_some() || &k != keys[key_idx].borrow() {
                    continue;
                }
                if let Some(prev) = pending.replace(key_idx) {
                    results[prev] = Some(v.clone());
                }
            }
            if let Some(last) = pending {
                results[last] = Some(v);
            }
        }

        Ok(results)
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`. Returns
    /// [`crate::qmdb::Error::OperationPruned`] if loc precedes the oldest retained location. The
    /// location is otherwise assumed valid.
    async fn get_from_loc(
        reader: &impl Contiguous<Item = Operation<F, K, V>>,
        key: &K,
        loc: Location<F>,
    ) -> Result<Option<V::Value>, Error<F>> {
        if loc < reader.bounds().start {
            return Err(Error::OperationPruned(loc));
        }

        let Operation::Set(k, v) = reader.read(*loc).await? else {
            unreachable!("location does not reference set operation. loc={loc}");
        };

        if k != *key { Ok(None) } else { Ok(Some(v)) }
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error<F>> {
        // The journal always ends with a commit operation.
        let last_commit_loc = self.bounds().end - 1;
        let Operation::Commit(metadata, _floor) =
            self.journal.journal.read(*last_commit_loc).await?
        else {
            unreachable!("no commit operation at location of last commit {last_commit_loc}");
        };

        Ok(metadata)
    }

    /// Analogous to proof but with respect to the state of the database when it had
    /// `historical_size` operations.
    ///
    /// # Contract
    ///
    /// `historical_size` must be a commit-boundary size: the operation at `historical_size - 1`
    /// must itself be a commit op. Non-commit-boundary sizes are not supported because the
    /// inactivity floor governing them is not directly retrievable.
    ///
    /// # Errors
    ///
    /// Returns [crate::merkle::Error::RangeOutOfBounds] if `historical_size` > number of
    /// operations, or if `start_loc` >= `historical_size`.
    /// Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] or [`Error::Merkle`]
    /// with [`crate::merkle::Error::ElementPruned`] if a required operation or Merkle node has
    /// been pruned.
    /// Returns [`Error::HistoricalFloorPruned`] if `historical_size - 1` is retained but is not a
    /// commit op, either because the caller passed a non-commit-boundary `historical_size` or
    /// because pruning removed the commit that would have governed `historical_size`.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.immutable.db.historical_proof",
        level = "info",
        skip_all,
        fields(
            historical_size = *historical_size,
            start_loc = *start_loc,
            max_ops = max_ops.get(),
        ),
    )]
    pub async fn historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, K, V>>), Error<F>> {
        if historical_size > self.journal.size() {
            return Err(crate::merkle::Error::RangeOutOfBounds(historical_size).into());
        }

        let inactive_peaks =
            crate::qmdb::inactive_peaks_at::<F, _>(&self.journal, historical_size).await?;

        Ok(self
            .journal
            .historical_proof(historical_size, start_loc, max_ops, inactive_peaks)
            .await?)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Merkle`] with [`crate::merkle::Error::RangeOutOfBounds`] if `start_loc`
    ///   >= the number of operations.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] or [`Error::Merkle`]
    ///   with [`crate::merkle::Error::ElementPruned`] if a required operation or Merkle node has
    ///   been pruned.
    pub async fn proof(
        &self,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, K, V>>), Error<F>> {
        self.historical_proof(self.bounds().end, start_loc, max_ops)
            .await
    }

    /// Prune operations prior to `prune_loc` without changing the db's root. Keys whose operations
    /// are no longer retained cannot be retrieved.
    ///
    /// The retained start in [`Self::bounds`] can remain below `prune_loc`.
    ///
    /// Pruning is irreversible and requires no prior commit. After a crash, the database remains
    /// recoverable; uncommitted operations are not guaranteed to survive.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    #[tracing::instrument(name = "qmdb.immutable.db.prune", level = "info", skip_all)]
    #[boxed]
    pub async fn prune(mut self, prune_loc: Location<F>) -> Result<Self, Error<F>> {
        let _timer = self.metrics.prune_timer();
        self.metrics.prune_calls.inc();
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }
        (self.journal, _) = self.journal.prune(prune_loc).await?;
        self.snapshot.prune(*self.bounds().start);
        self.update_metrics();
        Ok(self)
    }

    /// Return the canonical QMDB root of the db.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        self.journal.strategy()
    }

    /// Return the pinned Merkle nodes at the given location.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<H::Digest>, Error<F>> {
        self.journal
            .merkle
            .pinned_nodes_at(loc)
            .await
            .map_err(Into::into)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    #[tracing::instrument(name = "qmdb.immutable.db.sync", level = "info", skip_all)]
    pub async fn sync(mut self) -> Result<Self, Error<F>> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        self.journal = self.journal.sync().await?;
        Ok(self)
    }

    /// Begin durably persisting the journal state published by prior [`Db::apply_batch`]
    /// calls.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit],
    /// plus a best-effort attempt to bound the recovery needed on startup. Use [Self::sync] to
    /// guarantee none is needed. A new sync waits for the prior sync before starting. Failures
    /// of the deferred durability work surface on the returned handle. A failed data sync also
    /// fails the next durability operation. A failed recovery-watermark sync is not observed by
    /// [Self::commit], and a failed merkle-node sync may not be. Both resurface on the next
    /// [Self::sync].
    #[tracing::instrument(name = "qmdb.immutable.db.start_sync", level = "info", skip_all)]
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error<F>> {
        self.metrics.start_sync_calls.inc();
        let handle;
        (self.journal, handle) = self.journal.start_sync().await?;
        Ok((self, handle))
    }

    /// Durably commit the journal state published by prior [`Db::apply_batch`] calls.
    #[tracing::instrument(name = "qmdb.immutable.db.commit", level = "info", skip_all)]
    pub async fn commit(mut self) -> Result<Self, Error<F>> {
        let _timer = self.metrics.commit_timer();
        self.metrics.commit_calls.inc();
        self.journal = self.journal.commit().await?;
        Ok(self)
    }

    /// Destroy the db, removing all data from disk.
    #[boxed]
    pub async fn destroy(self) -> Result<(), Error<F>> {
        Ok(self.journal.destroy().await?)
    }

    /// The [`Commitment`](chain::Commitment) for the database's current state.
    pub(crate) fn commitment(&self) -> chain::Commitment<F, H::Digest> {
        chain::Commitment {
            size: self.journal.size(),
            root: self.root,
        }
    }

    /// Check that `batch` can be applied to the database in its current state, without
    /// applying it.
    ///
    /// [`Self::apply_batch`] runs the same validation but consumes the database when it
    /// fails; callers that want to reject a bad batch and keep the handle can check first.
    pub fn validate_batch(
        &self,
        batch: &batch::MerkleizedBatch<F, H::Digest, K, V, S>,
    ) -> Result<(), Error<F>> {
        batch.bounds.validate_apply_to(self.commitment())
    }

    /// Apply a [`batch::MerkleizedBatch`] to the database.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal.
    /// Call [`Db::commit`] or [`Db::sync`], or await the handle returned by
    /// [`Db::start_sync`], to make the applied state durable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleBatch`] if the database is at neither the batch's recorded database
    /// boundary nor an ancestor's tip.
    #[tracing::instrument(name = "qmdb.immutable.db.apply_batch", level = "info", skip_all)]
    pub async fn apply_batch(
        mut self,
        batch: Arc<batch::MerkleizedBatch<F, H::Digest, K, V, S>>,
    ) -> Result<Self, Error<F>> {
        let _timer = self.metrics.apply_batch_timer();
        self.metrics.apply_batch_calls.inc();
        self.validate_batch(&batch)?;
        let db_size = self.bounds().end;

        // Journal writes and snapshot inserts are independent until batch publication.
        let apply_snapshot = async {
            for (key, entry) in batch.diff.iter() {
                self.snapshot.insert(key, *entry.loc);
            }
            for (i, ancestor_diff) in batch.ancestor_diffs.iter().enumerate() {
                if batch.bounds.ancestors[i].size <= db_size {
                    continue;
                }
                for (key, entry) in ancestor_diff.iter() {
                    self.snapshot.insert(key, *entry.loc);
                }
            }
        };
        let (journal, ()) = futures::join!(
            self.journal.apply_batch(&batch.journal_batch),
            apply_snapshot
        );
        self.journal = journal?;

        // Update state.
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        self.root = batch.root();
        self.update_metrics();
        self.metrics
            .operations_applied
            .inc_by(*batch.bounds.tip.size - *db_size);
        Ok(self)
    }
}

impl<F, E, K, V, C, H, T, S> crate::qmdb::sync::Source for Db<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    Operation<F, K, V>: EncodeShared,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = Operation<F, K, V>;
    type Error = Error<F>;

    async fn serve(&self, request: crate::qmdb::sync::Request<F>) -> source::Result<Self> {
        self.journal.serve(request).await
    }
}
