use super::{Config, Operation, batch};
use crate::{
    Context,
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable},
    },
    merkle::{Family, Location, Proof},
    qmdb::{Error, chain, metrics::Metrics, sync::source, value::ValueEncoding},
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use std::{num::NonZeroU64, sync::Arc};
use tracing::{debug, warn};

/// Check that `locs` is strictly increasing and every location is below `end`.
pub(super) fn check_locations<F: Family>(
    locs: &[Location<F>],
    end: Location<F>,
) -> Result<(), Error<F>> {
    if let Some(pair) = locs.windows(2).find(|pair| pair[0] >= pair[1]) {
        return Err(Error::LocationOutOfOrder(pair[0], pair[1]));
    }
    // Strictly increasing, so only the last location can reach `end`.
    if let Some(&last) = locs.last()
        && last >= end
    {
        return Err(Error::LocationOutOfBounds(last, end));
    }
    Ok(())
}

/// A keyless authenticated database.
pub struct Db<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Authenticated journal of operations.
    pub(super) journal: authenticated::Journal<F, E, C, H, S>,

    /// Cached canonical operations root.
    pub(super) root: H::Digest,

    /// The inactivity floor declared by the last committed batch. Operations at locations below
    /// this value are considered inactive by the application and may be pruned.
    pub(super) inactivity_floor_loc: Location<F>,

    /// Metrics for this database.
    pub(super) metrics: Metrics<E>,
}

impl<F, E, V, C, H, S> std::fmt::Debug for Db<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("bounds", &self.bounds())
            .field("inactivity_floor", &self.inactivity_floor())
            .finish_non_exhaustive()
    }
}

impl<F, E, V, C, H, S> Db<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Initialize from the latest retained commit, discarding every operation after it.
    /// `Some(max_size)` selects the latest retained commit with at most `max_size` operations.
    /// `None` selects the latest retained state.
    ///
    /// After a bounded initialization past a prune, or a sync of a range that starts above the
    /// floor, the selected commit's inactivity floor can be below the retained start. A batch
    /// read of a location between the two that no batch chain holds then returns
    /// [`crate::journal::Error::ItemPruned`], while a database that retains the location answers
    /// it. Databases at the same commitment therefore answer batch reads alike only when each
    /// retains every operation from its floor onward.
    #[boxed]
    pub async fn init(
        context: E,
        cfg: Config<C::Config, S>,
        max_size: Option<Location<F>>,
    ) -> Result<Self, Error<F>>
    where
        C: authenticated::Backing<E>,
    {
        // Keyless restores commit fields without replaying a keyed snapshot, so its logical floor
        // may precede the retained operation prefix.
        let mut journal = crate::qmdb::init_journal::<F, E, C, H, S>(
            context.child("journal"),
            cfg.merkle,
            cfg.log,
            max_size,
            false,
        )
        .await?;
        let metrics = Metrics::new(context);
        if journal.size() == 0 {
            warn!("no operations found in log, creating initial commit");
            (journal, _) = journal
                .append(&Operation::Commit(None, Location::new(0)))
                .await?;
            journal = journal.sync().await?;
        }

        let (last_commit_loc, inactivity_floor_loc) = {
            let bounds = journal.bounds();
            let last_commit_loc = Location::new(
                bounds
                    .end
                    .checked_sub(1)
                    .expect("at least one commit should exist"),
            );
            let op = journal.read(*last_commit_loc).await?;
            let inactivity_floor_loc = op
                .inactivity_floor()
                .expect("last operation should be a commit with floor");
            (last_commit_loc, inactivity_floor_loc)
        };
        let inactive_peaks = F::inactive_peaks(last_commit_loc + 1, inactivity_floor_loc);
        let root = journal.root(inactive_peaks)?;

        let db = Self {
            journal,
            root,
            inactivity_floor_loc,
            metrics,
        };
        db.update_metrics();
        Ok(db)
    }

    /// Get the value at location `loc` in the database.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::LocationOutOfBounds`] if `loc` >= `self.bounds().end`.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] if `loc` <
    ///   `self.bounds().start`.
    pub async fn get(&self, loc: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let _timer = self.metrics.get_timer();
        self.metrics.get_calls.inc();
        self.metrics.lookups_requested.inc();
        let op_count = self.journal.bounds().end;
        if loc >= op_count {
            return Err(Error::LocationOutOfBounds(loc, Location::new(op_count)));
        }
        let op = self.journal.read(*loc).await?;

        let result = op.into_value();
        Ok(result)
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be strictly increasing.
    /// Returns results in the same order as the input locations.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::LocationOutOfOrder`] if the locations are not strictly increasing.
    /// - Returns [`Error::LocationOutOfBounds`] if any location >= `self.bounds().end`.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] if any location <
    ///   `self.bounds().start`.
    pub async fn get_many(&self, locs: &[Location<F>]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        if locs.is_empty() {
            return Ok(Vec::new());
        }

        let _timer = self.metrics.get_many_timer();
        self.metrics.get_many_calls.inc();
        self.metrics.lookups_requested.inc_by(locs.len() as u64);
        check_locations(locs, Location::new(self.journal.bounds().end))?;
        let positions: Vec<u64> = locs.iter().map(|loc| **loc).collect();
        let ops = self.journal.read_many(&positions).await?;
        let result = ops.into_iter().map(|op| op.into_value()).collect();
        Ok(result)
    }

    /// Returns the inactivity floor declared by the last committed batch.
    pub const fn inactivity_floor(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return the retained operation range `[start, end)`.
    ///
    /// Proof generation also requires the necessary Merkle nodes to be retained.
    pub fn bounds(&self) -> std::ops::Range<Location<F>> {
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

    /// Return the inactivity floor declared by the last committed batch, which is the upper bound
    /// on [`Self::prune`]'s `loc`.
    ///
    /// This logical boundary may precede the retained start in [`Self::bounds`].
    pub const fn sync_boundary(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error<F>> {
        // The journal always ends with a commit operation.
        let op = self.journal.read(*self.journal.size() - 1).await?;
        let Operation::Commit(metadata, _floor) = op else {
            unreachable!("last operation is not a commit");
        };

        Ok(metadata)
    }

    /// Return the root of the db.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        self.journal.strategy()
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
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, V>>), Error<F>> {
        self.historical_proof(self.bounds().end, start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the Merkle structure when it had
    /// `historical_size` operations.
    ///
    /// `historical_size` must be the size of a commit boundary.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Merkle`] with [`crate::merkle::Error::RangeOutOfBounds`] if `start_loc`
    ///   >= `historical_size` or `historical_size` > number of operations.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] or [`Error::Merkle`]
    ///   with [`crate::merkle::Error::ElementPruned`] if a required operation or Merkle node has
    ///   been pruned.
    /// - Returns [`Error::HistoricalFloorPruned`] if `historical_size - 1` is retained but is not a
    ///   commit op.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.keyless.db.historical_proof",
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
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, V>>), Error<F>> {
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

    /// Return the pinned Merkle nodes for a lower operation boundary of `loc`.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<H::Digest>, Error<F>> {
        self.journal
            .merkle
            .pinned_nodes_at(loc)
            .await
            .map_err(Into::into)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root.
    ///
    /// The retained start in [`Self::bounds`] can remain below `prune_loc`.
    ///
    /// `prune` requires no prior commit. After a crash, the database remains recoverable;
    /// uncommitted operations are not guaranteed to survive.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PruneBeyondMinRequired`] if `prune_loc` > the inactivity floor.
    #[tracing::instrument(name = "qmdb.keyless.db.prune", level = "info", skip_all)]
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
        self.update_metrics();
        Ok(self)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    #[tracing::instrument(name = "qmdb.keyless.db.sync", level = "info", skip_all)]
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
    #[tracing::instrument(name = "qmdb.keyless.db.start_sync", level = "info", skip_all)]
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error<F>> {
        self.metrics.start_sync_calls.inc();
        let handle;
        (self.journal, handle) = self.journal.start_sync().await?;
        Ok((self, handle))
    }

    /// Durably commit the journal state published by prior [`Db::apply_batch`] calls.
    #[tracing::instrument(name = "qmdb.keyless.db.commit", level = "info", skip_all)]
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
        batch: &batch::MerkleizedBatch<F, H::Digest, V, S>,
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
    #[tracing::instrument(name = "qmdb.keyless.db.apply_batch", level = "info", skip_all)]
    pub async fn apply_batch(
        mut self,
        batch: Arc<batch::MerkleizedBatch<F, H::Digest, V, S>>,
    ) -> Result<Self, Error<F>> {
        let _timer = self.metrics.apply_batch_timer();
        self.metrics.apply_batch_calls.inc();
        self.validate_batch(&batch)?;
        let start_loc = self.journal.size();

        self.journal = self.journal.apply_batch(&batch.journal_batch).await?;

        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        self.root = batch.root();
        let end_loc = batch.bounds.tip.size;
        debug!(size = ?end_loc, "applied batch");
        self.update_metrics();
        self.metrics
            .operations_applied
            .inc_by(*end_loc - *start_loc);
        Ok(self)
    }
}

impl<F, E, V, C, H, S> crate::qmdb::sync::Source for Db<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = Operation<F, V>;
    type Error = Error<F>;

    async fn serve(&self, request: crate::qmdb::sync::Request<F>) -> source::Result<Self> {
        self.journal.serve(request).await
    }
}
