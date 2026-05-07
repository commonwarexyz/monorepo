//! The [Keyless] qmdb allows for append-only storage of data that can later be retrieved by its
//! location. Both fixed-size and variable-size values are supported via the [fixed] and [variable]
//! submodules.
//!
//! # Examples
//!
//! ```ignore
//! // Simple mode: apply a batch, then durably commit it.
//! let batch = db.new_batch().append(value);
//! let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
//! db.apply_batch(merkleized).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Batches can still fork before you apply them.
//! let floor = db.inactivity_floor_loc();
//! let parent = db.new_batch().append(value_a);
//! let parent = parent.merkleize(&db, None, floor);
//!
//! let child_a = parent.new_batch();
//! let child_a = child_a.append(value_b);
//! let child_a = child_a.merkleize(&db, None, floor);
//!
//! let child_b = parent.new_batch();
//! let child_b = child_b.append(value_c);
//! let child_b = child_b.merkleize(&db, None, floor);
//!
//! db.apply_batch(child_a).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Sequential commit: apply parent then child.
//! let floor = db.inactivity_floor_loc();
//! let parent = db.new_batch().append(value_a);
//! let parent_m = parent.merkleize(&db, None, floor);
//! let child = parent_m.new_batch().append(value_b);
//! let child_m = child.merkleize(&db, None, floor);
//!
//! db.apply_batch(parent_m).await?;
//! db.apply_batch(child_m).await?;
//! db.commit().await?;
//! ```

use crate::{
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
        Error as JournalError,
    },
    merkle::{full::Config as MerkleConfig, Family, Location, Proof},
    qmdb::{any::value::ValueEncoding, Error},
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::{Sequential, Strategy};
use std::{num::NonZeroU64, sync::Arc};
use tracing::{debug, warn};

pub mod batch;
mod compact;
pub mod fixed;
mod operation;
pub(crate) mod sync;
pub mod variable;
pub use compact::{
    Config as CompactConfig, Db as CompactDb, MerkleizedBatch as CompactMerkleizedBatch,
    UnmerkleizedBatch as CompactUnmerkleizedBatch,
};
pub use operation::Operation;

/// Configuration for a [Keyless] authenticated db.
#[derive(Clone)]
pub struct Config<J, S: Strategy = Sequential> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle: MerkleConfig<S>,

    /// Configuration for the operations log journal.
    pub log: J,
}

/// A keyless authenticated database.
pub struct Keyless<F, E, V, C, H, S = Sequential>
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
    journal: authenticated::Journal<F, E, C, H, S>,

    /// Cached canonical operations root.
    root: H::Digest,

    /// The location of the last commit, if any.
    last_commit_loc: Location<F>,

    /// The inactivity floor declared by the last committed batch. Operations at locations below
    /// this value are considered inactive by the application and may be pruned.
    inactivity_floor_loc: Location<F>,
}

impl<F, E, V, C, H, S> Keyless<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    pub(crate) async fn init_from_journal(
        mut journal: authenticated::Journal<F, E, C, H, S>,
    ) -> Result<Self, Error<F>> {
        if journal.size().await == 0 {
            warn!("no operations found in log, creating initial commit");
            journal
                .append(&Operation::Commit(None, Location::new(0)))
                .await?;
            journal.sync().await?;
        }

        let last_commit_loc = journal
            .size()
            .await
            .checked_sub(1)
            .expect("at least one commit should exist");

        let inactivity_floor_loc = {
            let reader = journal.reader().await;
            let op = reader.read(*last_commit_loc).await?;
            op.has_floor()
                .expect("last operation should be a commit with floor")
        };
        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(*last_commit_loc + 1)),
            inactivity_floor_loc,
        );
        let root = journal.root(inactive_peaks)?;

        Ok(Self {
            journal,
            root,
            last_commit_loc,
            inactivity_floor_loc,
        })
    }

    /// Get the value at location `loc` in the database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOutOfBounds`] if `loc` >=
    /// `self.bounds().await.end`.
    pub async fn get(&self, loc: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let reader = self.journal.reader().await;
        let op_count = reader.bounds().end;
        if loc >= op_count {
            return Err(Error::LocationOutOfBounds(loc, Location::new(op_count)));
        }
        let op = reader.read(*loc).await?;

        Ok(op.into_value())
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be sorted in strictly ascending order (sorted and unique).
    /// Returns results in the same order as the input locations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOutOfBounds`] if any location >= `bounds().end`.
    pub async fn get_many(&self, locs: &[Location<F>]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        if locs.is_empty() {
            return Ok(Vec::new());
        }
        debug_assert!(
            locs.windows(2).all(|window| window[0] < window[1]),
            "locations must be sorted and unique"
        );
        let reader = self.journal.reader().await;
        let op_count = reader.bounds().end;
        for &loc in locs {
            if loc >= op_count {
                return Err(Error::LocationOutOfBounds(loc, Location::new(op_count)));
            }
        }
        let positions: Vec<u64> = locs.iter().map(|loc| **loc).collect();
        let ops = reader.read_many(&positions).await?;
        Ok(ops.into_iter().map(|op| op.into_value()).collect())
    }

    /// Returns the location of the last commit.
    pub const fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    /// Returns the inactivity floor declared by the last committed batch.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location<F>> {
        let bounds = self.journal.reader().await.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Return the most recent location from which this database can safely be synced, and the
    /// upper bound on [`Self::prune`]'s `loc`. For keyless databases, this equals the
    /// inactivity floor declared by the last committed batch.
    pub const fn sync_boundary(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error<F>> {
        let op = self
            .journal
            .reader()
            .await
            .read(*self.last_commit_loc)
            .await?;
        let Operation::Commit(metadata, _floor) = op else {
            return Ok(None);
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
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] if `start_loc` has
    ///   been pruned.
    pub async fn proof(
        &self,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, V>>), Error<F>> {
        self.historical_proof(self.bounds().await.end, start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the Merkle structure when it had
    /// `op_count` operations.
    ///
    /// `op_count` must be the size of a commit boundary.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Merkle`] with [`crate::merkle::Error::RangeOutOfBounds`] if `start_loc`
    ///   >= `op_count` or `op_count` > number of operations.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] if `start_loc` has
    ///   been pruned.
    /// - Returns [`Error::HistoricalFloorPruned`] if `op_count - 1` is retained but is not a commit
    ///   op.
    pub async fn historical_proof(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, V>>), Error<F>> {
        if op_count > self.journal.size().await {
            return Err(crate::merkle::Error::RangeOutOfBounds(op_count).into());
        }

        let reader = self.journal.reader().await;
        let inactive_peaks =
            crate::qmdb::inactive_peaks_at::<F, _>(&reader, op_count, |op| op.has_floor()).await?;

        Ok(self
            .journal
            .historical_proof(op_count, start_loc, max_ops, inactive_peaks)
            .await?)
    }

    /// Return the pinned Merkle nodes for a lower operation boundary of `loc`.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<H::Digest>, Error<F>> {
        if !loc.is_valid() {
            return Err(crate::merkle::Error::LocationOverflow(loc).into());
        }
        let futs: Vec<_> = F::nodes_to_pin(loc)
            .map(|p| async move {
                self.journal
                    .merkle
                    .get_node(p)
                    .await?
                    .ok_or(crate::merkle::Error::ElementPruned(p).into())
            })
            .collect();
        futures::future::try_join_all(futs).await
    }

    /// Prune historical operations prior to `loc`. This does not affect the db's root.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PruneBeyondMinRequired`] if `loc` > the inactivity floor declared by
    ///   the last committed batch.
    pub async fn prune(&mut self, loc: Location<F>) -> Result<(), Error<F>> {
        if loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                loc,
                self.inactivity_floor_loc,
            ));
        }
        self.journal.prune(loc).await?;

        Ok(())
    }

    /// Rewind the database to `size` operations, where `size` is the location of the next append.
    ///
    /// This rewinds both the operations journal and its Merkle structure to the historical state
    /// at `size`. The inactivity floor is restored from the rewind target commit operation, so
    /// the post-rewind floor matches the floor that was in effect at that commit.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::InvalidRewind`] if `size` is 0
    ///   or exceeds the current committed size.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] if the operation at
    ///   `size - 1` has been pruned.
    /// - Returns [`Error::UnexpectedData`] if the operation at `size - 1` is not a commit.
    ///
    /// Any error from this method is fatal for this handle. Rewind may mutate journal state
    /// before this method finishes updating in-memory rewind state. Callers must drop this
    /// database handle after any `Err` from `rewind` and reopen from storage.
    ///
    /// A successful rewind is not restart-stable until a subsequent [`Self::commit`] or
    /// [`Self::sync`].
    pub async fn rewind(&mut self, size: Location<F>) -> Result<(), Error<F>> {
        let rewind_size = *size;
        let current_size = *self.last_commit_loc + 1;
        if rewind_size == current_size {
            return Ok(());
        }
        if rewind_size == 0 || rewind_size > current_size {
            return Err(Error::Journal(crate::journal::Error::InvalidRewind(
                rewind_size,
            )));
        }

        let rewind_last_loc = Location::new(rewind_size - 1);
        let rewind_floor = {
            let reader = self.journal.reader().await;
            let bounds = reader.bounds();
            if rewind_size <= bounds.start {
                return Err(Error::Journal(crate::journal::Error::ItemPruned(
                    *rewind_last_loc,
                )));
            }
            let rewind_last_op = reader.read(*rewind_last_loc).await?;
            let Operation::Commit(_, floor) = rewind_last_op else {
                return Err(Error::UnexpectedData(rewind_last_loc));
            };
            floor
        };

        // Journal rewind happens before in-memory commit-location updates. If a later step fails,
        // this handle may be internally diverged and must be dropped by the caller.
        self.journal.rewind(rewind_size).await?;
        self.last_commit_loc = rewind_last_loc;
        self.inactivity_floor_loc = rewind_floor;
        let inactive_peaks = F::inactive_peaks(F::location_to_position(size), rewind_floor);
        self.root = self.journal.root(inactive_peaks)?;
        Ok(())
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.journal.sync().await.map_err(Into::into)
    }

    /// Durably commit the journal state published by prior [`Keyless::apply_batch`] calls.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.journal.commit().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        Ok(self.journal.destroy().await?)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<F, H, V, S> {
        let journal_size = *self.last_commit_loc + 1;
        batch::UnmerkleizedBatch::new(self, journal_size)
    }

    /// Create an initial [`batch::MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, H::Digest, V, S>> {
        let journal_size = *self.last_commit_loc + 1;
        Arc::new(batch::MerkleizedBatch {
            journal_batch: self.journal.to_merkleized_batch(),
            root: self.root,
            parent: None,
            base_size: journal_size,
            total_size: journal_size,
            db_size: journal_size,
            ancestor_batch_ends: Vec::new(),
            ancestor_new_inactivity_floor_locs: Vec::new(),
            new_inactivity_floor_loc: self.inactivity_floor_loc,
        })
    }

    /// Apply a [`batch::MerkleizedBatch`] to the database.
    ///
    /// A batch is valid only if every batch applied to the database since this batch's
    /// ancestor chain was created is an ancestor of this batch. Applying a batch from a
    /// different fork returns [`Error::StaleBatch`].
    ///
    /// Every commit operation in the batch chain (each unapplied ancestor's commit plus the
    /// tip's) must satisfy two per-commit invariants:
    ///
    /// 1. The floor is monotonically non-decreasing across the chain, starting from the
    ///    database's current inactivity floor.
    /// 2. The floor is at most the commit operation's own location (`total_size - 1` at that
    ///    point). A floor past the commit would let a later `prune(floor)` remove the last
    ///    readable commit from the journal.
    ///
    /// Violations return [`Error::FloorRegressed`] or [`Error::FloorBeyondSize`] identifying
    /// the offending floor and the bound it crossed (the prior validated floor, or the commit
    /// location, respectively). Floor validation happens before any journal mutation, so the
    /// database is untouched on floor errors.
    ///
    /// Returns the range of locations written.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the
    /// journal, but does not durably commit it. Call [`Keyless::commit`] or
    /// [`Keyless::sync`] to guarantee durability.
    pub async fn apply_batch(
        &mut self,
        batch: Arc<batch::MerkleizedBatch<F, H::Digest, V, S>>,
    ) -> Result<core::ops::Range<Location<F>>, Error<F>> {
        let db_size = *self.last_commit_loc + 1;
        let valid = db_size == batch.db_size
            || db_size == batch.base_size
            || batch.ancestor_batch_ends.contains(&db_size);
        if !valid {
            return Err(Error::StaleBatch {
                db_size,
                batch_db_size: batch.db_size,
                batch_base_size: batch.base_size,
            });
        }
        // Validate every unapplied commit's floor (each ancestor in the chain, then the tip)
        // before mutating the journal. The invariant is per-commit:
        //   - floors are monotonically non-decreasing across the chain, and
        //   - each floor is at most its own commit location (= total_size - 1 at that point).
        // Ancestors are stored newest-first, so walk in reverse to get oldest-first.
        let mut prev_floor = self.inactivity_floor_loc;
        for i in (0..batch.ancestor_batch_ends.len()).rev() {
            let ancestor_end = batch.ancestor_batch_ends[i];
            if ancestor_end <= db_size {
                // Already on disk — its floor was validated when it was first applied.
                continue;
            }
            let ancestor_floor = batch.ancestor_new_inactivity_floor_locs[i];
            let ancestor_commit_loc = Location::new(ancestor_end - 1);
            if ancestor_floor < prev_floor {
                return Err(Error::FloorRegressed(ancestor_floor, prev_floor));
            }
            if ancestor_floor > ancestor_commit_loc {
                return Err(Error::FloorBeyondSize(ancestor_floor, ancestor_commit_loc));
            }
            prev_floor = ancestor_floor;
        }
        // Tip checks chain off the last validated ancestor floor.
        if batch.new_inactivity_floor_loc < prev_floor {
            return Err(Error::FloorRegressed(
                batch.new_inactivity_floor_loc,
                prev_floor,
            ));
        }
        let tip_commit_loc = Location::new(batch.total_size - 1);
        if batch.new_inactivity_floor_loc > tip_commit_loc {
            return Err(Error::FloorBeyondSize(
                batch.new_inactivity_floor_loc,
                tip_commit_loc,
            ));
        }
        let start_loc = self.last_commit_loc + 1;

        self.journal.apply_batch(&batch.journal_batch).await?;

        self.last_commit_loc = Location::new(batch.total_size - 1);
        self.inactivity_floor_loc = batch.new_inactivity_floor_loc;
        self.root = batch.root;
        let end_loc = Location::new(batch.total_size);
        debug!(size = ?end_loc, "applied batch");
        Ok(start_loc..end_loc)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        journal::{contiguous::Mutable, Error as JournalError},
        qmdb::{self, verify_proof},
        Persistable,
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{deterministic, Supervisor as _};
    use commonware_utils::NZU64;
    use std::{future::Future, pin::Pin};

    pub(crate) type Reopen<D> =
        Box<dyn Fn(deterministic::Context) -> Pin<Box<dyn Future<Output = D> + Send>>>;

    /// Test value factory: creates distinct values from an index.
    pub(crate) trait TestValue: Clone + PartialEq + std::fmt::Debug + Send + Sync {
        fn make(i: u64) -> Self;
    }

    impl TestValue for Vec<u8> {
        fn make(i: u64) -> Self {
            vec![(i % 255) as u8; ((i % 13) + 7) as usize]
        }
    }

    impl TestValue for commonware_utils::sequence::U64 {
        fn make(i: u64) -> Self {
            Self::new(i * 10 + 1)
        }
    }

    pub(crate) async fn test_keyless_db_empty<F: Family, V, C, H>(
        context: deterministic::Context,
        db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let bounds = db.bounds().await;
        assert_eq!(bounds.end, 1); // initial commit should exist
        assert_eq!(bounds.start, Location::new(0));
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.last_commit_loc(), Location::new(0));

        // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
        let root = db.root();
        {
            db.new_batch().append(V::Value::make(1));
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);

        let mut db = reopen(context.child("db").with_attribute("index", 2)).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, 1);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Test calling commit on an empty db which should make it (durably) non-empty.
        let metadata = V::Value::make(99);
        let merkleized =
            db.new_batch()
                .merkleize(&db, Some(metadata.clone()), db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.bounds().await.end, 2); // 2 commit ops
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
        assert_eq!(
            db.get(Location::new(1)).await.unwrap(),
            Some(metadata.clone())
        ); // the commit op
        let root = db.root();

        // Commit op should remain after reopen even without clean shutdown.
        let db = reopen(context.child("db").with_attribute("index", 3)).await;
        assert_eq!(db.bounds().await.end, 2); // commit op should remain after re-open.
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), Location::new(1));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_build_basic<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Build a db with 2 values and make sure we can get them back.
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);

        {
            let batch = db.new_batch();
            let loc1 = batch.size();
            let batch = batch.append(v1.clone());
            let loc2 = batch.size();
            let batch = batch.append(v2.clone());
            assert_eq!(loc1, Location::new(1));
            assert_eq!(loc2, Location::new(2));
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }

        // Make sure closing/reopening gets us back to the same state.
        assert_eq!(db.bounds().await.end, 4); // 2 appends, 1 commit + 1 initial commit
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(Location::new(3)).await.unwrap(), None); // the commit op
        let root = db.root();
        db.sync().await.unwrap();
        drop(db);

        let db = reopen(context.child("db").with_attribute("index", 2)).await;
        assert_eq!(db.bounds().await.end, 4);
        assert_eq!(db.root(), root);
        assert_eq!(db.get(Location::new(1)).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(Location::new(2)).await.unwrap().unwrap(), v2);

        // Make sure commit operation remains after drop/reopen.
        drop(db);
        let db = reopen(context.child("db").with_attribute("index", 3)).await;
        assert_eq!(db.bounds().await.end, 4);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let root = db.root();
        const ELEMENTS: u64 = 100;

        // Create uncommitted appends then simulate failure.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        // Should rollback to the previous root.
        let mut db = reopen(context.child("db").with_attribute("index", 2)).await;
        assert_eq!(root, db.root());

        // Apply the updates and commit them this time.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 100));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();
        let root = db.root();

        // Create uncommitted appends then simulate failure.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 200));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        // Should rollback to the previous root.
        let mut db = reopen(context.child("db").with_attribute("index", 3)).await;
        assert_eq!(root, db.root());

        // Apply the updates and commit them this time.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 300));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();
        let root = db.root();

        // Make sure we can reopen and get back to the same state.
        drop(db);
        let db = reopen(context.child("db").with_attribute("index", 4)).await;
        assert_eq!(db.bounds().await.end, 2 * ELEMENTS + 3);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_proof<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = qmdb::hasher::<Sha256>();
        const ELEMENTS: u64 = 50;

        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        let root = db.root();

        let (proof, ops) = db.proof(Location::new(0), NZU64!(100)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root,));
        assert_eq!(ops.len() as u64, 1 + ELEMENTS + 1);

        let (proof, ops) = db.proof(Location::new(10), NZU64!(5)).await.unwrap();
        assert!(verify_proof(
            &hasher,
            &proof,
            Location::new(10),
            &ops,
            &root,
        ));
        assert_eq!(ops.len(), 5);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_metadata<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let metadata = V::Value::make(99);
        let merkleized = db.new_batch().append(V::Value::make(1)).merkleize(
            &db,
            Some(metadata.clone()),
            db.inactivity_floor_loc(),
        );
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        let merkleized = db
            .new_batch()
            .merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_pruning<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Initial floor is 0, so pruning past 0 should fail.
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));
        let result = db.prune(Location::new(1)).await;
        assert!(
            matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, floor))
                if prune_loc == Location::new(1) && floor == Location::new(0))
        );

        // Add values and commit, advancing the floor to the new commit location.
        let first_commit_loc = Location::<F>::new(3);
        let merkleized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(&db, None, first_commit_loc);
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.last_commit_loc(), first_commit_loc);
        assert_eq!(db.inactivity_floor_loc(), first_commit_loc);

        // Append one more, advancing the floor with it.
        let second_commit_loc = Location::<F>::new(5);
        let merkleized =
            db.new_batch()
                .append(V::Value::make(3))
                .merkleize(&db, None, second_commit_loc);
        db.apply_batch(merkleized).await.unwrap();

        // Valid prune: up to the floor (previous commit location).
        let root = db.root();
        assert!(db.prune(first_commit_loc).await.is_ok());
        assert_eq!(db.root(), root);

        // Pruning beyond the current floor fails.
        let new_floor = db.inactivity_floor_loc();
        let beyond = Location::new(*new_floor + 1);
        let result = db.prune(beyond).await;
        assert!(
            matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, floor))
                if prune_loc == beyond && floor == new_floor)
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_empty_db_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let root = db.root();
        const ELEMENTS: u64 = 200;

        // Reopen DB without clean shutdown and make sure the state is the same.
        let db = reopen(context.child("db").with_attribute("index", 2)).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // Simulate failure after inserting operations without a commit.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        let db = reopen(context.child("db").with_attribute("index", 3)).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // Repeat: simulate failure after inserting operations without a commit.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 500));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        let db = reopen(context.child("db").with_attribute("index", 4)).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // One last check: multiple batches of uncommitted appends.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS * 3 {
                batch = batch.append(V::Value::make(i + 1000));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        let mut db = reopen(context.child("db").with_attribute("index", 5)).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), Location::new(0));

        // Apply the ops one last time but fully commit them this time, then clean up.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 2000));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();
        let db = reopen(context.child("db").with_attribute("index", 6)).await;
        assert!(db.bounds().await.end > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_replay_with_trailing_appends<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Add some initial operations and commit.
        {
            let mut batch = db.new_batch();
            for i in 0..10u64 {
                batch = batch.append(V::Value::make(i));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();
        let committed_root = db.root();
        let committed_size = db.bounds().await.end;

        // Add exactly one more append (uncommitted).
        {
            db.new_batch().append(V::Value::make(99));
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);

        // Reopen and verify correct recovery.
        let mut db = reopen(context.child("db").with_attribute("index", 2)).await;
        assert_eq!(
            db.bounds().await.end,
            committed_size,
            "Should rewind to last commit"
        );
        assert_eq!(db.root(), committed_root, "Root should match last commit");
        assert_eq!(
            db.last_commit_loc(),
            committed_size - 1,
            "Last commit location should be correct"
        );

        // Verify we can append and commit new data after recovery.
        let new_value = V::Value::make(77);
        {
            let batch = db.new_batch();
            let loc = batch.size();
            let batch = batch.append(new_value.clone());
            assert_eq!(
                loc, committed_size,
                "New append should get the expected location"
            );
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();

        assert_eq!(db.get(committed_size).await.unwrap(), Some(new_value));

        let new_committed_root = db.root();
        let new_committed_size = db.bounds().await.end;

        // Add multiple uncommitted appends.
        {
            let mut batch = db.new_batch();
            for i in 0..5u64 {
                batch = batch.append(V::Value::make(200 + i));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);

        // Reopen and verify correct recovery.
        let db = reopen(context.child("db").with_attribute("index", 3)).await;
        assert_eq!(
            db.bounds().await.end,
            new_committed_size,
            "Should rewind to last commit with multiple trailing appends"
        );
        assert_eq!(
            db.root(),
            new_committed_root,
            "Root should match last commit after multiple appends"
        );
        assert_eq!(
            db.last_commit_loc(),
            new_committed_size - 1,
            "Last commit location should be correct after multiple appends"
        );

        db.destroy().await.unwrap();
    }

    /// `get_many` on the DB and on unmerkleized/merkleized batches returns
    /// results consistent with individual `get` calls.
    pub(crate) async fn test_keyless_get_many<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);
        let v3 = V::Value::make(3);

        // Commit v1 and v2 to disk.
        let batch = db.new_batch();
        let loc1 = batch.size();
        let batch = batch.append(v1.clone());
        let loc2 = batch.size();
        let batch = batch.append(v2.clone());
        db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
            .await
            .unwrap();
        db.commit().await.unwrap();

        // DB-level get_many.
        let results = db.get_many(&[loc1, loc2]).await.unwrap();
        assert_eq!(results, vec![Some(v1.clone()), Some(v2.clone())]);

        // Empty input.
        let results = db.get_many(&[]).await.unwrap();
        assert!(results.is_empty());

        // Unmerkleized batch: pending appends + DB fallthrough.
        let batch = db.new_batch();
        let loc3 = batch.size();
        let batch = batch.append(v3.clone());
        let results = batch.get_many(&[loc1, loc3], &db).await.unwrap();
        assert_eq!(results, vec![Some(v1.clone()), Some(v3.clone())]);

        // Merkleized batch: parent chain + DB fallthrough.
        let parent =
            db.new_batch()
                .append(v3.clone())
                .merkleize(&db, None, db.inactivity_floor_loc());
        let child = parent.new_batch::<Sha256>().append(V::Value::make(4));
        let results = child.get_many(&[loc1, loc2], &db).await.unwrap();
        assert_eq!(results, vec![Some(v1.clone()), Some(v2.clone())]);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_chained<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let v1 = V::Value::make(10);
        let v2 = V::Value::make(20);
        let v3 = V::Value::make(30);

        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(&db, None, db.inactivity_floor_loc());

        let child = parent_m.new_batch::<Sha256>();
        let loc2 = child.size();
        let child = child.append(v2.clone());
        let loc3 = child.size();
        let child = child.append(v3.clone());
        let child_m = child.merkleize(&db, None, db.inactivity_floor_loc());
        let child_root = child_m.root();

        db.apply_batch(child_m).await.unwrap();
        db.commit().await.unwrap();

        assert_eq!(db.root(), child_root);
        assert_eq!(db.get(loc1).await.unwrap(), Some(v1));
        assert_eq!(db.get(loc2).await.unwrap(), Some(v2));
        assert_eq!(db.get(loc3).await.unwrap(), Some(v3));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_batch<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let batch_a = db.new_batch().append(V::Value::make(10)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let batch_b = db.new_batch().append(V::Value::make(20)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );

        db.apply_batch(batch_a).await.unwrap();

        let result = db.apply_batch(batch_b).await;
        assert!(matches!(result, Err(Error::StaleBatch { .. })));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_partial_ancestor_commit<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Chain: DB <- A <- B <- C
        let a = db.new_batch().append(V::Value::make(10)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let b = a.new_batch::<H>().append(V::Value::make(20)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let c = b.new_batch::<H>().append(V::Value::make(30)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );

        let expected_root = c.root();

        // Apply only A, then apply C directly (B's items applied via ancestor batches).
        db.apply_batch(a).await.unwrap();
        db.apply_batch(c).await.unwrap();

        // Root must match what the full chain produces.
        assert_eq!(db.root(), expected_root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_to_batch<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let batch = db.new_batch();
        let loc1 = batch.size();
        let batch = batch.append(V::Value::make(10));
        db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
            .await
            .unwrap();

        let snapshot = db.to_batch();
        assert_eq!(snapshot.root(), db.root());

        let child_batch = snapshot.new_batch::<Sha256>();
        let loc2 = child_batch.size();
        let child_batch = child_batch.append(V::Value::make(20));
        db.apply_batch(child_batch.merkleize(&db, None, db.inactivity_floor_loc()))
            .await
            .unwrap();

        assert_eq!(db.get(loc1).await.unwrap(), Some(V::Value::make(10)));
        assert_eq!(db.get(loc2).await.unwrap(), Some(V::Value::make(20)));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_non_empty_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Append many values then commit, advancing the floor to the new commit so we can
        // later prune up to it.
        const ELEMENTS: u64 = 200;
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            let new_commit = Location::new(*db.last_commit_loc() + 1 + ELEMENTS);
            db.apply_batch(batch.merkleize(&db, None, new_commit))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();
        let root = db.root();
        let op_count = db.bounds().await.end;

        // Reopen DB without clean shutdown and make sure the state is the same.
        let db = reopen(context.child("db").with_attribute("index", 2)).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), op_count - 1);
        drop(db);

        // Insert many operations without commit, then simulate failure.
        let db = reopen(context.child("recovery_a")).await;
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 1000));
            }
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        let db = reopen(context.child("recovery_b")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        drop(db);

        // Repeat after pruning to the last commit.
        let mut db = reopen(context.child("db").with_attribute("index", 3)).await;
        db.prune(db.last_commit_loc()).await.unwrap();
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        db.sync().await.unwrap();
        drop(db);

        let db = reopen(context.child("recovery_c")).await;
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 2000));
            }
        }
        drop(db);
        let db = reopen(context.child("recovery_d")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        drop(db);

        // Apply the ops one last time but fully commit them this time, then clean up.
        let mut db = reopen(context.child("db").with_attribute("index", 4)).await;
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 3000));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }
        db.commit().await.unwrap();
        let db = reopen(context.child("db").with_attribute("index", 5)).await;
        let bounds = db.bounds().await;
        assert!(bounds.end > op_count);
        assert_ne!(db.root(), root);
        assert_eq!(db.last_commit_loc(), bounds.end - 1);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_proof_comprehensive<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = qmdb::hasher::<Sha256>();

        // Build a db with some values.
        const ELEMENTS: u64 = 100;
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }

        // Test that historical proof fails with op_count > number of operations.
        assert!(matches!(
            db.historical_proof(db.bounds().await.end + 1, Location::new(5), NZU64!(10))
                .await,
            Err(Error::<F>::Merkle(crate::merkle::Error::RangeOutOfBounds(
                _
            )))
        ));

        let root = db.root();

        for (start_loc, max_ops) in [
            (0, 10),
            (10, 5),
            (50, 20),
            (90, 15),
            (0, 1),
            (ELEMENTS - 1, 1),
            (ELEMENTS, 1),
        ] {
            let (proof, ops) = db
                .proof(Location::new(start_loc), NZU64!(max_ops))
                .await
                .unwrap();
            assert!(
                verify_proof(&hasher, &proof, Location::new(start_loc), &ops, &root,),
                "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops",
            );
            let expected_ops = std::cmp::min(max_ops, *db.bounds().await.end - start_loc);
            assert_eq!(ops.len() as u64, expected_ops);

            let wrong_root = Sha256::hash(&[0xFF; 32]);
            assert!(!verify_proof(
                &hasher,
                &proof,
                Location::new(start_loc),
                &ops,
                &wrong_root,
            ));
            if start_loc > 0 {
                assert!(!verify_proof(
                    &hasher,
                    &proof,
                    Location::new(start_loc - 1),
                    &ops,
                    &root,
                ));
            }
        }

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_proof_with_pruning<F: Family, V, C>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, Sha256>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = qmdb::hasher::<Sha256>();

        const ELEMENTS: u64 = 100;
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            let new_commit = Location::new(*db.last_commit_loc() + 1 + ELEMENTS);
            db.apply_batch(batch.merkleize(&db, None, new_commit))
                .await
                .unwrap();
        }

        {
            let mut batch = db.new_batch();
            for i in ELEMENTS..ELEMENTS * 2 {
                batch = batch.append(V::Value::make(i));
            }
            let new_commit = Location::new(*db.last_commit_loc() + 1 + ELEMENTS);
            db.apply_batch(batch.merkleize(&db, None, new_commit))
                .await
                .unwrap();
        }
        let root = db.root();

        const PRUNE_LOC: u64 = 30;
        db.prune(Location::new(PRUNE_LOC)).await.unwrap();
        let oldest_retained = db.bounds().await.start;
        assert_eq!(db.root(), root);

        db.sync().await.unwrap();
        drop(db);
        let mut db = reopen(context).await;
        assert_eq!(db.root(), root);

        for (start_loc, max_ops) in [
            (oldest_retained, 10),
            (Location::new(50), 20),
            (Location::new(150), 10),
            (Location::new(190), 15),
        ] {
            if start_loc < oldest_retained {
                continue;
            }
            let (proof, ops) = db.proof(start_loc, NZU64!(max_ops)).await.unwrap();
            assert!(verify_proof(&hasher, &proof, start_loc, &ops, &root,));
        }

        let aggressive_prune: Location<F> = Location::new(150);
        db.prune(aggressive_prune).await.unwrap();

        let new_oldest = db.bounds().await.start;
        let (proof, ops) = db.proof(new_oldest, NZU64!(20)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, new_oldest, &ops, &root,));

        let almost_all = db.bounds().await.end - 5;
        db.prune(almost_all).await.unwrap();
        let final_oldest = db.bounds().await.start;
        if final_oldest < db.bounds().await.end {
            let (final_proof, final_ops) = db.proof(final_oldest, NZU64!(10)).await.unwrap();
            assert!(verify_proof(
                &hasher,
                &final_proof,
                final_oldest,
                &final_ops,
                &root,
            ));
        }

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_get_out_of_bounds<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        assert!(db.get(Location::new(0)).await.unwrap().is_none());

        let merkleized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();

        assert_eq!(
            db.get(Location::new(1)).await.unwrap(),
            Some(V::Value::make(1))
        );
        assert!(db.get(Location::new(3)).await.unwrap().is_none());
        assert!(matches!(
            db.get(Location::new(4)).await,
            Err(Error::LocationOutOfBounds(loc, size))
                if loc == Location::new(4) && size == Location::new(4)
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_get<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let base_vals: Vec<V::Value> = (0..3).map(|i| V::Value::make(10 + i)).collect();
        let mut base_locs = Vec::new();
        {
            let mut batch = db.new_batch();
            for v in &base_vals {
                let loc = batch.size();
                batch = batch.append(v.clone());
                base_locs.push(loc);
            }
            db.apply_batch(batch.merkleize(&db, None, db.inactivity_floor_loc()))
                .await
                .unwrap();
        }

        let batch = db.new_batch();
        for (i, loc) in base_locs.iter().enumerate() {
            assert_eq!(
                batch.get(*loc, &db).await.unwrap(),
                Some(base_vals[i].clone()),
            );
        }

        let new_val = V::Value::make(99);
        let new_loc = batch.size();
        let batch = batch.append(new_val.clone());
        assert_eq!(batch.get(new_loc, &db).await.unwrap(), Some(new_val));
        assert_eq!(
            batch.get(Location::new(*new_loc + 1), &db).await.unwrap(),
            None
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_stacked_get<F: Family, V, C>(
        db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);

        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(&db, None, db.inactivity_floor_loc());

        let child = parent_m.new_batch::<Sha256>();
        assert_eq!(child.get(loc1, &db).await.unwrap(), Some(v1));

        let loc2 = child.size();
        let child = child.append(v2.clone());
        assert_eq!(child.get(loc2, &db).await.unwrap(), Some(v2));
        assert_eq!(child.get(Location::new(9999), &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_speculative_root<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let mut batch = db.new_batch();
        for i in 0u64..10 {
            batch = batch.append(V::Value::make(i));
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
        let speculative = merkleized.root();
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), speculative);

        let merkleized = db.new_batch().append(V::Value::make(100)).merkleize(
            &db,
            Some(V::Value::make(55)),
            db.inactivity_floor_loc(),
        );
        let speculative = merkleized.root();
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), speculative);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_merkleized_batch_get<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let base_val = V::Value::make(10);
        let merkleized =
            db.new_batch()
                .append(base_val.clone())
                .merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();

        let new_val = V::Value::make(20);
        let merkleized =
            db.new_batch()
                .append(new_val.clone())
                .merkleize(&db, None, db.inactivity_floor_loc());

        assert_eq!(
            merkleized.get(Location::new(1), &db).await.unwrap(),
            Some(base_val),
        );
        assert_eq!(
            merkleized.get(Location::new(3), &db).await.unwrap(),
            Some(new_val),
        );
        assert_eq!(merkleized.get(Location::new(4), &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_chained_apply_sequential<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);

        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(&db, None, db.inactivity_floor_loc());
        let parent_root = parent_m.root();

        db.apply_batch(parent_m).await.unwrap();
        assert_eq!(db.root(), parent_root);
        assert_eq!(db.get(loc1).await.unwrap(), Some(v1));

        let batch2 = db.new_batch();
        let loc2 = batch2.size();
        let batch2 = batch2.append(v2.clone());
        let batch2_m = batch2.merkleize(&db, None, db.inactivity_floor_loc());
        let batch2_root = batch2_m.root();
        db.apply_batch(batch2_m).await.unwrap();
        assert_eq!(db.root(), batch2_root);
        assert_eq!(db.get(loc2).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_many_sequential<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = qmdb::hasher::<Sha256>();

        const BATCHES: u64 = 20;
        const APPENDS_PER_BATCH: u64 = 5;
        let mut all_values: Vec<V::Value> = Vec::new();
        let mut all_locs: Vec<Location<F>> = Vec::new();

        for batch_idx in 0..BATCHES {
            let mut batch = db.new_batch();
            for j in 0..APPENDS_PER_BATCH {
                let v = V::Value::make(batch_idx * 10 + j);
                let loc = batch.size();
                batch = batch.append(v.clone());
                all_values.push(v);
                all_locs.push(loc);
            }
            let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
            db.apply_batch(merkleized).await.unwrap();
        }

        for (i, loc) in all_locs.iter().enumerate() {
            assert_eq!(db.get(*loc).await.unwrap(), Some(all_values[i].clone()));
        }

        let root = db.root();
        let (proof, ops) = db.proof(Location::new(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root,));
        assert_eq!(db.bounds().await.end, 1 + BATCHES * (APPENDS_PER_BATCH + 1));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_empty<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let merkleized = db.new_batch().append(V::Value::make(1)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        db.apply_batch(merkleized).await.unwrap();
        let root_before = db.root();
        let size_before = db.bounds().await.end;

        let merkleized = db
            .new_batch()
            .merkleize(&db, None, db.inactivity_floor_loc());
        let speculative = merkleized.root();
        db.apply_batch(merkleized).await.unwrap();

        assert_ne!(db.root(), root_before);
        assert_eq!(db.root(), speculative);
        assert_eq!(db.bounds().await.end, size_before + 1);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_chained_merkleized_get<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let base_val = V::Value::make(10);
        let floor = db.inactivity_floor_loc();
        db.apply_batch(
            db.new_batch()
                .append(base_val.clone())
                .merkleize(&db, None, floor),
        )
        .await
        .unwrap();

        let v1 = V::Value::make(1);
        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent_m = parent
            .append(v1.clone())
            .merkleize(&db, None, db.inactivity_floor_loc());

        let v2 = V::Value::make(2);
        let child = parent_m.new_batch::<Sha256>();
        let loc2 = child.size();
        let child_m = child
            .append(v2.clone())
            .merkleize(&db, None, db.inactivity_floor_loc());

        assert_eq!(
            child_m.get(Location::new(1), &db).await.unwrap(),
            Some(base_val),
        );
        assert_eq!(child_m.get(loc1, &db).await.unwrap(), Some(v1));
        assert_eq!(child_m.get(loc2, &db).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_large<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = qmdb::hasher::<Sha256>();
        const N: u64 = 500;
        let mut values = Vec::new();
        let mut locs = Vec::new();

        let mut batch = db.new_batch();
        for i in 0..N {
            let v = V::Value::make(i);
            locs.push(batch.size());
            batch = batch.append(v.clone());
            values.push(v);
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();

        for (i, loc) in locs.iter().enumerate() {
            assert_eq!(db.get(*loc).await.unwrap(), Some(values[i].clone()));
        }

        let root = db.root();
        let (proof, ops) = db.proof(Location::new(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root,));
        assert_eq!(db.bounds().await.end, 1 + N + 1);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_batch_chained<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let child_a = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(&db, None, db.inactivity_floor_loc());
        let child_b = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(3))
            .merkleize(&db, None, db.inactivity_floor_loc());

        db.apply_batch(child_a).await.unwrap();
        assert!(matches!(
            db.apply_batch(child_b).await,
            Err(Error::StaleBatch { .. })
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_sequential_commit_parent_then_child<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let child = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(&db, None, db.inactivity_floor_loc());

        db.apply_batch(parent).await.unwrap();
        db.apply_batch(child).await.unwrap();

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_batch_child_before_parent<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let child = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(&db, None, db.inactivity_floor_loc());

        db.apply_batch(child).await.unwrap();
        assert!(matches!(
            db.apply_batch(parent).await,
            Err(Error::StaleBatch { .. })
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_child_root_matches_pending_and_committed<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        Operation<F, V>: EncodeShared,
    {
        // Build the child while the parent is still pending.
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );
        let pending_child = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(&db, None, db.inactivity_floor_loc());

        // Commit the parent, then rebuild the same logical child from the
        // committed DB state and compare roots.
        db.apply_batch(parent).await.unwrap();
        db.commit().await.unwrap();

        let committed_child = db.new_batch().append(V::Value::make(2)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        );

        assert_eq!(pending_child.root(), committed_child.root());

        db.destroy().await.unwrap();
    }

    async fn commit_appends<F: Family, V, C, H>(
        db: &mut Keyless<F, deterministic::Context, V, C, H>,
        values: impl IntoIterator<Item = V::Value>,
        metadata: Option<V::Value>,
    ) -> core::ops::Range<Location<F>>
    where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Tests that don't specifically exercise floor behavior advance the floor to the new
        // commit location, so pruning up to the last commit works analogously to the pre-floor
        // semantics.
        let base_size = *db.last_commit_loc() + 1;
        let appends_iter: Vec<_> = values.into_iter().collect();
        let new_commit_loc = Location::new(base_size + appends_iter.len() as u64);
        let mut batch = db.new_batch();
        for value in appends_iter {
            batch = batch.append(value);
        }
        let range = db
            .apply_batch(batch.merkleize(db, metadata, new_commit_loc))
            .await
            .unwrap();
        db.commit().await.unwrap();
        range
    }

    pub(crate) async fn test_keyless_db_rewind_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let initial_root = db.root();
        let initial_size = db.bounds().await.end;

        let value_a = V::Value::make(1);
        let value_b = V::Value::make(2);
        let metadata_a = V::Value::make(3);
        let first_range = commit_appends(
            &mut db,
            [value_a.clone(), value_b.clone()],
            Some(metadata_a.clone()),
        )
        .await;

        let root_before = db.root();
        let size_before = db.bounds().await.end;
        let commit_before = db.last_commit_loc();
        assert_eq!(size_before, first_range.end);

        let value_c = V::Value::make(4);
        let metadata_b = V::Value::make(5);
        let second_range =
            commit_appends(&mut db, [value_c.clone()], Some(metadata_b.clone())).await;
        assert_eq!(second_range.start, size_before);
        assert_ne!(db.root(), root_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_b));

        db.rewind(size_before).await.unwrap();
        assert_eq!(db.root(), root_before);
        assert_eq!(db.bounds().await.end, size_before);
        assert_eq!(db.last_commit_loc(), commit_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a.clone()));
        assert_eq!(
            db.get(Location::new(1)).await.unwrap(),
            Some(value_a.clone())
        );
        assert_eq!(
            db.get(Location::new(2)).await.unwrap(),
            Some(value_b.clone())
        );
        assert!(
            matches!(
                db.get(Location::new(4)).await,
                Err(Error::LocationOutOfBounds(_, size)) if size == size_before
            ),
            "rewound append should be out of bounds",
        );

        db.commit().await.unwrap();
        drop(db);
        let mut db = reopen(context.child("reopen")).await;
        assert_eq!(db.root(), root_before);
        assert_eq!(db.bounds().await.end, size_before);
        assert_eq!(db.last_commit_loc(), commit_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
        assert_eq!(
            db.get(Location::new(1)).await.unwrap(),
            Some(value_a.clone())
        );
        assert_eq!(
            db.get(Location::new(2)).await.unwrap(),
            Some(value_b.clone())
        );
        assert!(matches!(
            db.get(Location::new(4)).await,
            Err(Error::LocationOutOfBounds(_, size)) if size == size_before
        ));

        db.rewind(initial_size).await.unwrap();
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.bounds().await.end, initial_size);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(matches!(
            db.get(Location::new(1)).await,
            Err(Error::LocationOutOfBounds(_, size)) if size == initial_size
        ));

        db.commit().await.unwrap();
        drop(db);
        let db = reopen(context.child("reopen_initial_boundary")).await;
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.bounds().await.end, initial_size);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(matches!(
            db.get(Location::new(1)).await,
            Err(Error::LocationOutOfBounds(_, size)) if size == initial_size
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_rewind_pruned_target_errors<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let first_range = commit_appends(&mut db, (0..16).map(V::Value::make), None).await;

        let mut round = 0u64;
        loop {
            round += 1;
            assert!(
                round <= 64,
                "failed to prune enough history for rewind test"
            );

            commit_appends(
                &mut db,
                (0..16).map(|i| V::Value::make(round * 100 + i)),
                None,
            )
            .await;
            db.prune(db.last_commit_loc()).await.unwrap();

            if db.bounds().await.start > first_range.start {
                break;
            }
        }

        let oldest_retained = db.bounds().await.start;
        let boundary_err = db.rewind(oldest_retained).await.unwrap_err();
        assert!(
            matches!(
                boundary_err,
                Error::Journal(crate::journal::Error::ItemPruned(_))
            ),
            "unexpected rewind error at retained boundary: {boundary_err:?}"
        );

        let err = db.rewind(first_range.start).await.unwrap_err();
        assert!(
            matches!(err, Error::Journal(crate::journal::Error::ItemPruned(_))),
            "unexpected rewind error: {err:?}"
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_floor_tracking<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Freshly created db has floor = 0.
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));

        // Apply a batch with a declared floor; the db's floor should update.
        let floor_a = Location::<F>::new(2);
        let merkleized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(&db, None, floor_a);
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), floor_a);

        // Reopen: floor should survive restart (it's part of the last commit operation).
        drop(db);
        let mut db = reopen(context.child("reopen")).await;
        assert_eq!(db.inactivity_floor_loc(), floor_a);

        // Floor may stay the same across a commit (monotonic non-decreasing).
        let merkleized = db
            .new_batch()
            .append(V::Value::make(3))
            .merkleize(&db, None, floor_a);
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), floor_a);

        // Floor may advance further.
        let floor_b = Location::<F>::new(5);
        let merkleized = db
            .new_batch()
            .append(V::Value::make(4))
            .merkleize(&db, None, floor_b);
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), floor_b);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_floor_regression_rejected<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Advance floor to 3.
        let merkleized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(&db, None, Location::new(3));
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(3));
        let root_before = db.root();
        let last_commit_before = db.last_commit_loc();

        // Try to commit with a lower floor; apply_batch rejects.
        let merkleized =
            db.new_batch()
                .append(V::Value::make(3))
                .merkleize(&db, None, Location::new(1));
        let err = db.apply_batch(merkleized).await.unwrap_err();
        assert!(
            matches!(err, Error::FloorRegressed(new, current) if *new == 1 && *current == 3),
            "unexpected error: {err:?}"
        );

        // DB state must be untouched: floor, last_commit_loc, and root unchanged.
        assert_eq!(db.inactivity_floor_loc(), Location::new(3));
        assert_eq!(db.last_commit_loc(), last_commit_before);
        assert_eq!(db.root(), root_before);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_floor_beyond_commit_loc_rejected<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Batch of 2 appends + 1 commit lands at locations [1..4); commit at 3, total_size = 4.
        // A floor > 3 (the commit location) is invalid — even floor == 4 (one past the commit)
        // is rejected so a subsequent prune cannot remove the last readable commit.
        let merkleized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(&db, None, Location::new(999));
        let err = db.apply_batch(merkleized).await.unwrap_err();
        assert!(
            matches!(err, Error::FloorBeyondSize(floor, commit) if *floor == 999 && *commit == 3),
            "unexpected error: {err:?}"
        );

        // Boundary: floor == total_size (= commit_loc + 1) is also rejected.
        let merkleized = db
            .new_batch()
            .append(V::Value::make(3))
            .append(V::Value::make(4))
            .merkleize(&db, None, Location::new(4));
        let err = db.apply_batch(merkleized).await.unwrap_err();
        assert!(
            matches!(err, Error::FloorBeyondSize(floor, commit) if *floor == 4 && *commit == 3),
            "unexpected error: {err:?}"
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_rewind_restores_floor<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // First commit: floor advances to 3 (= commit location).
        let floor_a = Location::<F>::new(3);
        let merkleized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(&db, None, floor_a);
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        let rewind_target = Location::new(*db.last_commit_loc() + 1);

        // Second commit: floor advances to 6.
        let floor_b = Location::<F>::new(6);
        let merkleized = db
            .new_batch()
            .append(V::Value::make(3))
            .append(V::Value::make(4))
            .merkleize(&db, None, floor_b);
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), floor_b);

        // Rewind to the first commit; floor should restore to floor_a.
        db.rewind(rewind_target).await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), floor_a);

        // Prune is now gated at floor_a. Pruning past it fails.
        let beyond = Location::new(*floor_a + 1);
        let err = db.prune(beyond).await.unwrap_err();
        assert!(matches!(err, Error::PruneBeyondMinRequired(_, _)));

        // Pruning up to the floor works.
        db.prune(floor_a).await.unwrap();

        db.destroy().await.unwrap();
    }

    /// Floor is embedded in the Commit operation and therefore in the Merkle root: two databases
    /// with identical appends but different floors must produce different roots.
    pub(crate) async fn test_keyless_db_floor_changes_root<F: Family, V, C, H>(
        mut db_a: Keyless<F, deterministic::Context, V, C, H>,
        mut db_b: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        let appends = [V::Value::make(1), V::Value::make(2)];

        // db_a commits with floor=0.
        let mut batch_a = db_a.new_batch();
        for v in appends.iter() {
            batch_a = batch_a.append(v.clone());
        }
        db_a.apply_batch(batch_a.merkleize(&db_a, None, Location::new(0)))
            .await
            .unwrap();

        // db_b commits the same appends but with floor=3 (= commit location).
        let mut batch_b = db_b.new_batch();
        for v in appends.iter() {
            batch_b = batch_b.append(v.clone());
        }
        db_b.apply_batch(batch_b.merkleize(&db_b, None, Location::new(3)))
            .await
            .unwrap();

        assert_ne!(db_a.root(), db_b.root());

        db_a.destroy().await.unwrap();
        db_b.destroy().await.unwrap();
    }

    /// A floor equal to the commit operation's location is on the tight boundary of acceptance.
    pub(crate) async fn test_keyless_db_floor_at_commit_loc_accepted<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // 2 appends + 1 commit on top of the initial commit: commit lands at location 3.
        // floor == 3 (= commit_loc) is the maximum accepted value under the per-commit bound.
        let commit_loc = Location::<F>::new(3);
        db.apply_batch(
            db.new_batch()
                .append(V::Value::make(1))
                .append(V::Value::make(2))
                .merkleize(&db, None, commit_loc),
        )
        .await
        .unwrap();
        assert_eq!(db.inactivity_floor_loc(), commit_loc);

        db.destroy().await.unwrap();
    }

    /// End-to-end: commit → drop → reopen → rewind → verify floor restored after a crash.
    pub(crate) async fn test_keyless_db_rewind_after_reopen_with_floor<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // First commit: 2 appends + commit, floor advances to 3.
        let floor_a = Location::<F>::new(3);
        db.apply_batch(
            db.new_batch()
                .append(V::Value::make(1))
                .append(V::Value::make(2))
                .merkleize(&db, None, floor_a),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        let rewind_target = Location::new(*db.last_commit_loc() + 1);

        // Second commit: 2 appends + commit, floor advances to 6.
        let floor_b = Location::<F>::new(6);
        db.apply_batch(
            db.new_batch()
                .append(V::Value::make(3))
                .append(V::Value::make(4))
                .merkleize(&db, None, floor_b),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();

        // Drop & reopen to simulate a crash after both commits were durable.
        drop(db);
        let mut db = reopen(context.child("reopen")).await;
        assert_eq!(db.inactivity_floor_loc(), floor_b);

        // Rewind to the first commit; floor should restore to floor_a.
        db.rewind(rewind_target).await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), floor_a);
        assert_eq!(db.last_commit_loc(), Location::new(3));

        // Commit the rewind so it's durable, then reopen and confirm the floor again.
        db.commit().await.unwrap();
        drop(db);
        let db = reopen(context.child("reopen").with_attribute("index", 2)).await;
        assert_eq!(db.inactivity_floor_loc(), floor_a);

        db.destroy().await.unwrap();
    }

    /// A chained batch that applies a tip with a floor *lower than* its parent's floor must
    /// be rejected — the parent's `Commit` is written to the journal by the same
    /// `journal.apply_batch` call, so its floor participates in the per-commit monotonicity
    /// invariant.
    pub(crate) async fn test_keyless_db_ancestor_floor_regression_rejected<F, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        F: Family,
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // parent: 1 append + commit at loc 2 with floor=2 (the parent's commit_loc).
        let parent =
            db.new_batch()
                .append(V::Value::make(1))
                .merkleize(&db, None, Location::new(2));
        // child: 1 append + commit at loc 4 with floor=1 (regressed from parent's floor=2).
        let child = parent.new_batch::<H>().append(V::Value::make(2)).merkleize(
            &db,
            None,
            Location::new(1),
        );

        let root_before = db.root();
        let last_commit_before = db.last_commit_loc();
        let floor_before = db.inactivity_floor_loc();

        let err = db.apply_batch(child).await.unwrap_err();
        assert!(
            matches!(err, Error::FloorRegressed(new, prev) if *new == 1 && *prev == 2),
            "unexpected error: {err:?}"
        );

        // DB state untouched by the rejected chain.
        assert_eq!(db.root(), root_before);
        assert_eq!(db.last_commit_loc(), last_commit_before);
        assert_eq!(db.inactivity_floor_loc(), floor_before);

        db.destroy().await.unwrap();
    }

    /// A chained batch where an *ancestor's* floor exceeds its own commit location must be
    /// rejected — identifying the ancestor's bound, not the tip's.
    pub(crate) async fn test_keyless_db_ancestor_floor_beyond_commit_loc_rejected<F, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        F: Family,
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // parent: 1 append + commit at loc 2. Declare floor = 3 (one past the commit).
        let parent =
            db.new_batch()
                .append(V::Value::make(1))
                .merkleize(&db, None, Location::new(3));
        // child: valid on its own (floor = 0 ≤ child's commit_loc), but parent's floor is bad.
        let child = parent.new_batch::<H>().append(V::Value::make(2)).merkleize(
            &db,
            None,
            Location::new(0),
        );

        let err = db.apply_batch(child).await.unwrap_err();
        // Error should identify the ancestor's commit_loc (2), not the tip's.
        assert!(
            matches!(err, Error::FloorBeyondSize(floor, commit) if *floor == 3 && *commit == 2),
            "unexpected error: {err:?}"
        );

        db.destroy().await.unwrap();
    }

    /// After committing with `floor = commit_loc` and pruning down to it, the live set is
    /// exactly one operation — the commit itself. This is the minimum non-empty live set
    /// achievable under the per-commit bound. The DB must remain fully usable: the commit is
    /// readable, the root is preserved, reopen recovers `inactivity_floor_loc` from the sole
    /// remaining op, and a follow-on batch applies cleanly on top.
    pub(crate) async fn test_keyless_db_single_commit_live_set<F, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        F: Family,
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // Initial commit is at loc 0. 3 appends + commit → commit lands at loc 4.
        // Declare floor = 4 (= commit_loc), the tight maximum.
        let metadata = V::Value::make(42);
        let commit_loc = Location::<F>::new(4);
        db.apply_batch(
            db.new_batch()
                .append(V::Value::make(1))
                .append(V::Value::make(2))
                .append(V::Value::make(3))
                .merkleize(&db, Some(metadata.clone()), commit_loc),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.last_commit_loc(), commit_loc);
        assert_eq!(db.inactivity_floor_loc(), commit_loc);
        let root_after_commit = db.root();

        // Prune at the floor — the maximum prune allowed under the invariant.
        // Pruning is blob-aligned, so `bounds.start` may not physically advance all the way
        // to `commit_loc`; what matters semantically is that the floor has authorized pruning
        // of everything below the commit and that any further prune is rejected.
        db.prune(commit_loc).await.unwrap();
        let bounds = db.bounds().await;
        assert!(
            bounds.start <= commit_loc,
            "prune must not advance bounds.start past the floor"
        );
        assert_eq!(bounds.end, Location::new(*commit_loc + 1));

        // Pruning one past the floor must be rejected — the floor is the hard ceiling.
        let err = db.prune(Location::new(*commit_loc + 1)).await.unwrap_err();
        assert!(matches!(err, Error::PruneBeyondMinRequired(p, f)
                if *p == *commit_loc + 1 && *f == *commit_loc));

        // The commit op remains readable; its metadata is intact.
        assert_eq!(db.get(commit_loc).await.unwrap(), Some(metadata.clone()));
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
        assert_eq!(db.last_commit_loc(), commit_loc);
        assert_eq!(db.inactivity_floor_loc(), commit_loc);
        // Prune does not affect the root (documented invariant on `prune`).
        assert_eq!(db.root(), root_after_commit);

        // Persist the prune, then reopen: `init_from_journal` must recover the floor from
        // the last commit op.
        db.sync().await.unwrap();
        drop(db);
        let mut db = reopen(context.child("reopened")).await;
        let reopened_bounds = db.bounds().await;
        assert_eq!(reopened_bounds.end, Location::new(*commit_loc + 1));
        assert_eq!(db.last_commit_loc(), commit_loc);
        assert_eq!(db.inactivity_floor_loc(), commit_loc);
        assert_eq!(db.root(), root_after_commit);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

        // A follow-on batch applies on top. Monotonicity requires the new floor to be at
        // least `commit_loc` (= 4); advancing to the new tight max (= 7) exercises the
        // ancestor-to-tip floor transition from a minimum-live-set starting point.
        let next_commit_loc = Location::<F>::new(7);
        let v5 = V::Value::make(5);
        let v6 = V::Value::make(6);
        db.apply_batch(
            db.new_batch()
                .append(v5.clone())
                .append(v6.clone())
                .merkleize(&db, None, next_commit_loc),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.last_commit_loc(), next_commit_loc);
        assert_eq!(db.inactivity_floor_loc(), next_commit_loc);

        // New appends readable; the original commit op is also still in the live set (not
        // re-pruned), so reading it still returns its metadata.
        assert_eq!(db.get(Location::new(5)).await.unwrap(), Some(v5));
        assert_eq!(db.get(Location::new(6)).await.unwrap(), Some(v6));
        assert_eq!(db.get(commit_loc).await.unwrap(), Some(metadata));

        db.destroy().await.unwrap();
    }

    /// A multi-level chain with strictly-monotonic, within-bounds floors applies cleanly.
    pub(crate) async fn test_keyless_db_chained_apply_with_valid_floors_succeeds<F, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        F: Family,
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<F, V>: EncodeShared,
    {
        // parent:     1 append, commit at loc 2, floor = 2.
        // child:      1 append, commit at loc 4, floor = 3.
        // grandchild: 1 append, commit at loc 6, floor = 5.
        let parent =
            db.new_batch()
                .append(V::Value::make(1))
                .merkleize(&db, None, Location::new(2));
        let child = parent.new_batch::<H>().append(V::Value::make(2)).merkleize(
            &db,
            None,
            Location::new(3),
        );
        let grandchild =
            child
                .new_batch::<H>()
                .append(V::Value::make(3))
                .merkleize(&db, None, Location::new(5));

        db.apply_batch(grandchild).await.unwrap();

        // Grandchild's commit is the last op; tip's floor is the live floor.
        assert_eq!(db.last_commit_loc(), Location::new(6));
        assert_eq!(db.inactivity_floor_loc(), Location::new(5));

        db.destroy().await.unwrap();
    }
}
