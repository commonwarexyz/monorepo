//! The [Keyless] qmdb allows for append-only storage of data that can later be retrieved by its
//! location. Both fixed-size and variable-size values are supported via the [fixed] and [variable]
//! submodules.
//!
//! # Examples
//!
//! ```ignore
//! // Simple mode: apply a batch, then durably commit it.
//! let loc = db.new_batch().size();  // location of the next append
//! let batch = db.new_batch().append(value);
//! let merkleized = batch.merkleize(None);
//! let finalized = merkleized.finalize();
//! db.apply_batch(finalized).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Batches can still fork before you apply them.
//! let parent = db.new_batch().append(value_a);
//! let parent = parent.merkleize(None);
//!
//! let child_a = parent.new_batch();
//! let child_a = child_a.append(value_b);
//! let child_a = child_a.merkleize(None);
//!
//! let child_b = parent.new_batch();
//! let child_b = child_b.append(value_c);
//! let child_b = child_b.merkleize(None);
//!
//! db.apply_batch(child_a.finalize()).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Advanced mode: while the previous batch is being committed, build one child batch from the
//! // the newly published state.
//! let parent = db.new_batch().append(value_a);
//! let parent_finalized = parent.merkleize(None).finalize();
//! db.apply_batch(parent_finalized).await?;
//!
//! let (child_finalized, commit_result) = futures::join!(
//!     async {
//!         let child = db.new_batch().append(value_b);
//!         child.merkleize(None).finalize()
//!     },
//!     db.commit(),
//! );
//! commit_result?;
//!
//! db.apply_batch(child_finalized).await?;
//! db.commit().await?;
//! ```

use crate::{
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
        Error as JournalError,
    },
    merkle::{journaled::Config as MerkleConfig, Family, Location, Proof},
    qmdb::{any::value::ValueEncoding, Error},
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use std::num::NonZeroU64;
use tracing::{debug, warn};

pub mod batch;
pub mod fixed;
mod operation;
pub mod variable;
pub use operation::Operation;

/// Configuration for a [Keyless] authenticated db.
#[derive(Clone)]
pub struct Config<J> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle: MerkleConfig,

    /// Configuration for the operations log journal.
    pub log: J,
}

/// A keyless authenticated database.
pub struct Keyless<F, E, V, C, H>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<V>>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    /// Authenticated journal of operations.
    journal: authenticated::Journal<F, E, C, H>,

    /// The location of the last commit, if any.
    last_commit_loc: Location<F>,
}

impl<F, E, V, C, H> Keyless<F, E, V, C, H>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    pub(crate) async fn init_from_journal(
        mut journal: authenticated::Journal<F, E, C, H>,
    ) -> Result<Self, Error<F>> {
        if journal.size().await == 0 {
            warn!("no operations found in log, creating initial commit");
            journal.append(&Operation::Commit(None)).await?;
            journal.sync().await?;
        }

        let last_commit_loc = journal
            .size()
            .await
            .checked_sub(1)
            .expect("at least one commit should exist");

        Ok(Self {
            journal,
            last_commit_loc,
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

    /// Returns the location of the last commit.
    pub const fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location<F>> {
        let bounds = self.journal.reader().await.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error<F>> {
        let op = self
            .journal
            .reader()
            .await
            .read(*self.last_commit_loc)
            .await?;
        let Operation::Commit(metadata) = op else {
            return Ok(None);
        };

        Ok(metadata)
    }

    /// Return the root of the db.
    pub fn root(&self) -> H::Digest {
        self.journal.root()
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
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<V>>), Error<F>> {
        self.historical_proof(self.bounds().await.end, start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the Merkle structure when it had
    /// `op_count` operations.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Merkle`] with [`crate::merkle::Error::RangeOutOfBounds`] if `start_loc`
    ///   >= `op_count` or `op_count` > number of operations.
    /// - Returns [`Error::Journal`] with [`crate::journal::Error::ItemPruned`] if `start_loc` has
    ///   been pruned.
    pub async fn historical_proof(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<V>>), Error<F>> {
        Ok(self
            .journal
            .historical_proof(op_count, start_loc, max_ops)
            .await?)
    }

    /// Prune historical operations prior to `loc`. This does not affect the db's root.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PruneBeyondMinRequired`] if `loc` > last commit point.
    pub async fn prune(&mut self, loc: Location<F>) -> Result<(), Error<F>> {
        if loc > self.last_commit_loc {
            return Err(Error::PruneBeyondMinRequired(loc, self.last_commit_loc));
        }
        self.journal.prune(loc).await?;

        Ok(())
    }

    /// Rewind the database to `size` operations, where `size` is the location of the next append.
    ///
    /// This rewinds both the operations journal and its Merkle structure to the historical state
    /// at `size`.
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
        {
            let reader = self.journal.reader().await;
            let bounds = reader.bounds();
            if rewind_size <= bounds.start {
                return Err(Error::Journal(crate::journal::Error::ItemPruned(
                    *rewind_last_loc,
                )));
            }
            let rewind_last_op = reader.read(*rewind_last_loc).await?;
            if !matches!(rewind_last_op, Operation::Commit(_)) {
                return Err(Error::UnexpectedData(rewind_last_loc));
            }
        }

        // Journal rewind happens before in-memory commit-location updates. If a later step fails,
        // this handle may be internally diverged and must be dropped by the caller.
        self.journal.rewind(rewind_size).await?;
        self.last_commit_loc = rewind_last_loc;
        Ok(())
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.journal.sync().await.map_err(Into::into)
    }

    /// Durably commit the journal state published by prior [`Keyless::apply_batch`]
    /// calls.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.journal.commit().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        Ok(self.journal.destroy().await?)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<F, H, V> {
        let journal_size = *self.last_commit_loc + 1;
        batch::UnmerkleizedBatch::new(self, journal_size)
    }

    /// Create an initial [`batch::MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> batch::MerkleizedBatch<F, H::Digest, V> {
        let journal_size = *self.last_commit_loc + 1;
        batch::MerkleizedBatch {
            journal_batch: self.journal.to_merkleized_batch(),
            total_size: journal_size,
            db_size: journal_size,
        }
    }

    /// Apply a changeset to the database.
    ///
    /// A changeset is only valid if the database has not been modified since the
    /// batch that produced it was created. Multiple batches can be forked from the
    /// same parent for speculative execution, but only one may be applied. Applying
    /// a stale changeset returns [`Error::StaleChangeset`].
    ///
    /// Returns the range of locations written.
    ///
    /// This publishes the batch to the in-memory database state and appends it to
    /// the journal, but does not durably commit it. Call [`Keyless::commit`] to
    /// wait for the underlying journal commit, or [`Keyless::sync`] for a
    /// stronger durability boundary.
    pub async fn apply_batch(
        &mut self,
        batch: batch::Changeset<F, H::Digest, V>,
    ) -> Result<core::ops::Range<Location<F>>, Error<F>> {
        let journal_size = *self.last_commit_loc + 1;
        if batch.db_size != journal_size {
            return Err(Error::StaleChangeset {
                expected: batch.db_size,
                actual: journal_size,
            });
        }
        let start_loc = self.last_commit_loc + 1;

        // Write all operations to the authenticated journal + apply Merkle changeset.
        self.journal.apply_batch(batch.journal_finalized).await?;

        // Update state.
        self.last_commit_loc = Location::new(batch.total_size - 1);

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
        merkle::hasher::Standard,
        qmdb::verify_proof,
        Persistable,
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{deterministic, Metrics};
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
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
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);

        let mut db = reopen(context.with_label("db2")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, 1);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Test calling commit on an empty db which should make it (durably) non-empty.
        let metadata = V::Value::make(99);
        let finalized = db.new_batch().merkleize(Some(metadata.clone())).finalize();
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.bounds().await.end, 2); // 2 commit ops
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
        assert_eq!(
            db.get(Location::new(1)).await.unwrap(),
            Some(metadata.clone())
        ); // the commit op
        let root = db.root();

        // Commit op should remain after reopen even without clean shutdown.
        let db = reopen(context.with_label("db3")).await;
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        // Build a db with 2 values and make sure we can get them back.
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);

        let finalized = {
            let batch = db.new_batch();
            let loc1 = batch.size();
            let batch = batch.append(v1.clone());
            let loc2 = batch.size();
            let batch = batch.append(v2.clone());
            assert_eq!(loc1, Location::new(1));
            assert_eq!(loc2, Location::new(2));
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Make sure closing/reopening gets us back to the same state.
        assert_eq!(db.bounds().await.end, 4); // 2 appends, 1 commit + 1 initial commit
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(Location::new(3)).await.unwrap(), None); // the commit op
        let root = db.root();
        db.sync().await.unwrap();
        drop(db);

        let db = reopen(context.with_label("db2")).await;
        assert_eq!(db.bounds().await.end, 4);
        assert_eq!(db.root(), root);
        assert_eq!(db.get(Location::new(1)).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(Location::new(2)).await.unwrap().unwrap(), v2);

        // Make sure commit operation remains after drop/reopen.
        drop(db);
        let db = reopen(context.with_label("db3")).await;
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let root = db.root();
        const ELEMENTS: u64 = 100;

        // Create uncommitted appends then simulate failure.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        // Should rollback to the previous root.
        let mut db = reopen(context.with_label("db2")).await;
        assert_eq!(root, db.root());

        // Apply the updates and commit them this time.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 100));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();

        // Create uncommitted appends then simulate failure.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 200));
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        // Should rollback to the previous root.
        let mut db = reopen(context.with_label("db3")).await;
        assert_eq!(root, db.root());

        // Apply the updates and commit them this time.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 300));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();

        // Make sure we can reopen and get back to the same state.
        drop(db);
        let db = reopen(context.with_label("db4")).await;
        assert_eq!(db.bounds().await.end, 2 * ELEMENTS + 3);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_proof<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = Standard::<Sha256>::new();
        const ELEMENTS: u64 = 50;

        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        let root = db.root();

        let (proof, ops) = db.proof(Location::new(0), NZU64!(100)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root));
        assert_eq!(ops.len() as u64, 1 + ELEMENTS + 1);

        let (proof, ops) = db.proof(Location::new(10), NZU64!(5)).await.unwrap();
        assert!(verify_proof(
            &hasher,
            &proof,
            Location::new(10),
            &ops,
            &root
        ));
        assert_eq!(ops.len(), 5);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_metadata<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let metadata = V::Value::make(99);
        let finalized = db
            .new_batch()
            .append(V::Value::make(1))
            .merkleize(Some(metadata.clone()))
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        let finalized = db.new_batch().merkleize(None).finalize();
        db.apply_batch(finalized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_pruning<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        // Test pruning empty database (no appends beyond initial commit).
        let result = db.prune(Location::new(1)).await;
        assert!(
            matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                if prune_loc == Location::new(1) && commit_loc == Location::new(0))
        );

        // Add values and commit.
        let finalized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();

        // op_count is 4 (initial_commit, v1, v2, commit), last_commit_loc is 3.
        let last_commit = db.last_commit_loc();
        assert_eq!(last_commit, Location::new(3));

        let finalized = db
            .new_batch()
            .append(V::Value::make(3))
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();

        // Test valid prune (at previous commit location 3).
        let root = db.root();
        assert!(db.prune(Location::new(3)).await.is_ok());
        assert_eq!(db.root(), root);

        // Test pruning beyond last commit.
        let new_last_commit = db.last_commit_loc();
        let beyond = Location::new(*new_last_commit + 1);
        let result = db.prune(beyond).await;
        assert!(
            matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                if prune_loc == beyond && commit_loc == new_last_commit)
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_empty_db_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let root = db.root();
        const ELEMENTS: u64 = 200;

        // Reopen DB without clean shutdown and make sure the state is the same.
        let db = reopen(context.with_label("db2")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // Simulate failure after inserting operations without a commit.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let db = reopen(context.with_label("db3")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // Repeat: simulate failure after inserting operations without a commit.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 500));
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let db = reopen(context.with_label("db4")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // One last check: multiple batches of uncommitted appends.
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS * 3 {
                batch = batch.append(V::Value::make(i + 1000));
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let mut db = reopen(context.with_label("db5")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), Location::new(0));

        // Apply the ops one last time but fully commit them this time, then clean up.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 2000));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let db = reopen(context.with_label("db6")).await;
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        // Add some initial operations and commit.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..10u64 {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let committed_root = db.root();
        let committed_size = db.bounds().await.end;

        // Add exactly one more append (uncommitted).
        {
            db.new_batch().append(V::Value::make(99));
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);

        // Reopen and verify correct recovery.
        let mut db = reopen(context.with_label("db2")).await;
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
        let finalized = {
            let batch = db.new_batch();
            let loc = batch.size();
            let batch = batch.append(new_value.clone());
            assert_eq!(
                loc, committed_size,
                "New append should get the expected location"
            );
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
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
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);

        // Reopen and verify correct recovery.
        let db = reopen(context.with_label("db3")).await;
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

    pub(crate) async fn test_keyless_batch_chained<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let v1 = V::Value::make(10);
        let v2 = V::Value::make(20);
        let v3 = V::Value::make(30);

        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);

        let child = parent_m.new_batch::<Sha256>();
        let loc2 = child.size();
        let child = child.append(v2.clone());
        let loc3 = child.size();
        let child = child.append(v3.clone());
        let child_m = child.merkleize(None);
        let child_root = child_m.root();

        db.apply_batch(child_m.finalize()).await.unwrap();
        db.commit().await.unwrap();

        assert_eq!(db.root(), child_root);
        assert_eq!(db.get(loc1).await.unwrap(), Some(v1));
        assert_eq!(db.get(loc2).await.unwrap(), Some(v2));
        assert_eq!(db.get(loc3).await.unwrap(), Some(v3));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_changeset<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let changeset_a = db
            .new_batch()
            .append(V::Value::make(10))
            .merkleize(None)
            .finalize();
        let changeset_b = db
            .new_batch()
            .append(V::Value::make(20))
            .merkleize(None)
            .finalize();

        db.apply_batch(changeset_a).await.unwrap();

        let result = db.apply_batch(changeset_b).await;
        assert!(matches!(result, Err(Error::StaleChangeset { .. })));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_to_batch<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let batch = db.new_batch();
        let loc1 = batch.size();
        let batch = batch.append(V::Value::make(10));
        db.apply_batch(batch.merkleize(None).finalize())
            .await
            .unwrap();

        let snapshot = db.to_batch();
        assert_eq!(snapshot.root(), db.root());

        let child_batch = snapshot.new_batch::<Sha256>();
        let loc2 = child_batch.size();
        let child_batch = child_batch.append(V::Value::make(20));
        db.apply_batch(child_batch.merkleize(None).finalize())
            .await
            .unwrap();

        assert_eq!(db.get(loc1).await.unwrap(), Some(V::Value::make(10)));
        assert_eq!(db.get(loc2).await.unwrap(), Some(V::Value::make(20)));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_finalize_from<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let parent = db.new_batch();
        let parent_loc = parent.size();
        let parent = parent.append(V::Value::make(1));
        let parent_m = parent.merkleize(None);

        let child = parent_m.new_batch::<Sha256>();
        let child_loc = child.size();
        let child = child.append(V::Value::make(2));
        let child_m = child.merkleize(None);

        db.apply_batch(parent_m.finalize()).await.unwrap();
        let current_db_size = *db.last_commit_loc() + 1;

        db.apply_batch(child_m.finalize_from(current_db_size))
            .await
            .unwrap();

        assert_eq!(db.get(parent_loc).await.unwrap(), Some(V::Value::make(1)));
        assert_eq!(db.get(child_loc).await.unwrap(), Some(V::Value::make(2)));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_non_empty_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        // Append many values then commit.
        const ELEMENTS: u64 = 200;
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();
        let op_count = db.bounds().await.end;

        // Reopen DB without clean shutdown and make sure the state is the same.
        let db = reopen(context.with_label("db2")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), op_count - 1);
        drop(db);

        // Insert many operations without commit, then simulate failure.
        let db = reopen(context.with_label("recovery_a")).await;
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 1000));
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let db = reopen(context.with_label("recovery_b")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        drop(db);

        // Repeat after pruning to the last commit.
        let mut db = reopen(context.with_label("db3")).await;
        db.prune(db.last_commit_loc()).await.unwrap();
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        db.sync().await.unwrap();
        drop(db);

        let db = reopen(context.with_label("recovery_c")).await;
        {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 2000));
            }
        }
        drop(db);
        let db = reopen(context.with_label("recovery_d")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        drop(db);

        // Apply the ops one last time but fully commit them this time, then clean up.
        let mut db = reopen(context.with_label("db4")).await;
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..ELEMENTS {
                batch = batch.append(V::Value::make(i + 3000));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let db = reopen(context.with_label("db5")).await;
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = Standard::<Sha256>::new();

        // Build a db with some values.
        const ELEMENTS: u64 = 100;
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

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
                verify_proof(&hasher, &proof, Location::new(start_loc), &ops, &root),
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
                &wrong_root
            ));
            if start_loc > 0 {
                assert!(!verify_proof(
                    &hasher,
                    &proof,
                    Location::new(start_loc - 1),
                    &ops,
                    &root
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = Standard::<Sha256>::new();

        const ELEMENTS: u64 = 100;
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        let finalized = {
            let mut batch = db.new_batch();
            for i in ELEMENTS..ELEMENTS * 2 {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
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
            assert!(verify_proof(&hasher, &proof, start_loc, &ops, &root));
        }

        let aggressive_prune: Location<F> = Location::new(150);
        db.prune(aggressive_prune).await.unwrap();

        let new_oldest = db.bounds().await.start;
        let (proof, ops) = db.proof(new_oldest, NZU64!(20)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, new_oldest, &ops, &root));

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
                &root
            ));
        }

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_db_get_out_of_bounds<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        assert!(db.get(Location::new(0)).await.unwrap().is_none());

        let finalized = db
            .new_batch()
            .append(V::Value::make(1))
            .append(V::Value::make(2))
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();

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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let base_vals: Vec<V::Value> = (0..3).map(|i| V::Value::make(10 + i)).collect();
        let mut base_locs = Vec::new();
        let finalized = {
            let mut batch = db.new_batch();
            for v in &base_vals {
                let loc = batch.size();
                batch = batch.append(v.clone());
                base_locs.push(loc);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);

        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);

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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let merkleized = {
            let mut batch = db.new_batch();
            for i in 0u64..10 {
                batch = batch.append(V::Value::make(i));
            }
            batch.merkleize(None)
        };
        let speculative = merkleized.root();
        db.apply_batch(merkleized.finalize()).await.unwrap();
        assert_eq!(db.root(), speculative);

        let merkleized = db
            .new_batch()
            .append(V::Value::make(100))
            .merkleize(Some(V::Value::make(55)));
        let speculative = merkleized.root();
        db.apply_batch(merkleized.finalize()).await.unwrap();
        assert_eq!(db.root(), speculative);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_merkleized_batch_get<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let base_val = V::Value::make(10);
        let finalized = db
            .new_batch()
            .append(base_val.clone())
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();

        let new_val = V::Value::make(20);
        let merkleized = db.new_batch().append(new_val.clone()).merkleize(None);

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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let v1 = V::Value::make(1);
        let v2 = V::Value::make(2);

        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);
        let parent_root = parent_m.root();

        db.apply_batch(parent_m.finalize()).await.unwrap();
        assert_eq!(db.root(), parent_root);
        assert_eq!(db.get(loc1).await.unwrap(), Some(v1));

        let batch2 = db.new_batch();
        let loc2 = batch2.size();
        let batch2 = batch2.append(v2.clone());
        let batch2_m = batch2.merkleize(None);
        let batch2_root = batch2_m.root();
        db.apply_batch(batch2_m.finalize()).await.unwrap();
        assert_eq!(db.root(), batch2_root);
        assert_eq!(db.get(loc2).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_many_sequential<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = Standard::<Sha256>::new();

        const BATCHES: u64 = 20;
        const APPENDS_PER_BATCH: u64 = 5;
        let mut all_values: Vec<V::Value> = Vec::new();
        let mut all_locs: Vec<Location<F>> = Vec::new();

        for batch_idx in 0..BATCHES {
            let finalized = {
                let mut batch = db.new_batch();
                for j in 0..APPENDS_PER_BATCH {
                    let v = V::Value::make(batch_idx * 10 + j);
                    let loc = batch.size();
                    batch = batch.append(v.clone());
                    all_values.push(v);
                    all_locs.push(loc);
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
        }

        for (i, loc) in all_locs.iter().enumerate() {
            assert_eq!(db.get(*loc).await.unwrap(), Some(all_values[i].clone()));
        }

        let root = db.root();
        let (proof, ops) = db.proof(Location::new(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root));
        assert_eq!(db.bounds().await.end, 1 + BATCHES * (APPENDS_PER_BATCH + 1));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_empty<F: Family, V, C, H>(
        mut db: Keyless<F, deterministic::Context, V, C, H>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let finalized = db
            .new_batch()
            .append(V::Value::make(1))
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        let root_before = db.root();
        let size_before = db.bounds().await.end;

        let merkleized = db.new_batch().merkleize(None);
        let speculative = merkleized.root();
        db.apply_batch(merkleized.finalize()).await.unwrap();

        assert_ne!(db.root(), root_before);
        assert_eq!(db.root(), speculative);
        assert_eq!(db.bounds().await.end, size_before + 1);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_batch_chained_merkleized_get<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let base_val = V::Value::make(10);
        db.apply_batch(
            db.new_batch()
                .append(base_val.clone())
                .merkleize(None)
                .finalize(),
        )
        .await
        .unwrap();

        let v1 = V::Value::make(1);
        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent_m = parent.append(v1.clone()).merkleize(None);

        let v2 = V::Value::make(2);
        let child = parent_m.new_batch::<Sha256>();
        let loc2 = child.size();
        let child_m = child.append(v2.clone()).merkleize(None);

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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared + std::fmt::Debug,
    {
        let hasher = Standard::<Sha256>::new();
        const N: u64 = 500;
        let mut values = Vec::new();
        let mut locs = Vec::new();

        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..N {
                let v = V::Value::make(i);
                locs.push(batch.size());
                batch = batch.append(v.clone());
                values.push(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        for (i, loc) in locs.iter().enumerate() {
            assert_eq!(db.get(*loc).await.unwrap(), Some(values[i].clone()));
        }

        let root = db.root();
        let (proof, ops) = db.proof(Location::new(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root));
        assert_eq!(db.bounds().await.end, 1 + N + 1);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_changeset_chained<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(None);
        let child_a = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(None)
            .finalize();
        let child_b = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(3))
            .merkleize(None)
            .finalize();

        db.apply_batch(child_a).await.unwrap();
        assert!(matches!(
            db.apply_batch(child_b).await,
            Err(Error::StaleChangeset { .. })
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_changeset_parent_before_child<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(None);
        let child_changeset = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(None)
            .finalize();
        db.apply_batch(parent.finalize()).await.unwrap();

        assert!(matches!(
            db.apply_batch(child_changeset).await,
            Err(Error::StaleChangeset { .. })
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_stale_changeset_child_before_parent<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(None);
        let child_changeset = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(None)
            .finalize();
        let parent_changeset = parent.finalize();

        db.apply_batch(child_changeset).await.unwrap();
        assert!(matches!(
            db.apply_batch(parent_changeset).await,
            Err(Error::StaleChangeset { .. })
        ));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_keyless_child_root_matches_pending_and_committed<F: Family, V, C>(
        mut db: Keyless<F, deterministic::Context, V, C, Sha256>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        Operation<V>: EncodeShared,
    {
        // Build the child while the parent is still pending.
        let parent = db.new_batch().append(V::Value::make(1)).merkleize(None);
        let pending_child = parent
            .new_batch::<Sha256>()
            .append(V::Value::make(2))
            .merkleize(None);

        // Commit the parent, then rebuild the same logical child from the
        // committed DB state and compare roots.
        db.apply_batch(parent.finalize()).await.unwrap();
        db.commit().await.unwrap();

        let committed_child = db.new_batch().append(V::Value::make(2)).merkleize(None);

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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
    {
        let mut batch = db.new_batch();
        for value in values {
            batch = batch.append(value);
        }
        let finalized = batch.merkleize(metadata).finalize();
        let range = db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        range
    }

    pub(crate) async fn test_keyless_db_rewind_recovery<F: Family, V, C, H>(
        context: deterministic::Context,
        mut db: Keyless<F, deterministic::Context, V, C, H>,
        reopen: Reopen<Keyless<F, deterministic::Context, V, C, H>>,
    ) where
        V: ValueEncoding<Value: TestValue>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
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
        let mut db = reopen(context.with_label("reopen")).await;
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
        let db = reopen(context.with_label("reopen_initial_boundary")).await;
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
        H: Hasher,
        Operation<V>: EncodeShared,
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
}
