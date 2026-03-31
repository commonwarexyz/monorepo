//! The [Keyless] qmdb allows for append-only storage of arbitrary variable-length data that can
//! later be retrieved by its location.
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
        contiguous::{
            variable::{Config as JournalConfig, Journal as ContiguousJournal},
            Contiguous, Mutable, Reader,
        },
    },
    merkle::{journaled::Config as MerkleConfig, Family, Location, Proof},
    qmdb::{any::VariableValue, operation::Committable, Error},
    Context,
};
use commonware_cryptography::Hasher;
use std::num::NonZeroU64;
use tracing::{debug, warn};

pub mod batch;
mod operation;
pub use operation::Operation;

/// Configuration for a [Keyless] authenticated db.
#[derive(Clone)]
pub struct Config<C> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle: MerkleConfig,

    /// Configuration for the variable-size operations log journal.
    pub log: JournalConfig<C>,
}

/// A keyless QMDB for variable length data.
type Journal<F, E, V, H> = authenticated::Journal<F, E, ContiguousJournal<E, Operation<V>>, H>;

/// A keyless authenticated database for variable-length data.
pub struct Keyless<F: Family, E: Context, V: VariableValue, H: Hasher> {
    /// Authenticated journal of operations.
    journal: Journal<F, E, V, H>,

    /// The location of the last commit, if any.
    last_commit_loc: Location<F>,
}

impl<F: Family, E: Context, V: VariableValue, H: Hasher> Keyless<F, E, V, H> {
    /// Get the value at location `loc` in the database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOutOfBounds`] if `loc` >=
    /// `self.bounds().await.end`.
    pub async fn get(&self, loc: Location<F>) -> Result<Option<V>, Error<F>> {
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
    pub async fn get_metadata(&self) -> Result<Option<V>, Error<F>> {
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

    /// Returns a [Keyless] qmdb initialized from `cfg`. Any uncommitted operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error<F>> {
        let mut journal = Journal::new(context, cfg.merkle, cfg.log, Operation::is_commit).await?;
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
    /// - Returns [`Error::Merkle`] if `op_count` or `start_loc` >
    ///   [Family::MAX_LEAVES].
    /// - Returns [`Error::Merkle`] if `start_loc` >= `op_count` or
    ///   `op_count` > number of operations.
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
    /// - Returns [`Error::PruneBeyondMinRequired`] if `loc`
    ///   > last commit point.
    /// - Returns [`Error::Merkle`] if `loc` > [Family::MAX_LEAVES].
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
    /// Returns an error when:
    /// - `size` is not a valid rewind target
    /// - the target's required logical range is not fully retained (for keyless, this means the
    ///   oldest retained location is already beyond the rewind boundary)
    /// - `size - 1` is not a commit operation
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
mod test {
    use super::*;
    use crate::{
        merkle::{hasher::Standard, mmb, mmr},
        qmdb::verify_proof,
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::Rng;
    use std::num::{NonZeroU16, NonZeroUsize};

    // Use some weird sizes here to test boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn db_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> Config<(commonware_codec::RangeCfg<usize>, ())> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            merkle: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: JournalConfig {
                partition: format!("log-journal-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((0..=10000).into(), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    type Db<F> = Keyless<F, deterministic::Context, Vec<u8>, Sha256>;

    fn loc<F: Family>(n: u64) -> Location<F> {
        Location::new(n)
    }

    /// Return a [Keyless] database initialized with a fixed config.
    async fn open_db<F: Family>(context: deterministic::Context) -> Db<F> {
        let cfg = db_config("partition", &context);
        Db::init(context, cfg).await.unwrap()
    }

    async fn commit_appends<F: Family>(
        db: &mut Db<F>,
        values: impl IntoIterator<Item = Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> core::ops::Range<Location<F>> {
        let mut batch = db.new_batch();
        for value in values {
            batch = batch.append(value);
        }
        let finalized = batch.merkleize(metadata).finalize();
        let range = db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        range
    }

    // Helper function to generate random values for batch appends.
    fn generate_values<T: Rng>(rng: &mut T, num_elements: usize) -> Vec<Vec<u8>> {
        (0..num_elements)
            .map(|_| vec![(rng.next_u32() % 255) as u8, (rng.next_u32() % 255) as u8])
            .collect()
    }

    async fn test_keyless_db_empty_inner<F: Family>(context: deterministic::Context) {
        let db: Db<F> = open_db::<F>(context.with_label("db1")).await;
        let bounds = db.bounds().await;
        assert_eq!(bounds.end, 1); // initial commit should exist
        assert_eq!(bounds.start, loc::<F>(0));

        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.last_commit_loc(), loc::<F>(0));

        // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
        let v1 = vec![1u8; 8];
        let root = db.root();
        {
            db.new_batch().append(v1);
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let mut db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, 1);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Test calling commit on an empty db which should make it (durably) non-empty.
        let metadata = vec![3u8; 10];
        let finalized = db.new_batch().merkleize(Some(metadata.clone())).finalize();
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.bounds().await.end, 2); // 2 commit ops
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
        assert_eq!(db.get(loc::<F>(1)).await.unwrap(), Some(metadata.clone())); // the commit op
        let root = db.root();

        // Commit op should remain after reopen even without clean shutdown.
        let db: Db<F> = open_db::<F>(context.with_label("db3")).await;
        assert_eq!(db.bounds().await.end, 2); // commit op should remain after re-open.
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), loc::<F>(1));

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_empty_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_empty_inner::<mmb::Family>);
    }

    async fn test_keyless_db_build_basic_inner<F: Family>(context: deterministic::Context) {
        // Build a db with 2 values and make sure we can get them back.
        let mut db: Db<F> = open_db::<F>(context.with_label("db1")).await;

        let v1 = vec![1u8; 8];
        let v2 = vec![2u8; 20];

        let finalized = {
            let batch = db.new_batch();
            let loc1 = batch.size();
            let batch = batch.append(v1.clone());
            let loc2 = batch.size();
            let batch = batch.append(v2.clone());
            assert_eq!(loc1, loc::<F>(1));
            assert_eq!(loc2, loc::<F>(2));
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        let loc1 = loc::<F>(1);
        let loc2 = loc::<F>(2);

        // Make sure closing/reopening gets us back to the same state.
        assert_eq!(db.bounds().await.end, 4); // 2 appends, 1 commit + 1 initial commit
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(loc::<F>(3)).await.unwrap(), None); // the commit op
        let root = db.root();
        db.sync().await.unwrap();
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(db.bounds().await.end, 4);
        assert_eq!(db.root(), root);

        assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

        {
            let batch = db.new_batch().append(v2);
            batch.append(v1);
            // Don't merkleize/finalize/apply -- simulate failed commit
        }

        // Make sure uncommitted items get rolled back.
        drop(db); // Simulate failed commit
        let db: Db<F> = open_db::<F>(context.with_label("db3")).await;
        assert_eq!(db.bounds().await.end, 4);
        assert_eq!(db.root(), root);

        // Make sure commit operation remains after drop/reopen.
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("db4")).await;
        assert_eq!(db.bounds().await.end, 4);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_build_basic_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_build_basic_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_build_basic_inner::<mmb::Family>);
    }

    async fn test_keyless_db_recovery_inner<F: Family>(mut context: deterministic::Context) {
        const ELEMENTS: usize = 1000;
        let db: Db<F> = open_db::<F>(context.with_label("db1")).await;
        let root = db.root();

        // Create uncommitted appends then simulate failure.
        {
            let mut batch = db.new_batch();
            for value in generate_values(&mut context, ELEMENTS) {
                batch = batch.append(value);
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        // Should rollback to the previous root.
        let mut db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(root, db.root());

        // Apply the updates and commit them this time.
        let finalized = {
            let mut batch = db.new_batch();
            for value in generate_values(&mut context, ELEMENTS) {
                batch = batch.append(value);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();

        // Create uncommitted appends then simulate failure.
        {
            let mut batch = db.new_batch();
            for value in generate_values(&mut context, ELEMENTS) {
                batch = batch.append(value);
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        // Should rollback to the previous root.
        let mut db: Db<F> = open_db::<F>(context.with_label("db3")).await;
        assert_eq!(root, db.root());

        // Apply the updates and commit them this time.
        let finalized = {
            let mut batch = db.new_batch();
            for value in generate_values(&mut context, ELEMENTS) {
                batch = batch.append(value);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();

        // Make sure we can reopen and get back to the same state.
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("db4")).await;
        assert_eq!(db.bounds().await.end, 2 * ELEMENTS as u64 + 3);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_recovery_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_recovery_inner::<mmb::Family>);
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// last committed state on re-open.
    async fn test_keyless_db_non_empty_db_recovery_inner<F: Family>(
        mut context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db1")).await;

        // Append many values then commit.
        const ELEMENTS: usize = 200;
        let finalized = {
            let mut batch = db.new_batch();
            for value in generate_values(&mut context, ELEMENTS) {
                batch = batch.append(value);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();
        let op_count = db.bounds().await.end;

        // Reopen DB without clean shutdown and make sure the state is the same.
        let db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), op_count - 1);
        drop(db);

        // Insert many operations without commit, then simulate failure.
        async fn recover_from_failure<F: Family>(
            mut context: deterministic::Context,
            label1: &str,
            label2: &str,
            root: <Sha256 as Hasher>::Digest,
            op_count: Location<F>,
        ) {
            let db: Db<F> = open_db::<F>(context.with_label(label1)).await;

            // Create uncommitted appends and simulate failure.
            {
                let mut batch = db.new_batch();
                for value in generate_values(&mut context, ELEMENTS) {
                    batch = batch.append(value);
                }
                // Don't merkleize/finalize/apply -- simulate failed commit
            }
            drop(db);
            let db: Db<F> = open_db::<F>(context.with_label(label2)).await;
            assert_eq!(db.bounds().await.end, op_count);
            assert_eq!(db.root(), root);
        }

        recover_from_failure::<F>(context.with_label("recovery1"), "a", "b", root, op_count).await;

        // Repeat recover_from_failure tests after successfully pruning to the last commit.
        let mut db: Db<F> = open_db::<F>(context.with_label("db3")).await;
        db.prune(db.last_commit_loc()).await.unwrap();
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        db.sync().await.unwrap();
        drop(db);

        recover_from_failure::<F>(context.with_label("recovery2"), "c", "d", root, op_count).await;

        // Apply the ops one last time but fully commit them this time, then clean up.
        let mut db: Db<F> = open_db::<F>(context.with_label("db4")).await;
        let finalized = {
            let mut batch = db.new_batch();
            for value in generate_values(&mut context, ELEMENTS) {
                batch = batch.append(value);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let db: Db<F> = open_db::<F>(context.with_label("db5")).await;
        let bounds = db.bounds().await;
        assert!(bounds.end > op_count);
        assert_ne!(db.root(), root);
        assert_eq!(db.last_commit_loc(), bounds.end - 1);

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_non_empty_db_recovery_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_db_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_non_empty_db_recovery_inner::<mmb::Family>);
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    async fn test_keyless_db_empty_db_recovery_inner<F: Family>(context: deterministic::Context) {
        let db: Db<F> = open_db::<F>(context.with_label("db1")).await;
        let root = db.root();

        // Reopen DB without clean shutdown and make sure the state is the same.
        let db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        fn build_values() -> Vec<Vec<u8>> {
            const ELEMENTS: u64 = 1000;
            (0..ELEMENTS)
                .map(|i| vec![(i % 255) as u8; ((i % 17) + 13) as usize])
                .collect()
        }

        // Simulate failure after inserting operations without a commit.
        {
            let mut batch = db.new_batch();
            for v in build_values() {
                batch = batch.append(v);
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("db3")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // Repeat: simulate failure after inserting operations without a commit.
        {
            let mut batch = db.new_batch();
            for v in build_values() {
                batch = batch.append(v);
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("db4")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);

        // One last check that re-open without proper shutdown still recovers the correct state.
        {
            let mut batch = db.new_batch();
            for v in build_values() {
                batch = batch.append(v);
            }
            for v in build_values() {
                batch = batch.append(v);
            }
            for v in build_values() {
                batch = batch.append(v);
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }
        drop(db);
        let mut db: Db<F> = open_db::<F>(context.with_label("db5")).await;
        assert_eq!(db.bounds().await.end, 1); // initial commit should exist
        assert_eq!(db.root(), root);
        assert_eq!(db.last_commit_loc(), loc::<F>(0));

        // Apply the ops one last time but fully commit them this time, then clean up.
        let finalized = {
            let mut batch = db.new_batch();
            for v in build_values() {
                batch = batch.append(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let db: Db<F> = open_db::<F>(context.with_label("db6")).await;
        assert!(db.bounds().await.end > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_empty_db_recovery_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_empty_db_recovery_inner::<mmb::Family>);
    }

    async fn test_keyless_db_proof_generation_and_verification_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut db: Db<F> = open_db::<F>(context.clone()).await;

        // Build a db with some values
        const ELEMENTS: u64 = 100;
        let mut values = Vec::new();
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                batch = batch.append(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Test that historical proof fails with op_count > number of operations
        assert!(matches!(
            db.historical_proof(db.bounds().await.end + 1, loc::<F>(5), NZU64!(10))
                .await,
            Err(Error::<F>::Merkle(crate::merkle::Error::RangeOutOfBounds(
                _
            )))
        ));

        let root = db.root();

        // Test proof generation for various ranges
        let test_cases = vec![
            (0, 10),           // First 10 operations
            (10, 5),           // Middle range
            (50, 20),          // Larger range
            (90, 15),          // Range that extends beyond end (should be limited)
            (0, 1),            // Single operation
            (ELEMENTS - 1, 1), // Last append operation
            (ELEMENTS, 1),     // The commit operation
        ];

        for (start_loc, max_ops) in test_cases {
            let (proof, ops) = db
                .proof(loc::<F>(start_loc), NZU64!(max_ops))
                .await
                .unwrap();

            // Verify the proof
            assert!(
                verify_proof(&hasher, &proof, loc::<F>(start_loc), &ops, &root),
                "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops",
            );

            // Check that we got the expected number of operations
            let expected_ops = std::cmp::min(max_ops, *db.bounds().await.end - start_loc);
            assert_eq!(
                ops.len() as u64,
                expected_ops,
                "Expected {expected_ops} operations, got {}",
                ops.len(),
            );

            // Verify operation types
            for (i, op) in ops.iter().enumerate() {
                let loc = start_loc + i as u64;
                if loc == 0 {
                    assert!(
                        matches!(op, Operation::Commit(None)),
                        "Expected Initial Commit operation at location {loc}, got {op:?}",
                    );
                } else if loc <= ELEMENTS {
                    // Should be an Append operation
                    assert!(
                        matches!(op, Operation::Append(_)),
                        "Expected Append operation at location {loc}, got {op:?}",
                    );
                } else if loc == ELEMENTS + 1 {
                    // Should be a Commit operation
                    assert!(
                        matches!(op, Operation::Commit(_)),
                        "Expected Commit operation at location {loc}, got {op:?}",
                    );
                }
            }

            // Verify that proof fails with wrong root
            let wrong_root = Sha256::hash(&[0xFF; 32]);
            assert!(
                !verify_proof(&hasher, &proof, loc::<F>(start_loc), &ops, &wrong_root),
                "Proof should fail with wrong root"
            );

            // Verify that proof fails with wrong start location
            if start_loc > 0 {
                assert!(
                    !verify_proof(&hasher, &proof, loc::<F>(start_loc - 1), &ops, &root),
                    "Proof should fail with wrong start location"
                );
            }
        }

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_generation_and_verification() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_proof_generation_and_verification_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_generation_and_verification_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_proof_generation_and_verification_inner::<mmb::Family>);
    }

    async fn test_keyless_db_proof_with_pruning_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();
        let mut db: Db<F> = open_db::<F>(context.with_label("db1")).await;

        // Build a db with some values
        const ELEMENTS: u64 = 100;
        let mut values = Vec::new();
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                batch = batch.append(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Add more elements and commit again
        let finalized = {
            let mut batch = db.new_batch();
            for i in ELEMENTS..ELEMENTS * 2 {
                let v = vec![(i % 255) as u8; ((i % 17) + 5) as usize];
                values.push(v.clone());
                batch = batch.append(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        let root = db.root();

        // Prune the first 30 operations
        const PRUNE_LOC: u64 = 30;
        db.prune(loc::<F>(PRUNE_LOC)).await.unwrap();

        // Verify pruning worked
        let oldest_retained = db.bounds().await.start;

        // Root should remain the same after pruning
        assert_eq!(db.root(), root, "Root should not change after pruning");

        db.sync().await.unwrap();
        drop(db);
        let mut db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(db.root(), root);
        let bounds = db.bounds().await;
        assert_eq!(bounds.end, 2 * ELEMENTS + 3);
        assert!(bounds.start <= PRUNE_LOC);

        // Test that we can't get pruned values
        for i in 0..*oldest_retained {
            let result = db.get(loc::<F>(i)).await;
            // Should either return None (for commit ops) or encounter pruned data
            match result {
                Ok(None) => {} // Commit operation or pruned
                Ok(Some(_)) => {
                    panic!("Should not be able to get pruned value at location {i}")
                }
                Err(_) => {} // Expected error for pruned data
            }
        }

        // Test proof generation after pruning - should work for non-pruned ranges
        let test_cases = vec![
            (oldest_retained, 10), // Starting from oldest retained
            (loc::<F>(50), 20),    // Middle range (if not pruned)
            (loc::<F>(150), 10),   // Later range
            (loc::<F>(190), 15),   // Near the end
        ];

        for (start_loc, max_ops) in test_cases {
            // Skip if start_loc is before oldest retained
            if start_loc < oldest_retained {
                continue;
            }

            let (proof, ops) = db.proof(start_loc, NZU64!(max_ops)).await.unwrap();

            // Verify the proof still works
            assert!(
                verify_proof(&hasher, &proof, start_loc, &ops, &root),
                "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops after pruning",
            );

            // Check that we got operations
            let expected_ops = std::cmp::min(max_ops, *db.bounds().await.end - *start_loc);
            assert_eq!(
                ops.len() as u64,
                expected_ops,
                "Expected {expected_ops} operations, got {}",
                ops.len(),
            );
        }

        // Test pruning more aggressively
        let aggressive_prune: Location<F> = loc::<F>(150);
        db.prune(aggressive_prune).await.unwrap();

        let new_oldest = db.bounds().await.start;
        assert!(new_oldest <= aggressive_prune);

        // Can still generate proofs for the remaining data
        let (proof, ops) = db.proof(new_oldest, NZU64!(20)).await.unwrap();
        assert!(
            verify_proof(&hasher, &proof, new_oldest, &ops, &root),
            "Proof should still verify after aggressive pruning"
        );

        // Test edge case: prune everything except the last few operations
        let almost_all = db.bounds().await.end - 5;
        db.prune(almost_all).await.unwrap();

        let bounds = db.bounds().await;
        let final_oldest = bounds.start;

        // Should still be able to prove the remaining operations
        if final_oldest < bounds.end {
            let (final_proof, final_ops) = db.proof(final_oldest, NZU64!(10)).await.unwrap();
            assert!(
                verify_proof(&hasher, &final_proof, final_oldest, &final_ops, &root),
                "Should be able to prove remaining operations after extensive pruning"
            );
        }

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_proof_with_pruning_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_with_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_proof_with_pruning_inner::<mmb::Family>);
    }

    async fn test_keyless_db_replay_with_trailing_appends_inner<F: Family>(
        context: deterministic::Context,
    ) {
        // Create initial database with committed data
        let mut db: Db<F> = open_db::<F>(context.with_label("db1")).await;

        // Add some initial operations and commit
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..10 {
                let v = vec![i as u8; 10];
                batch = batch.append(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let committed_root = db.root();
        let committed_size = db.bounds().await.end;

        // Add exactly one more append (uncommitted)
        {
            db.new_batch().append(vec![99u8; 20]);
            // Don't merkleize/finalize/apply -- simulate failed commit
        }

        // Simulate failure without commit
        drop(db);

        // Reopen database
        let mut db: Db<F> = open_db::<F>(context.with_label("db2")).await;

        // Verify correct recovery
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

        // Verify we can append and commit new data without issues
        let new_value = vec![77u8; 15];
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

        // Verify we can read the new value
        assert_eq!(db.get(committed_size).await.unwrap(), Some(new_value));

        let new_committed_root = db.root();
        let new_committed_size = db.bounds().await.end;

        // Add multiple uncommitted appends
        {
            let mut batch = db.new_batch();
            for i in 0..5 {
                let v = vec![(200 + i) as u8; 10];
                batch = batch.append(v);
            }
            // Don't merkleize/finalize/apply -- simulate failed commit
        }

        // Simulate failure without commit
        drop(db);

        // Reopen and verify correct recovery
        let db: Db<F> = open_db::<F>(context.with_label("db3")).await;
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

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_replay_with_trailing_appends_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_replay_with_trailing_appends_inner::<mmb::Family>);
    }

    async fn test_keyless_db_get_out_of_bounds_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.clone()).await;

        // Test getting from empty database
        let result = db.get(loc::<F>(0)).await.unwrap();
        assert!(result.is_none());

        // Add some values
        let v1 = vec![1u8; 8];
        let v2 = vec![2u8; 8];
        let finalized = db
            .new_batch()
            .append(v1.clone())
            .append(v2.clone())
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();

        // Test getting valid locations - should succeed
        assert_eq!(db.get(loc::<F>(1)).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(loc::<F>(2)).await.unwrap().unwrap(), v2);

        // Test getting out of bounds location
        let result = db.get(loc::<F>(3)).await.unwrap();
        assert!(result.is_none());

        // Test getting out of bounds location
        let result = db.get(loc::<F>(4)).await;
        assert!(
            matches!(result, Err(Error::<F>::LocationOutOfBounds(l, size)) if l == loc::<F>(4) && size == loc::<F>(4))
        );
        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_get_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_get_out_of_bounds_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_get_out_of_bounds_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_get_out_of_bounds_inner::<mmb::Family>);
    }

    async fn test_keyless_db_prune_beyond_commit_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.clone()).await;

        // Test pruning empty database (no commits)
        let result = db.prune(loc::<F>(1)).await;
        assert!(
            matches!(result, Err(Error::<F>::PruneBeyondMinRequired(prune_loc, commit_loc))
                if prune_loc == loc::<F>(1) && commit_loc == loc::<F>(0))
        );

        // Add values and commit
        let v1 = vec![1u8; 8];
        let v2 = vec![2u8; 8];
        let v3 = vec![3u8; 8];
        let finalized = db
            .new_batch()
            .append(v1.clone())
            .append(v2.clone())
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();

        // op_count is 4 (initial_commit, v1, v2, commit), last_commit_loc is 3
        let last_commit = db.last_commit_loc();
        assert_eq!(last_commit, loc::<F>(3));

        let finalized = {
            let batch = db.new_batch().append(v3.clone());
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Test valid prune (at previous commit location 3)
        assert!(db.prune(loc::<F>(3)).await.is_ok());

        // Test pruning beyond last commit
        let new_last_commit = db.last_commit_loc();
        let beyond = Location::new(*new_last_commit + 1);
        let result = db.prune(beyond).await;
        assert!(
            matches!(result, Err(Error::<F>::PruneBeyondMinRequired(prune_loc, commit_loc))
                if prune_loc == beyond && commit_loc == new_last_commit)
        );

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_prune_beyond_commit_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_prune_beyond_commit_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_prune_beyond_commit_inner::<mmb::Family>);
    }

    async fn test_keyless_db_rewind_recovery_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;
        let initial_root = db.root();
        let initial_size = db.bounds().await.end;

        let value_a = vec![1u8; 12];
        let value_b = vec![2u8; 16];
        let metadata_a = vec![3u8; 20];
        let first_range = commit_appends::<F>(
            &mut db,
            [value_a.clone(), value_b.clone()],
            Some(metadata_a.clone()),
        )
        .await;

        let root_before = db.root();
        let size_before = db.bounds().await.end;
        let commit_before = db.last_commit_loc();
        assert_eq!(size_before, first_range.end);

        let value_c = vec![4u8; 24];
        let metadata_b = vec![5u8; 8];
        let second_range =
            commit_appends::<F>(&mut db, [value_c.clone()], Some(metadata_b.clone())).await;
        assert_eq!(second_range.start, size_before);
        assert_ne!(db.root(), root_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_b));

        db.rewind(size_before).await.unwrap();
        assert_eq!(db.root(), root_before);
        assert_eq!(db.bounds().await.end, size_before);
        assert_eq!(db.last_commit_loc(), commit_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a.clone()));
        assert_eq!(db.get(loc::<F>(1)).await.unwrap(), Some(value_a));
        assert_eq!(db.get(loc::<F>(2)).await.unwrap(), Some(value_b));
        assert!(
            matches!(
                db.get(loc::<F>(4)).await,
                Err(Error::<F>::LocationOutOfBounds(_, size)) if size == size_before
            ),
            "rewound append should be out of bounds",
        );

        db.commit().await.unwrap();
        drop(db);
        let mut db: Db<F> = open_db::<F>(context.with_label("reopen")).await;
        assert_eq!(db.root(), root_before);
        assert_eq!(db.bounds().await.end, size_before);
        assert_eq!(db.last_commit_loc(), commit_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
        assert_eq!(db.get(loc::<F>(1)).await.unwrap(), Some(vec![1u8; 12]));
        assert_eq!(db.get(loc::<F>(2)).await.unwrap(), Some(vec![2u8; 16]));
        assert!(matches!(
            db.get(loc::<F>(4)).await,
            Err(Error::<F>::LocationOutOfBounds(_, size)) if size == size_before
        ));

        db.rewind(initial_size).await.unwrap();
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.bounds().await.end, initial_size);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(matches!(
            db.get(loc::<F>(1)).await,
            Err(Error::<F>::LocationOutOfBounds(_, size)) if size == initial_size
        ));

        db.commit().await.unwrap();
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("reopen_initial_boundary")).await;
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.bounds().await.end, initial_size);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(matches!(
            db.get(loc::<F>(1)).await,
            Err(Error::<F>::LocationOutOfBounds(_, size)) if size == initial_size
        ));

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_db_rewind_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_rewind_recovery_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_db_rewind_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_rewind_recovery_inner::<mmb::Family>);
    }

    async fn test_keyless_db_rewind_pruned_target_errors_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        let first_range =
            commit_appends::<F>(&mut db, (0..16).map(|i| vec![i as u8; 8]), None).await;

        let mut round = 0u64;
        loop {
            round += 1;
            assert!(
                round <= 64,
                "failed to prune enough history for rewind test"
            );

            commit_appends::<F>(&mut db, (0..16).map(|i| vec![(round + i) as u8; 8]), None).await;
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
                Error::<F>::Journal(crate::journal::Error::ItemPruned(_))
            ),
            "unexpected rewind error at retained boundary: {boundary_err:?}"
        );

        let err = db.rewind(first_range.start).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::<F>::Journal(crate::journal::Error::ItemPruned(_))
            ),
            "unexpected rewind error: {err:?}"
        );

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_db_rewind_pruned_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_rewind_pruned_target_errors_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_db_rewind_pruned_target_errors_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_db_rewind_pruned_target_errors_inner::<mmb::Family>);
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_db_futures_are_send<F: Family>(db: &mut Db<F>, loc: Location<F>) {
        is_send(db.get_metadata());
        is_send(db.proof(loc, NZU64!(1)));
        is_send(db.sync());
        is_send(db.get(loc));
        is_send(db.rewind(loc));
    }

    /// batch.get() reads pending appends and falls through to base DB.
    async fn test_keyless_batch_get_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Pre-populate with 3 values.
        let base_vals: Vec<Vec<u8>> = (0..3).map(|i| vec![(10 + i) as u8; 12]).collect();
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

        // Second batch: read base DB values through the batch.
        let batch = db.new_batch();
        for (i, loc) in base_locs.iter().enumerate() {
            assert_eq!(
                batch.get(*loc, &db).await.unwrap(),
                Some(base_vals[i].clone()),
                "base DB value at loc {loc} mismatch"
            );
        }

        // Pending append is visible.
        let new_val = vec![99u8; 16];
        let new_loc = batch.size();
        let batch = batch.append(new_val.clone());
        assert_eq!(batch.get(new_loc, &db).await.unwrap(), Some(new_val));

        // Location past the end returns None.
        let beyond = Location::new(*new_loc + 1);
        assert_eq!(batch.get(beyond, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_get() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_get_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_get_inner::<mmb::Family>);
    }

    /// Child batch reads parent chain values and its own appends.
    async fn test_keyless_batch_stacked_get_inner<F: Family>(context: deterministic::Context) {
        let db: Db<F> = open_db::<F>(context.with_label("db")).await;

        let v1 = vec![1u8; 8];
        let v2 = vec![2u8; 16];

        // Parent batch appends v1.
        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);

        // Child reads v1 from parent chain.
        let child = parent_m.new_batch::<Sha256>();
        assert_eq!(child.get(loc1, &db).await.unwrap(), Some(v1));

        // Child appends v2.
        let loc2 = child.size();
        let child = child.append(v2.clone());
        assert_eq!(child.get(loc2, &db).await.unwrap(), Some(v2));

        // Nonexistent location.
        let nonexistent = loc::<F>(9999);
        assert_eq!(child.get(nonexistent, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_stacked_get_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_stacked_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_stacked_get_inner::<mmb::Family>);
    }

    /// Metadata propagates through merkleize and clears with None.
    async fn test_keyless_batch_metadata_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Batch with metadata.
        let metadata = vec![42u8; 32];
        let finalized = db
            .new_batch()
            .append(vec![1u8; 8])
            .merkleize(Some(metadata.clone()))
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        // Second batch clears metadata.
        let finalized = db.new_batch().merkleize(None).finalize();
        db.apply_batch(finalized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_metadata_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_metadata_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_metadata_inner::<mmb::Family>);
    }

    /// MerkleizedBatch::root() matches db.root() after apply_batch().
    async fn test_keyless_batch_speculative_root_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        let merkleized = {
            let mut batch = db.new_batch();
            for i in 0u8..10 {
                batch = batch.append(vec![i; 16]);
            }
            batch.merkleize(None)
        };

        // Speculative root is available before apply.
        let speculative = merkleized.root();
        let finalized = merkleized.finalize();
        db.apply_batch(finalized).await.unwrap();

        assert_eq!(db.root(), speculative);

        // Second batch: verify again with metadata.
        let metadata = vec![55u8; 8];
        let merkleized = db
            .new_batch()
            .append(vec![0xAA; 20])
            .merkleize(Some(metadata));
        let speculative = merkleized.root();
        let finalized = merkleized.finalize();
        db.apply_batch(finalized).await.unwrap();

        assert_eq!(db.root(), speculative);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_speculative_root_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_speculative_root_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_speculative_root_inner::<mmb::Family>);
    }

    /// MerkleizedBatch::get() reads from the operation chain and base DB.
    async fn test_keyless_merkleized_batch_get_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Pre-populate base DB.
        let base_val = vec![10u8; 12];
        let finalized = db
            .new_batch()
            .append(base_val.clone())
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        // Locations: 0=initial commit, 1=append, 2=commit

        // Create a merkleized batch with new appends.
        let new_val = vec![20u8; 16];
        let merkleized = db.new_batch().append(new_val.clone()).merkleize(None);
        // Locations: 3=append, 4=commit

        // Read base DB value through merkleized batch.
        assert_eq!(
            merkleized.get(loc::<F>(1), &db).await.unwrap(),
            Some(base_val),
        );

        // Read this batch's append from the operation chain.
        assert_eq!(
            merkleized.get(loc::<F>(3), &db).await.unwrap(),
            Some(new_val),
        );

        // Commit op returns None (no metadata).
        assert_eq!(merkleized.get(loc::<F>(4), &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_merkleized_batch_get() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_merkleized_batch_get_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_merkleized_batch_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_merkleized_batch_get_inner::<mmb::Family>);
    }

    /// Chained child batch can be merkleized, finalized, and applied.
    ///
    /// The chained pattern builds speculative batches on top of each other
    /// without applying intermediates. Only the final child is applied, which
    /// contains all operations from the entire chain.
    async fn test_keyless_batch_chained_apply_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        let v1 = vec![1u8; 8];
        let v2 = vec![2u8; 16];
        let v3 = vec![3u8; 24];

        // Parent batch.
        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);
        let parent_root = parent_m.root();

        // Child batch built on top of parent.
        let child = parent_m.new_batch::<Sha256>();
        let loc2 = child.size();
        let child = child.append(v2.clone());
        let loc3 = child.size();
        let child = child.append(v3.clone());
        let child_m = child.merkleize(None);
        let child_root = child_m.root();

        // Roots should differ (child has more data).
        assert_ne!(parent_root, child_root);

        // Apply only the final child -- it contains everything.
        let child_finalized = child_m.finalize();
        db.apply_batch(child_finalized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.root(), child_root);
        assert_eq!(db.get(loc1).await.unwrap(), Some(v1));
        assert_eq!(db.get(loc2).await.unwrap(), Some(v2));
        assert_eq!(db.get(loc3).await.unwrap(), Some(v3));

        // Verify recovery after reopen.
        drop(db);
        let db: Db<F> = open_db::<F>(context.with_label("db2")).await;
        assert_eq!(db.root(), child_root);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_chained_apply_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_chained_apply_inner::<mmb::Family>);
    }

    /// Alternatively, chained batches can each be applied independently.
    async fn test_keyless_batch_chained_apply_sequential_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        let v1 = vec![1u8; 8];
        let v2 = vec![2u8; 16];

        // Parent batch.
        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);
        let parent_root = parent_m.root();

        // Finalize and apply parent first.
        let parent_finalized = parent_m.finalize();
        db.apply_batch(parent_finalized).await.unwrap();
        assert_eq!(db.root(), parent_root);
        assert_eq!(db.get(loc1).await.unwrap(), Some(v1));

        // Now create a second (independent) batch.
        let batch2 = db.new_batch();
        let loc2 = batch2.size();
        let batch2 = batch2.append(v2.clone());
        let batch2_m = batch2.merkleize(None);
        let batch2_root = batch2_m.root();
        let batch2_finalized = batch2_m.finalize();
        db.apply_batch(batch2_finalized).await.unwrap();
        assert_eq!(db.root(), batch2_root);
        assert_eq!(db.get(loc2).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_chained_apply_sequential_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_apply_sequential_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_chained_apply_sequential_inner::<mmb::Family>);
    }

    /// Many sequential batches accumulate correctly.
    async fn test_keyless_batch_many_sequential_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;
        let hasher = Standard::<Sha256>::new();

        const BATCHES: u64 = 20;
        const APPENDS_PER_BATCH: u64 = 5;

        let mut all_values: Vec<Vec<u8>> = Vec::new();
        let mut all_locs: Vec<Location<F>> = Vec::new();

        for batch_idx in 0..BATCHES {
            let finalized = {
                let mut batch = db.new_batch();
                for j in 0..APPENDS_PER_BATCH {
                    let v = vec![(batch_idx * 10 + j) as u8; 8];
                    let loc = batch.size();
                    batch = batch.append(v.clone());
                    all_values.push(v);
                    all_locs.push(loc);
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
        }

        // Verify all values are readable.
        for (i, loc) in all_locs.iter().enumerate() {
            assert_eq!(
                db.get(*loc).await.unwrap(),
                Some(all_values[i].clone()),
                "mismatch at index {i}, loc {loc}"
            );
        }

        // Verify proof over the full range.
        let root = db.root();
        let (proof, ops) = db.proof(loc::<F>(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, loc::<F>(0), &ops, &root));

        // Expected size: 1 initial commit + BATCHES * (APPENDS_PER_BATCH + 1 commit).
        let expected = 1 + BATCHES * (APPENDS_PER_BATCH + 1);
        assert_eq!(db.bounds().await.end, expected);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_many_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_many_sequential_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_many_sequential_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_many_sequential_inner::<mmb::Family>);
    }

    /// Empty batch (zero appends) produces correct speculative root.
    async fn test_keyless_batch_empty_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Apply a non-empty batch first so the DB has some state.
        let finalized = db
            .new_batch()
            .append(vec![1u8; 8])
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        let root_before = db.root();
        let size_before = db.bounds().await.end;

        // Empty batch with no appends.
        let merkleized = db.new_batch().merkleize(None);
        let speculative = merkleized.root();
        let finalized = merkleized.finalize();
        db.apply_batch(finalized).await.unwrap();

        // Root changed (a new Commit op was appended).
        assert_ne!(db.root(), root_before);
        assert_eq!(db.root(), speculative);
        // Size grew by exactly 1 (the Commit op).
        assert_eq!(db.bounds().await.end, size_before + 1);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_empty_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_empty_inner::<mmb::Family>);
    }

    /// MerkleizedBatch::get() works on a chained child's merkleized batch.
    async fn test_keyless_batch_chained_merkleized_get_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Pre-populate base DB.
        let base_val = vec![10u8; 12];
        let finalized = db
            .new_batch()
            .append(base_val.clone())
            .merkleize(None)
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        let base_loc = loc::<F>(1);

        // Parent batch appends v1.
        let v1 = vec![1u8; 8];
        let parent = db.new_batch();
        let loc1 = parent.size();
        let parent = parent.append(v1.clone());
        let parent_m = parent.merkleize(None);

        // Child batch appends v2.
        let v2 = vec![2u8; 16];
        let child = parent_m.new_batch::<Sha256>();
        let loc2 = child.size();
        let child = child.append(v2.clone());
        let child_m = child.merkleize(None);

        // Child's MerkleizedBatch can read all three layers:
        // base DB value
        assert_eq!(
            child_m.get(base_loc, &db).await.unwrap(),
            Some(base_val),
            "should read base DB value"
        );
        // parent chain value
        assert_eq!(
            child_m.get(loc1, &db).await.unwrap(),
            Some(v1),
            "should read parent chain value"
        );
        // child's own value
        assert_eq!(
            child_m.get(loc2, &db).await.unwrap(),
            Some(v2),
            "should read child's own value"
        );

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_merkleized_get() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_chained_merkleized_get_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_chained_merkleized_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_chained_merkleized_get_inner::<mmb::Family>);
    }

    /// Large single batch with many appends, verifying all values and proof.
    async fn test_keyless_batch_large_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;
        let hasher = Standard::<Sha256>::new();

        const N: u64 = 500;
        let mut values = Vec::new();
        let mut locs = Vec::new();

        let finalized = {
            let mut batch = db.new_batch();
            for i in 0..N {
                let v = vec![(i % 256) as u8; ((i % 29) + 3) as usize];
                let loc = batch.size();
                batch = batch.append(v.clone());
                locs.push(loc);
                values.push(v);
            }
            batch.merkleize(None).finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Verify every value.
        for (i, loc) in locs.iter().enumerate() {
            assert_eq!(
                db.get(*loc).await.unwrap(),
                Some(values[i].clone()),
                "mismatch at index {i}"
            );
        }

        // Verify proof over the full range.
        let root = db.root();
        let (proof, ops) = db.proof(loc::<F>(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, loc::<F>(0), &ops, &root));

        // Expected: 1 initial commit + N appends + 1 commit.
        assert_eq!(db.bounds().await.end, 1 + N + 1);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_large() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_large_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_keyless_batch_large_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_batch_large_inner::<mmb::Family>);
    }

    async fn test_stale_changeset_rejected_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Create two batches from the same DB state.
        let changeset_a = db.new_batch().append(vec![10]).merkleize(None).finalize();
        let changeset_b = db.new_batch().append(vec![20]).merkleize(None).finalize();

        // Apply the first -- should succeed.
        db.apply_batch(changeset_a).await.unwrap();
        let expected_root = db.root();
        let expected_bounds = db.bounds().await;
        let expected_last_commit = db.last_commit_loc();
        assert_eq!(db.get(loc::<F>(1)).await.unwrap(), Some(vec![10]));
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Apply the second -- should fail because the DB was modified.
        let result = db.apply_batch(changeset_b).await;
        assert!(
            matches!(result, Err(Error::<F>::StaleChangeset { .. })),
            "expected StaleChangeset error, got {result:?}"
        );
        assert_eq!(db.root(), expected_root);
        assert_eq!(db.bounds().await, expected_bounds);
        assert_eq!(db.last_commit_loc(), expected_last_commit);
        assert_eq!(db.get(loc::<F>(1)).await.unwrap(), Some(vec![10]));
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_stale_changeset_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_rejected_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_stale_changeset_rejected_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_rejected_inner::<mmb::Family>);
    }

    async fn test_stale_changeset_chained_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Parent batch.
        let parent = db.new_batch().append(vec![1]).merkleize(None);

        // Fork two children from the same parent.
        let child_a = parent
            .new_batch::<Sha256>()
            .append(vec![2])
            .merkleize(None)
            .finalize();
        let child_b = parent
            .new_batch::<Sha256>()
            .append(vec![3])
            .merkleize(None)
            .finalize();

        // Apply child A.
        db.apply_batch(child_a).await.unwrap();

        // Child B is stale.
        let result = db.apply_batch(child_b).await;
        assert!(
            matches!(result, Err(Error::<F>::StaleChangeset { .. })),
            "expected StaleChangeset error, got {result:?}"
        );

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_stale_changeset_chained() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_chained_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_stale_changeset_chained_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_chained_inner::<mmb::Family>);
    }

    async fn test_stale_changeset_parent_applied_before_child_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Parent batch.
        let parent = db.new_batch().append(vec![1]).merkleize(None);

        // Child batch.
        let child_changeset = parent
            .new_batch::<Sha256>()
            .append(vec![2])
            .merkleize(None)
            .finalize();

        // Apply parent first.
        let parent_changeset = parent.finalize();
        db.apply_batch(parent_changeset).await.unwrap();

        // Child is stale because it expected to be applied on top of the
        // pre-parent DB state.
        let result = db.apply_batch(child_changeset).await;
        assert!(
            matches!(result, Err(Error::<F>::StaleChangeset { .. })),
            "expected StaleChangeset error, got {result:?}"
        );

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_stale_changeset_parent_applied_before_child() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_parent_applied_before_child_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_stale_changeset_parent_applied_before_child_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_parent_applied_before_child_inner::<mmb::Family>);
    }

    /// Apply parent via finalize(), then child via finalize_from(). Both values present.
    async fn test_keyless_finalize_from_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Parent batch.
        let parent = db.new_batch();
        let parent_loc = parent.size();
        let parent = parent.append(vec![1]);
        let parent_m = parent.merkleize(None);

        // Child batch built on parent.
        let child = parent_m.new_batch::<Sha256>();
        let child_loc = child.size();
        let child = child.append(vec![2]);
        let child_m = child.merkleize(None);

        // Apply parent first.
        db.apply_batch(parent_m.finalize()).await.unwrap();
        let current_db_size = *db.last_commit_loc() + 1;

        // Apply child via finalize_from (rebased onto committed parent).
        db.apply_batch(child_m.finalize_from(current_db_size))
            .await
            .unwrap();

        // Both values present.
        assert_eq!(db.get(parent_loc).await.unwrap(), Some(vec![1]));
        assert_eq!(db.get(child_loc).await.unwrap(), Some(vec![2]));

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_keyless_finalize_from() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_finalize_from_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_keyless_finalize_from_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_finalize_from_inner::<mmb::Family>);
    }

    async fn test_keyless_child_root_matches_between_pending_and_committed_paths_inner<
        F: Family,
    >(
        context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Build the child while the parent is still pending.
        let parent = db.new_batch().append(vec![1]).merkleize(None);
        let pending_child = parent.new_batch::<Sha256>().append(vec![2]).merkleize(None);

        // Commit the parent, then rebuild the same logical child from the
        // committed DB state and compare roots.
        db.apply_batch(parent.finalize()).await.unwrap();
        db.commit().await.unwrap();

        let committed_child = db.new_batch().append(vec![2]).merkleize(None);

        assert_eq!(pending_child.root(), committed_child.root());

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_keyless_child_root_matches_between_pending_and_committed_paths() {
        let executor = deterministic::Runner::default();
        executor.start(
            test_keyless_child_root_matches_between_pending_and_committed_paths_inner::<
                mmr::Family,
            >,
        );
    }

    #[test_traced]
    fn test_keyless_child_root_matches_between_pending_and_committed_paths_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(
            test_keyless_child_root_matches_between_pending_and_committed_paths_inner::<
                mmb::Family,
            >,
        );
    }

    async fn test_stale_changeset_child_applied_before_parent_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Parent batch.
        let parent = db.new_batch().append(vec![1]).merkleize(None);

        // Child batch. Finalize both before applying either so the
        // borrow on `db` through `parent` is released.
        let child_changeset = parent
            .new_batch::<Sha256>()
            .append(vec![2])
            .merkleize(None)
            .finalize();
        let parent_changeset = parent.finalize();

        // Apply child first (it carries all parent ops too).
        db.apply_batch(child_changeset).await.unwrap();

        // Parent is stale.
        let result = db.apply_batch(parent_changeset).await;
        assert!(
            matches!(result, Err(Error::<F>::StaleChangeset { .. })),
            "expected StaleChangeset error, got {result:?}"
        );

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_stale_changeset_child_applied_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_child_applied_before_parent_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_stale_changeset_child_applied_before_parent_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_changeset_child_applied_before_parent_inner::<mmb::Family>);
    }

    /// to_batch() creates an owned snapshot whose root matches the committed DB.
    /// A child batch chained from it can be applied.
    async fn test_keyless_to_batch_inner<F: Family>(context: deterministic::Context) {
        let mut db: Db<F> = open_db::<F>(context.with_label("db")).await;

        // Populate.
        let batch = db.new_batch();
        let loc1 = batch.size();
        let batch = batch.append(vec![10]);
        db.apply_batch(batch.merkleize(None).finalize())
            .await
            .unwrap();

        // to_batch root matches committed root.
        let snapshot = db.to_batch();
        assert_eq!(snapshot.root(), db.root());

        // Chain a child from the snapshot, apply it.
        let child_batch = snapshot.new_batch::<Sha256>();
        let loc2 = child_batch.size();
        let child_batch = child_batch.append(vec![20]);
        let child = child_batch.merkleize(None);
        db.apply_batch(child.finalize()).await.unwrap();

        assert_eq!(db.get(loc1).await.unwrap(), Some(vec![10]));
        assert_eq!(db.get(loc2).await.unwrap(), Some(vec![20]));

        db.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_keyless_to_batch() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_to_batch_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_keyless_to_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_keyless_to_batch_inner::<mmb::Family>);
    }
}
