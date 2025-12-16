//! The [Keyless] qmdb allows for append-only storage of arbitrary variable-length data that can
//! later be retrieved by its location.
//!
//! The implementation consists of an `mmr` over the operations applied to the database and an
//! operations `log` storing these operations.
//!
//! The state of the operations log up until the last commit point is the "source of truth". In the
//! event of unclean shutdown, the mmr will be brought back into alignment with the log on startup.

use crate::{
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal as ContiguousJournal},
    },
    mmr::{
        journaled::Config as MmrConfig,
        mem::{Clean, Dirty, State},
        Location, Proof,
    },
    qmdb::{any::VariableValue, operation::Committable, Error},
};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::debug;

mod operation;
pub use operation::Operation;

/// Configuration for a [Keyless] authenticated db.
#[derive(Clone)]
pub struct Config<C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the operations log.
    pub log_partition: String,

    /// The size of the write buffer to use with the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding the operations log.
    pub log_codec_config: C,

    /// The max number of operations to put in each section of the operations log.
    pub log_items_per_section: NonZeroU64,

    /// An optional thread pool to use for parallelizing batch MMR operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// A keyless QMDB for variable length data.
type Journal<E, V, H, S> = authenticated::Journal<E, ContiguousJournal<E, Operation<V>>, H, S>;

pub struct Keyless<
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
    S: State<DigestOf<H>> = Dirty,
> {
    /// Authenticated journal of operations.
    journal: Journal<E, V, H, S>,

    /// The location of the last commit, if any.
    last_commit_loc: Option<Location>,
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher, S: State<DigestOf<H>>>
    Keyless<E, V, H, S>
{
    /// Get the value at location `loc` in the database.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOutOfBounds] if `loc` >= `self.op_count()`.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error> {
        let op_count = self.op_count();
        if loc >= op_count {
            return Err(Error::LocationOutOfBounds(loc, op_count));
        }
        let op = self.journal.read(loc).await?;

        Ok(op.into_value())
    }

    /// Get the number of operations (appends + commits) that have been applied to the db since
    /// inception.
    pub fn op_count(&self) -> Location {
        self.journal.size()
    }

    /// Returns the location of the last commit, if any.
    pub const fn last_commit_loc(&self) -> Option<Location> {
        self.last_commit_loc
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.journal.oldest_retained_loc()
    }

    /// Return the location before which all operations have been pruned.
    pub fn pruning_boundary(&self) -> Location {
        self.journal.pruning_boundary()
    }

    /// Append a value to the db, returning its location which can be used to retrieve it.
    pub async fn append(&mut self, value: V) -> Result<Location, Error> {
        self.journal
            .append(Operation::Append(value))
            .await
            .map_err(Into::into)
    }

    /// Get the metadata associated with the last commit, or None if no commit has been made.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        let Some(loc) = self.last_commit_loc else {
            return Ok(None);
        };
        let op = self.journal.read(loc).await?;
        let Operation::Commit(metadata) = op else {
            return Ok(None);
        };

        Ok(metadata)
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> Keyless<E, V, H, Clean<H::Digest>> {
    /// Returns a [Keyless] qmdb initialized from `cfg`. Any uncommitted operations will be discarded
    /// and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let mmr_cfg = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        };

        let journal_cfg = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_section,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.log_write_buffer,
        };

        let journal = Journal::new(context, mmr_cfg, journal_cfg, Operation::is_commit).await?;

        let last_commit_loc = journal.size().checked_sub(1);

        Ok(Self {
            journal,
            last_commit_loc,
        })
    }

    /// Return the root of the db.
    pub const fn root(&self) -> H::Digest {
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
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// - Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count` or `op_count` >
    ///   number of operations.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
        Ok(self
            .journal
            .historical_proof(op_count, start_loc, max_ops)
            .await?)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<Location, Error> {
        let loc = self.journal.append(Operation::Commit(metadata)).await?;
        self.journal.commit().await?;
        self.last_commit_loc = Some(loc);
        debug!(size = ?self.op_count(), "committed db");

        Ok(loc)
    }

    /// Prune historical operations prior to `loc`. This does not affect the db's root.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `loc` > last commit point.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `loc` > [crate::mmr::MAX_LOCATION]
    pub async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        let last_commit = self.last_commit_loc.unwrap_or(Location::new_unchecked(0));
        if loc > last_commit {
            return Err(Error::PruneBeyondMinRequired(loc, last_commit));
        }
        self.journal.prune(loc).await?;
        Ok(())
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.journal.sync().await.map_err(Into::into)
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(self) -> Result<(), Error> {
        Ok(self.journal.close().await?)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        Ok(self.journal.destroy().await?)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    /// Simulate failure by consuming the db but without syncing / closing the various structures.
    pub async fn simulate_failure(mut self, sync_log: bool, sync_mmr: bool) -> Result<(), Error> {
        if sync_log {
            self.journal.journal.sync().await.map_err(Error::Journal)?;
        }
        if sync_mmr {
            self.journal.mmr.sync().await.map_err(Error::Mmr)?;
        }

        Ok(())
    }

    #[cfg(test)]
    /// Simulate pruning failure by consuming the db and abandoning pruning operation mid-flight.
    pub(super) async fn simulate_prune_failure(mut self, loc: Location) -> Result<(), Error> {
        let last_commit = self.last_commit_loc.unwrap_or(Location::new_unchecked(0));
        if loc > last_commit {
            return Err(Error::PruneBeyondMinRequired(loc, last_commit));
        }
        // Perform the same steps as pruning except "crash" right after the log is pruned.
        self.journal.mmr.sync().await.map_err(Error::Mmr)?;
        assert!(
            self.journal
                .journal
                .prune(*loc)
                .await
                .map_err(Error::Journal)?,
            "nothing was pruned, so could not simulate failure"
        );

        // "fail" before mmr is pruned.
        Ok(())
    }

    /// Convert this database into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> Keyless<E, V, H, Dirty> {
        Keyless {
            journal: self.journal.into_dirty(),
            last_commit_loc: self.last_commit_loc,
        }
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> Keyless<E, V, H, Dirty> {
    /// Merkleize the database and compute the root digest.
    pub fn merkleize(self) -> Keyless<E, V, H, Clean<H::Digest>> {
        Keyless {
            journal: self.journal.merkleize(),
            last_commit_loc: self.last_commit_loc,
        }
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher, S: State<DigestOf<H>>>
    crate::qmdb::store::LogStore for Keyless<E, V, H, S>
{
    type Value = V;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    // All unpruned operations are active in a keyless store.
    fn inactivity_floor_loc(&self) -> Location {
        self.journal.pruning_boundary()
    }

    fn is_empty(&self) -> bool {
        self.op_count() == 0
    }

    async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.get_metadata().await
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> crate::qmdb::store::CleanStore
    for Keyless<E, V, H, Clean<H::Digest>>
{
    type Digest = H::Digest;
    type Operation = Operation<V>;
    type Dirty = Keyless<E, V, H, Dirty>;

    fn root(&self) -> Self::Digest {
        self.root()
    }

    async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        self.proof(start_loc, max_ops).await
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        self.historical_proof(historical_size, start_loc, max_ops)
            .await
    }

    fn into_dirty(self) -> Self::Dirty {
        self.into_dirty()
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> crate::qmdb::store::DirtyStore
    for Keyless<E, V, H, Dirty>
{
    type Digest = H::Digest;
    type Operation = Operation<V>;
    type Clean = Keyless<E, V, H, Clean<H::Digest>>;

    async fn merkleize(self) -> Result<Self::Clean, Error> {
        Ok(self.merkleize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        mmr::{mem::Mmr as MemMmr, StandardHasher as Standard},
        qmdb::verify_proof,
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};
    use rand::Rng;

    // Use some weird sizes here to test boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    fn db_config(suffix: &str) -> Config<(commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type Db = Keyless<deterministic::Context, Vec<u8>, Sha256, Clean<<Sha256 as Hasher>::Digest>>;

    /// Return a [Keyless] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> Db {
        Db::init(context, db_config("partition")).await.unwrap()
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert_eq!(
                db.root(),
                *MemMmr::default().merkleize(&mut hasher, None).root()
            );
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert_eq!(db.last_commit_loc(), None);

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let v1 = vec![1u8; 8];
            let root = db.root();
            db.append(v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = vec![3u8; 10];
            db.commit(Some(metadata.clone())).await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
            assert_eq!(
                db.get(Location::new_unchecked(0)).await.unwrap(),
                Some(metadata.clone())
            ); // the commit op
            let root = db.root();

            // Commit op should remain after reopen even without clean shutdown.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // commit op should remain after re-open.
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
            assert_eq!(db.root(), root);
            assert_eq!(db.last_commit_loc(), Some(Location::new_unchecked(0)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 values and make sure we can get them back.
            let mut db = open_db(context.clone()).await;

            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 20];

            let loc1 = db.append(v1.clone()).await.unwrap();
            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);

            let loc2 = db.append(v2.clone()).await.unwrap();
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            // Make sure closing/reopening gets us back to the same state.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 3); // 2 appends, 1 commit
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert_eq!(db.get(Location::new_unchecked(2)).await.unwrap(), None); // the commit op
            let root = db.root();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(), root);

            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            db.append(v2).await.unwrap();
            db.append(v1).await.unwrap();

            // Make sure uncommitted items get rolled back.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(), root);

            // Make sure commit operation remains after close/reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    // Helper function to append random elements to a database.
    async fn append_elements<T: Rng>(db: &mut Db, rng: &mut T, num_elements: usize) {
        for _ in 0..num_elements {
            let value = vec![(rng.next_u32() % 255) as u8, (rng.next_u32() % 255) as u8];
            db.append(value).await.unwrap();
        }
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_recovery() {
        let executor = deterministic::Runner::default();
        const ELEMENTS: usize = 1000;
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;
            let root = db.root();

            append_elements(&mut db, &mut context, ELEMENTS).await;

            // Simulate a failure before committing.
            db.simulate_failure(false, false).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply the updates and commit them this time.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            let root = db.root();

            // Append more values.
            append_elements(&mut db, &mut context, ELEMENTS).await;

            // Simulate a failure.
            db.simulate_failure(false, false).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply the updates.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            // Simulate a failure after syncing log but not MMR.
            db.simulate_failure(true, false).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply the updates.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            // Simulate a failure after syncing MMR but not log.
            db.simulate_failure(false, true).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply the updates and commit them this time.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            let root = db.root();

            // Make sure we can close/reopen and get back to the same state.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2 * ELEMENTS as u64 + 2);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Append many values then commit.
            const ELEMENTS: usize = 200;
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            let root = db.root();
            let op_count = db.op_count();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);
            assert_eq!(db.last_commit_loc(), Some(op_count - 1));
            db.close().await.unwrap();

            // Insert many operations without commit, then simulate various types of failures.
            async fn recover_from_failure(
                mut context: deterministic::Context,
                root: <Sha256 as Hasher>::Digest,
                op_count: Location,
            ) {
                let mut db = open_db(context.clone()).await;

                // Append operations and simulate failure.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                db.simulate_failure(false, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(), root);

                // Append operations and simulate failure after syncing log but not MMR.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                db.simulate_failure(true, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(), root);

                // Append operations and simulate failure after syncing MMR but not log.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                db.simulate_failure(false, true).await.unwrap();
                let db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(), root);
            }

            recover_from_failure(context.clone(), root, op_count).await;

            // Simulate a failure during pruning and ensure we recover.
            let db = open_db(context.clone()).await;
            let last_commit_loc = db.last_commit_loc().unwrap();
            db.simulate_prune_failure(last_commit_loc).await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);
            db.close().await.unwrap();

            // Repeat recover_from_failure tests after successfully pruning to the last commit.
            let mut db = open_db(context.clone()).await;
            db.prune(db.last_commit_loc().unwrap()).await.unwrap();
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);
            db.close().await.unwrap();

            recover_from_failure(context.clone(), root, op_count).await;

            // Apply the ops one last time but fully commit them this time, then clean up.
            let mut db = open_db(context.clone()).await;
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.root(), root);
            assert_eq!(db.last_commit_loc(), Some(db.op_count() - 1));

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery() {
        const ELEMENTS: u64 = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            let root = db.root();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            async fn apply_ops(db: &mut Db) {
                for i in 0..ELEMENTS {
                    let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                    db.append(v).await.unwrap();
                }
            }

            // Simulate various failure types after inserting operations without a commit.
            apply_ops(&mut db).await;
            db.simulate_failure(false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);
            assert_eq!(db.last_commit_loc(), None);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_generation_and_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Build a db with some values
            const ELEMENTS: u64 = 100;
            let mut values = Vec::new();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();

            // Test that historical proof fails with op_count > number of operations
            assert!(matches!(
                db.historical_proof(db.op_count() + 1, Location::new_unchecked(5), NZU64!(10))
                    .await,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
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
                let (proof, ops) = db.proof(Location::new_unchecked(start_loc), NZU64!(max_ops)).await.unwrap();

                // Verify the proof
                assert!(
                    verify_proof(&mut hasher, &proof, Location::new_unchecked(start_loc), &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops",
                );

                // Check that we got the expected number of operations
                let expected_ops = std::cmp::min(max_ops, *db.op_count() - start_loc);
                assert_eq!(
                    ops.len() as u64,
                    expected_ops,
                    "Expected {expected_ops} operations, got {}",
                    ops.len(),
                );

                // Verify operation types
                for (i, op) in ops.iter().enumerate() {
                    let loc = start_loc + i as u64;
                    if loc < ELEMENTS {
                        // Should be an Append operation
                        assert!(
                            matches!(op, Operation::Append(_)),
                            "Expected Append operation at location {loc}, got {op:?}",
                        );
                    } else if loc == ELEMENTS {
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
                    !verify_proof(&mut hasher, &proof, Location::new_unchecked(start_loc), &ops, &wrong_root),
                    "Proof should fail with wrong root"
                );

                // Verify that proof fails with wrong start location
                if start_loc > 0 {
                    assert!(
                        !verify_proof(&mut hasher, &proof, Location::new_unchecked(start_loc - 1), &ops, &root),
                        "Proof should fail with wrong start location"
                    );
                }
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Build a db with some values
            const ELEMENTS: u64 = 100;
            let mut values = Vec::new();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();

            // Add more elements and commit again
            for i in ELEMENTS..ELEMENTS * 2 {
                let v = vec![(i % 255) as u8; ((i % 17) + 5) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            println!("last commit loc: {}", db.last_commit_loc.unwrap());

            // Prune the first 30 operations
            const PRUNE_LOC: u64 = 30;
            db.prune(Location::new_unchecked(PRUNE_LOC)).await.unwrap();

            // Verify pruning worked
            let oldest_retained = db.oldest_retained_loc().unwrap();

            // Root should remain the same after pruning
            assert_eq!(
                db.root(),
                root,
                "Root should not change after pruning"
            );

            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.op_count(), 2 * ELEMENTS + 2);
            assert!(db.oldest_retained_loc().unwrap() <= PRUNE_LOC);

            // Test that we can't get pruned values
            for i in 0..*oldest_retained {
                let result = db.get(Location::new_unchecked(i)).await;
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
                (Location::new_unchecked(50), 20),                       // Middle range (if not pruned)
                (Location::new_unchecked(150), 10),                      // Later range
                (Location::new_unchecked(190), 15),                      // Near the end
            ];

            for (start_loc, max_ops) in test_cases {
                // Skip if start_loc is before oldest retained
                if start_loc < oldest_retained {
                    continue;
                }

                let (proof, ops) = db.proof(start_loc, NZU64!(max_ops)).await.unwrap();

                // Verify the proof still works
                assert!(
                    verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops after pruning",
                );

                // Check that we got operations
                let expected_ops = std::cmp::min(max_ops, *db.op_count() - *start_loc);
                assert_eq!(
                    ops.len() as u64,
                    expected_ops,
                    "Expected {expected_ops} operations, got {}",
                    ops.len(),
                );
            }

            // Test pruning more aggressively
            const AGGRESSIVE_PRUNE: Location = Location::new_unchecked(150);
            db.prune(AGGRESSIVE_PRUNE).await.unwrap();

            let new_oldest = db.oldest_retained_loc().unwrap();
            assert!(new_oldest <= AGGRESSIVE_PRUNE);

            // Can still generate proofs for the remaining data
            let (proof, ops) = db.proof(new_oldest, NZU64!(20)).await.unwrap();
            assert!(
                verify_proof(&mut hasher, &proof, new_oldest, &ops, &root),
                "Proof should still verify after aggressive pruning"
            );

            // Test edge case: prune everything except the last few operations
            let almost_all = db.op_count() - 5;
            db.prune(almost_all).await.unwrap();

            let final_oldest = db.oldest_retained_loc().unwrap();

            // Should still be able to prove the remaining operations
            if final_oldest < db.op_count() {
                let (final_proof, final_ops) = db.proof(final_oldest, NZU64!(10)).await.unwrap();
                assert!(
                    verify_proof(&mut hasher, &final_proof, final_oldest, &final_ops, &root),
                    "Should be able to prove remaining operations after extensive pruning"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create initial database with committed data
            let mut db = open_db(context.clone()).await;

            // Add some initial operations and commit
            for i in 0..10 {
                let v = vec![i as u8; 10];
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let committed_root = db.root();
            let committed_size = db.op_count();

            // Add exactly one more append (uncommitted)
            let uncommitted_value = vec![99u8; 20];
            db.append(uncommitted_value.clone()).await.unwrap();

            // Sync only the log (not MMR)
            db.simulate_failure(true, false).await.unwrap();

            // Reopen database
            let mut db = open_db(context.clone()).await;

            // Verify correct recovery
            assert_eq!(
                db.op_count(),
                committed_size,
                "Should rewind to last commit"
            );
            assert_eq!(db.root(), committed_root, "Root should match last commit");
            assert_eq!(
                db.last_commit_loc(),
                Some(committed_size - 1),
                "Last commit location should be correct"
            );

            // Verify the uncommitted append was properly discarded
            // We should be able to append new data without issues
            let new_value = vec![77u8; 15];
            let loc = db.append(new_value.clone()).await.unwrap();
            assert_eq!(
                loc, committed_size,
                "New append should get the expected location"
            );

            // Verify we can read the new value
            assert_eq!(db.get(loc).await.unwrap(), Some(new_value));

            // Test with multiple trailing appends to ensure robustness
            db.commit(None).await.unwrap();
            let new_committed_root = db.root();
            let new_committed_size = db.op_count();

            // Add multiple uncommitted appends
            for i in 0..5 {
                let v = vec![(200 + i) as u8; 10];
                db.append(v).await.unwrap();
            }

            // Simulate the same partial failure scenario
            db.simulate_failure(true, false).await.unwrap();

            // Reopen and verify correct recovery
            let db = open_db(context.clone()).await;
            assert_eq!(
                db.op_count(),
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
                Some(new_committed_size - 1),
                "Last commit location should be correct after multiple appends"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_get_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Test getting from empty database
            let result = db.get(Location::new_unchecked(0)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(0) && size == Location::new_unchecked(0))
            );

            // Add some values
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 8];
            db.append(v1.clone()).await.unwrap();
            db.append(v2.clone()).await.unwrap();
            db.commit(None).await.unwrap();

            // Test getting valid locations - should succeed
            assert_eq!(db.get(Location::new_unchecked(0)).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(Location::new_unchecked(1)).await.unwrap().unwrap(), v2);

            // Test getting out of bounds location
            let result = db.get(Location::new_unchecked(3)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(3) && size == Location::new_unchecked(3))
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Test pruning empty database (no commits)
            let result = db.prune(Location::new_unchecked(1)).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == Location::new_unchecked(1) && commit_loc == Location::new_unchecked(0))
            );

            // Add values and commit
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 8];
            let v3 = vec![3u8; 8];
            db.append(v1.clone()).await.unwrap();
            db.append(v2.clone()).await.unwrap();
            db.commit(None).await.unwrap();
            db.append(v3.clone()).await.unwrap();

            // op_count is 4 (v1, v2, commit, v3), last_commit_loc is 2
            let last_commit = db.last_commit_loc().unwrap();
            assert_eq!(last_commit, Location::new_unchecked(2));

            // Test valid prune (at last commit)
            assert!(db.prune(last_commit).await.is_ok());

            // Add more and commit again
            db.commit(None).await.unwrap();
            let new_last_commit = db.last_commit_loc().unwrap();

            // Test pruning beyond last commit
            let beyond = Location::new_unchecked(*new_last_commit + 1);
            let result = db.prune(beyond).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == beyond && commit_loc == new_last_commit)
            );

            db.destroy().await.unwrap();
        });
    }
}
