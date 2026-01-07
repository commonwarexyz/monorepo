//! The [Keyless] qmdb allows for append-only storage of arbitrary variable-length data that can
//! later be retrieved by its location.

use crate::{
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal as ContiguousJournal},
    },
    mmr::{journaled::Config as MmrConfig, Location, Proof},
    qmdb::{
        any::VariableValue,
        operation::Committable,
        store::{LogStore, MerkleizedStore, PrunableStore},
        DurabilityState, Durable, Error, MerkleizationState, Merkleized, NonDurable, Unmerkleized,
    },
};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage};
use core::{marker::PhantomData, ops::Range};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

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

/// A keyless authenticated database for variable-length data.
pub struct Keyless<
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
    M: MerkleizationState<DigestOf<H>> = Merkleized<H>,
    D: DurabilityState = Durable,
> {
    /// Authenticated journal of operations.
    journal: Journal<E, V, H, M>,

    /// The location of the last commit, if any.
    last_commit_loc: Location,

    /// Marker for durability state.
    _durability: PhantomData<D>,
}

// Impl block for functionality available in all states.
impl<
        E: Storage + Clock + Metrics,
        V: VariableValue,
        H: Hasher,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > Keyless<E, V, H, M, D>
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

    /// Returns the location of the last commit.
    pub const fn last_commit_loc(&self) -> Location {
        self.last_commit_loc
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Location {
        self.journal
            .oldest_retained_loc()
            .expect("at least one operation should exist")
    }

    /// Return the oldest location that is no longer required to be retained.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.journal.pruning_boundary()
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        let op = self.journal.read(self.last_commit_loc).await?;
        let Operation::Commit(metadata) = op else {
            return Ok(None);
        };

        Ok(metadata)
    }
}

// Implementation for the Clean state.
impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher>
    Keyless<E, V, H, Merkleized<H>, Durable>
{
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

        let mut journal = Journal::new(context, mmr_cfg, journal_cfg, Operation::is_commit).await?;
        if journal.size() == 0 {
            warn!("no operations found in log, creating initial commit");
            journal.append(Operation::Commit(None)).await?;
            journal.sync().await?;
        }

        let last_commit_loc = journal
            .size()
            .checked_sub(1)
            .expect("at least one commit should exist");

        Ok(Self {
            journal,
            last_commit_loc,
            _durability: PhantomData,
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

    /// Prune historical operations prior to `loc`. This does not affect the db's root.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `loc` > last commit point.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `loc` > [crate::mmr::MAX_LOCATION]
    pub async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        if loc > self.last_commit_loc {
            return Err(Error::PruneBeyondMinRequired(loc, self.last_commit_loc));
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

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        Ok(self.journal.destroy().await?)
    }

    /// Convert this database into the Mutable state for accepting new operations.
    pub fn into_mutable(self) -> Keyless<E, V, H, Unmerkleized, NonDurable> {
        Keyless {
            journal: self.journal.into_dirty(),
            last_commit_loc: self.last_commit_loc,
            _durability: PhantomData,
        }
    }
}

// Implementation for the Mutable state.
impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher>
    Keyless<E, V, H, Unmerkleized, NonDurable>
{
    /// Append a value to the db, returning its location which can be used to retrieve it.
    pub async fn append(&mut self, value: V) -> Result<Location, Error> {
        self.journal
            .append(Operation::Append(value))
            .await
            .map_err(Into::into)
    }

    /// Commits any pending operations and transitions the database to the Durable state.
    ///
    /// The caller can associate an arbitrary `metadata` value with the commit. Returns the
    /// `(start_loc, end_loc]` location range of committed operations. The end of the returned
    /// range includes the commit operation itself, and hence will always be equal to `op_count`.
    pub async fn commit(
        mut self,
        metadata: Option<V>,
    ) -> Result<(Keyless<E, V, H, Unmerkleized, Durable>, Range<Location>), Error> {
        let start_loc = self.last_commit_loc + 1;
        self.last_commit_loc = self.journal.append(Operation::Commit(metadata)).await?;
        self.journal.commit().await?;
        debug!(size = ?self.op_count(), "committed db");

        let op_count = self.op_count();
        let durable = Keyless {
            journal: self.journal,
            last_commit_loc: self.last_commit_loc,
            _durability: PhantomData,
        };

        Ok((durable, start_loc..op_count))
    }

    pub fn into_merkleized(self) -> Keyless<E, V, H, Merkleized<H>, Durable> {
        Keyless {
            journal: self.journal.merkleize(),
            last_commit_loc: self.last_commit_loc,
            _durability: PhantomData,
        }
    }
}

// Implementation for the (Unmerkleized, Durable) state.
impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher>
    Keyless<E, V, H, Unmerkleized, Durable>
{
    /// Convert this database into the Mutable state for accepting more operations without
    /// re-merkleizing.
    pub fn into_mutable(self) -> Keyless<E, V, H, Unmerkleized, NonDurable> {
        Keyless {
            journal: self.journal,
            last_commit_loc: self.last_commit_loc,
            _durability: PhantomData,
        }
    }

    /// Compute the merkle root and transition to the Merkleized, Durable state.
    pub fn into_merkleized(self) -> Keyless<E, V, H, Merkleized<H>, Durable> {
        Keyless {
            journal: self.journal.merkleize(),
            last_commit_loc: self.last_commit_loc,
            _durability: PhantomData,
        }
    }
}

// Implementation of MerkleizedStore for the Merkleized state (any durability).
impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher, D: DurabilityState> MerkleizedStore
    for Keyless<E, V, H, Merkleized<H>, D>
{
    type Digest = H::Digest;
    type Operation = Operation<V>;

    fn root(&self) -> Self::Digest {
        self.journal.root()
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        Ok(self
            .journal
            .historical_proof(historical_size, start_loc, max_ops)
            .await?)
    }
}

// Implementation of LogStore for all states.
impl<
        E: Storage + Clock + Metrics,
        V: VariableValue,
        H: Hasher,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > LogStore for Keyless<E, V, H, M, D>
{
    type Value = V;

    fn is_empty(&self) -> bool {
        // A keyless database is never "empty" in the traditional sense since it always
        // has at least one commit operation. We consider it empty if there are no appends.
        self.op_count() <= 1
    }

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<Self::Value>, Error> {
        self.get_metadata().await
    }
}

// Implementation of PrunableStore for the Merkleized state (any durability).
impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher, D: DurabilityState> PrunableStore
    for Keyless<E, V, H, Merkleized<H>, D>
{
    async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        if loc > self.last_commit_loc {
            return Err(Error::PruneBeyondMinRequired(loc, self.last_commit_loc));
        }
        self.journal.prune(loc).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{mmr::StandardHasher as Standard, qmdb::verify_proof};
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

    /// Type alias for the Merkleized, Durable state.
    type CleanDb = Keyless<deterministic::Context, Vec<u8>, Sha256, Merkleized<Sha256>, Durable>;

    /// Type alias for the Mutable (Unmerkleized, NonDurable) state.
    type MutableDb = Keyless<deterministic::Context, Vec<u8>, Sha256, Unmerkleized, NonDurable>;

    /// Return a [Keyless] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> CleanDb {
        CleanDb::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // initial commit should exist
            assert_eq!(db.oldest_retained_loc(), Location::new_unchecked(0));

            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert_eq!(db.last_commit_loc(), Location::new_unchecked(0));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let v1 = vec![1u8; 8];
            let root = db.root();
            let mut db = db.into_mutable();
            db.append(v1).await.unwrap();
            drop(db); // Simulate failed commit
            let db = open_db(context.clone()).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = vec![3u8; 10];
            let db = db.into_mutable();
            let (durable, _) = db.commit(Some(metadata.clone())).await.unwrap();
            let db = durable.into_merkleized();
            assert_eq!(db.op_count(), 2); // 2 commit ops
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
            assert_eq!(
                db.get(Location::new_unchecked(1)).await.unwrap(),
                Some(metadata.clone())
            ); // the commit op
            let root = db.root();

            // Commit op should remain after reopen even without clean shutdown.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2); // commit op should remain after re-open.
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
            assert_eq!(db.root(), root);
            assert_eq!(db.last_commit_loc(), Location::new_unchecked(1));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 values and make sure we can get them back.
            let db = open_db(context.clone()).await;
            let mut db = db.into_mutable();

            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 20];

            let loc1 = db.append(v1.clone()).await.unwrap();
            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);

            let loc2 = db.append(v2.clone()).await.unwrap();
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            // Make sure closing/reopening gets us back to the same state.
            let (durable, _) = db.commit(None).await.unwrap();
            let mut db = durable.into_merkleized();
            assert_eq!(db.op_count(), 4); // 2 appends, 1 commit + 1 initial commit
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert_eq!(db.get(Location::new_unchecked(3)).await.unwrap(), None); // the commit op
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.root(), root);

            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            let mut db = db.into_mutable();
            db.append(v2).await.unwrap();
            db.append(v1).await.unwrap();

            // Make sure uncommitted items get rolled back.
            drop(db); // Simulate failed commit
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.root(), root);

            // Make sure commit operation remains after drop/reopen.
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    // Helper function to append random elements to a database.
    async fn append_elements<T: Rng>(db: &mut MutableDb, rng: &mut T, num_elements: usize) {
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
            let db = open_db(context.clone()).await;
            let root = db.root();
            let mut db = db.into_mutable();

            append_elements(&mut db, &mut context, ELEMENTS).await;

            // Simulate a failure before committing.
            drop(db);
            // Should rollback to the previous root.
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply the updates and commit them this time.
            let mut db = db.into_mutable();
            append_elements(&mut db, &mut context, ELEMENTS).await;
            let (durable, _) = db.commit(None).await.unwrap();
            let db = durable.into_merkleized();
            let root = db.root();

            // Append more values.
            let mut db = db.into_mutable();
            append_elements(&mut db, &mut context, ELEMENTS).await;

            // Simulate a failure.
            drop(db);
            // Should rollback to the previous root.
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply the updates and commit them this time.
            let mut db = db.into_mutable();
            append_elements(&mut db, &mut context, ELEMENTS).await;
            let (durable, _) = db.commit(None).await.unwrap();
            let db = durable.into_merkleized();
            let root = db.root();

            // Make sure we can reopen and get back to the same state.
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2 * ELEMENTS as u64 + 3);
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
            let db = open_db(context.clone()).await;

            // Append many values then commit.
            const ELEMENTS: usize = 200;
            let mut db = db.into_mutable();
            append_elements(&mut db, &mut context, ELEMENTS).await;
            let (durable, _) = db.commit(None).await.unwrap();
            let db = durable.into_merkleized();
            let root = db.root();
            let op_count = db.op_count();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);
            assert_eq!(db.last_commit_loc(), op_count - 1);
            drop(db);

            // Insert many operations without commit, then simulate failure.
            async fn recover_from_failure(
                mut context: deterministic::Context,
                root: <Sha256 as Hasher>::Digest,
                op_count: Location,
            ) {
                let mut db = open_db(context.clone()).await.into_mutable();

                // Append operations and simulate failure.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                drop(db);
                let db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(), root);
            }

            recover_from_failure(context.clone(), root, op_count).await;

            // Repeat recover_from_failure tests after successfully pruning to the last commit.
            let mut db = open_db(context.clone()).await;
            db.prune(db.last_commit_loc()).await.unwrap();
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);
            db.sync().await.unwrap();
            drop(db);

            recover_from_failure(context.clone(), root, op_count).await;

            // Apply the ops one last time but fully commit them this time, then clean up.
            let mut db = open_db(context.clone()).await.into_mutable();
            append_elements(&mut db, &mut context, ELEMENTS).await;
            let (_durable, _) = db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.root(), root);
            assert_eq!(db.last_commit_loc(), db.op_count() - 1);

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
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // initial commit should exist
            assert_eq!(db.root(), root);

            async fn apply_ops(db: &mut MutableDb) {
                for i in 0..ELEMENTS {
                    let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                    db.append(v).await.unwrap();
                }
            }

            // Simulate failure after inserting operations without a commit.
            let mut db = db.into_mutable();
            apply_ops(&mut db).await;
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // initial commit should exist
            assert_eq!(db.root(), root);

            // Repeat: simulate failure after inserting operations without a commit.
            let mut db = db.into_mutable();
            apply_ops(&mut db).await;
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // initial commit should exist
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            let mut db = db.into_mutable();
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // initial commit should exist
            assert_eq!(db.root(), root);
            assert_eq!(db.last_commit_loc(), Location::new_unchecked(0));

            // Apply the ops one last time but fully commit them this time, then clean up.
            let mut db = db.into_mutable();
            apply_ops(&mut db).await;
            let (_db, _) = db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 1);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_generation_and_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let db = open_db(context.clone()).await;
            let mut db = db.into_mutable();

            // Build a db with some values
            const ELEMENTS: u64 = 100;
            let mut values = Vec::new();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            let (durable, _) = db.commit(None).await.unwrap();
            let db = durable.into_merkleized();

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
            let db = open_db(context.clone()).await;
            let mut db = db.into_mutable();

            // Build a db with some values
            const ELEMENTS: u64 = 100;
            let mut values = Vec::new();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            let (durable, _) = db.commit(None).await.unwrap();

            // Add more elements and commit again
            let mut db = durable.into_mutable();
            for i in ELEMENTS..ELEMENTS * 2 {
                let v = vec![(i % 255) as u8; ((i % 17) + 5) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            let (durable, _) = db.commit(None).await.unwrap();
            let mut db = durable.into_merkleized();
            let root = db.root();

            println!("last commit loc: {}", db.last_commit_loc());

            // Prune the first 30 operations
            const PRUNE_LOC: u64 = 30;
            db.prune(Location::new_unchecked(PRUNE_LOC)).await.unwrap();

            // Verify pruning worked
            let oldest_retained = db.oldest_retained_loc();

            // Root should remain the same after pruning
            assert_eq!(
                db.root(),
                root,
                "Root should not change after pruning"
            );

            db.sync().await.unwrap();
            drop(db);
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.op_count(), 2 * ELEMENTS + 3);
            assert!(db.oldest_retained_loc() <= PRUNE_LOC);

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

            let new_oldest = db.oldest_retained_loc();
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

            let final_oldest = db.oldest_retained_loc();

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
            let db = open_db(context.clone()).await;
            let mut db = db.into_mutable();

            // Add some initial operations and commit
            for i in 0..10 {
                let v = vec![i as u8; 10];
                db.append(v).await.unwrap();
            }
            let (durable, _) = db.commit(None).await.unwrap();
            let db = durable.into_merkleized();
            let committed_root = db.root();
            let committed_size = db.op_count();

            // Add exactly one more append (uncommitted)
            let uncommitted_value = vec![99u8; 20];
            let mut db = db.into_mutable();
            db.append(uncommitted_value.clone()).await.unwrap();

            // Simulate failure without commit
            drop(db);

            // Reopen database
            let db = open_db(context.clone()).await;

            // Verify correct recovery
            assert_eq!(
                db.op_count(),
                committed_size,
                "Should rewind to last commit"
            );
            assert_eq!(db.root(), committed_root, "Root should match last commit");
            assert_eq!(
                db.last_commit_loc(),
                committed_size - 1,
                "Last commit location should be correct"
            );

            // Verify the uncommitted append was properly discarded
            // We should be able to append new data without issues
            let mut db = db.into_mutable();
            let new_value = vec![77u8; 15];
            let loc = db.append(new_value.clone()).await.unwrap();
            assert_eq!(
                loc, committed_size,
                "New append should get the expected location"
            );

            // Verify we can read the new value
            assert_eq!(db.get(loc).await.unwrap(), Some(new_value));

            // Test with multiple trailing appends to ensure robustness
            let (durable, _) = db.commit(None).await.unwrap();
            let db = durable.into_merkleized();
            let new_committed_root = db.root();
            let new_committed_size = db.op_count();

            // Add multiple uncommitted appends
            let mut db = db.into_mutable();
            for i in 0..5 {
                let v = vec![(200 + i) as u8; 10];
                db.append(v).await.unwrap();
            }

            // Simulate failure without commit
            drop(db);

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
                new_committed_size - 1,
                "Last commit location should be correct after multiple appends"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_get_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;

            // Test getting from empty database
            let result = db.get(Location::new_unchecked(0)).await.unwrap();
            assert!(result.is_none());

            // Add some values
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 8];
            let mut db = db.into_mutable();
            db.append(v1.clone()).await.unwrap();
            db.append(v2.clone()).await.unwrap();
            let (durable, _) = db.commit(None).await.unwrap();

            // Test getting valid locations - should succeed
            assert_eq!(durable.get(Location::new_unchecked(1)).await.unwrap().unwrap(), v1);
            assert_eq!(durable.get(Location::new_unchecked(2)).await.unwrap().unwrap(), v2);

            // Test getting out of bounds location
            let result = durable.get(Location::new_unchecked(3)).await.unwrap();
            assert!(result.is_none());

            // Test getting out of bounds location
            let result = durable.get(Location::new_unchecked(4)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(4) && size == Location::new_unchecked(4))
            );

            let db = durable.into_merkleized();
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
            let mut db = db.into_mutable();
            db.append(v1.clone()).await.unwrap();
            db.append(v2.clone()).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_mutable();
            db.append(v3.clone()).await.unwrap();

            // op_count is 5 (initial_commit, v1, v2, commit, v3), last_commit_loc is 3
            let last_commit = db.last_commit_loc();
            assert_eq!(last_commit, Location::new_unchecked(3));

            // Test valid prune (at last commit) - need Clean state for prune
            let (durable, _) = db.commit(None).await.unwrap();
            let mut db = durable.into_merkleized();
            assert!(db.prune(Location::new_unchecked(3)).await.is_ok());

            // Test pruning beyond last commit
            let new_last_commit = db.last_commit_loc();
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
