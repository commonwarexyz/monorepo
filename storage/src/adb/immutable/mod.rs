//! An authenticated database (ADB) that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.

use crate::{
    adb::{
        align_mmr_and_log, build_snapshot_from_log, operation::variable::Operation, prune_db, Error,
    },
    index::{Index as _, Unordered as Index},
    journal::contiguous::variable,
    mmr::{
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Encode as _, Read};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::Array;
use futures::{future::TryFutureExt, try_join};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod sync;

/// Configuration for an [Immutable] authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [RStorage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [RStorage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [RStorage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each section of the journal.
    pub log_items_per_section: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// An authenticated database (ADB) that only supports adding new keyed values (no updates or
/// deletions), where values can have varying sizes.
pub struct Immutable<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `log`.
    mmr: Mmr<E, H>,

    /// A log of all operations applied to the db in order of occurrence. The _location_ of an
    /// operation is its position in this log, and corresponds to its leaf number in the MMR.
    log: variable::Journal<E, Operation<K, V>>,

    /// A map from each active key to the location of the operation that set its value.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Set].
    snapshot: Index<T, Location>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    hasher: Standard<H>,

    /// The location of the last commit operation, or None if no commit has been made.
    last_commit: Option<Location>,
}

impl<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T>
{
    /// Returns an [Immutable] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut hasher = Standard::<H>::new();

        let mut mmr = Mmr::init(
            context.with_label("mmr"),
            &mut hasher,
            MmrConfig {
                journal_partition: cfg.mmr_journal_partition,
                metadata_partition: cfg.mmr_metadata_partition,
                items_per_blob: cfg.mmr_items_per_blob,
                write_buffer: cfg.mmr_write_buffer,
                thread_pool: cfg.thread_pool,
                buffer_pool: cfg.buffer_pool.clone(),
            },
        )
        .await?;

        let mut log = variable::Journal::init(
            context.with_label("log"),
            variable::Config {
                partition: cfg.log_partition.clone(),
                items_per_section: cfg.log_items_per_section,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config.clone(),
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        let log_size = align_mmr_and_log(&mut mmr, &mut log, &mut hasher).await?;

        let mut snapshot: Index<T, Location> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());

        // Get the start of the log.
        let start_loc = match log.oldest_retained_pos() {
            Some(pos) => Location::new_unchecked(pos),
            None => Location::new_unchecked(log.size()),
        };

        // Build snapshot from the log.
        build_snapshot_from_log(start_loc, &log, &mut snapshot, |_, _| {}).await?;

        let last_commit = log_size.checked_sub(1).map(Location::new_unchecked);

        Ok(Immutable {
            mmr,
            log,
            snapshot,
            hasher,
            last_commit,
        })
    }

    /// Returns an [Immutable] built from the config and sync data in `cfg`.
    #[allow(clippy::type_complexity)]
    pub async fn init_synced(
        context: E,
        mut cfg: sync::Config<E, K, V, T, H::Digest, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        // Initialize MMR for sync
        let mut mmr = Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: MmrConfig {
                    journal_partition: cfg.db_config.mmr_journal_partition,
                    metadata_partition: cfg.db_config.mmr_metadata_partition,
                    items_per_blob: cfg.db_config.mmr_items_per_blob,
                    write_buffer: cfg.db_config.mmr_write_buffer,
                    thread_pool: cfg.db_config.thread_pool.clone(),
                    buffer_pool: cfg.db_config.buffer_pool.clone(),
                },
                range: Position::try_from(cfg.range.start)?
                    ..Position::try_from(cfg.range.end.saturating_add(1))?,
                pinned_nodes: cfg.pinned_nodes,
            },
        )
        .await?;

        let mut hasher = Standard::new();
        let log_size = align_mmr_and_log(&mut mmr, &mut cfg.log, &mut hasher).await?;

        let mut snapshot: Index<T, Location> = Index::init(
            context.with_label("snapshot"),
            cfg.db_config.translator.clone(),
        );

        // Get the start of the log.
        let start_loc = match cfg.log.oldest_retained_pos() {
            Some(pos) => Location::new_unchecked(pos),
            None => Location::new_unchecked(log_size),
        };

        // Build snapshot from the log
        build_snapshot_from_log(start_loc, &cfg.log, &mut snapshot, |_, _| {}).await?;

        let last_commit = log_size.checked_sub(1).map(Location::new_unchecked);

        let mut db = Immutable {
            mmr,
            log: cfg.log,
            snapshot,
            hasher: Standard::<H>::new(),
            last_commit,
        };

        db.sync().await?;
        Ok(db)
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_pos().map(Location::new_unchecked)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root or
    /// current snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        let last_commit_loc = self.last_commit.unwrap_or(Location::new_unchecked(0));
        let op_count = self.op_count();
        prune_db(
            &mut self.mmr,
            &mut self.log,
            &mut self.hasher,
            loc,
            last_commit_loc,
            op_count,
        )
        .await?;

        Ok(())
    }

    /// Get the value of `key` in the db, or None if it has no value or its corresponding operation
    /// has been pruned.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let oldest = self
            .oldest_retained_loc()
            .unwrap_or(Location::new_unchecked(0));
        let iter = self.snapshot.get(key);
        for &loc in iter {
            if loc < oldest {
                continue;
            }
            if let Some(v) = self.get_from_loc(key, loc).await? {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`. Returns
    /// [Error::OperationPruned] if loc precedes the oldest retained location. The location is
    /// otherwise assumed valid.
    async fn get_from_loc(&self, key: &K, loc: Location) -> Result<Option<V>, Error> {
        let pruning_boundary = match self.oldest_retained_loc() {
            Some(oldest) => oldest,
            None => self.op_count(),
        };
        if loc < pruning_boundary {
            return Err(Error::OperationPruned(loc));
        }

        let Operation::Set(k, v) = self.log.read(*loc).await? else {
            return Err(Error::UnexpectedData(loc));
        };

        if k != *key {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> Location {
        Location::new_unchecked(self.log.size())
    }

    /// Sets `key` to have value `value`, assuming `key` hasn't already been assigned. The operation
    /// is reflected in the snapshot, but will be subject to rollback until the next successful
    /// `commit`. Attempting to set an already-set key results in undefined behavior.
    ///
    /// Any keys that have been pruned and map to the same translated key will be dropped
    /// during this call.
    pub async fn set(&mut self, key: K, value: V) -> Result<(), Error> {
        let op_count = self.op_count();
        let oldest = self
            .oldest_retained_loc()
            .unwrap_or(Location::new_unchecked(0));
        self.snapshot
            .insert_and_prune(&key, op_count, |v| *v < oldest);

        let op = Operation::Set(key, value);
        self.apply_op(op).await
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut Standard<H>) -> H::Digest {
        self.mmr.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    pub(super) async fn apply_op(&mut self, op: Operation<K, V>) -> Result<(), Error> {
        let encoded_op = op.encode();

        // Create a future that updates the MMR.
        let mmr_fut = async {
            self.mmr.add_batched(&mut self.hasher, &encoded_op).await?;
            Ok::<(), Error>(())
        };

        // Create a future that appends the operation to the log.
        let log_fut = async {
            self.log.append(op).await?;
            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(mmr_fut, log_fut)?;

        Ok(())
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn proof(
        &self,
        start_index: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        let op_count = self.op_count();
        self.historical_proof(op_count, start_index, max_ops).await
    }

    /// Analogous to proof but with respect to the state of the database when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `op_count` > number of operations, or
    /// if `start_loc` >= `op_count`.
    /// Returns [`Error::OperationPruned`] if `start_loc` has been pruned.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        let current_op_count = self.op_count();
        if op_count > current_op_count {
            return Err(crate::mmr::Error::RangeOutOfBounds(op_count).into());
        }
        if start_loc >= op_count {
            return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
        }
        let pruning_boundary = match self.oldest_retained_loc() {
            Some(oldest) => oldest,
            None => self.op_count(),
        };
        if start_loc < pruning_boundary {
            return Err(Error::OperationPruned(start_loc));
        }

        let mmr_size = Position::try_from(op_count)?;
        let end_loc = std::cmp::min(op_count, start_loc.saturating_add(max_ops.get()));
        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_loc..end_loc)
            .await?;
        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        for loc in *start_loc..*end_loc {
            let op = self.log.read(loc).await?;
            ops.push(op);
        }

        Ok((proof, ops))
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        self.last_commit = Some(self.op_count());
        let op = Operation::<K, V>::Commit(metadata);
        let encoded_op = op.encode();

        // Create a future that updates the MMR.
        let mmr_fut = async {
            self.mmr.add_batched(&mut self.hasher, &encoded_op).await?;
            self.mmr.merkleize(&mut self.hasher);
            Ok::<(), Error>(())
        };

        // Create a future that appends the operation to the log and syncs it.
        let log_fut = async {
            self.log.append(op).await?;
            self.log.sync_data().await?;
            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(mmr_fut, log_fut)?;

        Ok(())
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };
        let Operation::Commit(metadata) = self.log.read(*last_commit).await? else {
            unreachable!("no commit operation at location of last commit {last_commit}");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.log.sync().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        try_join!(
            self.log.close().map_err(Error::Journal),
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.log.destroy().map_err(Error::Journal),
            self.mmr.destroy().map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the log to the commit point, but without
    /// fully committing the MMR's cached elements to trigger MMR node recovery on reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_mmr(mut self, write_limit: usize) -> Result<(), Error>
    where
        V: Default,
    {
        self.apply_op(Operation::Commit(None)).await?;
        self.log.close().await?;
        self.mmr
            .simulate_partial_sync(&mut self.hasher, write_limit)
            .await?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the MMR to the commit point, but without
    /// fully committing the log, requiring rollback of the MMR and log upon reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_log(mut self) -> Result<(), Error>
    where
        V: Default,
    {
        self.apply_op(Operation::Commit(None)).await?;
        let log_size = self.log.size();

        self.mmr.close(&mut self.hasher).await?;
        // Rewind the operation log over the commit op to force rollback to the previous commit.
        if log_size > 0 {
            self.log.rewind(log_size - 1).await?;
        }
        self.log.close().await?;

        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;
    const ITEMS_PER_SECTION: u64 = 5;

    pub(crate) fn db_config(
        suffix: &str,
    ) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_{suffix}"),
            log_items_per_section: NZU64!(ITEMS_PER_SECTION),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Immutable] type used in these unit tests.
    type ImmutableTest = Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Return an [Immutable] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> ImmutableTest {
        ImmutableTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![4, 5, 6, 7];
            let root = db.root(&mut hasher);
            db.set(k1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op added
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_immutable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let k1 = Sha256::fill(1u8);
            let k2 = Sha256::fill(2u8);
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];

            assert!(db.get(&k1).await.unwrap().is_none());
            assert!(db.get(&k2).await.unwrap().is_none());

            // Set the first key.
            db.set(k1, v1.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 1);
            // Commit the first key.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 2);
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(1), metadata.clone()))
            );
            // Set the second key.
            db.set(k2, v2.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(db.op_count(), 3);

            // Make sure we can still get metadata.
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(1), metadata))
            );

            // Commit the second key.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 4);
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(3), None))
            );

            // Capture state.
            let root = db.root(&mut hasher);

            // Add an uncommitted op then close the db.
            let k3 = Sha256::fill(3u8);
            let v3 = vec![9, 10, 11];
            db.set(k3, v3).await.unwrap();
            assert_eq!(db.op_count(), 5);
            assert_ne!(db.root(&mut hasher), root);

            // Close & reopen, make sure state is restored to last commit point.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.get(&k3).await.unwrap().is_none());
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(3), None))
            );

            // Cleanup.
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs and prove ranges over them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);

            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), ELEMENTS + 1);
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
            }

            // Make sure all ranges of 5 operations are provable, including truncated ranges at the
            // end.
            let max_ops = NZU64!(5);
            for i in 0..*db.op_count() {
                let (proof, log) = db.proof(Location::new_unchecked(i), max_ops).await.unwrap();
                assert!(verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(i),
                    &log,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_mmr_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);
            db.sync().await.unwrap();
            let halfway_root = db.root(&mut hasher);

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // We partially write only 101 of the cached MMR nodes to simulate a failure.
            db.simulate_failed_commit_mmr(101).await.unwrap();

            // Recovery should replay the log to regenerate the mmr.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            let root = db.root(&mut hasher);
            assert_ne!(root, halfway_root);

            // Close & reopen could preserve the final commit.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_log_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert a single key and then commit to create a first commit point.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![1, 2, 3];
            db.set(k1, v1).await.unwrap();
            db.commit(None).await.unwrap();
            let first_commit_root = db.root(&mut hasher);

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS + 2);
            db.sync().await.unwrap();

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Simulate failure to write the full locations map.
            db.simulate_failed_commit_log().await.unwrap();

            // Recovery should back up to previous commit point.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2);
            let root = db.root(&mut hasher);
            assert_eq!(root, first_commit_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_pruning() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs and prove ranges over them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);

            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // Prune the db to the first half of the operations.
            db.prune(Location::new_unchecked(ELEMENTS / 2))
                .await
                .unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // items_per_section is 5, so half should be exactly at a blob boundary, in which case
            // the actual pruning location should match the requested.
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(oldest_retained_loc, Location::new_unchecked(ELEMENTS / 2));

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 1;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), ELEMENTS + 1);
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(oldest_retained_loc, Location::new_unchecked(ELEMENTS / 2));

            // Prune to a non-blob boundary.
            let loc = Location::new_unchecked(ELEMENTS / 2 + (ITEMS_PER_SECTION * 2 - 1));
            db.prune(loc).await.unwrap();
            // Actual boundary should be a multiple of 5.
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(
                oldest_retained_loc,
                Location::new_unchecked(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Confirm boundary persists across restart.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(
                oldest_retained_loc,
                Location::new_unchecked(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 3;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Confirm behavior of trying to create a proof of pruned items is as expected.
            let pruned_pos = ELEMENTS / 2;
            let proof_result = db
                .proof(
                    Location::new_unchecked(pruned_pos),
                    NZU64!(pruned_pos + 100),
                )
                .await;
            assert!(matches!(proof_result, Err(Error::OperationPruned(pos)) if pos == pruned_pos));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_immutable_db_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Test pruning empty database (no commits)
            let result = db.prune(Location::new_unchecked(1)).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == Location::new_unchecked(1) && commit_loc == Location::new_unchecked(0))
            );

            // Add key-value pairs and commit
            let k1 = Digest::from(*b"12345678901234567890123456789012");
            let k2 = Digest::from(*b"abcdefghijklmnopqrstuvwxyz123456");
            let k3 = Digest::from(*b"99999999999999999999999999999999");
            let v1 = vec![1u8; 16];
            let v2 = vec![2u8; 16];
            let v3 = vec![3u8; 16];

            db.set(k1, v1.clone()).await.unwrap();
            db.set(k2, v2.clone()).await.unwrap();
            db.commit(None).await.unwrap();
            db.set(k3, v3.clone()).await.unwrap();

            // op_count is 4 (k1, k2, commit, k3), last_commit is at location 2
            let last_commit = db.last_commit.unwrap();
            assert_eq!(last_commit, Location::new_unchecked(2));

            // Test valid prune (at last commit)
            assert!(db.prune(last_commit).await.is_ok());

            // Add more and commit again
            db.commit(None).await.unwrap();
            let new_last_commit = db.last_commit.unwrap();

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
