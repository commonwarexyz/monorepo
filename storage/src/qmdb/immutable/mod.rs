//! An authenticated database that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::{
        authenticated,
        contiguous::{
            variable::{self, Config as JournalConfig},
            Contiguous as _, Reader,
        },
    },
    kv,
    mmr::{journaled::Config as MmrConfig, Location, Proof},
    qmdb::{any::VariableValue, build_snapshot_from_log, Error},
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher as CHasher;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
};
use tracing::warn;

pub mod batch;
mod operation;
pub use operation::Operation;

type Journal<E, K, V, H> = authenticated::Journal<E, variable::Journal<E, Operation<K, V>>, H>;

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

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

/// An authenticated database that only supports adding new keyed values (no updates or
/// deletions), where values can have varying sizes.
pub struct Immutable<
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
> {
    /// Authenticated journal of operations.
    journal: Journal<E, K, V, H>,

    /// A map from each active key to the location of the operation that set its value.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Set].
    snapshot: Index<T, Location>,

    /// The location of the last commit operation.
    last_commit_loc: Location,
}

impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T>
{
    /// Return the Location of the next operation appended to this db.
    pub async fn size(&self) -> Location {
        self.bounds().await.end
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location> {
        let bounds = self.journal.reader().await.bounds();
        Location::new_unchecked(bounds.start)..Location::new_unchecked(bounds.end)
    }

    /// Get the value of `key` in the db, or None if it has no value or its corresponding operation
    /// has been pruned.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let iter = self.snapshot.get(key);
        let reader = self.journal.reader().await;
        let oldest = reader.bounds().start;
        for &loc in iter {
            if loc < oldest {
                continue;
            }
            if let Some(v) = Self::get_from_loc(&reader, key, loc).await? {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`. Returns
    /// [Error::OperationPruned] if loc precedes the oldest retained location. The location is
    /// otherwise assumed valid.
    async fn get_from_loc(
        reader: &impl Reader<Item = Operation<K, V>>,
        key: &K,
        loc: Location,
    ) -> Result<Option<V>, Error> {
        if loc < reader.bounds().start {
            return Err(Error::OperationPruned(loc));
        }

        let Operation::Set(k, v) = reader.read(*loc).await? else {
            return Err(Error::UnexpectedData(loc));
        };

        if k != *key {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        let last_commit_loc = self.last_commit_loc;
        let Operation::Commit(metadata) = self
            .journal
            .journal
            .reader()
            .await
            .read(*last_commit_loc)
            .await?
        else {
            unreachable!("no commit operation at location of last commit {last_commit_loc}");
        };

        Ok(metadata)
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
        Ok(self
            .journal
            .historical_proof(op_count, start_loc, max_ops)
            .await?)
    }

    /// Prune operations prior to `prune_loc`. This does not affect the db's root, but it will
    /// affect retrieval of any keys that were set prior to `prune_loc`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > last commit location.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        if loc > self.last_commit_loc {
            return Err(Error::PruneBeyondMinRequired(loc, self.last_commit_loc));
        }
        self.journal.prune(loc).await?;

        Ok(())
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
        start_index: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        let op_count = self.bounds().await.end;
        self.historical_proof(op_count, start_index, max_ops).await
    }

    /// Returns an [Immutable] qmdb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mmr_cfg = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            page_cache: cfg.page_cache.clone(),
        };

        let journal_cfg = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_section,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            page_cache: cfg.page_cache.clone(),
            write_buffer: cfg.log_write_buffer,
        };

        let mut journal = Journal::new(
            context.clone(),
            mmr_cfg,
            journal_cfg,
            Operation::<K, V>::is_commit,
        )
        .await?;

        if journal.size().await == 0 {
            warn!("Authenticated log is empty, initialized new db.");
            journal.append(&Operation::Commit(None)).await?;
            journal.sync().await?;
        }

        let mut snapshot = Index::new(context.with_label("snapshot"), cfg.translator.clone());

        let last_commit_loc = {
            // Get the start of the log.
            let reader = journal.reader().await;
            let start_loc = Location::new_unchecked(reader.bounds().start);

            // Build snapshot from the log.
            build_snapshot_from_log(start_loc, &reader, &mut snapshot, |_, _| {}).await?;

            Location::new_unchecked(
                reader
                    .bounds()
                    .end
                    .checked_sub(1)
                    .expect("commit should exist"),
            )
        };

        Ok(Self {
            journal,
            snapshot,
            last_commit_loc,
        })
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        Ok(self.journal.sync().await?)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        Ok(self.journal.destroy().await?)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    pub(super) async fn apply_op(&mut self, op: Operation<K, V>) -> Result<(), Error> {
        self.journal.append(&op).await?;

        Ok(())
    }

    /// Sets `key` to have value `value`, assuming `key` hasn't already been assigned. The operation
    /// is reflected in the snapshot, but will be subject to rollback until the next successful
    /// `commit`. Attempting to set an already-set key results in undefined behavior.
    ///
    /// Any keys that have been pruned and map to the same translated key will be dropped
    /// during this call.
    pub async fn set(&mut self, key: K, value: V) -> Result<(), Error> {
        let bounds = self.bounds().await;
        self.snapshot
            .insert_and_prune(&key, bounds.end, |v| *v < bounds.start);

        let op = Operation::Set(key, value);
        self.apply_op(op).await
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    /// Returns the range of committed locations. Note that even if no
    /// operations were added since the last commit, this is a root-state changing operation.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<Range<Location>, Error> {
        let loc = self.journal.append(&Operation::Commit(metadata)).await?;
        self.journal.commit().await?;
        self.last_commit_loc = loc;
        Ok(loc..loc + 1)
    }

    /// Create a new batch. Borrows `&self` immutably so multiple batches can
    /// coexist.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(&self) -> batch::Batch<'_, E, K, V, H, T, Journal<E, K, V, H>> {
        let journal_size = *self.last_commit_loc + 1;
        batch::Batch {
            immutable: self,
            journal_parent: &self.journal,
            mutations: std::collections::BTreeMap::new(),
            parent_overlay: std::collections::BTreeMap::new(),
            parent_operation_chain: Vec::new(),
            parent_total_size: journal_size,
        }
    }

    /// Apply a finalized batch to the database.
    ///
    /// Writes all operations to the journal, flushes, updates snapshot, and
    /// updates state. Returns the range of locations written.
    pub async fn apply_batch(
        &mut self,
        batch: batch::FinalizedBatch<K, H::Digest, V>,
    ) -> Result<Range<Location>, Error> {
        let start_loc = Location::new_unchecked(*self.last_commit_loc + 1);

        // Write all operations to the authenticated journal + apply MMR changeset.
        self.journal.apply_batch(batch.journal_finalized).await?;

        // Flush journal to disk.
        self.journal.commit().await?;

        // Apply snapshot deltas.
        let bounds = self.journal.reader().await.bounds();
        for delta in batch.snapshot_deltas {
            match delta {
                batch::SnapshotDelta::Insert { key, new_loc } => {
                    self.snapshot
                        .insert_and_prune(&key, new_loc, |v| *v < bounds.start);
                }
            }
        }

        // Update state.
        self.last_commit_loc = batch.new_last_commit_loc;

        let end_loc = Location::new_unchecked(*self.last_commit_loc + 1);
        Ok(start_loc..end_loc)
    }
}

impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    kv::Gettable for Immutable<E, K, V, H, T>
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    crate::qmdb::store::LogStore for Immutable<E, K, V, H, T>
{
    type Value = V;

    async fn bounds(&self) -> std::ops::Range<Location> {
        self.bounds().await
    }

    async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.get_metadata().await
    }
}

impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    crate::qmdb::store::MerkleizedStore for Immutable<E, K, V, H, T>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;

    fn root(&self) -> Self::Digest {
        self.root()
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
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{mmr::StandardHasher, qmdb::verify_proof, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, BufferPooler, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);
    const ITEMS_PER_SECTION: u64 = 5;

    pub(crate) fn db_config(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal-{suffix}"),
            mmr_metadata_partition: format!("metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log-{suffix}"),
            log_items_per_section: NZU64!(ITEMS_PER_SECTION),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Return an [Immutable] database initialized with a fixed config.
    async fn open_db(
        context: deterministic::Context,
    ) -> Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap> {
        let cfg = db_config("partition", &context);
        Immutable::init(context, cfg).await.unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.with_label("first")).await;
            let bounds = db.bounds().await;
            assert_eq!(bounds.end, 1);
            assert_eq!(bounds.start, Location::new_unchecked(0));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![4, 5, 6, 7];
            let root = db.root();
            let mut db = db;
            db.set(k1, v1).await.unwrap();
            drop(db); // Simulate failed commit
            let db = open_db(context.with_label("second")).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.bounds().await.end, 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let mut db = db;
            db.commit(None).await.unwrap();
            assert_eq!(db.bounds().await.end, 2); // commit op added
            let root = db.root();
            drop(db);

            let db = open_db(context.with_label("third")).await;
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_immutable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys.
            let db = open_db(context.with_label("first")).await;

            let k1 = Sha256::fill(1u8);
            let k2 = Sha256::fill(2u8);
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];

            assert!(db.get(&k1).await.unwrap().is_none());
            assert!(db.get(&k2).await.unwrap().is_none());

            // Set the first key.
            let mut db = db;
            db.set(k1, v1.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.bounds().await.end, 2);
            // Commit the first key.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.bounds().await.end, 3);
            assert_eq!(db.get_metadata().await.unwrap(), metadata.clone());
            // Set the second key.
            db.set(k2, v2.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(db.bounds().await.end, 4);

            // Make sure we can still get metadata.
            assert_eq!(db.get_metadata().await.unwrap(), metadata);

            // Commit the second key.
            db.commit(None).await.unwrap();
            assert_eq!(db.bounds().await.end, 5);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Capture state.
            let root = db.root();

            // Add an uncommitted op then simulate failure.
            let k3 = Sha256::fill(3u8);
            let v3 = vec![9, 10, 11];
            db.set(k3, v3).await.unwrap();
            assert_eq!(db.bounds().await.end, 6);

            // Reopen, make sure state is restored to last commit point.
            drop(db); // Simulate failed commit
            let db = open_db(context.with_label("second")).await;
            assert!(db.get(&k3).await.unwrap().is_none());
            assert_eq!(db.bounds().await.end, 5);
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata().await.unwrap(), None);

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
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.with_label("first")).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.bounds().await.end, ELEMENTS + 1);

            db.commit(None).await.unwrap();
            assert_eq!(db.bounds().await.end, ELEMENTS + 2);

            // Drop & reopen the db, making sure it has exactly the same state.
            let root = db.root();
            drop(db);

            let db = open_db(context.with_label("second")).await;
            assert_eq!(root, db.root());
            assert_eq!(db.bounds().await.end, ELEMENTS + 2);
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
            }

            // Make sure all ranges of 5 operations are provable, including truncated ranges at the
            // end.
            let max_ops = NZU64!(5);
            for i in 0..*db.bounds().await.end {
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
            let mut db = open_db(context.with_label("first")).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.bounds().await.end, ELEMENTS + 1);
            db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            let halfway_root = db.root();

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Commit without merkleizing the MMR, then drop to simulate failure.
            // The commit persists the data to the journal, but the MMR is not synced.
            db.commit(None).await.unwrap();
            drop(db); // Drop before merkleizing

            // Recovery should replay the log to regenerate the MMR.
            // op_count = 1002 (first batch + commit) + 1000 (second batch) + 1 (second commit) = 2003
            let db = open_db(context.with_label("second")).await;
            assert_eq!(db.bounds().await.end, 2003);
            let root = db.root();
            assert_ne!(root, halfway_root);

            // Drop & reopen could preserve the final commit.
            drop(db);
            let db = open_db(context.with_label("third")).await;
            assert_eq!(db.bounds().await.end, 2003);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_log_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("first")).await;

            // Insert a single key and then commit to create a first commit point.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![1, 2, 3];
            db.set(k1, v1).await.unwrap();
            db.commit(None).await.unwrap();
            let first_commit_root = db.root();

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.bounds().await.end, ELEMENTS + 3);

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Simulate failure.
            drop(db);

            // Recovery should back up to previous commit point.
            let db = open_db(context.with_label("second")).await;
            assert_eq!(db.bounds().await.end, 3);
            let root = db.root();
            assert_eq!(root, first_commit_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_pruning() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs then prune some of them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("first")).await;

            for i in 1u64..ELEMENTS+1 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.bounds().await.end, ELEMENTS + 1);

            db.commit(None).await.unwrap();
            assert_eq!(db.bounds().await.end, ELEMENTS + 2);

            // Prune the db to the first half of the operations.
            db.prune(Location::new_unchecked((ELEMENTS+2) / 2))
                .await
                .unwrap();
            let bounds = db.bounds().await;
            assert_eq!(bounds.end, ELEMENTS + 2);

            // items_per_section is 5, so half should be exactly at a blob boundary, in which case
            // the actual pruning location should match the requested.
            let oldest_retained_loc = bounds.start;
            assert_eq!(oldest_retained_loc, Location::new_unchecked(ELEMENTS / 2));

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 1;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Drop & reopen the db, making sure it has exactly the same state.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);

            let mut db = open_db(context.with_label("second")).await;
            assert_eq!(root, db.root());
            let bounds = db.bounds().await;
            assert_eq!(bounds.end, ELEMENTS + 2);
            let oldest_retained_loc = bounds.start;
            assert_eq!(oldest_retained_loc, Location::new_unchecked(ELEMENTS / 2));

            // Prune to a non-blob boundary.
            let loc = Location::new_unchecked(ELEMENTS / 2 + (ITEMS_PER_SECTION * 2 - 1));
            db.prune(loc).await.unwrap();
            // Actual boundary should be a multiple of 5.
            let oldest_retained_loc = db.bounds().await.start;
            assert_eq!(
                oldest_retained_loc,
                Location::new_unchecked(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Confirm boundary persists across restart.
            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.with_label("third")).await;
            let oldest_retained_loc = db.bounds().await.start;
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
            assert!(matches!(proof_result, Err(Error::Journal(crate::journal::Error::ItemPruned(pos))) if pos == pruned_pos));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_immutable_db_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("test")).await;

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

            // op_count is 5 (initial_commit, k1, k2, commit, k3), last_commit is at location 3
            assert_eq!(*db.last_commit_loc, 3);

            // Test valid prune (at last commit)
            db.commit(None).await.unwrap();
            assert!(db.prune(Location::new_unchecked(3)).await.is_ok());

            // Test pruning beyond last commit
            let new_last_commit = db.last_commit_loc;
            let beyond = new_last_commit + 1;
            let result = db.prune(beyond).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == beyond && commit_loc == new_last_commit)
            );

            db.destroy().await.unwrap();
        });
    }

    use crate::{
        kv::tests::{assert_gettable, assert_send},
        qmdb::store::tests::{assert_log_store, assert_merkleized_store},
    };

    type Db = Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    #[allow(dead_code)]
    fn assert_db_futures_are_send(db: &mut Db, key: Digest, value: Vec<u8>, loc: Location) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
        assert_send(db.set(key, value));
        assert_send(db.commit(None));
    }

    #[test_traced("INFO")]
    fn test_immutable_batch_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Keys must be in sorted order for both paths to produce same root.
            let k1 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
            let k2 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2");
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];

            // Build via batch.
            let batch_cfg = db_config("batch", &context);
            let mut batch_db: Db = Immutable::init(context.with_label("batch"), batch_cfg)
                .await
                .unwrap();
            let mut batch = batch_db.new_batch();
            batch.set(k1, v1.clone());
            batch.set(k2, v2.clone());

            // Verify get works during batch.
            assert_eq!(batch.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(batch.get(&k2).await.unwrap().unwrap(), v2);

            let merkleized = batch.merkleize(None);
            let batch_root = merkleized.root();

            // Verify get works on merkleized batch.
            assert_eq!(merkleized.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(merkleized.get(&k2).await.unwrap().unwrap(), v2);

            let finalized = merkleized.finalize();
            batch_db.apply_batch(finalized).await.unwrap();

            // Build via sequential (keys in sorted order).
            let seq_cfg = db_config("sequential", &context);
            let mut seq_db: Db = Immutable::init(context.with_label("sequential"), seq_cfg)
                .await
                .unwrap();
            seq_db.set(k1, v1.clone()).await.unwrap();
            seq_db.set(k2, v2.clone()).await.unwrap();
            seq_db.commit(None).await.unwrap();

            // Roots should match.
            assert_eq!(batch_db.root(), seq_db.root());
            assert_eq!(batch_db.root(), batch_root);

            // State should match.
            assert_eq!(batch_db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(batch_db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(batch_db.bounds().await, seq_db.bounds().await);

            batch_db.destroy().await.unwrap();
            seq_db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_immutable_batch_stacked_equals_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Keys in sorted order for both paths.
            let k1 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
            let k2 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2");
            let k3 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3");
            let k4 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4");
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];
            let v3 = vec![9, 10];
            let v4 = vec![11, 12, 13, 14];

            // Build via stacked batches.
            let batch_cfg = db_config("batch", &context);
            let mut batch_db: Db = Immutable::init(context.with_label("batch"), batch_cfg)
                .await
                .unwrap();
            let mut parent_batch = batch_db.new_batch();
            parent_batch.set(k1, v1.clone());
            parent_batch.set(k2, v2.clone());
            let parent_merkleized = parent_batch.merkleize(None);

            let mut child_batch = parent_merkleized.new_batch();
            child_batch.set(k3, v3.clone());
            child_batch.set(k4, v4.clone());
            let child_merkleized = child_batch.merkleize(None);
            let stacked_root = child_merkleized.root();

            let finalized = child_merkleized.finalize();
            batch_db.apply_batch(finalized).await.unwrap();

            // Build via sequential (keys in sorted order on each commit).
            let seq_cfg = db_config("sequential", &context);
            let mut seq_db: Db = Immutable::init(context.with_label("sequential"), seq_cfg)
                .await
                .unwrap();
            seq_db.set(k1, v1).await.unwrap();
            seq_db.set(k2, v2).await.unwrap();
            seq_db.commit(None).await.unwrap();
            seq_db.set(k3, v3).await.unwrap();
            seq_db.set(k4, v4).await.unwrap();
            seq_db.commit(None).await.unwrap();

            // Roots should match.
            assert_eq!(batch_db.root(), seq_db.root());
            assert_eq!(batch_db.root(), stacked_root);
            assert_eq!(batch_db.bounds().await, seq_db.bounds().await);

            batch_db.destroy().await.unwrap();
            seq_db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_immutable_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let k1 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
            let k2 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2");
            let k3 = Digest::from(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3");
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];
            let v3 = vec![9, 10];

            let db = open_db(context.with_label("db")).await;

            // Create parent batch.
            let mut parent_batch = db.new_batch();
            parent_batch.set(k1, v1.clone());
            parent_batch.set(k2, v2.clone());
            let parent_merkleized = parent_batch.merkleize(None);

            // Child batch should be able to read parent's values.
            let mut child_batch = parent_merkleized.new_batch();
            child_batch.set(k3, v3.clone());

            // Read parent values from child batch.
            assert_eq!(child_batch.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(child_batch.get(&k2).await.unwrap().unwrap(), v2);
            // Read child's own value.
            assert_eq!(child_batch.get(&k3).await.unwrap().unwrap(), v3);

            // Read parent values from parent merkleized.
            assert_eq!(parent_merkleized.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(parent_merkleized.get(&k2).await.unwrap().unwrap(), v2);

            db.destroy().await.unwrap();
        });
    }
}
