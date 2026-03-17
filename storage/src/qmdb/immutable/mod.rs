//! An authenticated database that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.
//!
//! # Examples
//!
//! ```ignore
//! // Simple mode: apply a batch, then durably commit it.
//! let merkleized = db.new_batch()
//!     .set(key, value)
//!     .merkleize(None);
//! let finalized = merkleized.finalize();
//! db.apply_batch(finalized).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Batches can still fork before you apply them.
//! let parent = db.new_batch()
//!     .set(key_a, value_a)
//!     .merkleize(None);
//!
//! let child_a = parent.new_batch::<Sha256>()
//!     .set(key_b, value_b)
//!     .merkleize(None);
//!
//! let child_b = parent.new_batch::<Sha256>()
//!     .set(key_c, value_c)
//!     .merkleize(None);
//!
//! db.apply_batch(child_a.finalize()).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Advanced mode: while the previous batch is being committed, build exactly
//! // one child batch from the newly published state.
//! let parent_finalized = db.new_batch()
//!     .set(key_a, value_a)
//!     .merkleize(None).finalize();
//! db.apply_batch(parent_finalized).await?;
//!
//! let (child_finalized, commit_result) = futures::join!(
//!     async {
//!         db.new_batch()
//!             .set(key_b, value_b)
//!             .merkleize(None).finalize()
//!     },
//!     db.commit(),
//! );
//! commit_result?;
//!
//! db.apply_batch(child_finalized).await?;
//! db.commit().await?;
//! ```

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::{
        authenticated,
        contiguous::{
            variable::{self, Config as JournalConfig},
            Contiguous as _, Reader,
        },
    },
    mmr::{iterator::nodes_to_pin, journaled::Config as MmrConfig, Location, Position, Proof},
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

// Shared read-only functionality.
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
        Location::new(bounds.start)..Location::new(bounds.end)
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

    /// Return the pinned MMR nodes at the given location.
    pub async fn pinned_nodes_at(&self, loc: Location) -> Result<Vec<H::Digest>, Error> {
        let pos = Position::try_from(loc)?;
        let futs: Vec<_> = nodes_to_pin(pos)
            .map(|p| async move {
                self.journal
                    .mmr
                    .get_node(p)
                    .await?
                    .ok_or(crate::mmr::Error::ElementPruned(p).into())
            })
            .collect();
        futures::future::try_join_all(futs).await
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
            let start_loc = Location::new(reader.bounds().start);

            // Build snapshot from the log.
            build_snapshot_from_log(start_loc, &reader, &mut snapshot, |_, _| {}).await?;

            Location::new(
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
    pub async fn sync(&self) -> Result<(), Error> {
        Ok(self.journal.sync().await?)
    }

    /// Durably commit the journal state published by prior [`Immutable::apply_batch`] calls.
    pub async fn commit(&self) -> Result<(), Error> {
        Ok(self.journal.commit().await?)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        Ok(self.journal.destroy().await?)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<H, K, V> {
        let journal_size = *self.last_commit_loc + 1;
        batch::UnmerkleizedBatch::new(self, journal_size)
    }

    /// Apply a changeset to the database.
    ///
    /// A changeset is only valid if the database has not been modified since the batch that
    /// produced it was created. Multiple batches can be forked from the same parent for speculative
    /// execution, but only one may be applied. Applying a stale changeset returns
    /// [`Error::StaleChangeset`].
    ///
    /// Returns the range of locations written.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal, but
    /// does not durably commit it. Call [`Immutable::commit`] to wait for the underlying journal
    /// commit, or [`Immutable::sync`] for a stronger durability boundary.
    pub async fn apply_batch(
        &mut self,
        batch: batch::Changeset<K, H::Digest, V>,
    ) -> Result<Range<Location>, Error> {
        let journal_size = *self.last_commit_loc + 1;
        if batch.db_size != journal_size {
            return Err(Error::StaleChangeset {
                expected: batch.db_size,
                actual: journal_size,
            });
        }
        let start_loc = Location::new(journal_size);

        // Write all operations to the authenticated journal + apply MMR changeset.
        self.journal.apply_batch(batch.journal_finalized).await?;

        // Apply snapshot diffs.
        let bounds = self.journal.reader().await.bounds();
        for diff in batch.snapshot_diffs {
            match diff {
                batch::SnapshotDiff::Insert { key, new_loc } => {
                    self.snapshot
                        .insert_and_prune(&key, new_loc, |v| *v < bounds.start);
                }
            }
        }

        // Update state.
        self.last_commit_loc = Location::new(batch.total_size - 1);

        let end_loc = Location::new(batch.total_size);
        Ok(start_loc..end_loc)
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{mmr::StandardHasher, qmdb::verify_proof, translator::TwoCap};
    use commonware_cryptography::{sha256, sha256::Digest, Sha256};
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
            assert_eq!(bounds.start, Location::new(0));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![4, 5, 6, 7];
            let root = db.root();
            {
                let _batch = db.new_batch().set(k1, v1);
                // Don't merkleize/finalize/apply -- simulate failed commit
            }
            drop(db);
            let mut db = open_db(context.with_label("second")).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.bounds().await.end, 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let finalized = db.new_batch().merkleize(None).finalize();
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
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
            let mut db = open_db(context.with_label("first")).await;

            let k1 = Sha256::fill(1u8);
            let k2 = Sha256::fill(2u8);
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];

            assert!(db.get(&k1).await.unwrap().is_none());
            assert!(db.get(&k2).await.unwrap().is_none());

            // Set and commit the first key.
            let metadata = Some(vec![99, 100]);
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(k1, v1.clone());
                batch.merkleize(metadata.clone()).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.bounds().await.end, 3);
            assert_eq!(db.get_metadata().await.unwrap(), metadata.clone());

            // Set and commit the second key.
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(k2, v2.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(db.bounds().await.end, 5);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Capture state.
            let root = db.root();

            // Add an uncommitted op then simulate failure.
            let k3 = Sha256::fill(3u8);
            let v3 = vec![9, 10, 11];
            {
                let _batch = db.new_batch().set(k3, v3);
                // Don't merkleize/finalize/apply -- simulate failed commit
            }

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

            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![i as u8; 100];
                    batch = batch.set(k, v);
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
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
                let (proof, log) = db.proof(Location::new(i), max_ops).await.unwrap();
                assert!(verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new(i),
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

            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![i as u8; 100];
                    batch = batch.set(k, v);
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.bounds().await.end, ELEMENTS + 2);
            db.sync().await.unwrap();
            let halfway_root = db.root();

            // Insert another 1000 keys then commit.
            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![i as u8; 100];
                    batch = batch.set(k, v);
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            drop(db); // Drop before syncing

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
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(k1, v1);
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            let first_commit_root = db.root();

            // Simulate failure. Sets that are never merkleized/applied are lost.
            // Recovery should restore the last commit point.
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

            // Batch writes keys in BTreeMap-sorted order, so build the sorted key
            // list to map between journal locations and keys.
            let mut sorted_keys: Vec<sha256::Digest> = (1u64..ELEMENTS + 1)
                .map(|i| Sha256::hash(&i.to_be_bytes()))
                .collect();
            sorted_keys.sort();
            // Location 0: initial commit; locations 1..=ELEMENTS: Set ops in sorted
            // key order; location ELEMENTS+1: batch commit.
            // key_at_loc(L) = sorted_keys[L - 1] for 1 <= L <= ELEMENTS.

            let finalized = {
                let mut batch = db.new_batch();
                for i in 1u64..ELEMENTS + 1 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![i as u8; 100];
                    batch = batch.set(k, v);
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.bounds().await.end, ELEMENTS + 2);

            // Prune the db to the first half of the operations.
            db.prune(Location::new((ELEMENTS + 2) / 2))
                .await
                .unwrap();
            let bounds = db.bounds().await;
            assert_eq!(bounds.end, ELEMENTS + 2);

            // items_per_section is 5, so half should be exactly at a blob boundary, in which case
            // the actual pruning location should match the requested.
            let oldest_retained_loc = bounds.start;
            assert_eq!(oldest_retained_loc, Location::new(ELEMENTS / 2));

            // Try to fetch a pruned key (at location oldest_retained - 1).
            let pruned_key = sorted_keys[*oldest_retained_loc as usize - 2];
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key (at location oldest_retained).
            let unpruned_key = sorted_keys[*oldest_retained_loc as usize - 1];
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
            assert_eq!(oldest_retained_loc, Location::new(ELEMENTS / 2));

            // Prune to a non-blob boundary.
            let loc = Location::new(ELEMENTS / 2 + (ITEMS_PER_SECTION * 2 - 1));
            db.prune(loc).await.unwrap();
            // Actual boundary should be a multiple of 5.
            let oldest_retained_loc = db.bounds().await.start;
            assert_eq!(
                oldest_retained_loc,
                Location::new(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Confirm boundary persists across restart.
            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.with_label("third")).await;
            let oldest_retained_loc = db.bounds().await.start;
            assert_eq!(
                oldest_retained_loc,
                Location::new(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Try to fetch a pruned key (at location oldest_retained - 3).
            let pruned_key = sorted_keys[*oldest_retained_loc as usize - 4];
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key (at location oldest_retained).
            let unpruned_key = sorted_keys[*oldest_retained_loc as usize - 1];
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Confirm behavior of trying to create a proof of pruned items is as expected.
            let pruned_pos = ELEMENTS / 2;
            let proof_result = db
                .proof(
                    Location::new(pruned_pos),
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
            let result = db.prune(Location::new(1)).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == Location::new(1) && commit_loc == Location::new(0))
            );

            // Add key-value pairs and commit
            let k1 = Digest::from(*b"12345678901234567890123456789012");
            let k2 = Digest::from(*b"abcdefghijklmnopqrstuvwxyz123456");
            let k3 = Digest::from(*b"99999999999999999999999999999999");
            let v1 = vec![1u8; 16];
            let v2 = vec![2u8; 16];
            let v3 = vec![3u8; 16];

            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(k1, v1.clone());
                batch = batch.set(k2, v2.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // op_count is 4 (initial_commit, k1, k2, commit), last_commit is at location 3
            assert_eq!(*db.last_commit_loc, 3);

            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(k3, v3.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // Test valid prune (at previous commit location 3)
            assert!(db.prune(Location::new(3)).await.is_ok());

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

    type Db = Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_db_futures_are_send(db: &mut Db, key: Digest, loc: Location) {
        is_send(db.get(&key));
        is_send(db.get_metadata());
        is_send(db.proof(loc, NZU64!(1)));
        is_send(db.sync());
    }

    /// batch.get() reads pending mutations and falls through to base DB.
    #[test_traced("INFO")]
    fn test_immutable_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = db_config("readthrough", &context);
            let mut db: Db = Immutable::init(context.with_label("db"), cfg)
                .await
                .unwrap();

            // Pre-populate with key A.
            let key_a = Sha256::hash(&0u64.to_be_bytes());
            let val_a = vec![1u8; 8];
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(key_a, val_a.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // batch.get(&A) should return DB value.
            let mut batch = db.new_batch();
            assert_eq!(batch.get(&key_a, &db).await.unwrap(), Some(val_a));

            // Set B in batch, batch.get(&B) returns the value.
            let key_b = Sha256::hash(&1u64.to_be_bytes());
            let val_b = vec![2u8; 8];
            batch = batch.set(key_b, val_b.clone());
            assert_eq!(batch.get(&key_b, &db).await.unwrap(), Some(val_b));

            // Nonexistent key.
            let key_c = Sha256::hash(&2u64.to_be_bytes());
            assert_eq!(batch.get(&key_c, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Child batch reads parent diff and adds its own mutations.
    #[test_traced("INFO")]
    fn test_immutable_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = db_config("stacked-get", &context);
            let db: Db = Immutable::init(context.with_label("db"), cfg)
                .await
                .unwrap();

            // Parent batch: set A.
            let key_a = Sha256::hash(&0u64.to_be_bytes());
            let val_a = vec![10u8; 8];
            let mut parent = db.new_batch();
            parent = parent.set(key_a, val_a.clone());
            let parent_m = parent.merkleize(None);

            // Child reads parent's A.
            let mut child = parent_m.new_batch::<Sha256>();
            assert_eq!(child.get(&key_a, &db).await.unwrap(), Some(val_a));

            // Child sets B.
            let key_b = Sha256::hash(&1u64.to_be_bytes());
            let val_b = vec![20u8; 8];
            child = child.set(key_b, val_b.clone());
            assert_eq!(child.get(&key_b, &db).await.unwrap(), Some(val_b));

            // Nonexistent key.
            let key_c = Sha256::hash(&2u64.to_be_bytes());
            assert_eq!(child.get(&key_c, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Two-level stacked batch finalize and apply works end-to-end.
    #[test_traced("INFO")]
    fn test_immutable_batch_stacked_finalize_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = db_config("stacked-apply", &context);
            let mut db: Db = Immutable::init(context.with_label("db"), cfg)
                .await
                .unwrap();

            // Sort keys so operations are in BTreeMap order (same as merkleize writes).
            let mut kvs_first: Vec<(Digest, Vec<u8>)> = (0u64..5)
                .map(|i| (Sha256::hash(&i.to_be_bytes()), vec![i as u8; 8]))
                .collect();
            kvs_first.sort_by(|a, b| a.0.cmp(&b.0));

            let mut kvs_second: Vec<(Digest, Vec<u8>)> = (5u64..10)
                .map(|i| (Sha256::hash(&i.to_be_bytes()), vec![i as u8; 8]))
                .collect();
            kvs_second.sort_by(|a, b| a.0.cmp(&b.0));

            // Parent batch: set keys 0..5.
            let mut parent = db.new_batch();
            for (k, v) in &kvs_first {
                parent = parent.set(*k, v.clone());
            }
            let parent_m = parent.merkleize(None);

            // Child batch: set keys 5..10.
            let mut child = parent_m.new_batch::<Sha256>();
            for (k, v) in &kvs_second {
                child = child.set(*k, v.clone());
            }
            let child_m = child.merkleize(None);
            let expected_root = child_m.root();
            let finalized = child_m.finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(db.root(), expected_root);

            // All 10 keys should be accessible.
            for (k, v) in kvs_first.iter().chain(kvs_second.iter()) {
                assert_eq!(db.get(k).await.unwrap(), Some(v.clone()));
            }

            db.destroy().await.unwrap();
        });
    }

    /// MerkleizedBatch::root() matches db.root() after apply_batch().
    #[test_traced("INFO")]
    fn test_immutable_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let merkleized = {
                let mut batch = db.new_batch();
                for i in 0u8..10 {
                    let k = Sha256::hash(&[i]);
                    batch = batch.set(k, vec![i; 16]);
                }
                batch.merkleize(None)
            };

            let speculative = merkleized.root();
            let finalized = merkleized.finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.root(), speculative);

            // Second batch with metadata.
            let metadata = vec![55u8; 8];
            let merkleized = {
                let mut batch = db.new_batch();
                let k = Sha256::hash(&[0xAA]);
                batch = batch.set(k, vec![0xAA; 20]);
                batch.merkleize(Some(metadata))
            };
            let speculative = merkleized.root();
            let finalized = merkleized.finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.root(), speculative);

            db.destroy().await.unwrap();
        });
    }

    /// MerkleizedBatch::get() reads from diff and base DB.
    #[test_traced("INFO")]
    fn test_immutable_merkleized_batch_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            // Pre-populate base DB.
            let key_a = Sha256::hash(&0u64.to_be_bytes());
            let val_a = vec![10u8; 12];
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(key_a, val_a.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // Create a merkleized batch with a new key.
            let key_b = Sha256::hash(&1u64.to_be_bytes());
            let val_b = vec![20u8; 16];
            let mut batch = db.new_batch();
            batch = batch.set(key_b, val_b.clone());
            let merkleized = batch.merkleize(None);

            // Read base DB value through merkleized batch.
            assert_eq!(merkleized.get(&key_a, &db).await.unwrap(), Some(val_a));

            // Read this batch's key from the diff.
            assert_eq!(merkleized.get(&key_b, &db).await.unwrap(), Some(val_b));

            // Nonexistent key.
            let key_c = Sha256::hash(&2u64.to_be_bytes());
            assert_eq!(merkleized.get(&key_c, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Independent sequential batches applied one at a time.
    #[test_traced("INFO")]
    fn test_immutable_batch_sequential_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key_a = Sha256::hash(&0u64.to_be_bytes());
            let val_a = vec![1u8; 8];

            // First batch.
            let mut batch = db.new_batch();
            batch = batch.set(key_a, val_a.clone());
            let m = batch.merkleize(None);
            let root1 = m.root();
            db.apply_batch(m.finalize()).await.unwrap();
            assert_eq!(db.root(), root1);
            assert_eq!(db.get(&key_a).await.unwrap(), Some(val_a));

            // Second independent batch.
            let key_b = Sha256::hash(&1u64.to_be_bytes());
            let val_b = vec![2u8; 16];
            let mut batch = db.new_batch();
            batch = batch.set(key_b, val_b.clone());
            let m = batch.merkleize(None);
            let root2 = m.root();
            db.apply_batch(m.finalize()).await.unwrap();
            assert_eq!(db.root(), root2);
            assert_eq!(db.get(&key_b).await.unwrap(), Some(val_b));

            db.destroy().await.unwrap();
        });
    }

    /// Many sequential batches accumulate correctly.
    #[test_traced("INFO")]
    fn test_immutable_batch_many_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;
            let mut hasher = StandardHasher::<Sha256>::new();

            const BATCHES: u64 = 20;
            const KEYS_PER_BATCH: u64 = 5;

            let mut all_kvs: Vec<(Digest, Vec<u8>)> = Vec::new();

            for batch_idx in 0..BATCHES {
                let finalized = {
                    let mut batch = db.new_batch();
                    for j in 0..KEYS_PER_BATCH {
                        let seed = batch_idx * 100 + j;
                        let k = Sha256::hash(&seed.to_be_bytes());
                        let v = vec![seed as u8; 8];
                        batch = batch.set(k, v.clone());
                        all_kvs.push((k, v));
                    }
                    batch.merkleize(None).finalize()
                };
                db.apply_batch(finalized).await.unwrap();
            }

            // Verify all key-values are readable.
            for (k, v) in &all_kvs {
                assert_eq!(db.get(k).await.unwrap(), Some(v.clone()));
            }

            // Verify proof over the full range.
            let root = db.root();
            let (proof, ops) = db.proof(Location::new(0), NZU64!(10000)).await.unwrap();
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new(0),
                &ops,
                &root
            ));

            // Expected: 1 initial commit + BATCHES * (KEYS_PER_BATCH + 1 commit).
            let expected = 1 + BATCHES * (KEYS_PER_BATCH + 1);
            assert_eq!(db.bounds().await.end, expected);

            db.destroy().await.unwrap();
        });
    }

    /// Empty batch (zero mutations) produces correct speculative root.
    #[test_traced("INFO")]
    fn test_immutable_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            // Apply a non-empty batch first.
            let finalized = {
                let mut batch = db.new_batch();
                let k = Sha256::hash(&[1u8]);
                batch = batch.set(k, vec![1u8; 8]);
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            let root_before = db.root();
            let size_before = db.bounds().await.end;

            // Empty batch with no mutations.
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
        });
    }

    /// MerkleizedBatch::get() works on a chained child's merkleized batch.
    #[test_traced("INFO")]
    fn test_immutable_batch_chained_merkleized_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            // Pre-populate base DB.
            let key_a = Sha256::hash(&0u64.to_be_bytes());
            let val_a = vec![10u8; 12];
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(key_a, val_a.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // Parent batch sets key B.
            let key_b = Sha256::hash(&1u64.to_be_bytes());
            let val_b = vec![1u8; 8];
            let mut parent = db.new_batch();
            parent = parent.set(key_b, val_b.clone());
            let parent_m = parent.merkleize(None);

            // Child batch sets key C.
            let key_c = Sha256::hash(&2u64.to_be_bytes());
            let val_c = vec![2u8; 16];
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.set(key_c, val_c.clone());
            let child_m = child.merkleize(None);

            // Child's MerkleizedBatch can read all three layers:
            // base DB value
            assert_eq!(child_m.get(&key_a, &db).await.unwrap(), Some(val_a));
            // parent diff value
            assert_eq!(child_m.get(&key_b, &db).await.unwrap(), Some(val_b));
            // child's own value
            assert_eq!(child_m.get(&key_c, &db).await.unwrap(), Some(val_c));
            // nonexistent key
            let key_d = Sha256::hash(&3u64.to_be_bytes());
            assert_eq!(child_m.get(&key_d, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Large single batch, verifying all values and proof.
    #[test_traced("INFO")]
    fn test_immutable_batch_large() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;
            let mut hasher = StandardHasher::<Sha256>::new();

            const N: u64 = 500;
            let mut kvs: Vec<(Digest, Vec<u8>)> = Vec::new();

            let finalized = {
                let mut batch = db.new_batch();
                for i in 0..N {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 256) as u8; ((i % 29) + 3) as usize];
                    batch = batch.set(k, v.clone());
                    kvs.push((k, v));
                }
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // Verify every value.
            for (k, v) in &kvs {
                assert_eq!(db.get(k).await.unwrap(), Some(v.clone()));
            }

            // Verify proof over the full range.
            let root = db.root();
            let (proof, ops) = db.proof(Location::new(0), NZU64!(1000)).await.unwrap();
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new(0),
                &ops,
                &root
            ));

            // Expected: 1 initial commit + N sets + 1 commit.
            assert_eq!(db.bounds().await.end, 1 + N + 1);

            db.destroy().await.unwrap();
        });
    }

    /// Child batch overrides same key set by parent.
    #[test_traced("INFO")]
    fn test_immutable_batch_chained_key_override() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key = Sha256::hash(&0u64.to_be_bytes());
            let val_parent = vec![1u8; 8];
            let val_child = vec![2u8; 16];

            // Parent sets key.
            let mut parent = db.new_batch();
            parent = parent.set(key, val_parent.clone());
            let parent_m = parent.merkleize(None);

            // Child overrides same key.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.set(key, val_child.clone());

            // Child's pending mutation wins over parent diff.
            assert_eq!(child.get(&key, &db).await.unwrap(), Some(val_child.clone()));

            let child_m = child.merkleize(None);

            // After merkleize, child's diff wins.
            assert_eq!(
                child_m.get(&key, &db).await.unwrap(),
                Some(val_child.clone())
            );

            // Apply and verify.
            let finalized = child_m.finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(val_child));

            db.destroy().await.unwrap();
        });
    }

    /// Same key set across two sequential applied batches. The immutable DB
    /// keeps all versions -- `get()` returns the earliest non-pruned value.
    /// After pruning the first version, `get()` returns the second.
    #[test_traced("INFO")]
    fn test_immutable_batch_sequential_key_override() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                // Use items_per_section=1 so pruning is granular.
                log_items_per_section: NZU64!(1),
                ..db_config("key-override", &context)
            };
            let mut db: Db = Immutable::init(context.with_label("db"), cfg)
                .await
                .unwrap();

            let key = Sha256::hash(&0u64.to_be_bytes());
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 16];

            // First batch sets key.
            // Layout: 0=initial commit, 1=Set(key,v1), 2=Commit
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(key, v1.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(v1.clone()));

            // Second batch sets same key to different value.
            // Layout continues: 3=Set(key,v2), 4=Commit
            let finalized = {
                let mut batch = db.new_batch();
                batch = batch.set(key, v2.clone());
                batch.merkleize(None).finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // Immutable DB returns the earliest non-pruned value.
            assert_eq!(db.get(&key).await.unwrap(), Some(v1.clone()));

            // Prune past the first Set (loc 1). With items_per_section=1,
            // pruning to loc 2 should remove the blob containing loc 1.
            db.prune(Location::new(2)).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(v2.clone()));

            // Verify persists across reopen.
            db.sync().await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    /// Metadata propagates through merkleize and clears with None.
    #[test_traced("INFO")]
    fn test_immutable_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            // Batch with metadata.
            let metadata = vec![42u8; 32];
            let finalized = {
                let mut batch = db.new_batch();
                let k = Sha256::hash(&[1u8]);
                batch = batch.set(k, vec![1u8; 8]);
                batch.merkleize(Some(metadata.clone())).finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Second batch clears metadata.
            let finalized = db.new_batch().merkleize(None).finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create two batches from the same DB state.
            let changeset_a = {
                let mut batch = db.new_batch();
                batch = batch.set(key1, vec![10]);
                batch.merkleize(None).finalize()
            };
            let changeset_b = {
                let mut batch = db.new_batch();
                batch = batch.set(key2, vec![20]);
                batch.merkleize(None).finalize()
            };

            // Apply the first -- should succeed.
            db.apply_batch(changeset_a).await.unwrap();
            let expected_root = db.root();
            let expected_bounds = db.bounds().await;
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), None);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Apply the second -- should fail because the DB was modified.
            let result = db.apply_batch(changeset_b).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset error, got {result:?}"
            );
            assert_eq!(db.root(), expected_root);
            assert_eq!(db.bounds().await, expected_bounds);
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), None);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);
            let key3 = Sha256::hash(&[3]);

            // Parent batch.
            let mut parent = db.new_batch();
            parent = parent.set(key1, vec![1]);
            let parent_m = parent.merkleize(None);

            // Fork two children from the same parent.
            let child_a = {
                let mut batch = parent_m.new_batch::<Sha256>();
                batch = batch.set(key2, vec![2]);
                batch.merkleize(None).finalize()
            };
            let child_b = {
                let mut batch = parent_m.new_batch::<Sha256>();
                batch = batch.set(key3, vec![3]);
                batch.merkleize(None).finalize()
            };

            // Apply child A.
            db.apply_batch(child_a).await.unwrap();

            // Child B is stale.
            let result = db.apply_batch(child_b).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset error, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_parent_applied_before_child() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Parent batch.
            let mut parent = db.new_batch();
            parent = parent.set(key1, vec![1]);
            let parent_m = parent.merkleize(None);

            // Child batch.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.set(key2, vec![2]);
            let child_changeset = child.merkleize(None).finalize();

            // Apply parent first.
            let parent_changeset = parent_m.finalize();
            db.apply_batch(parent_changeset).await.unwrap();

            // Child is stale because it expected to be applied on top of the
            // pre-parent DB state.
            let result = db.apply_batch(child_changeset).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset error, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Apply parent via finalize(), then child via finalize_from(). Both keys present.
    #[test_traced]
    fn test_immutable_finalize_from() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Parent batch.
            let mut parent = db.new_batch();
            parent = parent.set(key1, vec![1]);
            let parent_m = parent.merkleize(None);

            // Child batch built on parent.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.set(key2, vec![2]);
            let child_m = child.merkleize(None);

            // Apply parent first.
            db.apply_batch(parent_m.finalize()).await.unwrap();
            let current_db_size = *db.last_commit_loc + 1;

            // Apply child via finalize_from (rebased onto committed parent).
            db.apply_batch(child_m.finalize_from(current_db_size))
                .await
                .unwrap();

            // Both keys present.
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![1]));
            assert_eq!(db.get(&key2).await.unwrap(), Some(vec![2]));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_child_applied_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Parent batch.
            let mut parent = db.new_batch();
            parent = parent.set(key1, vec![1]);
            let parent_m = parent.merkleize(None);

            // Child batch. Finalize both before applying either so the
            // borrow on `db` through `parent_m` is released.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.set(key2, vec![2]);
            let child_changeset = child.merkleize(None).finalize();
            let parent_changeset = parent_m.finalize();

            // Apply child first (it carries all parent ops too).
            db.apply_batch(child_changeset).await.unwrap();

            // Parent is stale.
            let result = db.apply_batch(parent_changeset).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset error, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// to_batch() creates an owned snapshot whose root matches the committed DB.
    /// A child batch chained from it can be applied.
    #[test_traced]
    fn test_immutable_to_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await;

            // Populate.
            let key1 = Sha256::hash(&[1]);
            let mut batch = db.new_batch();
            batch = batch.set(key1, vec![10]);
            db.apply_batch(batch.merkleize(None).finalize())
                .await
                .unwrap();

            // to_batch root matches committed root.
            let snapshot = db.to_batch();
            assert_eq!(snapshot.root(), db.root());

            // Chain a child from the snapshot, apply it.
            let key2 = Sha256::hash(&[2]);
            let child = snapshot
                .new_batch::<Sha256>()
                .set(key2, vec![20])
                .merkleize(None);
            db.apply_batch(child.finalize()).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), Some(vec![20]));

            db.destroy().await.unwrap();
        });
    }
}
