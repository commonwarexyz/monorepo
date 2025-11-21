//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use the dbs in [crate::adb::any::fixed]
//! instead for better performance._

use crate::{
    adb::{
        any::OperationLog,
        operation::{variable::Operation, Committable as _},
        store::Db,
        Error,
    },
    index::{unordered::Index, Unordered as _},
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, Location, Proof, StandardHasher},
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use commonware_utils::Array;
use std::num::{NonZeroU64, NonZeroUsize};

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the log of operations.
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

type Contiguous<E, K, V> = Journal<E, Operation<K, V>>;

type AuthenticatedLog<E, K, V, H> =
    authenticated::Journal<E, Contiguous<E, K, V>, Operation<K, V>, H>;

type AnyLog<E, K, V, H, T> =
    OperationLog<E, Contiguous<E, K, V>, Operation<K, V>, Index<T, Location>, H, T>;

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key.
pub struct Any<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator> {
    /// The authenticated log of [Operation]s.
    log: AnyLog<E, K, V, H, T>,
}

impl<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns a [Any] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mmr_config = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        };

        let journal_config = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_section,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.log_write_buffer,
        };

        let log = AuthenticatedLog::<E, K, V, H>::new(
            context.with_label("log"),
            mmr_config,
            journal_config,
            Operation::<K, V>::is_commit,
        )
        .await?;

        let snapshot = Index::init(context.with_label("snapshot"), cfg.translator);
        let log = OperationLog::init(log, snapshot, |_, _| {}).await?;

        Ok(Self { log })
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_loc()
    }

    /// Return the location before which all operations have been pruned.
    pub fn pruning_boundary(&self) -> Location {
        self.log.pruning_boundary()
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.log.inactivity_floor_loc
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut StandardHasher<H>) -> H::Digest {
        self.log.root(hasher)
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
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= [Self::op_count].
    /// Returns [crate::mmr::Error::ElementPruned] if some element needed to generate the proof has been pruned.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `op_count` or `start_loc` >
    /// self.op_count().
    /// Returns [crate::mmr::Error::ElementPruned] if some element needed to generate the proof
    /// has been pruned.
    ///
    /// # Panics
    ///
    /// Panics if there are uncommitted operations.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.log
            .historical_proof(op_count, start_loc, max_ops)
            .await
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.log.raise_floor().await?;

        // Commit the log to ensure this commit is durable.
        self.log
            .commit(Operation::CommitFloor(metadata, inactivity_floor_loc))
            .await
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    ///
    /// # Errors
    ///
    /// Returns Error if there is some underlying storage failure.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(last_commit) = self.log.last_commit else {
            return Ok(None);
        };

        let Operation::CommitFloor(metadata, _) = self.log.read(last_commit).await? else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Simulate an unclean shutdown by consuming the db. If commit_log is true, the underlying
    /// authenticated log will be be committed before consuming.
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(mut self, commit_log: bool) -> Result<(), Error> {
        if commit_log {
            self.log.log.commit().await?;
        }

        Ok(())
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator> Db<K, V>
    for Any<E, K, V, H, T>
{
    fn op_count(&self) -> Location {
        self.log.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.log.inactivity_floor_loc
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.log.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.log
            .update_key_with_op(Operation::Update(key, value))
            .await
            .map(|_| ())
    }

    async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        self.log
            .create_key_with_op(Operation::Update(key, value))
            .await
    }

    async fn delete(&mut self, key: K) -> Result<bool, Error> {
        self.log
            .delete_key(Operation::Delete(key))
            .await
            .map(|o| o.is_some())
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.log.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.log.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};
    use std::collections::HashMap;

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn db_config(suffix: &str) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_section: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AnyTest = Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_commit_on_empty_db() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = StandardHasher::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.log.oldest_retained_loc(), None);
            assert_eq!(db.log.pruning_boundary(), Location::new_unchecked(0));
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            let empty_root = db.root(&mut hasher);
            assert_eq!(empty_root, MemMmr::default().root(&mut hasher));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Sha256::fill(1u8);
            let v1 = vec![1u8; 8];
            db.update(d1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), empty_root);
            assert_eq!(db.op_count(), 0);

            let empty_proof = Proof::default();
            assert!(verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &empty_root
            ));

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

            // Re-opening the DB without a clean shutdown should still recover the correct state.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(&mut hasher), root);

            // Empty proof should no longer verify.
            assert!(!verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &root
            ));

            // Single op proof should verify.
            let (proof, ops) = db
                .proof(Location::new_unchecked(0), NZU64!(1))
                .await
                .unwrap();
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root
            ));

            // Add one more op.
            db.commit(None).await.unwrap();
            // Historical proof from larger db should match proof from smaller db.
            let (proof2, ops2) = db
                .historical_proof(
                    Location::new_unchecked(1),
                    Location::new_unchecked(0),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(proof, proof2);
            assert_eq!(ops, ops2);

            // Proof will not verify against the root of the bigger db.
            let root2 = db.root(&mut hasher);
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root2
            ));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            db.update(d1, vec![2u8; 20]).await.unwrap();
            for _ in 1..100 {
                db.commit(None).await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.op_count() - db.log.inactivity_floor_loc <= 3);
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 20];

            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());

            assert!(db.create(d1, v1.clone()).await.unwrap());
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v1);
            assert!(db.get(&d2).await.unwrap().is_none());

            assert!(db.create(d2, v1.clone()).await.unwrap());
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

            db.delete(d1).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

            db.update(d1, v2.clone()).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

            db.update(d2, v1.clone()).await.unwrap();
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

            assert_eq!(db.op_count(), 5); // 4 updates, 1 deletion.
            assert_eq!(db.log.snapshot.keys(), 2);
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(0));
            db.commit(None).await.unwrap();

            // Make sure create won't modify active keys.
            assert!(!db.create(d1, v1.clone()).await.unwrap());
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

            // Should have moved 3 active operations to tip, leading to floor of 6.
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(6));
            assert_eq!(db.op_count(), 9); // floor of 6 + 2 active keys + 1 commit.

            // Delete all keys.
            assert!(db.delete(d1).await.unwrap());
            assert!(db.delete(d2).await.unwrap());
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 11); // 2 new delete ops.
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(6));

            db.commit(None).await.unwrap();
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(11));
            assert_eq!(db.op_count(), 12); // only commit should remain.

            // Multiple deletions of the same key should be a no-op.
            assert!(!db.delete(d1).await.unwrap());
            assert_eq!(db.op_count(), 12);

            // Deletions of non-existent keys should be a no-op.
            let d3 = Sha256::fill(3u8);
            assert!(!db.delete(d3).await.unwrap());
            assert_eq!(db.op_count(), 12);

            // Make sure closing/reopening gets us back to the same state.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.op_count(), 13);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 13);
            assert_eq!(db.root(&mut hasher), root);

            // Make sure we can still get the metadata.
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(12), metadata))
            );

            // Re-activate the keys by updating them.
            db.update(d1, v1.clone()).await.unwrap();
            db.update(d2, v2.clone()).await.unwrap();
            db.delete(d1).await.unwrap();
            db.update(d2, v1.clone()).await.unwrap();
            db.update(d1, v2.clone()).await.unwrap();
            assert_eq!(db.log.snapshot.keys(), 2);

            // Make sure last_commit is updated by changing the metadata back to None.
            db.commit(None).await.unwrap();
            let metadata = db.get_metadata().await.unwrap();
            assert_eq!(metadata, Some((Location::new_unchecked(21), None)));

            // Confirm close/reopen gets us back to the same state.
            assert_eq!(db.op_count(), 22);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;

            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.log.snapshot.keys(), 2);
            assert_eq!(db.op_count(), 22);
            let metadata = db.get_metadata().await.unwrap();
            assert_eq!(metadata, Some((Location::new_unchecked(21), None)));

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit(None).await.unwrap();

            assert!(db.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root(&mut hasher);
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.snapshot.keys(), 2);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(0));
            assert_eq!(
                db.log.oldest_retained_loc().unwrap(),
                Location::new_unchecked(0)
            ); // no pruning yet
            assert_eq!(db.log.snapshot.items(), 857);

            // Test that commit will raise the activity floor.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(837));
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(
                db.log.oldest_retained_loc().unwrap(),
                Location::new_unchecked(833),
            );
            assert_eq!(db.log.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(837));
            assert_eq!(db.log.snapshot.items(), 857);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(837));
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.log.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = NZU64!(4);
            let end_loc = db.op_count();
            let start_pos = db.log.log.mmr.pruned_to_pos();
            let start_loc = Location::try_from(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.commit(None).await.unwrap();

            let root = db.root(&mut hasher);
            assert!(start_loc < db.log.inactivity_floor_loc);

            for loc in *start_loc..*end_loc {
                let (proof, log) = db
                    .proof(Location::new_unchecked(loc), max_ops)
                    .await
                    .unwrap();
                assert!(verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(loc),
                    &log,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    pub fn test_any_variable_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone()).await;
            let iter = db.log.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&(j * 1000 + i).to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                    db.update(k, v.clone()).await.unwrap();
                    map.insert(k, v);
                }
                db.commit(None).await.unwrap();
            }
            let k = Sha256::hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit(None).await.unwrap();
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert!(db.get(&k).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root(&mut hasher);
            assert_eq!(db.op_count(), 1960);
            assert_eq!(
                Location::try_from(db.log.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1960))
            );
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(755));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.log.inactivity_floor_loc).await.unwrap();
            assert_eq!(
                db.log.oldest_retained_loc().unwrap(),
                Location::new_unchecked(749)
            );
            assert_eq!(db.log.snapshot.items(), 857);

            // Confirm state is preserved after close and reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 1960);
            assert_eq!(
                Location::try_from(db.log.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1960))
            );
            assert_eq!(db.log.inactivity_floor_loc, Location::new_unchecked(755));
            assert_eq!(
                db.log.oldest_retained_loc().unwrap(),
                Location::new_unchecked(749)
            );
            assert_eq!(db.log.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root(&mut hasher);
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_more_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.log.inactivity_floor_loc, inactivity_floor_loc);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the log).
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.update(key1, vec![10]).await.unwrap();
            db.update(key2, vec![20]).await.unwrap();
            db.update(key3, vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }
}
