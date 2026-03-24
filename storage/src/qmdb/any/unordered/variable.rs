//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::unordered::fixed]
//! instead for better performance._

use crate::{
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{unordered, value::VariableEncoding, VariableConfig, VariableValue},
        operation::Key,
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

pub type Update<K, V> = unordered::Update<K, VariableEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<E, K, V, H, T> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>>;

impl<E: Storage + Clock + Metrics, K: Key, V: VariableValue, H: Hasher, T: Translator>
    Db<E, K, V, H, T>
where
    Operation<K, V>: Codec,
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        Self::init_with_callback(context, cfg, None, |_, _| {}).await
    }

    /// Initialize the DB, invoking `callback` for each operation processed during recovery.
    ///
    /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the
    /// snapshot is built from the log, `callback` is invoked for each operation with its activity
    /// status and previous location (if any).
    pub(crate) async fn init_with_callback(
        context: E,
        cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        crate::qmdb::any::init(context, cfg, known_inactivity_floor, callback).await
    }
}

/// Partitioned index variants that divide the key space into `2^(P*8)` partitions.
///
/// See [partitioned::Db] for the generic type, or use the convenience aliases:
/// - [partitioned::p256::Db] for 256 partitions (P=1)
/// - [partitioned::p64k::Db] for 65,536 partitions (P=2)
pub mod partitioned {
    pub use super::{Operation, Update};
    use crate::{
        index::partitioned::unordered::Index,
        journal::contiguous::variable::Journal,
        mmr::Location,
        qmdb::{
            any::{VariableConfig, VariableValue},
            operation::Key,
            Error,
        },
        translator::Translator,
    };
    use commonware_codec::{Codec, Read};
    use commonware_cryptography::Hasher;
    use commonware_runtime::{Clock, Metrics, Storage};

    /// A key-value QMDB with a partitioned snapshot index and variable-size values.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<E, K, V, H, T, const P: usize> = crate::qmdb::any::unordered::Db<
        E,
        Journal<E, Operation<K, V>>,
        Index<T, Location, P>,
        H,
        Update<K, V>,
    >;

    impl<
            E: Storage + Clock + Metrics,
            K: Key,
            V: VariableValue,
            H: Hasher,
            T: Translator,
            const P: usize,
        > Db<E, K, V, H, T, P>
    where
        Operation<K, V>: Codec,
    {
        /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
        /// discarded and the state of the db will be as of the last committed operation.
        pub async fn init(
            context: E,
            cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
        ) -> Result<Self, Error> {
            Self::init_with_callback(context, cfg, None, |_, _| {}).await
        }

        /// Initialize the DB, invoking `callback` for each operation processed during recovery.
        ///
        /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
        /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the
        /// snapshot is built from the log, `callback` is invoked for each operation with its activity
        /// status and previous location (if any).
        pub(crate) async fn init_with_callback(
            context: E,
            cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
            known_inactivity_floor: Option<Location>,
            callback: impl FnMut(bool, Option<Location>),
        ) -> Result<Self, Error> {
            crate::qmdb::any::init(context, cfg, known_inactivity_floor, callback).await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Variable-value DB with 256 partitions.
        pub type Db<E, K, V, H, T> = super::Db<E, K, V, H, T, 1>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Variable-value DB with 65,536 partitions.
        pub type Db<E, K, V, H, T> = super::Db<E, K, V, H, T, 2>;
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{index::Unordered as _, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Runner as _,
    };
    use commonware_utils::{test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    pub(crate) fn create_test_config(seed: u64, pooler: &impl BufferPooler) -> VarConfig {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        VariableConfig {
            mmr_config: crate::mmr::journaled::Config {
                journal_partition: format!("journal-{seed}"),
                metadata_partition: format!("metadata-{seed}"),
                items_per_blob: NZU64!(13),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: crate::journal::contiguous::variable::Config {
                partition: format!("log-journal-{seed}"),
                items_per_section: NZU64!(7),
                write_buffer: NZUsize!(1024),
                compression: None,
                codec_config: ((), ((0..=10000).into(), ())),
                page_cache,
            },
            translator: TwoCap,
        }
    }

    pub(crate) type VarConfig =
        VariableConfig<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))>;

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest = Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed, &context);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Deterministic byte vector generator for variable-value tests.
    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Create n random operations using the default seed (0). Some portion of
    /// the updates are deletes. create_test_ops(n) is a prefix of
    /// create_test_ops(n') for n < n'.
    pub(crate) fn create_test_ops(
        n: usize,
    ) -> Vec<unordered::Operation<Digest, VariableEncoding<Vec<u8>>>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed. Use different seeds
    /// when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(
        n: usize,
        seed: u64,
    ) -> Vec<unordered::Operation<Digest, VariableEncoding<Vec<u8>>>> {
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(unordered::Operation::Delete(prev_key));
            } else {
                let value = to_bytes(rng.next_u64());
                ops.push(unordered::Operation::Update(unordered::Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(
        db: &mut AnyTest,
        ops: Vec<unordered::Operation<Digest, VariableEncoding<Vec<u8>>>>,
    ) {
        let finalized = {
            let mut batch = db.new_batch();
            for op in ops {
                match op {
                    unordered::Operation::Update(unordered::Update(key, value)) => {
                        batch = batch.write(key, Some(value));
                    }
                    unordered::Operation::Delete(key) => {
                        batch = batch.write(key, None);
                    }
                    unordered::Operation::CommitFloor(_, _) => {
                        panic!("CommitFloor not supported in apply_ops");
                    }
                }
            }
            batch.merkleize(None, db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();
    }

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        let cfg = create_test_config(0, &context);
        AnyTest::init(context, cfg).await.unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            crate::qmdb::any::test::test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let db = open_db(context.with_label("open1")).await;
            let root = db.root();

            // Build a batch but don't apply it (simulate failure before commit).
            {
                let mut batch = db.new_batch();
                for i in 0..ELEMENTS {
                    batch = batch.write(
                        Sha256::hash(&i.to_be_bytes()),
                        Some(vec![(i % 255) as u8; ((i % 13) + 7) as usize]),
                    );
                }
                let _ = batch.merkleize(None, &db).await.unwrap().finalize();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open2")).await;
            assert_eq!(root, db.root());

            // Re-apply the updates and commit them this time.
            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                    batch = batch.write(k, Some(v));
                }
                batch.merkleize(None, &db).await.unwrap().finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            let root = db.root();

            // Update every 3rd key but don't apply (simulate failure).
            {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    if i % 3 != 0 {
                        continue;
                    }
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                    batch = batch.write(k, Some(v));
                }
                let _ = batch.merkleize(None, &db).await.unwrap().finalize();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open3")).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    if i % 3 != 0 {
                        continue;
                    }
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                    batch = batch.write(k, Some(v));
                }
                batch.merkleize(None, &db).await.unwrap().finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            let root = db.root();

            // Delete every 7th key but don't apply (simulate failure).
            {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    if i % 7 != 1 {
                        continue;
                    }
                    let k = Sha256::hash(&i.to_be_bytes());
                    batch = batch.write(k, None);
                }
                let _ = batch.merkleize(None, &db).await.unwrap().finalize();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open4")).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    if i % 7 != 1 {
                        continue;
                    }
                    let k = Sha256::hash(&i.to_be_bytes());
                    batch = batch.write(k, None);
                }
                batch.merkleize(None, &db).await.unwrap().finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();

            let root = db.root();
            let inactivity_floor = db.inactivity_floor_loc();
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(inactivity_floor).await.unwrap();
            let bounds = db.bounds().await;
            let snapshot_items = db.snapshot.items();

            db.sync().await.unwrap();
            drop(db);

            // Confirm state is preserved after reopen.
            let db = open_db(context.with_label("open5")).await;
            assert_eq!(root, db.root());
            assert_eq!(db.bounds().await, bounds);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor);
            assert_eq!(db.snapshot.items(), snapshot_items);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_any_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            let finalized = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .write(key2, Some(vec![20]))
                .write(key3, Some(vec![30]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create two batches from the same DB state.
            let changeset_a = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            let changeset_b = db
                .new_batch()
                .write(key2, Some(vec![20]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();

            // Apply the first -- should succeed.
            db.apply_batch(changeset_a).await.unwrap();
            let expected_root = db.root();
            let expected_bounds = db.bounds().await;
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), None);

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

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);
            let key3 = Sha256::hash(&[3]);

            // Commit initial state.
            let finalized = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();

            // Create a parent batch, then fork two children.
            let parent = db
                .new_batch()
                .write(key2, Some(vec![20]))
                .merkleize(None, &db)
                .await
                .unwrap();

            let child_a = parent
                .new_batch::<Sha256>()
                .write(key3, Some(vec![30]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            let child_b = parent
                .new_batch::<Sha256>()
                .write(key3, Some(vec![40]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();

            // Apply child_a, then child_b should be stale.
            db.apply_batch(child_a).await.unwrap();
            let result = db.apply_batch(child_b).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset error for sibling, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_parent_applied_before_child() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create parent, then child.
            let parent = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(None, &db)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .write(key2, Some(vec![20]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            let parent = parent.finalize();

            // Apply parent first -- child should now be stale.
            db.apply_batch(parent).await.unwrap();
            let result = db.apply_batch(child).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset for child after parent applied, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_changeset_child_applied_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create parent, then child.
            let parent = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(None, &db)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .write(key2, Some(vec![20]))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            let parent = parent.finalize();

            // Apply child first -- parent should now be stale.
            db.apply_batch(child).await.unwrap();
            let result = db.apply_batch(parent).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset for parent after child applied, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            mmr::{iterator::nodes_to_pin, journaled::Mmr},
            qmdb::any::sync::tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest>;

        impl FromSyncTestable for AnyTest {
            type Mmr = TestMmr;

            fn into_log_components(self) -> (Self::Mmr, Self::Journal) {
                (self.log.mmr, self.log.journal)
            }

            async fn pinned_nodes_at(&self, loc: Location) -> Vec<Digest> {
                join_all(nodes_to_pin(loc).map(|p| self.log.mmr.get_node(p)))
                    .await
                    .into_iter()
                    .map(|n| n.unwrap().unwrap())
                    .collect()
            }
        }
    }

    /// Regression test for https://github.com/commonwarexyz/monorepo/issues/2787
    #[allow(dead_code, clippy::manual_async_fn)]
    fn issue_2787_regression(
        db: &crate::qmdb::immutable::Immutable<
            deterministic::Context,
            Digest,
            Vec<u8>,
            Sha256,
            TwoCap,
        >,
        key: Digest,
    ) -> impl std::future::Future<Output = ()> + Send + use<'_> {
        async move {
            let _ = db.get(&key).await;
        }
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_non_trait_futures_are_send(db: &AnyTest, key: Digest, value: Vec<u8>) {
        let batch = db.new_batch().write(key, Some(value));
        is_send(batch.merkleize(None, db));
        is_send(db.get_with_loc(&key));
    }

    /// Owned batch root matches the borrow-based batch root.
    #[test_traced("WARN")]
    fn test_owned_batch_root_matches() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Apply some initial data.
            apply_ops(&mut db, create_test_ops(20)).await;
            db.commit().await.unwrap();

            // Build an owned batch from committed state.
            let base = db.to_batch();

            // Create a child batch via owned and via borrow-based API. Same ops.
            let ops = create_test_ops_seeded(10, 99);

            // Borrow-based path.
            let borrow_root = {
                let mut batch = db.new_batch();
                for op in &ops {
                    match op {
                        unordered::Operation::Update(unordered::Update(k, v)) => {
                            batch = batch.write(*k, Some(v.clone()));
                        }
                        unordered::Operation::Delete(k) => {
                            batch = batch.write(*k, None);
                        }
                        _ => unreachable!(),
                    }
                }
                batch.merkleize(None, &db).await.unwrap().root()
            };

            // Owned batch path.
            let batch_root = {
                let mut batch = base.new_batch::<Sha256>();
                for op in &ops {
                    match op {
                        unordered::Operation::Update(unordered::Update(k, v)) => {
                            batch = batch.write(*k, Some(v.clone()));
                        }
                        unordered::Operation::Delete(k) => {
                            batch = batch.write(*k, None);
                        }
                        _ => unreachable!(),
                    }
                }
                let merkleized = batch.merkleize(None, &db).await.unwrap();
                merkleized.root()
            };

            assert_eq!(borrow_root, batch_root);

            db.destroy().await.unwrap();
        });
    }

    /// Owned batch changeset can be applied to the database.
    #[test_traced("WARN")]
    fn test_owned_batch_changeset_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Apply initial data.
            apply_ops(&mut db, create_test_ops(20)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Build a child batch via owned API, convert to changeset, and apply.
            let key = Digest::random(&mut commonware_utils::test_rng_seeded(200));
            let value = vec![42u8; 16];
            let child_batch = {
                let batch = base.new_batch::<Sha256>().write(key, Some(value.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Apply the batch's changeset.
            let changeset = child_batch.finalize();
            db.apply_batch(changeset).await.unwrap();
            db.commit().await.unwrap();

            // Verify the key was written.
            let fetched = db.get(&key).await.unwrap();
            assert_eq!(fetched.unwrap(), value);

            db.destroy().await.unwrap();
        });
    }

    /// Batch chains: parent batch committed, child applied with finalize_from.
    #[test_traced("WARN")]
    fn test_owned_batch_chain_commit_parent_first() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Build initial data.
            apply_ops(&mut db, create_test_ops(10)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Parent batch (via owned API).
            let key_a = Digest::random(&mut commonware_utils::test_rng_seeded(300));
            let val_a = vec![1u8; 10];
            let parent_batch = {
                let batch = base.new_batch::<Sha256>().write(key_a, Some(val_a.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Child batch (built on parent batch).
            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(301));
            let val_b = vec![2u8; 10];
            let child_batch = {
                let batch = parent_batch
                    .new_batch::<Sha256>()
                    .write(key_b, Some(val_b.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Commit parent first.
            let parent_changeset = parent_batch.finalize();
            db.apply_batch(parent_changeset).await.unwrap();
            db.commit().await.unwrap();

            // Now commit child using finalize_from (relative to new DB size).
            let current_db_size = *db.bounds().await.end;
            let child_changeset = child_batch.finalize_from(current_db_size);
            db.apply_batch(child_changeset).await.unwrap();
            db.commit().await.unwrap();

            // Both keys should be readable.
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);

            db.destroy().await.unwrap();
        });
    }

    /// Multiple forks from the same batch.
    #[test_traced("WARN")]
    fn test_owned_batch_multiple_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(10)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Fork A.
            let key_a = Digest::random(&mut commonware_utils::test_rng_seeded(400));
            let fork_a = {
                let batch = base.new_batch::<Sha256>().write(key_a, Some(vec![10u8; 8]));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Fork B (different key, same parent).
            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(401));
            let fork_b = {
                let batch = base.new_batch::<Sha256>().write(key_b, Some(vec![20u8; 8]));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Roots differ.
            assert_ne!(fork_a.root(), fork_b.root());

            // Apply fork A.
            db.apply_batch(fork_a.finalize()).await.unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), vec![10u8; 8]);
            assert!(db.get(&key_b).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    /// Batches can be stored in a homogeneous collection.
    #[test_traced("WARN")]
    fn test_owned_batch_homogeneous_collection() {
        use crate::qmdb::any::batch::MerkleizedBatch;
        use commonware_cryptography::sha256;
        use std::collections::HashMap;

        type Snap = MerkleizedBatch<sha256::Digest, super::Update<Digest, Vec<u8>>>;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(10)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Build several batches at different depths and store them by root.
            let mut collection: HashMap<sha256::Digest, Snap> = HashMap::new();

            // Depth 1.
            let batch1 = {
                let key = Digest::random(&mut commonware_utils::test_rng_seeded(500));
                let batch = base.new_batch::<Sha256>().write(key, Some(vec![1u8; 8]));
                batch.merkleize(None, &db).await.unwrap()
            };
            collection.insert(batch1.root(), batch1);

            // Depth 2 (retrieve batch1 from collection, build child).
            let batch1_root = *collection.keys().next().unwrap();
            let batch1_ref = collection.get(&batch1_root).unwrap();
            let batch2 = {
                let key = Digest::random(&mut commonware_utils::test_rng_seeded(501));
                let batch = batch1_ref
                    .new_batch::<Sha256>()
                    .write(key, Some(vec![2u8; 8]));
                batch.merkleize(None, &db).await.unwrap()
            };
            collection.insert(batch2.root(), batch2);

            // All batches in the same HashMap -- type erasure works.
            assert_eq!(collection.len(), 2);

            db.destroy().await.unwrap();
        });
    }

    /// Batch chains: parent inserts key, child deletes it.
    #[test_traced("WARN")]
    fn test_owned_batch_chain_delete_after_ancestor_insert() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Parent batch: insert key_x.
            let key_x = Digest::random(&mut commonware_utils::test_rng_seeded(700));
            let val_a = vec![10u8; 8];
            let parent_batch = {
                let batch = base.new_batch::<Sha256>().write(key_x, Some(val_a.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Child batch: delete key_x.
            let child_batch = {
                let batch = parent_batch.new_batch::<Sha256>().write(key_x, None);
                batch.merkleize(None, &db).await.unwrap()
            };

            // Commit parent.
            let parent_changeset = parent_batch.finalize();
            db.apply_batch(parent_changeset).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Commit child using finalize_from.
            let current_db_size = *db.bounds().await.end;
            let child_changeset = child_batch.finalize_from(current_db_size);
            db.apply_batch(child_changeset).await.unwrap();
            db.commit().await.unwrap();

            // key_x should be deleted.
            assert!(db.get(&key_x).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    /// Batch chains: parent and child both modify the same key.
    #[test_traced("WARN")]
    fn test_owned_batch_chain_overlapping_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Build initial data.
            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Parent batch: insert key_x with value_a.
            let key_x = Digest::random(&mut commonware_utils::test_rng_seeded(600));
            let val_a = vec![10u8; 8];
            let parent_batch = {
                let batch = base.new_batch::<Sha256>().write(key_x, Some(val_a.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Child batch: update key_x to value_b (overlapping key).
            let val_b = vec![20u8; 8];
            let child_batch = {
                let batch = parent_batch
                    .new_batch::<Sha256>()
                    .write(key_x, Some(val_b.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Commit parent first.
            let parent_changeset = parent_batch.finalize();
            db.apply_batch(parent_changeset).await.unwrap();
            db.commit().await.unwrap();

            // key_x should have parent's value.
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Now commit child using finalize_from.
            let current_db_size = *db.bounds().await.end;
            let child_changeset = child_batch.finalize_from(current_db_size);
            db.apply_batch(child_changeset).await.unwrap();
            db.commit().await.unwrap();

            // key_x should now have child's value.
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_b);

            db.destroy().await.unwrap();
        });
    }

    /// Three-deep batch chain: grandparent -> parent -> child.
    /// Commit each layer sequentially using `finalize_from`.
    #[test_traced("WARN")]
    fn test_owned_batch_chain_three_deep() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(10)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Grandparent: insert key_a.
            let key_a = Digest::random(&mut commonware_utils::test_rng_seeded(900));
            let val_a = vec![1u8; 10];
            let grandparent_batch = {
                let batch = base.new_batch::<Sha256>().write(key_a, Some(val_a.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Parent: insert key_b.
            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(901));
            let val_b = vec![2u8; 10];
            let parent_batch = {
                let batch = grandparent_batch
                    .new_batch::<Sha256>()
                    .write(key_b, Some(val_b.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Child: insert key_c.
            let key_c = Digest::random(&mut commonware_utils::test_rng_seeded(902));
            let val_c = vec![3u8; 10];
            let child_batch = {
                let batch = parent_batch
                    .new_batch::<Sha256>()
                    .write(key_c, Some(val_c.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Commit grandparent.
            db.apply_batch(grandparent_batch.finalize()).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);

            // Commit parent via finalize_from.
            let current_db_size = *db.bounds().await.end;
            db.apply_batch(parent_batch.finalize_from(current_db_size))
                .await
                .unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);

            // Commit child via finalize_from.
            let current_db_size = *db.bounds().await.end;
            db.apply_batch(child_batch.finalize_from(current_db_size))
                .await
                .unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_c).await.unwrap().unwrap(), val_c);

            // All three keys readable.
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);
            assert_eq!(db.get(&key_c).await.unwrap().unwrap(), val_c);

            db.destroy().await.unwrap();
        });
    }

    /// Three-deep chain where each layer touches the same key.
    #[test_traced("WARN")]
    fn test_owned_batch_chain_three_deep_overlapping_key() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();
            let key_x = Digest::random(&mut commonware_utils::test_rng_seeded(910));

            // Grandparent: insert key_x = val_a.
            let val_a = vec![10u8; 8];
            let grandparent_batch = {
                let batch = base.new_batch::<Sha256>().write(key_x, Some(val_a.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Parent: update key_x = val_b.
            let val_b = vec![20u8; 8];
            let parent_batch = {
                let batch = grandparent_batch
                    .new_batch::<Sha256>()
                    .write(key_x, Some(val_b.clone()));
                batch.merkleize(None, &db).await.unwrap()
            };

            // Child: delete key_x.
            let child_batch = {
                let batch = parent_batch.new_batch::<Sha256>().write(key_x, None);
                batch.merkleize(None, &db).await.unwrap()
            };

            // Commit grandparent.
            db.apply_batch(grandparent_batch.finalize()).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Commit parent via finalize_from.
            let current_db_size = *db.bounds().await.end;
            db.apply_batch(parent_batch.finalize_from(current_db_size))
                .await
                .unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_b);

            // Commit child via finalize_from.
            let current_db_size = *db.bounds().await.end;
            db.apply_batch(child_batch.finalize_from(current_db_size))
                .await
                .unwrap();
            db.commit().await.unwrap();
            assert!(db.get(&key_x).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }
}
