//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::unordered::fixed]
//! instead for better performance._

use crate::{
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    merkle::{Family, Location},
    qmdb::{
        any::{unordered, value::VariableEncoding, VariableConfig, VariableValue},
        operation::Key,
        Error, RootSpec,
    },
    translator::Translator,
    Context,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;

pub type Update<K, V> = unordered::Update<K, VariableEncoding<V>>;
pub type Operation<F, K, V> = unordered::Operation<F, K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<F, E, K, V, H, T> =
    super::Db<F, E, Journal<E, Operation<F, K, V>>, Index<T, Location<F>>, H, Update<K, V>>;

impl<F: Family + RootSpec, E: Context, K: Key, V: VariableValue, H: Hasher, T: Translator>
    Db<F, E, K, V, H, T>
where
    Operation<F, K, V>: Codec,
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <Operation<F, K, V> as Read>::Cfg>,
    ) -> Result<Self, Error<F>> {
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
        cfg: VariableConfig<T, <Operation<F, K, V> as Read>::Cfg>,
        known_inactivity_floor: Option<Location<F>>,
        callback: impl FnMut(bool, Option<Location<F>>),
    ) -> Result<Self, Error<F>> {
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
        merkle::{Family, Location},
        qmdb::{
            any::{VariableConfig, VariableValue},
            operation::Key,
            Error, RootSpec,
        },
        translator::Translator,
        Context,
    };
    use commonware_codec::{Codec, Read};
    use commonware_cryptography::Hasher;

    /// A key-value QMDB with a partitioned snapshot index and variable-size values.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<F, E, K, V, H, T, const P: usize> = crate::qmdb::any::unordered::Db<
        F,
        E,
        Journal<E, Operation<F, K, V>>,
        Index<T, Location<F>, P>,
        H,
        Update<K, V>,
    >;

    impl<
            F: Family + RootSpec,
            E: Context,
            K: Key,
            V: VariableValue,
            H: Hasher,
            T: Translator,
            const P: usize,
        > Db<F, E, K, V, H, T, P>
    where
        Operation<F, K, V>: Codec,
    {
        /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
        /// discarded and the state of the db will be as of the last committed operation.
        pub async fn init(
            context: E,
            cfg: VariableConfig<T, <Operation<F, K, V> as Read>::Cfg>,
        ) -> Result<Self, Error<F>> {
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
            cfg: VariableConfig<T, <Operation<F, K, V> as Read>::Cfg>,
            known_inactivity_floor: Option<Location<F>>,
            callback: impl FnMut(bool, Option<Location<F>>),
        ) -> Result<Self, Error<F>> {
            crate::qmdb::any::init(context, cfg, known_inactivity_floor, callback).await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Variable-value DB with 256 partitions.
        pub type Db<F, E, K, V, H, T> = super::Db<F, E, K, V, H, T, 1>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Variable-value DB with 65,536 partitions.
        pub type Db<F, E, K, V, H, T> = super::Db<F, E, K, V, H, T, 2>;
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{index::Unordered as _, mmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::{
        num::{NonZeroU16, NonZeroUsize},
        sync::Arc,
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    pub(crate) fn create_test_config(seed: u64, pooler: &impl BufferPooler) -> VarConfig {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        VariableConfig {
            merkle_config: crate::mmr::full::Config {
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
            split_root: true,
            root_bagging: <mmr::Family as crate::qmdb::RootSpec>::root_spec(0).bagging,
        }
    }

    pub(crate) type VarConfig =
        VariableConfig<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))>;

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<mmr::Family, deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

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
    ) -> Vec<unordered::Operation<mmr::Family, Digest, VariableEncoding<Vec<u8>>>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed. Use different seeds
    /// when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(
        n: usize,
        seed: u64,
    ) -> Vec<unordered::Operation<mmr::Family, Digest, VariableEncoding<Vec<u8>>>> {
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
        ops: Vec<unordered::Operation<mmr::Family, Digest, VariableEncoding<Vec<u8>>>>,
    ) {
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
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
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
                let _ = batch.merkleize(&db, None).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open2")).await;
            assert_eq!(root, db.root());

            // Re-apply the updates and commit them this time.
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
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
                let _ = batch.merkleize(&db, None).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open3")).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
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
                let _ = batch.merkleize(&db, None).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open4")).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                batch = batch.write(k, None);
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
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

            let merkleized = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .write(key2, Some(vec![20]))
                .write(key3, Some(vec![30]))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

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
    fn test_stale_batch_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create two batches from the same DB state.
            let batch_a = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let batch_b = db
                .new_batch()
                .write(key2, Some(vec![20]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Apply the first -- should succeed.
            db.apply_batch(batch_a).await.unwrap();
            let expected_root = db.root();
            let expected_bounds = db.bounds().await;
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), None);

            // Apply the second -- should fail because the DB was modified.
            let result = db.apply_batch(batch_b).await;
            assert!(
                matches!(result, Err(Error::StaleBatch { .. })),
                "expected StaleBatch error, got {result:?}"
            );
            assert_eq!(db.root(), expected_root);
            assert_eq!(db.bounds().await, expected_bounds);
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Sibling batches with different operation counts are still detected
    /// as stale.
    #[test_traced]
    fn test_stale_batch_rejected_different_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // A writes 1 key, B writes 5 keys -- different total_size.
            let batch_a = db
                .new_batch()
                .write(Sha256::hash(&[1]), Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let batch_b = db
                .new_batch()
                .write(Sha256::hash(&[2]), Some(vec![20]))
                .write(Sha256::hash(&[3]), Some(vec![30]))
                .write(Sha256::hash(&[4]), Some(vec![40]))
                .write(Sha256::hash(&[5]), Some(vec![50]))
                .write(Sha256::hash(&[6]), Some(vec![60]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // B has more ops than A.
            assert!(batch_b.total_size > batch_a.total_size);

            // Apply A, then B must be stale.
            db.apply_batch(batch_a).await.unwrap();
            let result = db.apply_batch(batch_b).await;
            assert!(
                matches!(result, Err(Error::StaleBatch { .. })),
                "expected StaleBatch for asymmetric sibling, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Applying C (grandchild of A) after only A is committed must
    /// apply B's data + C's data. Uncommitted ancestor B's snapshot
    /// entries are applied via ancestor_diffs with committed_locs override.
    #[test_traced]
    fn test_partial_ancestor_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);
            let key3 = Sha256::hash(&[3]);

            // Chain: DB <- A <- B <- C
            let a = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let b = a
                .new_batch::<Sha256>()
                .write(key2, Some(vec![20]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let c = b
                .new_batch::<Sha256>()
                .write(key3, Some(vec![30]))
                .merkleize(&db, None)
                .await
                .unwrap();

            let expected_root = c.root();

            // Apply only A, then apply C directly (B uncommitted).
            db.apply_batch(a).await.unwrap();
            db.apply_batch(c).await.unwrap();

            assert_eq!(db.root(), expected_root);
            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), Some(vec![20]));
            assert_eq!(db.get(&key3).await.unwrap(), Some(vec![30]));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_batch_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);
            let key3 = Sha256::hash(&[3]);

            // Commit initial state.
            let merkleized = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            // Create a parent batch, then fork two children.
            let parent = db
                .new_batch()
                .write(key2, Some(vec![20]))
                .merkleize(&db, None)
                .await
                .unwrap();

            let child_a = parent
                .new_batch::<Sha256>()
                .write(key3, Some(vec![30]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let child_b = parent
                .new_batch::<Sha256>()
                .write(key3, Some(vec![40]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Apply child_a, then child_b should be stale.
            db.apply_batch(child_a).await.unwrap();
            let result = db.apply_batch(child_b).await;
            assert!(
                matches!(result, Err(Error::StaleBatch { .. })),
                "expected StaleBatch error for sibling, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Apply parent then child -- this is the sequential commit pattern
    /// and must succeed. `apply_batch` detects that the child's ancestors
    /// were committed and applies only the child's own operations.
    #[test_traced]
    fn test_sequential_commit_parent_then_child() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create parent, then child.
            let parent = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .write(key2, Some(vec![20]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Apply parent first, then child -- sequential commit.
            db.apply_batch(parent).await.unwrap();
            db.apply_batch(child).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&key2).await.unwrap(), Some(vec![20]));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_stale_batch_child_applied_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);

            // Create parent, then child.
            let parent = db
                .new_batch()
                .write(key1, Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .write(key2, Some(vec![20]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Apply child first -- parent should now be stale.
            db.apply_batch(child).await.unwrap();
            let result = db.apply_batch(parent).await;
            assert!(
                matches!(result, Err(Error::StaleBatch { .. })),
                "expected StaleBatch for parent after child applied, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            merkle::mmr::{self, full::Mmr},
            qmdb::any::sync::tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest>;

        impl FromSyncTestable for AnyTest {
            type Merkle = TestMmr;

            fn into_log_components(self) -> (Self::Merkle, Self::Journal) {
                (self.log.merkle, self.log.journal)
            }

            async fn pinned_nodes_at(&self, loc: mmr::Location) -> Vec<Digest> {
                join_all(mmr::Family::nodes_to_pin(loc).map(|p| self.log.merkle.get_node(p)))
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
        db: &crate::qmdb::immutable::variable::Db<
            mmr::Family,
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
        is_send(batch.merkleize(db, None));
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
            let borrow_root = batch.merkleize(&db, None).await.unwrap().root();

            // Owned batch path.
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
            let batch_root = batch.merkleize(&db, None).await.unwrap().root();

            assert_eq!(borrow_root, batch_root);

            db.destroy().await.unwrap();
        });
    }

    /// Owned batch can be merkleized and applied to the database.
    #[test_traced("WARN")]
    fn test_owned_batch_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Apply initial data.
            apply_ops(&mut db, create_test_ops(20)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Build a child batch via owned API, merkleize, and apply.
            let key = Digest::random(&mut commonware_utils::test_rng_seeded(200));
            let value = vec![42u8; 16];
            let child_batch = base
                .new_batch::<Sha256>()
                .write(key, Some(value.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Apply the batch.
            db.apply_batch(child_batch).await.unwrap();
            db.commit().await.unwrap();

            // Verify the key was written.
            let fetched = db.get(&key).await.unwrap();
            assert_eq!(fetched.unwrap(), value);

            db.destroy().await.unwrap();
        });
    }

    /// Batch chains: parent batch committed, child applied sequentially.
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
            let parent_batch = base
                .new_batch::<Sha256>()
                .write(key_a, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child batch (built on parent batch).
            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(301));
            let val_b = vec![2u8; 10];
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
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
            let fork_a = base
                .new_batch::<Sha256>()
                .write(key_a, Some(vec![10u8; 8]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Fork B (different key, same parent).
            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(401));
            let fork_b = base
                .new_batch::<Sha256>()
                .write(key_b, Some(vec![20u8; 8]))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Roots differ.
            assert_ne!(fork_a.root(), fork_b.root());

            // Apply fork A.
            db.apply_batch(fork_a).await.unwrap();
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

        type Snap = MerkleizedBatch<mmr::Family, sha256::Digest, super::Update<Digest, Vec<u8>>>;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(10)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Build several batches at different depths and store them by root.
            let mut collection: HashMap<sha256::Digest, Arc<Snap>> = HashMap::new();

            // Depth 1.
            let key = Digest::random(&mut commonware_utils::test_rng_seeded(500));
            let batch1 = base
                .new_batch::<Sha256>()
                .write(key, Some(vec![1u8; 8]))
                .merkleize(&db, None)
                .await
                .unwrap();
            collection.insert(batch1.root(), batch1);

            // Depth 2 (retrieve batch1 from collection, build child).
            let batch1_root = *collection.keys().next().unwrap();
            let batch1_ref = collection.get(&batch1_root).unwrap();
            let key = Digest::random(&mut commonware_utils::test_rng_seeded(501));
            let batch2 = batch1_ref
                .new_batch::<Sha256>()
                .write(key, Some(vec![2u8; 8]))
                .merkleize(&db, None)
                .await
                .unwrap();
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
            let parent_batch = base
                .new_batch::<Sha256>()
                .write(key_x, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child batch: delete key_x.
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_x, None)
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
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
            let parent_batch = base
                .new_batch::<Sha256>()
                .write(key_x, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child batch: update key_x to value_b (overlapping key).
            let val_b = vec![20u8; 8];
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_x, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();

            // key_x should have parent's value.
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
            db.commit().await.unwrap();

            // key_x should now have child's value.
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_b);

            db.destroy().await.unwrap();
        });
    }

    /// Three-deep batch chain: grandparent -> parent -> child.
    /// Commit each layer sequentially.
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
            let grandparent_batch = base
                .new_batch::<Sha256>()
                .write(key_a, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Parent: insert key_b.
            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(901));
            let val_b = vec![2u8; 10];
            let parent_batch = grandparent_batch
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child: insert key_c.
            let key_c = Digest::random(&mut commonware_utils::test_rng_seeded(902));
            let val_c = vec![3u8; 10];
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_c, Some(val_c.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(grandparent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);

            // Commit parent.
            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
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
            let grandparent_batch = base
                .new_batch::<Sha256>()
                .write(key_x, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Parent: update key_x = val_b.
            let val_b = vec![20u8; 8];
            let parent_batch = grandparent_batch
                .new_batch::<Sha256>()
                .write(key_x, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child: delete key_x.
            let child_batch = parent_batch
                .new_batch::<Sha256>()
                .write(key_x, None)
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(grandparent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_a);

            // Commit parent.
            db.apply_batch(parent_batch).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&key_x).await.unwrap().unwrap(), val_b);

            // Commit child.
            db.apply_batch(child_batch).await.unwrap();
            db.commit().await.unwrap();
            assert!(db.get(&key_x).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    /// After committing and dropping an ancestor, building a new child
    /// from a surviving descendant must not panic or return wrong data.
    /// Regression test: the Merkleizer's `read_op` fell into the
    /// "ancestor chain" region for operations that belonged to the freed
    /// ancestor, causing wrong indexing.
    #[test_traced("WARN")]
    fn test_new_child_after_ancestor_committed_and_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            // Chain: DB <-- a <-- b
            let key_a = Digest::random(&mut commonware_utils::test_rng_seeded(800));
            let val_a = vec![10u8; 8];
            let a = db
                .new_batch()
                .write(key_a, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(801));
            let val_b = vec![20u8; 8];
            let b = a
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Commit a and drop it. b's Weak<a> becomes invalid.
            db.apply_batch(a).await.unwrap();
            db.commit().await.unwrap();

            // Build c from b. This must not panic despite a being freed.
            let key_c = Digest::random(&mut commonware_utils::test_rng_seeded(802));
            let val_c = vec![30u8; 8];
            let c = b
                .new_batch::<Sha256>()
                .write(key_c, Some(val_c.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Commit b (skip_ancestors path since a is committed).
            db.apply_batch(b).await.unwrap();
            db.commit().await.unwrap();

            // Commit c.
            db.apply_batch(c).await.unwrap();
            db.commit().await.unwrap();

            // All three keys present with correct values.
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);
            assert_eq!(db.get(&key_c).await.unwrap().unwrap(), val_c);

            db.destroy().await.unwrap();
        });
    }

    /// Regression: applying a batch after its ancestor Arc is dropped (without
    /// committing) must still apply the ancestor's snapshot diffs. Before the
    /// fix, the Weak parent chain was dead and ancestor diffs were silently
    /// lost, causing the journal and snapshot to diverge.
    #[test_traced("WARN")]
    fn test_apply_batch_after_ancestor_dropped_without_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            apply_ops(&mut db, create_test_ops(5)).await;
            db.commit().await.unwrap();

            let base = db.to_batch();

            // Chain: base <-- a <-- b <-- c
            let key_a = Digest::random(&mut commonware_utils::test_rng_seeded(700));
            let val_a = vec![1u8; 10];
            let a = base
                .new_batch::<Sha256>()
                .write(key_a, Some(val_a.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            let key_b = Digest::random(&mut commonware_utils::test_rng_seeded(701));
            let val_b = vec![2u8; 10];
            let b = a
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            let key_c = Digest::random(&mut commonware_utils::test_rng_seeded(702));
            let val_c = vec![3u8; 10];
            let c = b
                .new_batch::<Sha256>()
                .write(key_c, Some(val_c.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Drop a and b without committing. Their Weak refs in c are now dead.
            drop(a);
            drop(b);

            // Apply only the tip. This is !skip_ancestors (db hasn't changed).
            // Before the fix, a's and b's snapshot diffs would be silently lost.
            db.apply_batch(c).await.unwrap();
            db.commit().await.unwrap();

            // All three keys must be in the snapshot.
            assert_eq!(db.get(&key_a).await.unwrap().unwrap(), val_a);
            assert_eq!(db.get(&key_b).await.unwrap().unwrap(), val_b);
            assert_eq!(db.get(&key_c).await.unwrap().unwrap(), val_c);

            db.destroy().await.unwrap();
        });
    }
}
