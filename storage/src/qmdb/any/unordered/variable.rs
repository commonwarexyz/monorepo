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
        any::{init_variable, unordered, value::VariableEncoding, VariableConfig, VariableValue},
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
        init_variable(context, cfg, known_inactivity_floor, callback, |ctx, t| {
            Index::new(ctx, t)
        })
        .await
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
            any::{init_variable, VariableConfig, VariableValue},
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
            init_variable(context, cfg, known_inactivity_floor, callback, |ctx, t| {
                Index::new(ctx, t)
            })
            .await
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
    use crate::{
        index::Unordered as _,
        kv::tests::{assert_batchable, assert_gettable, assert_send},
        qmdb::store::{
            tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
            LogStore,
        },
        translator::TwoCap,
    };
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
        VariableConfig {
            mmr_journal_partition: format!("journal-{seed}"),
            mmr_metadata_partition: format!("metadata-{seed}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log-journal-{seed}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((), ((0..=10000).into(), ())),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
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
        for op in ops {
            match op {
                unordered::Operation::Update(unordered::Update(key, value)) => {
                    db.write_batch([(key, Some(value))]).await.unwrap();
                }
                unordered::Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await.unwrap();
                }
                unordered::Operation::CommitFloor(_, _) => {
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
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
            let mut db = open_db(context.with_label("open1")).await;
            let root = db.root();
            db.write_batch((0..ELEMENTS).map(|i| {
                (
                    Sha256::hash(&i.to_be_bytes()),
                    Some(vec![(i % 255) as u8; ((i % 13) + 7) as usize]),
                )
            }))
            .await
            .unwrap();

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open2")).await;
            assert_eq!(root, db.root());

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open3")).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.write_batch([(k, None)]).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let mut db = open_db(context.with_label("open4")).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.write_batch([(k, None)]).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root();
            assert_eq!(db.bounds().await.end, 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.bounds().await.start, Location::new_unchecked(756));
            assert_eq!(db.snapshot.items(), 857);

            db.sync().await.unwrap();
            drop(db);

            // Confirm state is preserved after reopen.
            let db = open_db(context.with_label("open5")).await;
            assert_eq!(root, db.root());
            assert_eq!(db.bounds().await.end, 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            assert_eq!(db.bounds().await.start, Location::new_unchecked(756));
            assert_eq!(db.snapshot.items(), 857);

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

            db.write_batch([(key1, Some(vec![10]))]).await.unwrap();
            db.write_batch([(key2, Some(vec![20]))]).await.unwrap();
            db.write_batch([(key3, Some(vec![30]))]).await.unwrap();
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

    // TODO(step5): Re-enable once batch_tests is updated for TestableAny.
    // #[test_traced("DEBUG")]
    // fn test_any_unordered_variable_batch() {
    //     batch_tests::test_batch(|mut ctx| async move {
    //         let seed = ctx.next_u64();
    //         let cfg = create_test_config(seed, &ctx);
    //         AnyTest::init(ctx, cfg).await.unwrap()
    //     });
    // }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            mmr::{iterator::nodes_to_pin, journaled::Mmr, Position},
            qmdb::any::sync::tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest>;

        impl FromSyncTestable for AnyTest {
            type Mmr = TestMmr;

            fn into_log_components(self) -> (Self::Mmr, Self::Journal) {
                (self.log.mmr, self.log.journal)
            }

            async fn pinned_nodes_at(&self, pos: Position) -> Vec<Digest> {
                join_all(nodes_to_pin(pos).map(|p| self.log.mmr.get_node(p)))
                    .await
                    .into_iter()
                    .map(|n| n.unwrap().unwrap())
                    .collect()
            }

            fn pinned_nodes_from_map(&self, pos: Position) -> Vec<Digest> {
                let map = self.log.mmr.get_pinned_nodes();
                nodes_to_pin(pos).map(|p| *map.get(&p).unwrap()).collect()
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

    #[allow(dead_code)]
    fn assert_db_futures_are_send(db: &mut AnyTest, key: Digest, value: Vec<u8>, loc: Location) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
        assert_send(db.write_batch([(key, Some(value.clone()))]));
        assert_send(db.write_batch([(key, None)]));
        assert_batchable(db, key, value);
        assert_send(db.get_with_loc(&key));
        assert_send(db.commit(None));
    }

    // ============================================================
    // Batch API comparison tests
    // ============================================================

    /// Helper: apply operations via the old path (write_batch + commit).
    /// Passes ALL operations to a single write_batch call (matching the batch API semantics).
    async fn apply_old_path(
        db: &mut AnyTest,
        ops: &[(Digest, Option<Vec<u8>>)],
        metadata: Option<Vec<u8>>,
    ) {
        db.write_batch(ops.iter().map(|(k, v)| (*k, v.clone())))
            .await
            .unwrap();
        db.commit(metadata).await.unwrap();
    }

    /// Helper: apply operations via the new batch path (new_batch + write + merkleize + finalize + apply_batch).
    async fn apply_new_path(
        db: &mut AnyTest,
        ops: &[(Digest, Option<Vec<u8>>)],
        metadata: Option<Vec<u8>>,
    ) {
        let mut batch = db.new_batch();
        for (key, value) in ops {
            batch.write(*key, value.clone());
        }
        let merkleized = batch.merkleize(metadata).await.unwrap();
        let finalized = merkleized.finalize();
        db.apply_batch(finalized).await.unwrap();
    }

    /// Compare two DBs state: root, inactivity floor, active keys.
    fn assert_db_state_eq(old: &AnyTest, new: &AnyTest) {
        assert_eq!(old.root(), new.root(), "root mismatch");
        assert_eq!(
            old.inactivity_floor_loc(),
            new.inactivity_floor_loc(),
            "inactivity floor mismatch"
        );
        assert_eq!(old.active_keys, new.active_keys, "active_keys mismatch");
        assert_eq!(
            old.last_commit_loc, new.last_commit_loc,
            "last_commit_loc mismatch"
        );
    }

    /// Test: single update produces identical state via old and new paths.
    #[test_traced("WARN")]
    fn test_batch_single_update() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            let key = Sha256::hash(&0u64.to_be_bytes());
            let value = vec![1, 2, 3, 4, 5];
            let ops = vec![(key, Some(value))];

            apply_old_path(&mut old_db, &ops, None).await;
            apply_new_path(&mut new_db, &ops, None).await;

            assert_db_state_eq(&old_db, &new_db);

            // Verify key is gettable.
            let old_val = old_db.get(&key).await.unwrap();
            let new_val = new_db.get(&key).await.unwrap();
            assert_eq!(old_val, new_val);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: multiple updates in one batch produce identical state.
    #[test_traced("WARN")]
    fn test_batch_multiple_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            let ops: Vec<_> = (0u64..50)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    let value = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                    (key, Some(value))
                })
                .collect();

            apply_old_path(&mut old_db, &ops, None).await;
            apply_new_path(&mut new_db, &ops, None).await;

            assert_db_state_eq(&old_db, &new_db);

            // Verify all keys are gettable.
            for (key, expected) in &ops {
                let old_val = old_db.get(key).await.unwrap();
                let new_val = new_db.get(key).await.unwrap();
                assert_eq!(old_val, new_val);
                assert_eq!(old_val.as_ref(), expected.as_ref());
            }

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: updates then deletes, all in one batch.
    #[test_traced("WARN")]
    fn test_batch_updates_and_deletes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            // First commit: create some keys.
            let create_ops: Vec<_> = (0u64..20)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    let value = vec![(i % 255) as u8; 10];
                    (key, Some(value))
                })
                .collect();

            apply_old_path(&mut old_db, &create_ops, None).await;
            apply_new_path(&mut new_db, &create_ops, None).await;
            assert_db_state_eq(&old_db, &new_db);

            // Second commit: update some, delete some.
            // Only include keys that are already in the db to keep it simple.
            let mut mixed_ops = Vec::new();
            for i in 0u64..20 {
                let key = Sha256::hash(&i.to_be_bytes());
                if i % 3 == 0 {
                    // Delete every 3rd key.
                    mixed_ops.push((key, None));
                } else {
                    // Update others with new values.
                    mixed_ops.push((key, Some(vec![((i + 1) % 255) as u8; 15])));
                }
            }

            apply_old_path(&mut old_db, &mixed_ops, None).await;
            apply_new_path(&mut new_db, &mixed_ops, None).await;

            assert_db_state_eq(&old_db, &new_db);

            // Verify individual key states.
            for i in 0u64..20 {
                let key = Sha256::hash(&i.to_be_bytes());
                let old_val = old_db.get(&key).await.unwrap();
                let new_val = new_db.get(&key).await.unwrap();
                assert_eq!(old_val, new_val, "mismatch at key {i}");
            }

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: multiple sequential commits produce identical state.
    #[test_traced("WARN")]
    fn test_batch_multiple_commits() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            for round in 0u64..5 {
                let ops: Vec<_> = (0u64..20)
                    .map(|i| {
                        let key = Sha256::hash(&(round * 100 + i).to_be_bytes());
                        let value = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                        (key, Some(value))
                    })
                    .collect();

                apply_old_path(&mut old_db, &ops, None).await;
                apply_new_path(&mut new_db, &ops, None).await;

                assert_db_state_eq(&old_db, &new_db);
            }

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: metadata is correctly stored.
    #[test_traced("WARN")]
    fn test_batch_with_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            let key = Sha256::hash(&0u64.to_be_bytes());
            let value = vec![42u8; 10];
            let metadata = vec![99u8; 5];
            let ops = vec![(key, Some(value))];

            apply_old_path(&mut old_db, &ops, Some(metadata.clone())).await;
            apply_new_path(&mut new_db, &ops, Some(metadata.clone())).await;

            assert_db_state_eq(&old_db, &new_db);

            let old_meta = old_db.get_metadata().await.unwrap();
            let new_meta = new_db.get_metadata().await.unwrap();
            assert_eq!(old_meta, new_meta);
            assert_eq!(old_meta, Some(metadata));

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: speculative root from merkleize matches root after apply_batch.
    #[test_traced("WARN")]
    fn test_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            let ops: Vec<_> = (0u64..30)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    let value = vec![(i % 255) as u8; 10];
                    (key, Some(value))
                })
                .collect();

            let mut batch = db.new_batch();
            for (key, value) in &ops {
                batch.write(*key, value.clone());
            }
            let merkleized = batch.merkleize(None).await.unwrap();
            let speculative_root = merkleized.root();
            let finalized = merkleized.finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(
                speculative_root,
                db.root(),
                "speculative root should match committed root"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Test: Batch::get reads through mutations and falls back to db.
    #[test_traced("WARN")]
    fn test_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // First commit some keys.
            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let key3 = Sha256::hash(&3u64.to_be_bytes());
            apply_new_path(&mut db, &[(key1, Some(vec![1]))], None).await;

            // Create a batch that writes key2 and deletes key1.
            let mut batch = db.new_batch();
            batch.write(key2, Some(vec![2]));
            batch.write(key1, None);

            // key2 is in pending mutations.
            assert_eq!(batch.get(&key2).await.unwrap(), Some(vec![2]));
            // key1 was deleted in this batch.
            assert_eq!(batch.get(&key1).await.unwrap(), None);
            // key3 falls through to db (not found).
            assert_eq!(batch.get(&key3).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Large mixed workload: creates, updates, deletes across multiple commits.
    #[test_traced("WARN")]
    fn test_batch_large_mixed_workload() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            // Commit 1: Create 100 keys.
            let ops: Vec<_> = (0u64..100)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    let value = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                    (key, Some(value))
                })
                .collect();
            apply_old_path(&mut old_db, &ops, None).await;
            apply_new_path(&mut new_db, &ops, None).await;
            assert_db_state_eq(&old_db, &new_db);

            // Commit 2: Update every 3rd key, delete every 7th.
            let mut ops2 = Vec::new();
            for i in 0u64..100 {
                let key = Sha256::hash(&i.to_be_bytes());
                if i % 7 == 1 {
                    ops2.push((key, None));
                } else if i % 3 == 0 {
                    ops2.push((
                        key,
                        Some(vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize]),
                    ));
                }
            }
            apply_old_path(&mut old_db, &ops2, None).await;
            apply_new_path(&mut new_db, &ops2, None).await;
            assert_db_state_eq(&old_db, &new_db);

            // Commit 3: Add 50 new keys + update some existing.
            let mut ops3 = Vec::new();
            for i in 100u64..150 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops3.push((key, Some(vec![(i % 255) as u8; 10])));
            }
            for i in 0u64..20 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops3.push((key, Some(vec![42u8; 10])));
            }
            apply_old_path(&mut old_db, &ops3, Some(vec![0xAB])).await;
            apply_new_path(&mut new_db, &ops3, Some(vec![0xAB])).await;
            assert_db_state_eq(&old_db, &new_db);

            // Verify all keys.
            for i in 0u64..150 {
                let key = Sha256::hash(&i.to_be_bytes());
                let old_val = old_db.get(&key).await.unwrap();
                let new_val = new_db.get(&key).await.unwrap();
                assert_eq!(old_val, new_val, "mismatch at key {i}");
            }

            // Verify metadata.
            let old_meta = old_db.get_metadata().await.unwrap();
            let new_meta = new_db.get_metadata().await.unwrap();
            assert_eq!(old_meta, new_meta);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: empty batch (no mutations) still produces a valid CommitFloor.
    #[test_traced("WARN")]
    fn test_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            // Old path: commit with no operations.
            apply_old_path(&mut old_db, &[], None).await;
            apply_new_path(&mut new_db, &[], None).await;

            assert_db_state_eq(&old_db, &new_db);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: delete a key that doesn't exist is a no-op.
    #[test_traced("WARN")]
    fn test_batch_delete_nonexistent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            let nonexistent_key = Sha256::hash(&999u64.to_be_bytes());
            let ops = vec![(nonexistent_key, None)];

            apply_old_path(&mut old_db, &ops, None).await;
            apply_new_path(&mut new_db, &ops, None).await;

            assert_db_state_eq(&old_db, &new_db);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    // ============================================================
    // Stacking tests (Step 3)
    // ============================================================

    /// Test: stacking two batches produces the same state as two sequential commits.
    #[test_traced("WARN")]
    fn test_batch_stacked_equals_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Sequential: two separate commits.
            let mut seq_db = create_test_db(context.with_label("seq")).await;
            let ops1: Vec<_> = (0u64..20)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, Some(vec![(i % 255) as u8; 10]))
                })
                .collect();
            let ops2: Vec<_> = (20u64..40)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, Some(vec![(i % 255) as u8; 10]))
                })
                .collect();
            apply_new_path(&mut seq_db, &ops1, None).await;
            apply_new_path(&mut seq_db, &ops2, None).await;

            // Stacked: parent batch + child batch, applied together.
            let mut stacked_db = create_test_db(context.with_label("stacked")).await;
            let mut batch1 = stacked_db.new_batch();
            for (key, value) in &ops1 {
                batch1.write(*key, value.clone());
            }
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            // Create a child batch on the merkleized parent.
            let mut batch2 = merkleized1.new_batch();
            for (key, value) in &ops2 {
                batch2.write(*key, value.clone());
            }
            let merkleized2 = batch2.merkleize(None).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

            // Verify all keys are gettable.
            for i in 0u64..40 {
                let key = Sha256::hash(&i.to_be_bytes());
                let seq_val = seq_db.get(&key).await.unwrap();
                let stacked_val = stacked_db.get(&key).await.unwrap();
                assert_eq!(seq_val, stacked_val, "mismatch at key {i}");
            }

            seq_db.destroy().await.unwrap();
            stacked_db.destroy().await.unwrap();
        });
    }

    /// Test: stacking with overlapping keys (child updates a parent-created key).
    #[test_traced("WARN")]
    fn test_batch_stacked_overlapping_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut seq_db = create_test_db(context.with_label("seq")).await;
            let mut stacked_db = create_test_db(context.with_label("stacked")).await;

            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let val_a = vec![1u8; 10];
            let val_b = vec![2u8; 10];

            // Sequential: create key1+key2 in commit 1, update key1 in commit 2.
            apply_new_path(
                &mut seq_db,
                &[(key1, Some(val_a.clone())), (key2, Some(val_b.clone()))],
                None,
            )
            .await;
            apply_new_path(&mut seq_db, &[(key1, Some(vec![99u8; 10]))], None).await;

            // Stacked: same operations.
            let mut batch1 = stacked_db.new_batch();
            batch1.write(key1, Some(val_a.clone()));
            batch1.write(key2, Some(val_b.clone()));
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            let mut batch2 = merkleized1.new_batch();
            batch2.write(key1, Some(vec![99u8; 10]));
            let merkleized2 = batch2.merkleize(None).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

            let seq_val = seq_db.get(&key1).await.unwrap();
            let stacked_val = stacked_db.get(&key1).await.unwrap();
            assert_eq!(seq_val, stacked_val);
            assert_eq!(stacked_val, Some(vec![99u8; 10]));

            seq_db.destroy().await.unwrap();
            stacked_db.destroy().await.unwrap();
        });
    }

    /// Test: stacking with deletes (child deletes a parent-created key).
    #[test_traced("WARN")]
    fn test_batch_stacked_create_then_delete() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut seq_db = create_test_db(context.with_label("seq")).await;
            let mut stacked_db = create_test_db(context.with_label("stacked")).await;

            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let val = vec![1u8; 10];

            // Sequential: create key1+key2 in commit 1, delete key1 in commit 2.
            apply_new_path(
                &mut seq_db,
                &[(key1, Some(val.clone())), (key2, Some(val.clone()))],
                None,
            )
            .await;
            apply_new_path(&mut seq_db, &[(key1, None)], None).await;

            // Stacked: same operations.
            let mut batch1 = stacked_db.new_batch();
            batch1.write(key1, Some(val.clone()));
            batch1.write(key2, Some(val.clone()));
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            let mut batch2 = merkleized1.new_batch();
            batch2.write(key1, None);
            let merkleized2 = batch2.merkleize(None).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

            assert_eq!(seq_db.get(&key1).await.unwrap(), None);
            assert_eq!(stacked_db.get(&key1).await.unwrap(), None);
            assert_eq!(
                seq_db.get(&key2).await.unwrap(),
                stacked_db.get(&key2).await.unwrap()
            );

            seq_db.destroy().await.unwrap();
            stacked_db.destroy().await.unwrap();
        });
    }

    /// Test: stacked batch get() reads through parent overlay.
    #[test_traced("WARN")]
    fn test_batch_stacked_get_reads_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            // Commit key1 to base DB.
            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let key3 = Sha256::hash(&3u64.to_be_bytes());
            apply_new_path(&mut db, &[(key1, Some(vec![1]))], None).await;

            // Parent batch: write key2, delete key1.
            let mut batch1 = db.new_batch();
            batch1.write(key2, Some(vec![2]));
            batch1.write(key1, None);
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            // Child batch: write key3.
            let mut batch2 = merkleized1.new_batch();
            batch2.write(key3, Some(vec![3]));

            // key1 was deleted by parent -> None.
            assert_eq!(batch2.get(&key1).await.unwrap(), None);
            // key2 was created by parent -> vec![2].
            assert_eq!(batch2.get(&key2).await.unwrap(), Some(vec![2]));
            // key3 is in this batch's mutations -> vec![3].
            assert_eq!(batch2.get(&key3).await.unwrap(), Some(vec![3]));

            db.destroy().await.unwrap();
        });
    }

    /// Test: speculative root from stacked batch matches committed root.
    #[test_traced("WARN")]
    fn test_batch_stacked_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            let mut batch1 = db.new_batch();
            for i in 0u64..20 {
                let key = Sha256::hash(&i.to_be_bytes());
                batch1.write(key, Some(vec![(i % 255) as u8; 10]));
            }
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            let mut batch2 = merkleized1.new_batch();
            for i in 20u64..40 {
                let key = Sha256::hash(&i.to_be_bytes());
                batch2.write(key, Some(vec![(i % 255) as u8; 10]));
            }
            let merkleized2 = batch2.merkleize(None).await.unwrap();
            let speculative_root = merkleized2.root();
            let finalized = merkleized2.finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(
                speculative_root,
                db.root(),
                "stacked speculative root should match committed root"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Test: large stacked workload with mixed operations.
    #[test_traced("WARN")]
    fn test_batch_stacked_large_workload() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut seq_db = create_test_db(context.with_label("seq")).await;
            let mut stacked_db = create_test_db(context.with_label("stacked")).await;

            // Pre-populate both DBs with 50 keys.
            let initial_ops: Vec<_> = (0u64..50)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, Some(vec![(i % 255) as u8; 10]))
                })
                .collect();
            apply_new_path(&mut seq_db, &initial_ops, None).await;
            apply_new_path(&mut stacked_db, &initial_ops, None).await;

            // Batch 1: update 20 existing keys, create 20 new keys, delete 10.
            let mut ops1 = Vec::new();
            for i in 0u64..20 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops1.push((key, Some(vec![42u8; 10])));
            }
            for i in 50u64..70 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops1.push((key, Some(vec![(i % 255) as u8; 10])));
            }
            for i in 20u64..30 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops1.push((key, None));
            }

            // Batch 2: update some from batch 1, create more, delete some batch-1-created.
            let mut ops2 = Vec::new();
            for i in 0u64..10 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops2.push((key, Some(vec![99u8; 10])));
            }
            for i in 70u64..80 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops2.push((key, Some(vec![(i % 255) as u8; 10])));
            }
            for i in 50u64..55 {
                let key = Sha256::hash(&i.to_be_bytes());
                ops2.push((key, None));
            }

            // Sequential path.
            apply_new_path(&mut seq_db, &ops1, None).await;
            apply_new_path(&mut seq_db, &ops2, Some(vec![0xBE])).await;

            // Stacked path.
            let mut batch1 = stacked_db.new_batch();
            for (key, value) in &ops1 {
                batch1.write(*key, value.clone());
            }
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            let mut batch2 = merkleized1.new_batch();
            for (key, value) in &ops2 {
                batch2.write(*key, value.clone());
            }
            let merkleized2 = batch2.merkleize(Some(vec![0xBE])).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

            // Verify all keys.
            for i in 0u64..80 {
                let key = Sha256::hash(&i.to_be_bytes());
                let seq_val = seq_db.get(&key).await.unwrap();
                let stacked_val = stacked_db.get(&key).await.unwrap();
                assert_eq!(seq_val, stacked_val, "mismatch at key {i}");
            }

            seq_db.destroy().await.unwrap();
            stacked_db.destroy().await.unwrap();
        });
    }

    /// Test: parent deletes a key that existed in the base DB, child re-creates it.
    /// Validates that base_old_loc is properly propagated through the batch chain.
    #[test_traced("WARN")]
    fn test_batch_stacked_delete_then_recreate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut seq_db = create_test_db(context.with_label("seq")).await;
            let mut stacked_db = create_test_db(context.with_label("stacked")).await;

            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());

            // Commit key1 and key2 to the base DB.
            let initial_ops = vec![(key1, Some(vec![1u8; 10])), (key2, Some(vec![2u8; 10]))];
            apply_new_path(&mut seq_db, &initial_ops, None).await;
            apply_new_path(&mut stacked_db, &initial_ops, None).await;
            assert_db_state_eq(&seq_db, &stacked_db);

            // Sequential: delete key1, then re-create with new value.
            apply_new_path(&mut seq_db, &[(key1, None)], None).await;
            apply_new_path(&mut seq_db, &[(key1, Some(vec![99u8; 10]))], None).await;

            // Stacked: parent deletes key1, child re-creates it.
            let mut batch1 = stacked_db.new_batch();
            batch1.write(key1, None);
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            let mut batch2 = merkleized1.new_batch();
            batch2.write(key1, Some(vec![99u8; 10]));
            let merkleized2 = batch2.merkleize(None).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

            assert_eq!(stacked_db.get(&key1).await.unwrap(), Some(vec![99u8; 10]),);
            assert_eq!(
                seq_db.get(&key1).await.unwrap(),
                stacked_db.get(&key1).await.unwrap(),
            );
            assert_eq!(
                seq_db.get(&key2).await.unwrap(),
                stacked_db.get(&key2).await.unwrap(),
            );

            seq_db.destroy().await.unwrap();
            stacked_db.destroy().await.unwrap();
        });
    }
}
