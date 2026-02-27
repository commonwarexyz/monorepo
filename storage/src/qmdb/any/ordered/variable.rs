//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, maintains a next-key ordering for each active key, and allows values to have
//! variable sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::ordered::fixed]
//! instead for better performance._

use crate::{
    index::ordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{init_variable, ordered, value::VariableEncoding, VariableConfig, VariableValue},
        operation::Key,
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

pub type Update<K, V> = ordered::Update<K, VariableEncoding<V>>;
pub type Operation<K, V> = ordered::Operation<K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<E, K, V, H, T> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>>;

impl<E: Storage + Clock + Metrics, K: Key, V: VariableValue, H: Hasher, T: Translator>
    Db<E, K, V, H, T>
where
    Operation<K, V>: Codec,
{
    /// Returns a [Db] QMDB initialized from `cfg`. Any uncommitted log operations will be
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
        index::partitioned::ordered::Index,
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

    /// An ordered key-value QMDB with a partitioned snapshot index and variable-size values.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<E, K, V, H, T, const P: usize> = crate::qmdb::any::ordered::Db<
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
        kv::{
            tests::{assert_batchable, assert_gettable, assert_send},
            Batchable as _, Deletable as _, Updatable as _,
        },
        mmr::{Location, Position},
        qmdb::{
            any::{
                ordered::test::{
                    test_ordered_any_db_basic, test_ordered_any_db_empty,
                    test_ordered_any_update_collision_edge_case,
                },
                test::variable_db_config,
            },
            store::tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, test_rng_seeded, NZUsize, NZU16, NZU64};
    use rand::RngCore;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: u16 = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    pub(crate) type VarConfig =
        VariableConfig<TwoCap, ((), (commonware_codec::RangeCfg<usize>, ()))>;

    /// Type aliases for concrete [Db] types used in these unit tests.
    pub(crate) type AnyTest = Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    pub(crate) fn create_test_config(seed: u64, pooler: &impl BufferPooler) -> VarConfig {
        VariableConfig {
            mmr_journal_partition: format!("mmr-journal-{seed}"),
            mmr_metadata_partition: format!("mmr-metadata-{seed}"),
            mmr_items_per_blob: NZU64!(12), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_partition: format!("log-journal-{seed}"),
            log_items_per_blob: NZU64!(14), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            log_compression: None,
            log_codec_config: ((), ((0..=10000).into(), ())),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, NZU16!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

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
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed. Use different seeds
    /// when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(n: usize, seed: u64) -> Vec<Operation<Digest, Vec<u8>>> {
        let mut rng = test_rng_seeded(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = to_bytes(rng.next_u64());
                ops.push(Operation::Update(ordered::Update {
                    key,
                    value,
                    next_key,
                }));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Vec<u8>>>) {
        for op in ops {
            match op {
                Operation::Update(data) => {
                    db.write_batch([(data.key, Some(data.value))])
                        .await
                        .unwrap();
                }
                Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await.unwrap();
                }
                Operation::CommitFloor(_, _) => {
                    // CommitFloor consumes self - not supported in this helper.
                    // Test data from create_test_ops never includes CommitFloor.
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
    }

    // Tests using FixedBytes<4> keys (for edge cases that require specific key patterns)

    /// Type alias for a variable db with FixedBytes<4> keys.
    type VariableDb = Db<Context, FixedBytes<4>, Digest, Sha256, TwoCap>;

    /// Return a variable db with FixedBytes<4> keys.
    async fn open_variable_db(context: Context) -> VariableDb {
        let cfg = variable_db_config("fixed-bytes-var-partition", &context);
        VariableDb::init(context, cfg).await.unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.with_label("initial")).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.with_label("initial")).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_update_collision_edge_case_variable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    /// Builds a db with two colliding keys, and creates a new one between them using a batch
    /// update.
    #[test_traced("WARN")]
    fn test_ordered_any_update_batch_create_between_collisions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db(context.clone()).await;

            // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
            // collisions.
            let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
            let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
            let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 7u8, 0u8]);
            let val = Sha256::fill(1u8);

            db.write_batch([(key1.clone(), Some(val))]).await.unwrap();
            db.write_batch([(key3.clone(), Some(val))]).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            // Batch-insert the middle key.
            let mut batch = db.start_batch();
            batch.update(key2.clone(), val).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key1);

            db.commit(None).await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    /// Batch create/delete cases where the deleted key is the previous key of a newly created key,
    /// and vice-versa.
    #[test_traced("WARN")]
    fn test_ordered_any_batch_create_delete_prev_links() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let key1 = FixedBytes::from([0x10u8, 0x00, 0x00, 0x00]);
            let key2 = FixedBytes::from([0x20u8, 0x00, 0x00, 0x00]);
            let key3 = FixedBytes::from([0x30u8, 0x00, 0x00, 0x00]);
            let val1 = Sha256::fill(1u8);
            let val2 = Sha256::fill(2u8);
            let val3 = Sha256::fill(3u8);

            // Delete the previous key of a newly created key.
            let mut db = open_variable_db(context.with_label("first")).await;
            db.write_batch([(key1.clone(), Some(val1))]).await.unwrap();
            db.write_batch([(key3.clone(), Some(val3))]).await.unwrap();
            db.commit(None).await.unwrap();

            let mut batch = db.start_batch();
            batch.delete(key1.clone()).await.unwrap();
            batch.create(key2.clone(), val2).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert!(db.get(&key1).await.unwrap().is_none());
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert_eq!(db.get(&key3).await.unwrap(), Some(val3));
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key2);
            db.commit(None).await.unwrap();
            db.destroy().await.unwrap();

            // Create a key that becomes the previous key of a concurrently deleted key.
            let mut db = open_variable_db(context.with_label("second")).await;
            db.write_batch([(key1.clone(), Some(val1))]).await.unwrap();
            db.write_batch([(key3.clone(), Some(val3))]).await.unwrap();
            db.commit(None).await.unwrap();

            let mut batch = db.start_batch();
            batch.create(key2.clone(), val2).await.unwrap();
            batch.delete(key3.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(val1));
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert!(db.get(&key3).await.unwrap().is_none());
            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key1);
            db.commit(None).await.unwrap();
            db.destroy().await.unwrap();
        });
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
        assert_send(db.get_all(&key));
        assert_send(db.get_with_loc(&key));
        assert_send(db.get_span(&key));
        assert_send(db.commit(None));
    }

    // ============================================================
    // Batch API comparison tests (Step 2)
    // ============================================================

    /// Helper: apply operations via the old path (write_batch + commit).
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

    /// Helper: apply operations via the new batch path.
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
    fn test_batch_ordered_single_update() {
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

            let old_val = old_db.get(&key).await.unwrap();
            let new_val = new_db.get(&key).await.unwrap();
            assert_eq!(old_val, new_val);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: multiple updates in one batch produce identical state.
    #[test_traced("WARN")]
    fn test_batch_ordered_multiple_updates() {
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
    fn test_batch_ordered_updates_and_deletes() {
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
            let mut mixed_ops = Vec::new();
            for i in 0u64..20 {
                let key = Sha256::hash(&i.to_be_bytes());
                if i % 3 == 0 {
                    mixed_ops.push((key, None));
                } else {
                    mixed_ops.push((key, Some(vec![((i + 1) % 255) as u8; 15])));
                }
            }

            apply_old_path(&mut old_db, &mixed_ops, None).await;
            apply_new_path(&mut new_db, &mixed_ops, None).await;

            assert_db_state_eq(&old_db, &new_db);

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
    fn test_batch_ordered_multiple_commits() {
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
    fn test_batch_ordered_with_metadata() {
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

    /// Test: speculative root matches committed root.
    #[test_traced("WARN")]
    fn test_batch_ordered_speculative_root() {
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
    fn test_batch_ordered_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let key3 = Sha256::hash(&3u64.to_be_bytes());
            apply_new_path(&mut db, &[(key1, Some(vec![1]))], None).await;

            let mut batch = db.new_batch();
            batch.write(key2, Some(vec![2]));
            batch.write(key1, None);

            assert_eq!(batch.get(&key2).await.unwrap(), Some(vec![2]));
            assert_eq!(batch.get(&key1).await.unwrap(), None);
            assert_eq!(batch.get(&key3).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Large mixed workload: creates, updates, deletes across multiple commits.
    #[test_traced("WARN")]
    fn test_batch_ordered_large_mixed_workload() {
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

            for i in 0u64..150 {
                let key = Sha256::hash(&i.to_be_bytes());
                let old_val = old_db.get(&key).await.unwrap();
                let new_val = new_db.get(&key).await.unwrap();
                assert_eq!(old_val, new_val, "mismatch at key {i}");
            }

            let old_meta = old_db.get_metadata().await.unwrap();
            let new_meta = new_db.get_metadata().await.unwrap();
            assert_eq!(old_meta, new_meta);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: empty batch (no mutations) still produces a valid CommitFloor.
    #[test_traced("WARN")]
    fn test_batch_ordered_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut old_db = create_test_db(context.with_label("old")).await;
            let mut new_db = create_test_db(context.with_label("new")).await;

            apply_old_path(&mut old_db, &[], None).await;
            apply_new_path(&mut new_db, &[], None).await;

            assert_db_state_eq(&old_db, &new_db);

            old_db.destroy().await.unwrap();
            new_db.destroy().await.unwrap();
        });
    }

    /// Test: delete a key that doesn't exist is a no-op.
    #[test_traced("WARN")]
    fn test_batch_ordered_delete_nonexistent() {
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
    // Batch stacking tests (ordered)
    // ============================================================

    /// Test: stacking two ordered batches produces the same state as two sequential commits.
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

            let mut batch2 = merkleized1.new_batch();
            for (key, value) in &ops2 {
                batch2.write(*key, value.clone());
            }
            let merkleized2 = batch2.merkleize(None).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

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

            // Sequential: create key1+key2, then delete key1.
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

    /// Test: stacked batch get() reads through parent overlay (ordered variant).
    #[test_traced("WARN")]
    fn test_batch_stacked_get_reads_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context).await;

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

            assert_eq!(batch2.get(&key1).await.unwrap(), None);
            assert_eq!(batch2.get(&key2).await.unwrap(), Some(vec![2]));
            assert_eq!(batch2.get(&key3).await.unwrap(), Some(vec![3]));

            db.destroy().await.unwrap();
        });
    }

    /// Test: speculative root from stacked ordered batch matches committed root.
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

    /// Test: large stacked workload with mixed operations (ordered variant).
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
            assert_db_state_eq(&seq_db, &stacked_db);

            // Batch 1: update first 20, delete next 10.
            let ops1: Vec<_> = (0u64..20)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, Some(vec![0xAAu8; 10]))
                })
                .chain((20u64..30).map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, None)
                }))
                .collect();

            // Batch 2: add 20 new keys, update some of batch 1's updates.
            let ops2: Vec<_> = (50u64..70)
                .map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, Some(vec![(i % 255) as u8; 10]))
                })
                .chain((0u64..10).map(|i| {
                    let key = Sha256::hash(&i.to_be_bytes());
                    (key, Some(vec![0xBBu8; 10]))
                }))
                .collect();

            // Sequential.
            apply_new_path(&mut seq_db, &ops1, None).await;
            apply_new_path(&mut seq_db, &ops2, Some(vec![0xCC])).await;

            // Stacked.
            let mut batch1 = stacked_db.new_batch();
            for (key, value) in &ops1 {
                batch1.write(*key, value.clone());
            }
            let merkleized1 = batch1.merkleize(None).await.unwrap();

            let mut batch2 = merkleized1.new_batch();
            for (key, value) in &ops2 {
                batch2.write(*key, value.clone());
            }
            let merkleized2 = batch2.merkleize(Some(vec![0xCC])).await.unwrap();
            let finalized = merkleized2.finalize();
            stacked_db.apply_batch(finalized).await.unwrap();

            assert_db_state_eq(&seq_db, &stacked_db);

            for i in 0u64..70 {
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
}
