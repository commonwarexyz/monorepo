use crate::{
    index::ordered::Index as OrderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr::Location,
    qmdb::{
        any::{
            init_fixed_authenticated_log, Db, FixedConfig, FixedEncoding, FixedValue,
            OrderedOperation, OrderedUpdate,
        },
        Error,
    },
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

/// A QMDB implementation with ordered keys and fixed-length values.
pub type Fixed<E, K, V, H, T> = Db<
    E,
    K,
    FixedEncoding<V>,
    OrderedUpdate<K, FixedEncoding<V>>,
    FixedJournal<E, OrderedOperation<K, FixedEncoding<V>>>,
    OrderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher, T: Translator>
    Fixed<E, K, V, H, T>
where
    OrderedOperation<K, FixedEncoding<V>>: CodecFixed<Cfg = ()>,
{
    /// Returns a [Fixed] qmdb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: FixedConfig<T>) -> Result<Self, Error> {
        Self::init_with_callback(context, cfg, None, |_, _| {}).await
    }

    /// Initialize the DB, invoking `callback` for each operation processed during recovery.
    ///
    /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the snapshot
    /// is built from the log, `callback` is invoked for each operation with its activity status and
    /// previous location (if any).
    pub(crate) async fn init_with_callback(
        context: E,
        cfg: FixedConfig<T>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_fixed_authenticated_log(context.clone(), cfg).await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(OrderedOperation::CommitFloor(
                None,
                Location::new_unchecked(0),
            ))
            .await?;
            log.sync().await?;
        }
        let index = OrderedIndex::new(context.with_label("index"), translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

#[cfg(test)]
pub(crate) mod test {
    // Import generic test functions from parent test module
    use super::{
        super::test::{
            test_ordered_any_db_basic, test_ordered_any_db_empty,
            test_ordered_any_db_empty_recovery, test_ordered_any_db_historical_proof_basic,
            test_ordered_any_db_historical_proof_different_historical_sizes,
            test_ordered_any_db_historical_proof_edge_cases,
            test_ordered_any_db_historical_proof_invalid, test_ordered_any_db_log_replay,
            test_ordered_any_db_multiple_commits_delete_replayed,
            test_ordered_any_db_non_empty_recovery,
            test_ordered_any_db_span_maintenance_under_collisions,
            test_ordered_any_update_collision_edge_case,
        },
        *,
    };
    use crate::{
        index::ordered::Index,
        mmr::{Location, StandardHasher as Standard},
        qmdb::{
            any::test::fixed_db_config,
            store::{batch_tests, Batchable as _, CleanStore as _},
            verify_proof,
        },
        translator::{OneCap, Translator, TwoCap},
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context, Runner},
        Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
    use rand::RngCore;
    use std::collections::HashMap;

    /// A type alias for the concrete database type used in these unit tests.
    type FixedDb = Db<
        Context,
        FixedBytes<4>,
        FixedEncoding<Digest>,
        OrderedUpdate<FixedBytes<4>, FixedEncoding<Digest>>,
        FixedJournal<Context, OrderedOperation<FixedBytes<4>, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a fixed config.
    pub(crate) async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    fn any_db_config(suffix: &str) -> FixedConfig<TwoCap> {
        FixedConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete database type used in fixed-size unit tests.
    pub(crate) type DbTest = Db<
        deterministic::Context,
        Digest,
        FixedEncoding<Digest>,
        OrderedUpdate<Digest, FixedEncoding<Digest>>,
        FixedJournal<deterministic::Context, OrderedOperation<Digest, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a fixed config.
    pub(crate) async fn open_db_test(context: deterministic::Context) -> DbTest {
        DbTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    pub(crate) fn create_test_config(seed: u64) -> FixedConfig<TwoCap> {
        create_generic_test_config::<TwoCap>(seed, TwoCap)
    }

    pub(crate) fn create_generic_test_config<T: Translator>(seed: u64, t: T) -> FixedConfig<T> {
        FixedConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(12), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(14), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: t,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_db_test(mut context: Context) -> DbTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        DbTest::init(context, config).await.unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_translated_key_collision_edge_case() {
        let executor = Runner::default();
        executor.start(|mut context| async move {
            let seed = context.next_u64();
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db = Db::<
                Context,
                FixedBytes<2>,
                FixedEncoding<i32>,
                OrderedUpdate<FixedBytes<2>, FixedEncoding<i32>>,
                FixedJournal<Context, OrderedOperation<FixedBytes<2>, FixedEncoding<i32>>>,
                Index<OneCap, Location>,
                Sha256,
            >::init(context.clone(), config)
            .await
            .unwrap();
            let key1 = FixedBytes::<2>::new([1u8, 1u8]);
            let key2 = FixedBytes::<2>::new([1u8, 3u8]);
            // Create some keys that will not be added to the snapshot.
            let early_key = FixedBytes::<2>::new([0u8, 2u8]);
            let late_key = FixedBytes::<2>::new([3u8, 0u8]);
            let middle_key = FixedBytes::<2>::new([1u8, 2u8]);

            db.update(key1.clone(), 1).await.unwrap();
            db.update(key2.clone(), 2).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (1, key2.clone()));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (2, key1.clone()));
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            db.delete(key1.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key2.clone());

            db.delete(key2.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().is_none());
            assert!(db.get_span(&key2).await.unwrap().is_none());

            db.commit(None).await.unwrap();
            assert!(db.is_empty());

            // Update the keys in opposite order from earlier.
            db.update(key2.clone(), 2).await.unwrap();
            db.update(key1.clone(), 1).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (1, key2.clone()));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (2, key1.clone()));
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            // Delete the keys in opposite order from earlier.
            db.delete(key2.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            db.delete(key1.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().is_none());
            assert!(db.get_span(&key2).await.unwrap().is_none());
            db.commit(None).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_build_and_authenticate() {
        let executor = Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db_test(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
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

            db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();

            // Close & reopen and ensure state matches.
            let root = db.root();
            db.close().await.unwrap();
            let db = open_db_test(context.clone()).await;
            assert_eq!(root, db.root());

            // State matches reference map.
            for i in 0u64..ELEMENTS {
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

            for loc in *db.inactivity_floor_loc()..*db.op_count() {
                let loc = Location::new_unchecked(loc);
                let (proof, ops) = db.proof(loc, NZU64!(10)).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, loc, &ops, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_ordered_any_fixed_batch() {
        batch_tests::test_batch(|ctx| async move { create_db_test(ctx).await });
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_non_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_db_test(context.clone()).await;
            test_ordered_any_db_non_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_db_test(context.clone()).await;
            test_ordered_any_db_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_db_test(context.clone()).await;
            test_ordered_any_db_log_replay(context, db, |ctx| Box::pin(open_db_test(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_multiple_commits_delete_gets_replayed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_db_test(context.clone()).await;
            test_ordered_any_db_multiple_commits_delete_replayed(
                context,
                db,
                |ctx| Box::pin(open_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    type FixedOperation = OrderedOperation<Digest, FixedEncoding<Digest>>;

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_fixed_test_ops(n') is a suffix of create_fixed_test_ops(n) for n' > n.
    fn create_fixed_test_ops(n: usize) -> Vec<FixedOperation> {
        use commonware_math::algebra::Random;
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(FixedOperation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                ops.push(FixedOperation::Update(OrderedUpdate {
                    key,
                    value,
                    next_key,
                }));
                prev_key = key;
            }
        }
        ops
    }

    /// Helper to apply test operations to a database.
    async fn apply_fixed_test_ops(db: &mut DbTest, n: usize) {
        let ops = create_fixed_test_ops(n);
        for op in ops {
            match op {
                FixedOperation::Update(data) => {
                    db.update(data.key, data.value).await.unwrap();
                }
                FixedOperation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                FixedOperation::CommitFloor(metadata, _) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_basic(context, db, to_digest, |db, n| {
                Box::pin(async move { apply_fixed_test_ops(db, n).await })
            })
            .await;
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_edge_cases() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_edge_cases(
                context.clone(),
                db,
                to_digest,
                |db, n| Box::pin(async move { apply_fixed_test_ops(db, n).await }),
                |ctx| Box::pin(create_db_test(ctx)),
            )
            .await;
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_different_historical_sizes(
                context,
                db,
                to_digest,
                |db, n| Box::pin(async move { apply_fixed_test_ops(db, n).await }),
            )
            .await;
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_invalid() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_invalid(context, db, to_digest, |db, n| {
                Box::pin(async move { apply_fixed_test_ops(db, n).await })
            })
            .await;
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_span_maintenance_under_collisions() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_span_maintenance_under_collisions(db).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_update_collision_edge_case() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    /// Builds a db with one key, and then creates another non-colliding key preceeding it in a
    /// batch. The prev_key search will have to "cycle around" in order to find the correct next_key
    /// value.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_batch_create_with_cycling_next_key() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db(context.clone()).await;

            let mid_key = FixedBytes::from([0xAAu8; 4]);
            let val = Sha256::fill(1u8);

            db.create(mid_key.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            // Batch-insert a preceeding non-translated-colliding key.
            let preceeding_key = FixedBytes::from([0x55u8; 4]);
            let mut batch = db.start_batch();
            assert!(batch.create(preceeding_key.clone(), val).await.unwrap());
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&preceeding_key).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&mid_key).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&preceeding_key).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, mid_key);
            let span2 = db.get_span(&mid_key).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, preceeding_key);

            db.destroy().await.unwrap();
        });
    }

    /// Builds a db with three keys A < B < C, then batch-deletes B. Verifies that A's next_key is
    /// correctly updated to C (skipping the deleted B).
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_batch_delete_middle_key() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db(context.clone()).await;

            let key_a = FixedBytes::from([0x11u8; 4]);
            let key_b = FixedBytes::from([0x22u8; 4]);
            let key_c = FixedBytes::from([0x33u8; 4]);
            let val = Sha256::fill(1u8);

            // Create three keys in order: A -> B -> C -> A (circular)
            db.create(key_a.clone(), val).await.unwrap();
            db.create(key_b.clone(), val).await.unwrap();
            db.create(key_c.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            // Verify initial spans
            let span_a = db.get_span(&key_a).await.unwrap().unwrap();
            assert_eq!(span_a.1.next_key, key_b);
            let span_b = db.get_span(&key_b).await.unwrap().unwrap();
            assert_eq!(span_b.1.next_key, key_c);
            let span_c = db.get_span(&key_c).await.unwrap().unwrap();
            assert_eq!(span_c.1.next_key, key_a);

            // Batch-delete the middle key B
            let mut batch = db.start_batch();
            batch.delete(key_b.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            // Verify B is deleted
            assert!(db.get(&key_b).await.unwrap().is_none());

            // Verify A's next_key is now C (not B)
            let span_a = db.get_span(&key_a).await.unwrap().unwrap();
            assert_eq!(span_a.1.next_key, key_c);

            // Verify C's next_key is still A
            let span_c = db.get_span(&key_c).await.unwrap().unwrap();
            assert_eq!(span_c.1.next_key, key_a);

            db.destroy().await.unwrap();
        });
    }
}
