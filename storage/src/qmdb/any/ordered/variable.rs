use crate::{
    index::ordered::Index as OrderedIndex,
    journal::contiguous::variable::Journal as VariableJournal,
    mmr::Location,
    qmdb::{
        any::{
            init_variable_authenticated_log, Db, OrderedOperation, OrderedUpdate, VariableConfig,
            VariableEncoding, VariableValue,
        },
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

/// A QMDB implementation with ordered keys and variable-length values.
pub type Variable<E, K, V, H, T> = Db<
    E,
    K,
    VariableEncoding<V>,
    OrderedUpdate<K, VariableEncoding<V>>,
    VariableJournal<E, OrderedOperation<K, VariableEncoding<V>>>,
    OrderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Variable<E, K, V, H, T>
where
    OrderedOperation<K, VariableEncoding<V>>: Codec,
{
    /// Returns a [Variable] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <OrderedOperation<K, VariableEncoding<V>> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_variable_authenticated_log(context.clone(), cfg).await?;

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
        Self::init_from_log(index, log, None, |_, _| {}).await
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
        mmr::Location,
        qmdb::{
            any::test::variable_db_config,
            store::{batch_tests, Batchable as _},
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};

    /// A type alias for the concrete database type used in these unit tests.
    type VariableDb = Db<
        Context,
        FixedBytes<4>,
        VariableEncoding<Digest>,
        OrderedUpdate<FixedBytes<4>, VariableEncoding<Digest>>,
        VariableJournal<Context, OrderedOperation<FixedBytes<4>, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a variable config.
    pub(crate) async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("partition"))
            .await
            .unwrap()
    }

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    /// A type alias for the concrete database type used in variable-size unit tests with Digest values.
    type DbTest = Db<
        Context,
        Digest,
        VariableEncoding<Digest>,
        OrderedUpdate<Digest, VariableEncoding<Digest>>,
        VariableJournal<Context, OrderedOperation<Digest, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    fn create_test_config(seed: u64) -> VariableConfig<TwoCap, ()> {
        VariableConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(12), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(14), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            log_compression: None,
            log_codec_config: (),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Return a database initialized with a variable config for tests.
    async fn open_db_test(context: Context) -> DbTest {
        DbTest::init(context, create_test_config(12345))
            .await
            .unwrap()
    }

    /// Create a test database with unique partition names
    async fn create_db_test(mut context: Context) -> DbTest {
        use rand::RngCore;
        let seed = context.next_u64();
        let config = create_test_config(seed);
        DbTest::init(context, config).await.unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_non_empty_db_recovery() {
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
    fn test_ordered_any_variable_empty_db_recovery() {
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
    fn test_ordered_any_variable_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_db_test(context.clone()).await;
            test_ordered_any_db_log_replay(context, db, |ctx| Box::pin(open_db_test(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_multiple_commits_delete_gets_replayed() {
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

    /// Helper to apply random operations to a database.
    async fn apply_variable_ops(db: &mut DbTest, n: usize) {
        use commonware_math::algebra::Random;
        use rand::{rngs::StdRng, SeedableRng};
        static mut COUNTER: u64 = 0;
        // Use a counter to generate different keys each call
        let seed = unsafe {
            COUNTER += 1;
            COUNTER
        };
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..n {
            let key = Digest::random(&mut rng);
            let value = Digest::random(&mut rng);
            db.update(key, value).await.unwrap();
        }
    }

    #[test]
    fn test_ordered_any_variable_db_historical_proof_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_basic(context, db, to_digest, |db, n| {
                Box::pin(async move { apply_variable_ops(db, n).await })
            })
            .await;
        });
    }

    #[test]
    fn test_ordered_any_variable_db_historical_proof_edge_cases() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_edge_cases(
                context.clone(),
                db,
                to_digest,
                |db, n| Box::pin(async move { apply_variable_ops(db, n).await }),
            )
            .await;
        });
    }

    #[test]
    fn test_ordered_any_variable_db_historical_proof_different_historical_sizes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_different_historical_sizes(
                context,
                db,
                to_digest,
                |db, n| Box::pin(async move { apply_variable_ops(db, n).await }),
            )
            .await;
        });
    }

    #[test]
    fn test_ordered_any_variable_db_historical_proof_invalid() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_db_test(context.clone()).await;
            test_ordered_any_db_historical_proof_invalid(context, db, to_digest, |db, n| {
                Box::pin(async move { apply_variable_ops(db, n).await })
            })
            .await;
        });
    }

    #[test]
    fn test_ordered_any_variable_db_span_maintenance_under_collisions() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_span_maintenance_under_collisions(db).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_update_collision_edge_case() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    /// Builds a db with two colliding keys, and creates a new one between them using a batch
    /// update.
    #[test_traced("WARN")]
    fn test_ordered_any_variable_batch_create_between_collisions() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db(context.clone()).await;

            // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
            // collisions.
            let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
            let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
            let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 7u8, 0u8]);
            let val = Sha256::fill(1u8);

            db.update(key1.clone(), val).await.unwrap();
            db.update(key3.clone(), val).await.unwrap();
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

            db.destroy().await.unwrap();
        });
    }

    /// Batch create/delete cases where the deleted key is the previous key of a newly created key,
    /// and vice-versa.
    #[test_traced("WARN")]
    fn test_ordered_any_variable_batch_create_delete_prev_links() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let key1 = FixedBytes::from([0x10u8, 0x00, 0x00, 0x00]);
            let key2 = FixedBytes::from([0x20u8, 0x00, 0x00, 0x00]);
            let key3 = FixedBytes::from([0x30u8, 0x00, 0x00, 0x00]);
            let val1 = Sha256::fill(1u8);
            let val2 = Sha256::fill(2u8);
            let val3 = Sha256::fill(3u8);

            // Delete the previous key of a newly created key.
            let mut db = open_variable_db(context.clone()).await;
            db.update(key1.clone(), val1).await.unwrap();
            db.update(key3.clone(), val3).await.unwrap();
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
            db.destroy().await.unwrap();

            // Create a key that becomes the previous key of a concurrently deleted key.
            let mut db = open_variable_db(context.clone()).await;
            db.update(key1.clone(), val1).await.unwrap();
            db.update(key3.clone(), val3).await.unwrap();
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
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_ordered_any_variable_batch() {
        batch_tests::test_batch(|ctx| async move { create_db_test(ctx).await });
    }
}
