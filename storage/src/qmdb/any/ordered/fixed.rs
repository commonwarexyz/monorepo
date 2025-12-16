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
    use super::*;
    use crate::{
        index::ordered::Index,
        mmr::{Location, StandardHasher as Standard},
        qmdb::{
            any::test::fixed_db_config,
            store::{batch_tests, CleanStore as _},
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

    // Import generic test functions from parent test module
    use super::super::test::{test_ordered_any_db_basic, test_ordered_any_db_empty};

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
}
