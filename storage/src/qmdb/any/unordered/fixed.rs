use crate::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr::Location,
    qmdb::{
        any::{
            init_fixed_authenticated_log, Db, FixedConfig, FixedEncoding, FixedValue,
            UnorderedOperation, UnorderedUpdate,
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

/// A QMDB implementation with unordered keys and fixed-length values.
pub type Fixed<E, K, V, H, T> = Db<
    E,
    K,
    FixedEncoding<V>,
    UnorderedUpdate<K, FixedEncoding<V>>,
    FixedJournal<E, UnorderedOperation<K, FixedEncoding<V>>>,
    UnorderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher, T: Translator>
    Fixed<E, K, V, H, T>
where
    UnorderedOperation<K, FixedEncoding<V>>: CodecFixed<Cfg = ()>,
{
    /// Returns a [Fixed] QMDB initialized from `cfg`. Any uncommitted log operations will be
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
            log.append(UnorderedOperation::CommitFloor(
                None,
                Location::new_unchecked(0),
            ))
            .await?;
            log.sync().await?;
        }
        let index = UnorderedIndex::new(context.with_label("index"), translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

#[cfg(test)]
pub(crate) mod test {
    // Import generic test functions from parent test module
    use super::{
        super::test::{
            test_any_db_build_and_authenticate, test_any_db_empty, test_any_db_empty_recovery,
            test_any_db_historical_proof_basic,
            test_any_db_historical_proof_different_historical_sizes,
            test_any_db_historical_proof_edge_cases, test_any_db_historical_proof_invalid,
            test_any_db_multiple_commits_delete_replayed, test_any_db_non_empty_recovery,
        },
        *,
    };
    use crate::{
        index::{unordered::Index, Unordered as _},
        mmr::Location,
        qmdb::{
            any::test::fixed_db_config,
            store::{batch_tests, CleanStore as _},
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// A type alias for the concrete database type used in these unit tests.
    type FixedDb = Db<
        Context,
        Digest,
        FixedEncoding<Digest>,
        UnorderedUpdate<Digest, FixedEncoding<Digest>>,
        FixedJournal<Context, UnorderedOperation<Digest, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a fixed config.
    pub(crate) async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("INFO")]
    fn test_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_any_db_empty(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_fixed_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            super::super::test::test_any_db_basic(context, db, |ctx| Box::pin(open_fixed_db(ctx)))
                .await;
        });
    }

    // Janky page & cache sizes to exercise boundary conditions.
    const FIXED_PAGE_SIZE: usize = 101;
    const FIXED_PAGE_CACHE_SIZE: usize = 11;

    type FixedOperation = UnorderedOperation<Digest, FixedEncoding<Digest>>;

    /// A type alias for the concrete database type used in fixed-size unit tests.
    pub(crate) type FixedDbTest = Db<
        Context,
        Digest,
        FixedEncoding<Digest>,
        UnorderedUpdate<Digest, FixedEncoding<Digest>>,
        FixedJournal<Context, FixedOperation>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    pub(crate) fn fixed_db_test_config(suffix: &str) -> FixedConfig<TwoCap> {
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
            buffer_pool: PoolRef::new(NZUsize!(FIXED_PAGE_SIZE), NZUsize!(FIXED_PAGE_CACHE_SIZE)),
        }
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    /// Return a database initialized with a fixed config.
    async fn open_fixed_db_test(context: Context) -> FixedDbTest {
        FixedDbTest::init(context, fixed_db_test_config("partition"))
            .await
            .unwrap()
    }

    pub(crate) fn create_fixed_test_config(seed: u64) -> FixedConfig<TwoCap> {
        FixedConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(13), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(11), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(FIXED_PAGE_SIZE), NZUsize!(FIXED_PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_fixed_db_test(mut context: Context) -> FixedDbTest {
        let seed = context.next_u64();
        let config = create_fixed_test_config(seed);
        FixedDbTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_fixed_test_ops(n') is a suffix of create_fixed_test_ops(n) for n' > n.
    pub(crate) fn create_fixed_test_ops(n: usize) -> Vec<FixedOperation> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(FixedOperation::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(FixedOperation::Update(UnorderedUpdate(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_fixed_ops(db: &mut FixedDbTest, ops: Vec<FixedOperation>) {
        for op in ops {
            match op {
                FixedOperation::Update(UnorderedUpdate(key, value)) => {
                    db.update(key, value).await.unwrap();
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

    #[test_traced("WARN")]
    fn test_any_fixed_db_build_and_authenticate() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_non_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_non_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_any_fixed_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db_test(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_fixed_db_test(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_multiple_commits_delete_gets_replayed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_multiple_commits_delete_replayed(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_any_fixed_batch() {
        batch_tests::test_batch(|ctx| async move { create_fixed_db_test(ctx).await });
    }

    /// Helper to apply random operations to a database.
    async fn apply_fixed_test_ops(db: &mut FixedDbTest, n: usize) {
        let ops = create_fixed_test_ops(n);
        for op in ops {
            match op {
                FixedOperation::Update(UnorderedUpdate(key, value)) => {
                    db.update(key, value).await.unwrap();
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
    fn test_any_fixed_db_historical_proof_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_fixed_db_test(context.clone()).await;
            test_any_db_historical_proof_basic(context, db, |db, n| {
                Box::pin(async move { apply_fixed_test_ops(db, n).await })
            })
            .await;
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_edge_cases() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_fixed_db_test(context.clone()).await;
            test_any_db_historical_proof_edge_cases(
                context.clone(),
                db,
                |db, n| Box::pin(async move { apply_fixed_test_ops(db, n).await }),
                |ctx| Box::pin(create_fixed_db_test(ctx)),
                create_fixed_test_ops,
            )
            .await;
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_fixed_db_test(context.clone()).await;
            test_any_db_historical_proof_different_historical_sizes(
                context.clone(),
                db,
                |db, n| Box::pin(async move { apply_fixed_test_ops(db, n).await }),
                |ctx| Box::pin(create_fixed_db_test(ctx)),
                create_fixed_test_ops,
            )
            .await;
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_invalid() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_fixed_db_test(context.clone()).await;
            test_any_db_historical_proof_invalid(context, db, |db, n| {
                Box::pin(async move { apply_fixed_test_ops(db, n).await })
            })
            .await;
        });
    }
}
