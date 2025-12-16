use crate::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::variable::Journal as VariableJournal,
    mmr::Location,
    qmdb::{
        any::{
            init_variable_authenticated_log, Db, UnorderedOperation, UnorderedUpdate,
            VariableConfig, VariableEncoding, VariableValue,
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

/// A variable-size unordered database with standard journal and index types.
pub type Variable<E, K, V, H, T> = Db<
    E,
    K,
    VariableEncoding<V>,
    UnorderedUpdate<K, VariableEncoding<V>>,
    VariableJournal<E, UnorderedOperation<K, VariableEncoding<V>>>,
    UnorderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Variable<E, K, V, H, T>
where
    UnorderedOperation<K, VariableEncoding<V>>: Codec,
{
    /// Returns a [Variable] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <UnorderedOperation<K, VariableEncoding<V>> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_variable_authenticated_log(context.clone(), cfg).await?;

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
        Self::init_from_log(index, log, None, |_, _| {}).await
    }
}

#[cfg(test)]
pub(crate) mod test {
    // Import generic test functions from parent test module
    use super::{
        super::test::{
            test_any_db_build_and_authenticate, test_any_db_empty,
            test_any_db_historical_proof_basic,
            test_any_db_historical_proof_different_historical_sizes,
            test_any_db_historical_proof_edge_cases, test_any_db_historical_proof_invalid,
            test_any_db_multiple_commits_delete_replayed,
        },
        *,
    };
    use crate::{
        index::{unordered::Index, Unordered as _},
        mmr::Location,
        qmdb::{
            any::test::variable_db_config,
            store::{batch_tests, CleanStore as _},
            Error,
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
    type VariableDb = Db<
        Context,
        Digest,
        VariableEncoding<Digest>,
        UnorderedUpdate<Digest, VariableEncoding<Digest>>,
        VariableJournal<Context, UnorderedOperation<Digest, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a variable config.
    pub(crate) async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            super::super::test::test_any_db_basic(context, db, |ctx| {
                Box::pin(open_variable_db(ctx))
            })
            .await;
        });
    }

    const VARIABLE_PAGE_SIZE: usize = 77;
    const VARIABLE_PAGE_CACHE_SIZE: usize = 9;

    fn variable_any_db_config(
        suffix: &str,
    ) -> VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(
                NZUsize!(VARIABLE_PAGE_SIZE),
                NZUsize!(VARIABLE_PAGE_CACHE_SIZE),
            ),
        }
    }

    /// A type alias for the concrete database type used in variable-size unit tests.
    type VariableDbTest = Db<
        Context,
        Digest,
        VariableEncoding<Vec<u8>>,
        UnorderedUpdate<Digest, VariableEncoding<Vec<u8>>>,
        VariableJournal<Context, UnorderedOperation<Digest, VariableEncoding<Vec<u8>>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Deterministic byte vector generator for variable-value tests.
    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Return a database initialized with a variable config.
    async fn open_variable_db_test(context: Context) -> VariableDbTest {
        VariableDbTest::init(context, variable_any_db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_any_variable_db_build_and_authenticate() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db_test(context.clone()).await;
            test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_variable_db_test(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_any_variable_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db_test(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = to_bytes(i);
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_variable_db_test(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_any_variable_db_multiple_commits_delete_gets_replayed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db_test(context.clone()).await;
            test_any_db_multiple_commits_delete_replayed(
                context,
                db,
                |ctx| Box::pin(open_variable_db_test(ctx)),
                |i| vec![(i % 255) as u8; ((i % 7) + 3) as usize],
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_any_variable_db_recovery() {
        let executor = Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = open_variable_db_test(context.clone()).await;
            let root = db.root();

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
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
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());

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
            let root = db.root();

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
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root();
            assert_eq!(db.op_count(), 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(756)
            );
            assert_eq!(db.snapshot.items(), 857);

            // Confirm state is preserved after close and reopen.
            db.close().await.unwrap();
            let db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(756)
            );
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_non_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db_test(context.clone()).await;

            // Insert 1000 keys then sync.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root();
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(), root);

            async fn apply_more_ops(db: &mut VariableDbTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_variable_db_test(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let db = open_variable_db_test(context.clone()).await;
            let root = db.root();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            async fn apply_ops(db: &mut VariableDbTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Insert another 1000 keys then simulate failure after syncing the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_variable_db_test(context.clone()).await;
            assert!(db.op_count() > 1);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_prune_beyond_inactivity_floor() {
        let executor = Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_variable_db_test(context.clone()).await;

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

    #[test_traced("DEBUG")]
    fn test_any_variable_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let cfg = variable_any_db_config(&format!("batch_{seed}"));
            VariableDbTest::init(ctx, cfg).await.unwrap()
        });
    }

    type VariableOperation = UnorderedOperation<Digest, VariableEncoding<Vec<u8>>>;

    /// Create n random operations for variable-size testing. Some portion of the updates are deletes.
    /// create_variable_test_ops(n') is a suffix of create_variable_test_ops(n) for n' > n.
    fn create_variable_test_ops(n: usize) -> Vec<VariableOperation> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(VariableOperation::Delete(prev_key));
            } else {
                let value = to_bytes(i as u64);
                ops.push(VariableOperation::Update(UnorderedUpdate(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Helper to apply random operations to a database.
    async fn apply_variable_test_ops(db: &mut VariableDbTest, n: usize) {
        let ops = create_variable_test_ops(n);
        for op in ops {
            match op {
                VariableOperation::Update(UnorderedUpdate(key, value)) => {
                    db.update(key, value).await.unwrap();
                }
                VariableOperation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                VariableOperation::CommitFloor(metadata, _) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    /// Create a variable test database with unique partition names
    async fn create_variable_db_test(mut context: Context) -> VariableDbTest {
        let seed = context.next_u64();
        let cfg = variable_any_db_config(&format!("test_{seed}"));
        VariableDbTest::init(context, cfg).await.unwrap()
    }

    #[test]
    fn test_any_variable_db_historical_proof_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_variable_db_test(context.clone()).await;
            test_any_db_historical_proof_basic(context, db, |db, n| {
                Box::pin(async move { apply_variable_test_ops(db, n).await })
            })
            .await;
        });
    }

    #[test]
    fn test_any_variable_db_historical_proof_edge_cases() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_variable_db_test(context.clone()).await;
            test_any_db_historical_proof_edge_cases(
                context.clone(),
                db,
                |db, n| Box::pin(async move { apply_variable_test_ops(db, n).await }),
                |ctx| Box::pin(create_variable_db_test(ctx)),
                create_variable_test_ops,
            )
            .await;
        });
    }

    #[test]
    fn test_any_variable_db_historical_proof_different_historical_sizes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_variable_db_test(context.clone()).await;
            test_any_db_historical_proof_different_historical_sizes(
                context.clone(),
                db,
                |db, n| Box::pin(async move { apply_variable_test_ops(db, n).await }),
                |ctx| Box::pin(create_variable_db_test(ctx)),
                create_variable_test_ops,
            )
            .await;
        });
    }

    #[test]
    fn test_any_variable_db_historical_proof_invalid() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = create_variable_db_test(context.clone()).await;
            test_any_db_historical_proof_invalid(context, db, |db, n| {
                Box::pin(async move { apply_variable_test_ops(db, n).await })
            })
            .await;
        });
    }
}
