use crate::{
    adb::{
        immutable,
        operation::variable::{immutable::Operation, Value},
        sync, Error,
    },
    journal::contiguous::variable,
    mmr::Location,
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::ops::Range;

impl<E, K, V, H, T> sync::Database for immutable::Immutable<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Value,
    H: Hasher,
    T: Translator,
{
    type Op = Operation<K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = immutable::Config<T, V::Cfg>;
    type Digest = H::Digest;
    type Context = E;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, Error> {
        // Initialize contiguous journal for the sync range
        variable::Journal::init_sync(
            context.with_label("log"),
            variable::Config {
                items_per_section: config.log_items_per_section,
                partition: config.log_partition.clone(),
                compression: config.log_compression,
                codec_config: config.log_codec_config.clone(),
                buffer_pool: config.buffer_pool.clone(),
                write_buffer: config.log_write_buffer,
            },
            *range.start..*range.end,
        )
        .await
    }

    /// Returns a [super::Immutable] initialized data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the MMR journal is empty or the last item is before the range start, it creates a
    ///   fresh MMR from the provided `pinned_nodes`
    /// - If the MMR journal has data but is incomplete (has length < range end), missing operations
    ///   from the log are applied to bring it up to the target state
    /// - If the MMR journal has data beyond the range end, it is rewound to match the sync target
    ///
    /// # Returns
    ///
    /// A [super::Immutable] db populated with the state from the given range.
    /// The pruning boundary is set to the range start.
    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, Error> {
        let sync_config = Config {
            db_config,
            log: journal,
            range,
            pinned_nodes,
            apply_batch_size,
        };
        Self::init_synced(context, sync_config).await
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, Error> {
        let size = journal.size();

        if size <= range.start {
            // Destroy and recreate
            journal.destroy().await?;
            Self::create_journal(context, config, range).await
        } else {
            // Prune to range start (position-based, not section-based)
            journal
                .prune(*range.start)
                .await
                .map_err(crate::adb::Error::from)?;

            // Verify size is within range
            let size = journal.size();
            if size > range.end {
                return Err(crate::adb::Error::UnexpectedData(Location::new_unchecked(
                    size,
                )));
            }

            Ok(journal)
        }
    }
}

/// Configuration for syncing an [immutable::Immutable] to a target state.
pub struct Config<E, K, V, T, D, C>
where
    E: Storage + Metrics,
    K: Array,
    V: Value,
    T: Translator,
    D: commonware_cryptography::Digest,
{
    /// Database configuration.
    pub db_config: immutable::Config<T, C>,

    /// The [immutable::Immutable]'s log of operations. It has elements within the range.
    /// Reports the range start as its pruning boundary (oldest retained operation index).
    pub log: variable::Journal<E, Operation<K, V>>,

    /// Sync range - operations outside this range are pruned or not synced.
    pub range: Range<Location>,

    /// The pinned nodes the MMR needs at the pruning boundary (range start), in the order
    /// specified by `Proof::nodes_to_pin`.
    /// If `None`, the pinned nodes will be computed from the MMR's journal and metadata,
    /// which are expected to have the necessary pinned nodes.
    pub pinned_nodes: Option<Vec<D>>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,
}

#[cfg(test)]
mod tests {
    use crate::{
        adb::{
            immutable,
            operation::variable::immutable::Operation,
            sync::{
                self,
                engine::{Config, NextStep},
                Engine, Target,
            },
        },
        mmr::Location,
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256, Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _, RwLock};
    use commonware_utils::{NZUsize, NZU64};
    use futures::{channel::mpsc, SinkExt as _};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use rstest::rstest;
    use std::{
        collections::HashMap,
        num::{NonZeroU64, NonZeroUsize},
        sync::Arc,
    };

    /// Type alias for sync tests with simple codec config
    type ImmutableSyncTest = immutable::Immutable<
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        crate::translator::TwoCap,
    >;

    /// Create a simple config for sync tests
    fn create_sync_config(suffix: &str) -> immutable::Config<crate::translator::TwoCap, ()> {
        const PAGE_SIZE: NonZeroUsize = NZUsize!(77);
        const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);
        const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(5);

        immutable::Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_{suffix}"),
            log_items_per_section: ITEMS_PER_SECTION,
            log_compression: None,
            log_codec_config: (),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: deterministic::Context) -> ImmutableSyncTest {
        let seed = context.next_u64();
        let config = create_sync_config(&format!("sync_test_{seed}"));
        ImmutableSyncTest::init(context, config).await.unwrap()
    }

    /// Create n random Set operations.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<Operation<sha256::Digest, sha256::Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut ops = Vec::new();
        for _i in 0..n {
            let key = sha256::Digest::random(&mut rng);
            let value = sha256::Digest::random(&mut rng);
            ops.push(Operation::Set(key, value));
        }
        ops
    }

    /// Applies the given operations to the database.
    async fn apply_ops(
        db: &mut ImmutableSyncTest,
        ops: Vec<Operation<sha256::Digest, sha256::Digest>>,
    ) {
        for op in ops {
            match op {
                Operation::Set(key, value) => {
                    db.set(key, value).await.unwrap();
                }
                Operation::Commit(metadata) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    #[rstest]
    #[case::singleton_batch_size_one(1, NZU64!(1))]
    #[case::singleton_batch_size_gt_db_size(1, NZU64!(2))]
    #[case::batch_size_one(1000, NZU64!(1))]
    #[case::floor_div_db_batch_size(1000, NZU64!(3))]
    #[case::floor_div_db_batch_size_2(1000, NZU64!(999))]
    #[case::div_db_batch_size(1000, NZU64!(100))]
    #[case::db_size_eq_batch_size(1000, NZU64!(1000))]
    #[case::batch_size_gt_db_size(1000, NZU64!(1001))]
    fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            let metadata = Some(Sha256::fill(1));
            target_db.commit(metadata).await.unwrap();
            let target_op_count = target_db.op_count();
            let target_oldest_retained_loc = target_db.oldest_retained_loc().unwrap();
            let target_root = target_db.root();

            // Capture target database state before moving into config
            let mut expected_kvs: HashMap<sha256::Digest, sha256::Digest> = HashMap::new();
            for op in &target_db_ops {
                if let Operation::Set(key, value) = op {
                    expected_kvs.insert(*key, *value);
                }
            }

            let db_config = create_sync_config(&format!("sync_client_{}", context.next_u64()));

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    range: target_oldest_retained_loc..target_op_count,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let mut got_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify database state
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(
                got_db.oldest_retained_loc().unwrap(),
                target_oldest_retained_loc
            );

            // Verify the root digest matches the target
            assert_eq!(got_db.root(), target_root);

            // Verify that the synced database matches the target state
            for (key, expected_value) in &expected_kvs {
                let synced_value = got_db.get(key).await.unwrap();
                assert_eq!(synced_value, Some(*expected_value));
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs: HashMap<sha256::Digest, sha256::Digest> = HashMap::new();
            for _i in 0..expected_kvs.len() {
                let key = sha256::Digest::random(&mut rng);
                let value = sha256::Digest::random(&mut rng);
                new_ops.push(Operation::Set(key, value));
                new_kvs.insert(key, value);
            }

            // Apply new operations to both databases
            apply_ops(&mut got_db, new_ops.clone()).await;
            {
                let mut target_db = target_db.write().await;
                apply_ops(&mut target_db, new_ops).await;
            }

            // Verify both databases have the same state after additional operations
            for (key, expected_value) in &new_kvs {
                let synced_value = got_db.get(key).await.unwrap();
                let target_value = {
                    let target_db = target_db.read().await;
                    target_db.get(key).await.unwrap()
                };
                assert_eq!(synced_value, Some(*expected_value));
                assert_eq!(target_value, Some(*expected_value));
            }

            got_db.destroy().await.unwrap();
            let target_db = Arc::try_unwrap(target_db).map_or_else(
                |_| panic!("Failed to unwrap Arc - still has references"),
                |rw_lock| rw_lock.into_inner(),
            );
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that sync works when the target database is initially empty
    #[test_traced("WARN")]
    fn test_sync_empty_to_nonempty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create an empty target database
            let mut target_db = create_test_db(context.clone()).await;
            target_db.commit(Some(Sha256::fill(1))).await.unwrap(); // Commit to establish a valid root

            let target_op_count = target_db.op_count();
            let target_oldest_retained_loc = target_db.oldest_retained_loc().unwrap();
            let target_root = target_db.root();

            let db_config = create_sync_config(&format!("empty_sync_{}", context.next_u64()));
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: target_root,
                    range: target_oldest_retained_loc..target_op_count,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let got_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify database state
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(
                got_db.oldest_retained_loc().unwrap(),
                target_oldest_retained_loc
            );
            assert_eq!(got_db.root(), target_root);
            assert_eq!(got_db.get_metadata().await.unwrap(), Some(Sha256::fill(1)));

            got_db.destroy().await.unwrap();
            let target_db = Arc::try_unwrap(target_db).map_or_else(
                |_| panic!("Failed to unwrap Arc - still has references"),
                |rw_lock| rw_lock.into_inner(),
            );
            target_db.destroy().await.unwrap();
        });
    }

    /// Test demonstrating that a synced database can be reopened and retain its state.
    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit(Some(Sha256::fill(0))).await.unwrap();

            // Capture target state
            let target_root = target_db.root();
            let lower_bound = target_db.oldest_retained_loc().unwrap();
            let op_count = target_db.op_count();

            // Perform sync
            let db_config = create_sync_config("persistence_test");
            let context_clone = context.clone();
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    range: lower_bound..op_count,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let synced_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify initial sync worked
            assert_eq!(synced_db.root(), target_root);

            // Save state before closing
            let expected_root = synced_db.root();
            let expected_op_count = synced_db.op_count();
            let expected_oldest_retained_loc = synced_db.oldest_retained_loc().unwrap();

            // Close and reopen the database to test persistence
            synced_db.close().await.unwrap();
            let reopened_db = ImmutableSyncTest::init(context_clone, db_config)
                .await
                .unwrap();

            // Verify state is preserved
            assert_eq!(reopened_db.root(), expected_root);
            assert_eq!(reopened_db.op_count(), expected_op_count);
            assert_eq!(
                reopened_db.oldest_retained_loc().unwrap(),
                expected_oldest_retained_loc
            );

            // Verify data integrity
            for op in &target_ops {
                if let Operation::Set(key, value) = op {
                    let stored_value = reopened_db.get(key).await.unwrap();
                    assert_eq!(stored_value, Some(*value));
                }
            }

            reopened_db.destroy().await.unwrap();
            let target_db = Arc::try_unwrap(target_db).map_or_else(
                |_| panic!("Failed to unwrap Arc - still has references"),
                |rw_lock| rw_lock.into_inner(),
            );
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that target updates work correctly during sync
    #[test_traced("WARN")]
    fn test_target_update_during_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate initial target database
            let mut target_db = create_test_db(context.clone()).await;
            let initial_ops = create_test_ops(50);
            apply_ops(&mut target_db, initial_ops.clone()).await;
            target_db.commit(None).await.unwrap();

            // Capture the state after first commit
            let initial_lower_bound = target_db.oldest_retained_loc().unwrap();
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root();

            // Add more operations to create the extended target
            let additional_ops = create_test_ops(25);
            apply_ops(&mut target_db, additional_ops.clone()).await;
            target_db.commit(None).await.unwrap();
            let final_upper_bound = target_db.op_count();
            let final_root = target_db.root();

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial smaller target and very small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let client = {
                let config = Config {
                    context: context.clone(),
                    db_config: create_sync_config(&format!("update_test_{}", context.next_u64())),
                    target: Target {
                        root: initial_root,
                        range: initial_lower_bound..initial_upper_bound,
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(2), // Very small batch size to ensure multiple batches needed
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_rx: Some(update_receiver),
                };
                let mut client: Engine<ImmutableSyncTest, _> = Engine::new(config).await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal().size();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Send target update with SAME lower bound but higher upper bound
            update_sender
                .send(Target {
                    root: final_root,
                    range: initial_lower_bound..final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            assert_eq!(synced_db.root(), final_root);

            // Verify the target database matches the synced database
            let target_db = Arc::try_unwrap(target_db).map_or_else(
                |_| panic!("Failed to unwrap Arc - still has references"),
                |rw_lock| rw_lock.into_inner(),
            );
            {
                assert_eq!(synced_db.op_count(), target_db.op_count());
                assert_eq!(
                    synced_db.oldest_retained_loc(),
                    target_db.oldest_retained_loc()
                );
                assert_eq!(synced_db.root(), target_db.root());
            }

            // Verify all expected operations are present in the synced database
            let all_ops = [initial_ops, additional_ops].concat();
            for op in &all_ops {
                if let Operation::Set(key, value) = op {
                    let synced_value = synced_db.get(key).await.unwrap();
                    assert_eq!(synced_value, Some(*value));
                }
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that invalid bounds are rejected
    #[test]
    fn test_sync_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let db_config = create_sync_config(&format!("invalid_bounds_{}", context.next_u64()));
            let config = Config {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: sha256::Digest::from([1u8; 32]),
                    range: Location::new_unchecked(31)..Location::new_unchecked(31),
                },
                context,
                resolver: Arc::new(commonware_runtime::RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let result: Result<ImmutableSyncTest, _> = sync::sync(config).await;
            match result {
                Err(sync::Error::Engine(sync::EngineError::InvalidTarget {
                    lower_bound_pos,
                    upper_bound_pos,
                })) => {
                    assert_eq!(lower_bound_pos, Location::new_unchecked(31));
                    assert_eq!(upper_bound_pos, Location::new_unchecked(31));
                }
                _ => panic!("Expected InvalidTarget error"),
            }
        });
    }

    /// Test that sync works when target database has operations beyond the requested range
    /// of operations to sync.
    #[test]
    fn test_sync_subset_of_target_database() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(30);
            // Apply all but the last operation
            apply_ops(&mut target_db, target_ops[..29].to_vec()).await;
            target_db.commit(None).await.unwrap();

            let target_root = target_db.root();
            let lower_bound = target_db.oldest_retained_loc().unwrap();
            let op_count = target_db.op_count();

            // Add final op after capturing the range
            apply_ops(&mut target_db, target_ops[29..].to_vec()).await;
            target_db.commit(None).await.unwrap();

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: create_sync_config(&format!("subset_{}", context.next_u64())),
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: target_root,
                    range: lower_bound..op_count,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let synced_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify state matches the specified range
            assert_eq!(synced_db.root(), target_root);
            assert_eq!(synced_db.op_count(), op_count);

            synced_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    // Test syncing where the sync client has some but not all of the operations in the target
    // database.
    #[test]
    fn test_sync_use_existing_db_partial_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let original_ops = create_test_ops(50);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_sync_config(&format!("partial_{}", context.next_u64()));
            let mut sync_db: ImmutableSyncTest =
                immutable::Immutable::init(context.clone(), sync_db_config.clone())
                    .await
                    .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, original_ops.clone()).await;
            apply_ops(&mut sync_db, original_ops.clone()).await;
            target_db.commit(None).await.unwrap();
            sync_db.commit(None).await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Add one more operation and commit the target database
            let last_op = create_test_ops(1);
            apply_ops(&mut target_db, last_op.clone()).await;
            target_db.commit(None).await.unwrap();
            let root = target_db.root();
            let lower_bound = target_db.oldest_retained_loc().unwrap();
            let upper_bound = target_db.op_count(); // Up to the last operation

            // Reopen the sync database and sync it to the target database
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let sync_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound);
            assert_eq!(sync_db.root(), root);

            sync_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    /// Test case where existing database on disk exactly matches the sync target
    #[test]
    fn test_sync_use_existing_db_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_ops = create_test_ops(40);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_config = create_sync_config(&format!("exact_{}", context.next_u64()));
            let mut sync_db: ImmutableSyncTest =
                immutable::Immutable::init(context.clone(), sync_config.clone())
                    .await
                    .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, target_ops.clone()).await;
            apply_ops(&mut sync_db, target_ops.clone()).await;
            target_db.commit(None).await.unwrap();
            sync_db.commit(None).await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Prepare target
            let root = target_db.root();
            let lower_bound = target_db.oldest_retained_loc().unwrap();
            let upper_bound = target_db.op_count();

            // Sync should complete immediately without fetching
            let resolver = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: sync_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                context,
                resolver: resolver.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let sync_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(sync_db.op_count(), upper_bound);
            assert_eq!(sync_db.root(), root);

            sync_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(resolver).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    /// Test that the client fails to sync if the lower bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit(None).await.unwrap();

            target_db.prune(Location::new_unchecked(10)).await.unwrap();

            // Capture initial target state
            let initial_lower_bound = target_db.oldest_retained_loc().unwrap();
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root();

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("lb_dec_{}", context.next_u64())),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<ImmutableSyncTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased lower bound
            update_sender
                .send(Target {
                    root: initial_root,
                    range: initial_lower_bound.checked_sub(1).unwrap()..initial_upper_bound,
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(
                    sync::EngineError::SyncTargetMovedBackward { .. }
                ))
            ));

            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    /// Test that the client fails to sync if the upper bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let initial_lower_bound = target_db.oldest_retained_loc().unwrap();
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root();

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("ub_dec_{}", context.next_u64())),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<ImmutableSyncTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased upper bound
            update_sender
                .send(Target {
                    root: initial_root,
                    range: initial_lower_bound..(initial_upper_bound - 1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(
                    sync::EngineError::SyncTargetMovedBackward { .. }
                ))
            ));

            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    /// Test that the client succeeds when bounds are updated
    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let initial_lower_bound = target_db.oldest_retained_loc().unwrap();
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root();

            // Apply more operations to the target database
            let more_ops = create_test_ops(5);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit(None).await.unwrap();

            target_db.prune(Location::new_unchecked(10)).await.unwrap();
            target_db.commit(None).await.unwrap();

            // Capture final target state
            let final_lower_bound = target_db.oldest_retained_loc().unwrap();
            let final_upper_bound = target_db.op_count();
            let final_root = target_db.root();

            // Assert we're actually updating the bounds
            assert_ne!(final_lower_bound, initial_lower_bound);
            assert_ne!(final_upper_bound, initial_upper_bound);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("bounds_inc_{}", context.next_u64())),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: Some(update_receiver),
            };

            // Send target update with increased upper bound
            update_sender
                .send(Target {
                    root: final_root,
                    range: final_lower_bound..final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify the synced database has the expected state
            assert_eq!(synced_db.root(), final_root);
            assert_eq!(synced_db.op_count(), final_upper_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), final_lower_bound);

            synced_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    /// Test that the client fails to sync with invalid bounds (lower > upper)
    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(25);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture initial target state
            let initial_lower_bound = target_db.oldest_retained_loc().unwrap();
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root();

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("invalid_update_{}", context.next_u64())),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<ImmutableSyncTest, _> = Engine::new(config).await.unwrap();

            // Send target update with invalid bounds (lower > upper)
            update_sender
                .send(Target {
                    root: initial_root,
                    range: initial_upper_bound..initial_lower_bound,
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::InvalidTarget { .. }))
            ));

            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            let inner = target_db.into_inner();
            inner.destroy().await.unwrap();
        });
    }

    /// Test that target updates can be sent even after the client is done
    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit(None).await.unwrap();

            // Capture target state
            let lower_bound = target_db.oldest_retained_loc().unwrap();
            let upper_bound = target_db.op_count();
            let root = target_db.root();

            // Create client with target that will complete immediately
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_sync_config(&format!("done_{}", context.next_u64())),
                fetch_batch_size: NZU64!(20),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };

            // Complete the sync
            let synced_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Attempt to apply a target update after sync is complete to verify we don't panic
            let _ = update_sender
                .send(Target {
                    root: sha256::Digest::from([2u8; 32]),
                    range: lower_bound + 1..upper_bound + 1,
                })
                .await;

            // Verify the synced database has the expected state
            assert_eq!(synced_db.root(), root);
            assert_eq!(synced_db.op_count(), upper_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), lower_bound);

            synced_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }
}
