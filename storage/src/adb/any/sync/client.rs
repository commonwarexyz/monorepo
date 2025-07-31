use super::Error;
use crate::{
    adb::{
        operation::Fixed,
        sync::{
            engine::{SyncTarget, SyncTargetUpdateReceiver},
            error::SyncError,
            resolver::Resolver,
        },
    },
    mmr,
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics as MetricsTrait, Storage};
use commonware_utils::Array;
use std::num::NonZeroU64;

/// Configuration for the sync client
pub struct Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    /// Context for the database.
    pub context: E,

    /// Channel for receiving target updates.
    pub update_receiver: Option<SyncTargetUpdateReceiver<H::Digest>>,

    /// Database configuration.
    pub db_config: crate::adb::any::Config<T>,

    /// Maximum operations to fetch per batch.
    pub fetch_batch_size: NonZeroU64,

    /// Synchronization target (root digest and operation bounds).
    pub target: SyncTarget<H::Digest>,

    /// Resolves requests for proofs and operations.
    pub resolver: R,

    /// Hasher for root digests.
    pub hasher: mmr::hasher::Standard<H>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,

    /// Maximum number of outstanding requests for operation batches.
    /// Higher values increase parallelism.
    pub max_outstanding_requests: usize,
}

impl<E, K, V, H, T, R> Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    /// Validate the configuration parameters
    pub fn validate(&self) -> Result<(), crate::adb::sync::error::SyncError<Error, R::Error>> {
        // Validate bounds (inclusive)
        if self.target.lower_bound_ops > self.target.upper_bound_ops {
            return Err(SyncError::InvalidTarget {
                lower_bound_pos: self.target.lower_bound_ops,
                upper_bound_pos: self.target.upper_bound_ops,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        adb::{
            any::{
                sync::{new_client, sync},
                Any,
            },
            operation::Fixed,
            sync::{
                engine::{StepResult, SyncTarget},
                resolver::tests::FailResolver,
            },
        },
        mmr::{hasher::Standard, iterator::leaf_num_to_pos},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner, RwLock};
    use commonware_utils::NZU64;
    use futures::{channel::mpsc, SinkExt};
    use rand::RngCore;
    use std::sync::Arc;
    use test_case::test_case;

    type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    fn create_test_config(seed: u64) -> crate::adb::any::Config<TwoCap> {
        const PAGE_SIZE: usize = 128;
        const PAGE_CACHE_SIZE: usize = 1024 * 1024;

        crate::adb::any::Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: 1024,
            mmr_write_buffer: 64,
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: 1024,
            log_write_buffer: 64,
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: commonware_runtime::buffer::PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            pruning_delay: 100,
        }
    }

    async fn create_test_db(mut context: deterministic::Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    fn create_test_ops(n: usize) -> Vec<Fixed<Digest, Digest>> {
        use commonware_cryptography::Digest as _;
        use rand::{rngs::StdRng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Fixed::Deleted(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Fixed::Update(key, value));
                prev_key = key;
            }
        }
        ops
    }

    async fn apply_ops(db: &mut AnyTest, ops: Vec<Fixed<Digest, Digest>>) {
        for op in ops {
            match op {
                Fixed::Update(key, value) => {
                    db.update(key, value).await.unwrap();
                }
                Fixed::Deleted(key) => {
                    db.delete(key).await.unwrap();
                }
                Fixed::Commit(_) => {
                    // Commit operations are handled automatically by the database
                    // when commit() is called, so we can ignore them here
                }
            }
        }
    }

    fn create_test_hasher() -> Standard<Sha256> {
        Standard::<Sha256>::new()
    }

    #[test_traced]
    fn test_sync_basic() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            // Create source database with some operations
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(5);
            apply_ops(&mut source_db, ops.clone()).await;
            source_db.commit().await.unwrap();
            let target_root = source_db.root(&mut create_test_hasher());

            // Create resolver from source database
            let source_db = Arc::new(RwLock::new(source_db));
            let config = Config {
                context: context.with_label("sync"),
                update_receiver: None,
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(2),
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops: {
                        let db = source_db.read().await;
                        db.inactivity_floor_loc
                    },
                    upper_bound_ops: {
                        let db = source_db.read().await;
                        db.op_count().saturating_sub(1)
                    },
                },
                resolver: source_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 2,
                max_outstanding_requests: 2,
            };

            // Sync the database
            let synced_db = sync(config).await.unwrap();

            // Verify roots match
            let expected_root = source_db.read().await.root(&mut create_test_hasher());
            let actual_root = synced_db.root(&mut create_test_hasher());
            assert_eq!(actual_root, expected_root);

            // Cleanup
            Arc::try_unwrap(source_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
            synced_db.destroy().await.unwrap();
        });
    }

    #[test_case(1, 0; "lower_bound_greater_than_upper_bound")]
    #[test_traced]
    fn test_sync_invalid_bounds(lower_bound: u64, upper_bound: u64) {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let resolver = FailResolver::<Digest, Digest, Digest>::new();
            let target_root = Digest::from([0; 32]);

            let config = Config {
                context: context.with_label("sync"),
                update_receiver: None,
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(2),
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                resolver,
                hasher: create_test_hasher(),
                apply_batch_size: 2,
                max_outstanding_requests: 2,
            };

            // Attempt to sync - should fail due to invalid bounds
            let result = sync(config).await;
            assert!(result.is_err(), "Expected sync to fail with invalid bounds");
            if let Err(error) = result {
                match error {
                    crate::adb::sync::error::SyncError::InvalidTarget { .. } => {}
                    other => panic!("Expected InvalidTarget error, got: {other:?}"),
                }
            }
        });
    }

    #[test_traced]
    fn test_sync_resolver_fails() {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let resolver = FailResolver::<Digest, Digest, Digest>::new();
            let target_root = Digest::from([0; 32]);

            let config = Config {
                context: context.with_label("sync"),
                update_receiver: None,
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(2),
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops: 0,
                    upper_bound_ops: 4,
                },
                resolver,
                hasher: create_test_hasher(),
                apply_batch_size: 2,
                max_outstanding_requests: 2,
            };

            // Attempt to sync - should fail due to resolver error
            let result = sync(config).await;
            assert!(result.is_err());
        });
    }

    /// Comprehensive sync test with various batch sizes
    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(100, NZU64!(1); "db with batch size 1")]
    #[test_case(100, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(100, NZU64!(99); "db size not evenly divided by batch size; different batch size")]
    #[test_case(100, NZU64!(50); "db size divided by batch size")]
    #[test_case(100, NZU64!(100); "db size == batch size")]
    #[test_case(100, NZU64!(101); "batch size > db size")]
    #[test_traced]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc;
            let target_log_size = target_db.log.size().await.unwrap();
            let mut hasher = create_test_hasher();
            let target_root = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the inactivity floor, not 0
            let lower_bound_ops = target_db.inactivity_floor_loc;

            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size,
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops,
                    upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                },
                context: context.clone(),
                resolver: target_db.clone(),
                hasher,
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let got_db = sync(config).await.unwrap();

            // Verify database state
            let mut hasher = create_test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.log.size().await.unwrap(), target_log_size);
            assert_eq!(
                got_db.ops.pruned_to_pos(),
                leaf_num_to_pos(target_inactivity_floor)
            );

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher), target_root);

            // Verify that key-value operations work correctly by checking a few operations
            for op in target_db_ops.iter().take(10) {
                if let Some(key) = op.to_key() {
                    let target_value = target_db.read().await.get(key).await.unwrap();
                    let synced_value = got_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }

            // Cleanup
            got_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test syncing a subset of the target database operations
    #[test_traced]
    fn test_sync_subset_of_target_database() {
        const TARGET_DB_OPS: usize = 1000;
        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(TARGET_DB_OPS);
            // Apply all but the last operation
            apply_ops(&mut target_db, target_ops[0..TARGET_DB_OPS - 1].to_vec()).await;
            target_db.commit().await.unwrap();

            let mut hasher = create_test_hasher();
            let upper_bound_ops = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Add another operation after the sync range
            let final_op = &target_ops[TARGET_DB_OPS - 1];
            apply_ops(&mut target_db, vec![final_op.clone()]).await;
            target_db.commit().await.unwrap();

            // Start of the sync range is after the inactivity floor
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context,
                resolver: Arc::new(RwLock::new(target_db)),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };

            let synced_db = sync(config).await.unwrap();

            // Verify the synced database has the correct range of operations
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound_ops);
            assert_eq!(synced_db.oldest_retained_loc(), Some(lower_bound_ops));
            assert_eq!(
                synced_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            assert_eq!(synced_db.op_count(), upper_bound_ops + 1);

            // Verify the final root digest matches our target
            assert_eq!(synced_db.root(&mut hasher), root);

            // Verify the synced database doesn't have any operations beyond the sync range.
            assert_eq!(
                synced_db.get(final_op.to_key().unwrap()).await.unwrap(),
                None
            );

            synced_db.destroy().await.unwrap();
        });
    }

    /// Test syncing with existing database that partially matches target
    #[test_traced]
    fn test_sync_use_existing_db_partial_match() {
        const ORIGINAL_DB_OPS: usize = 1_000;

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let original_ops = create_test_ops(ORIGINAL_DB_OPS);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_test_config(1337);
            let mut sync_db = AnyTest::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, original_ops.clone()).await;
            apply_ops(&mut sync_db, original_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            let original_db_op_count = target_db.op_count();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Add one more operation and commit the target database
            let last_op = create_test_ops(1);
            apply_ops(&mut target_db, last_op.clone()).await;
            target_db.commit().await.unwrap();
            let mut hasher = create_test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1; // Up to the last operation

            // Reopen the sync database and sync it to the target database
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let sync_db = sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(
                sync_db.inactivity_floor_loc,
                target_db.read().await.inactivity_floor_loc
            );
            assert_eq!(sync_db.oldest_retained_loc().unwrap(), lower_bound_ops);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.read().await.log.size().await.unwrap()
            );
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify that the operations in the overlapping range are present and correct
            for i in lower_bound_ops..original_db_op_count {
                let expected_op = target_db.read().await.log.read(i).await.unwrap();
                let synced_op = sync_db.log.read(i).await.unwrap();
                assert_eq!(expected_op, synced_op);
            }

            for target_op in &original_ops {
                if let Some(key) = target_op.to_key() {
                    let target_value = target_db.read().await.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }
            // Verify the last operation is present
            let last_key = last_op[0].to_key().unwrap();
            let last_value = *last_op[0].to_value().unwrap();
            assert_eq!(sync_db.get(last_key).await.unwrap(), Some(last_value));

            sync_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test case where existing database on disk exactly matches the sync target
    #[test_traced]
    fn test_sync_use_existing_db_exact_match() {
        const NUM_OPS: usize = 1_000;

        let runner = deterministic::Runner::default();
        runner.start(|mut context| async move {
            let target_ops = create_test_ops(NUM_OPS);

            // Create two databases
            let target_config = create_test_config(context.next_u64());
            let mut target_db = AnyTest::init(context.clone(), target_config).await.unwrap();
            let sync_config = create_test_config(context.next_u64());
            let mut sync_db = AnyTest::init(context.clone(), sync_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, target_ops.clone()).await;
            apply_ops(&mut sync_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            target_db.sync().await.unwrap();
            sync_db.sync().await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Reopen sync_db
            let mut hasher = create_test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1;

            // sync_db should never ask the resolver for operations
            // because it is already complete. Use a resolver that always fails
            // to ensure that it's not being used.
            let resolver = FailResolver::<Digest, Digest, Digest>::new();
            let config = Config {
                db_config: sync_config, // Use same config to access same partitions
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let sync_db = sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(sync_db.op_count(), target_db.op_count());
            assert_eq!(sync_db.oldest_retained_loc().unwrap(), lower_bound_ops);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.log.size().await.unwrap()
            );
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );

            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify state matches for sample operations
            for target_op in &target_ops {
                if let Some(key) = target_op.to_key() {
                    let target_value = target_db.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }

            sync_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that the client fails to sync if the lower bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            // Send target update with decreased lower bound (before starting sync)
            update_sender
                .send(SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound.saturating_sub(1),
                    upper_bound_ops: initial_upper_bound.saturating_add(1),
                })
                .await
                .unwrap();

            // Start sync - it should fail when processing the target update
            let result = sync(config).await;
            assert!(matches!(
                result,
                Err(crate::adb::sync::error::SyncError::SyncTargetMovedBackward { .. })
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
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
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            // Send target update with decreased upper bound (before starting sync)
            update_sender
                .send(SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound.saturating_sub(1),
                })
                .await
                .unwrap();

            // Start sync - it should fail when processing the target update
            let result = sync(config).await;
            assert!(matches!(
                result,
                Err(crate::adb::sync::error::SyncError::SyncTargetMovedBackward { .. })
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
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
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Apply more operations to the target database
            let more_ops = create_test_ops(1);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture final target state
            let mut hasher = create_test_hasher();
            let final_lower_bound = target_db.inactivity_floor_loc;
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Create client with placeholder initial target (stale compared to final target)
            let (mut update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(1),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: Some(update_receiver),
            };

            // Send target update with increased bounds
            update_sender
                .send(SyncTarget {
                    root: final_root,
                    lower_bound_ops: final_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            let synced_db = sync(config).await.unwrap();

            // Verify the synced database has the expected state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.op_count(), final_upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc, final_lower_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), final_lower_bound);
            assert_eq!(synced_db.root(&mut hasher), final_root);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Send target update with invalid bounds (lower > upper)
            update_sender
                .send(SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_upper_bound, // Greater than upper bound
                    upper_bound_ops: initial_lower_bound, // Less than lower bound
                })
                .await
                .unwrap();

            let result = sync(config).await;
            assert!(matches!(
                result,
                Err(crate::adb::sync::error::SyncError::InvalidTarget { .. })
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
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
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = create_test_hasher();
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);

            // Create client with target that will complete immediately
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(20),
                target: SyncTarget {
                    root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Complete the sync
            let synced_db = sync(config).await.unwrap();

            // Attempt to apply a target update after sync is complete to verify
            // we don't panic
            let _ = update_sender
                .send(SyncTarget {
                    root: Digest::from([2u8; 32]),
                    lower_bound_ops: lower_bound + 1,
                    upper_bound_ops: upper_bound + 1,
                })
                .await;

            // Verify the synced database has the expected state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), root);
            assert_eq!(synced_db.op_count(), upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound);

            synced_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client can handle target updates during sync execution
    #[test_case(1, 1)]
    #[test_case(1, 2)]
    #[test_case(1, 100)]
    #[test_case(2, 1)]
    #[test_case(2, 2)]
    #[test_case(2, 100)]
    // Regression test: panicked when we didn't set pinned nodes after updating target
    #[test_case(20, 10)]
    #[test_case(100, 1)]
    #[test_case(100, 2)]
    #[test_case(100, 100)]
    #[test_case(100, 1000)]
    #[test_traced("WARN")]
    fn test_target_update_during_sync(initial_ops: usize, additional_ops: usize) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database with initial operations
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(initial_ops);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial target and small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Step the client to process a batch
            let client = {
                let mut client = new_client(config).await.unwrap();
                client.schedule_requests().await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        StepResult::Continue(new_client) => new_client,
                        StepResult::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal.size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Modify the target database by adding more operations
            let additional_ops = create_test_ops(additional_ops);
            let new_root = {
                let mut db = target_db.write().await;
                apply_ops(&mut db, additional_ops).await;
                db.commit().await.unwrap();

                // Capture new target state
                let mut hasher = create_test_hasher();
                let new_lower_bound = db.inactivity_floor_loc;
                let new_upper_bound = db.op_count() - 1;
                let new_root = db.root(&mut hasher);

                // Send target update with new target
                update_sender
                    .send(SyncTarget {
                        root: new_root,
                        lower_bound_ops: new_lower_bound,
                        upper_bound_ops: new_upper_bound,
                    })
                    .await
                    .unwrap();

                new_root
            };

            // Complete the sync
            let mut client = client;
            let synced_db: Any<_, _, _, _, _> = loop {
                match client.step().await.unwrap() {
                    StepResult::Continue(new_client) => client = new_client,
                    StepResult::Complete(database) => break database,
                }
            };

            // Verify the synced database has the expected final state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), new_root);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            {
                assert_eq!(synced_db.op_count(), target_db.op_count());
                assert_eq!(
                    synced_db.inactivity_floor_loc,
                    target_db.inactivity_floor_loc
                );
                assert_eq!(
                    synced_db.oldest_retained_loc().unwrap(),
                    target_db.inactivity_floor_loc
                );
                assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));
            }

            // Verify the expected operations are present in the synced database.
            for i in synced_db.inactivity_floor_loc..synced_db.op_count() {
                let got = synced_db.log.read(i).await.unwrap();
                let expected = target_db.log.read(i).await.unwrap();
                assert_eq!(got, expected);
            }
            for i in synced_db.ops.oldest_retained_pos().unwrap()..synced_db.ops.size() {
                let got = synced_db.ops.get_node(i).await.unwrap();
                let expected = target_db.ops.get_node(i).await.unwrap();
                assert_eq!(got, expected);
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test target update with same lower bound but higher upper bound
    #[test_traced("WARN")]
    fn test_target_same_lower_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a larger target database to ensure pruning occurs
            let mut target_db = create_test_db(context.clone()).await;
            let initial_ops = create_test_ops(100);
            apply_ops(&mut target_db, initial_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture the state after first commit (this will have a non-zero inactivity floor)
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Add more operations to create the extended target
            let additional_ops = create_test_ops(50);
            apply_ops(&mut target_db, additional_ops).await;
            target_db.commit().await.unwrap();
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial smaller target and very small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(2), // Very small batch size to ensure multiple batches needed
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Step the client to process a batch
            let client = {
                let mut client = new_client(config).await.unwrap();
                client.schedule_requests().await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        StepResult::Continue(new_client) => new_client,
                        StepResult::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal.size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Send target update with SAME lower bound but higher upper bound
            update_sender
                .send(SyncTarget {
                    root: final_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let mut client = client;
            let synced_db: Any<_, _, _, _, _> = loop {
                match client.step().await.unwrap() {
                    StepResult::Continue(new_client) => client = new_client,
                    StepResult::Complete(database) => break database,
                }
            };

            // Verify the synced database has the expected final state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };

            assert_eq!(synced_db.op_count(), target_db.op_count());
            assert_eq!(
                synced_db.inactivity_floor_loc,
                target_db.inactivity_floor_loc
            );
            assert_eq!(
                synced_db.oldest_retained_loc().unwrap(),
                initial_lower_bound
            );
            assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));

            // Verify the expected operations are present in the synced database.
            for i in synced_db.inactivity_floor_loc..synced_db.op_count() {
                let got = synced_db.log.read(i).await.unwrap();
                let expected = target_db.log.read(i).await.unwrap();
                assert_eq!(got, expected);
            }
            for i in synced_db.ops.oldest_retained_pos().unwrap()..synced_db.ops.size() {
                let got = synced_db.ops.get_node(i).await.unwrap();
                let expected = target_db.ops.get_node(i).await.unwrap();
                assert_eq!(got, expected);
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test demonstrating that a synced database can be reopened and retain its state.
    #[test_traced]
    fn test_sync_database_persistence() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = create_test_hasher();
            let target_root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count() - 1;

            // Perform sync
            let db_config = create_test_config(42);
            let context_clone = context.clone();
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                context,
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let synced_db = sync(config).await.unwrap();

            // Verify initial sync worked
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), target_root);

            // Save state before closing
            let expected_root = synced_db.root(&mut hasher);
            let expected_op_count = synced_db.op_count();
            let expected_inactivity_floor_loc = synced_db.inactivity_floor_loc;
            let expected_oldest_retained_loc = synced_db.oldest_retained_loc();
            let expected_pruned_to_pos = synced_db.ops.pruned_to_pos();

            // Close the database
            synced_db.close().await.unwrap();

            // Re-open the database
            let reopened_db = AnyTest::init(context_clone, db_config).await.unwrap();

            // Verify the state is unchanged
            assert_eq!(reopened_db.root(&mut hasher), expected_root);
            assert_eq!(reopened_db.op_count(), expected_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                expected_inactivity_floor_loc
            );
            assert_eq!(
                reopened_db.oldest_retained_loc(),
                expected_oldest_retained_loc
            );
            assert_eq!(reopened_db.ops.pruned_to_pos(), expected_pruned_to_pos);

            // Cleanup
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
            reopened_db.destroy().await.unwrap();
        });
    }
}
