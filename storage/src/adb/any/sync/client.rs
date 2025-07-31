use super::Error;
use crate::{
    adb::{
        operation::Fixed,
        sync::{
            engine::{SyncTarget, SyncTargetUpdateReceiver},
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
    pub fn validate(&self) -> Result<(), Error> {
        // Validate bounds (inclusive)
        if self.target.lower_bound_ops > self.target.upper_bound_ops {
            return Err(Error::InvalidTarget {
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
            any::{sync::sync, Any},
            operation::Fixed,
            sync::{engine::SyncTarget, resolver::tests::FailResolver},
        },
        mmr::{hasher::Standard, iterator::leaf_num_to_pos},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner, RwLock};
    use commonware_utils::NZU64;
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
            pruning_delay: 10,
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
                    super::super::Error::InvalidTarget { .. } => {}
                    other => panic!("Expected InvalidTarget error, got: {:?}", other),
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
}
