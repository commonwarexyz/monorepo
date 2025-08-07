use crate::{
    adb::{
        any::{sync::verifier::Verifier, Any, SyncConfig},
        operation::Fixed,
        sync::{Journal, Target},
    },
    journal::fixed,
    mmr::hasher::Standard,
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

mod verifier;

pub type Error = crate::adb::Error;

impl<E, K, V, H, T> crate::adb::sync::Database for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Op = Fixed<K, V>;
    type Journal = crate::journal::fixed::Journal<E, Fixed<K, V>>;
    type Verifier = Verifier<H>;
    type Error = crate::adb::Error;
    type Config = crate::adb::any::Config<T>;
    type Digest = H::Digest;
    type Context = E;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, <Self::Journal as Journal>::Error> {
        let journal_config = fixed::Config {
            partition: config.log_journal_partition.clone(),
            items_per_blob: config.log_items_per_blob,
            write_buffer: config.log_write_buffer,
            buffer_pool: config.buffer_pool.clone(),
        };

        fixed::Journal::<E, Fixed<K, V>>::init_sync(
            context.with_label("log"),
            journal_config,
            lower_bound,
            upper_bound,
        )
        .await
    }

    fn create_verifier() -> Self::Verifier {
        Verifier::new(Standard::<H>::new())
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: Target<Self::Digest>,
        apply_batch_size: usize,
    ) -> Result<Self, Self::Error> {
        // Build the complete database from the journal
        let db = Any::init_synced(
            context,
            SyncConfig {
                db_config,
                log: journal,
                lower_bound: target.lower_bound_ops,
                upper_bound: target.upper_bound_ops,
                pinned_nodes,
                apply_batch_size,
            },
        )
        .await?;

        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        let mut standard_hasher = Standard::<H>::new();
        Any::root(self, &mut standard_hasher)
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, Self::Error> {
        let has_operations = journal
            .has_operations_from(lower_bound)
            .await
            .map_err(crate::adb::Error::from)?;

        if !has_operations {
            // Close the existing journal before creating a new one
            journal.close().await.map_err(crate::adb::Error::from)?;

            // Create a new journal with the new bounds
            Self::create_journal(context, config, lower_bound, upper_bound)
                .await
                .map_err(crate::adb::Error::from)
        } else {
            // Just prune to the lower bound
            journal
                .prune(lower_bound)
                .await
                .map_err(crate::adb::Error::from)?;
            Ok(journal)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        adb::{
            any::test::{apply_ops, create_test_config, create_test_db, create_test_ops, AnyTest},
            operation::Fixed,
            sync::{
                self,
                engine::{EngineConfig, NextStep},
                resolver::tests::FailResolver,
                Engine, Target,
            },
        },
        mmr::{hasher::Standard, iterator::leaf_num_to_pos},
    };
    use commonware_cryptography::{sha256, Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, RwLock};
    use commonware_utils::NZU64;
    use futures::{channel::mpsc, SinkExt as _};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroU64,
        sync::Arc,
    };
    use test_case::test_case;

    fn test_hasher() -> Standard<Sha256> {
        Standard::<Sha256>::new()
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(1000, NZU64!(1); "db with batch size 1")]
    #[test_case(1000, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(1000, NZU64!(999); "db size not evenly divided by batch size; different batch size")]
    #[test_case(1000, NZU64!(100); "db size divided by batch size")]
    #[test_case(1000, NZU64!(1000); "db size == batch size")]
    #[test_case(1000, NZU64!(1001); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc;
            let target_log_size = target_db.log.size().await.unwrap();
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the inactivity floor, not 0
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Capture target database state and deleted keys before moving into config
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &target_db_ops {
                match op {
                    Fixed::Update(key, _) => {
                        if let Some((value, loc)) = target_db.get_with_loc(key).await.unwrap() {
                            expected_kvs.insert(*key, (value, loc));
                            deleted_keys.remove(key);
                        }
                    }
                    Fixed::Deleted(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    _ => {}
                }
            }

            let db_config = create_test_config(context.next_u64());

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    lower_bound_ops,
                    upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let mut got_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state
            let mut hasher = test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.log.size().await.unwrap(), target_log_size);
            assert_eq!(
                got_db.ops.pruned_to_pos(),
                leaf_num_to_pos(target_inactivity_floor)
            );

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher), target_root);

            // Verify that the synced database matches the target state
            for (key, &(value, loc)) in &expected_kvs {
                let synced_opt = got_db.get_with_loc(key).await.unwrap();
                assert_eq!(synced_opt, Some((value, loc)));
            }
            // Verify that deleted keys are absent
            for key in &deleted_keys {
                assert!(got_db.get_with_loc(key).await.unwrap().is_none(),);
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs = HashMap::new();
            for _ in 0..expected_kvs.len() {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                new_ops.push(Fixed::Update(key, value));
                new_kvs.insert(key, value);
            }
            apply_ops(&mut got_db, new_ops.clone()).await;
            apply_ops(&mut *target_db.write().await, new_ops).await;
            got_db.commit().await.unwrap();
            target_db.write().await.commit().await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db.read().await.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }

            let final_target_root = target_db.write().await.root(&mut hasher);
            assert_eq!(got_db.root(&mut hasher), final_target_root);

            // Capture the database state before closing
            let final_synced_op_count = got_db.op_count();
            let final_synced_inactivity_floor = got_db.inactivity_floor_loc;
            let final_synced_log_size = got_db.log.size().await.unwrap();
            let final_synced_oldest_retained_loc = got_db.oldest_retained_loc();
            let final_synced_pruned_to_pos = got_db.ops.pruned_to_pos();
            let final_synced_root = got_db.root(&mut hasher);

            // Close the database
            got_db.close().await.unwrap();

            // Reopen the database using the same configuration and verify the state is unchanged
            let reopened_db = AnyTest::init(context, db_config).await.unwrap();

            // Compare state against the database state before closing
            assert_eq!(reopened_db.op_count(), final_synced_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                final_synced_inactivity_floor
            );
            assert_eq!(reopened_db.log.size().await.unwrap(), final_synced_log_size);
            assert_eq!(
                reopened_db.oldest_retained_loc(),
                final_synced_oldest_retained_loc,
            );
            assert_eq!(reopened_db.ops.pruned_to_pos(), final_synced_pruned_to_pos);
            assert_eq!(reopened_db.root(&mut hasher), final_synced_root);

            // Verify that the original key-value pairs are still correct
            for (key, &(value, _loc)) in &expected_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap();
                assert_eq!(reopened_value, Some(value));
            }

            // Verify all new key-value pairs are still correct
            for (key, &value) in &new_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap().unwrap();
                assert_eq!(reopened_value, value);
            }

            // Verify that deleted keys are still absent
            for key in &deleted_keys {
                assert!(reopened_db.get(key).await.unwrap().is_none());
            }

            // Cleanup
            reopened_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that invalid bounds are rejected
    #[test]
    fn test_sync_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let db_config = create_test_config(context.next_u64());
            let config = EngineConfig {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: sha256::Digest::from([1u8; 32]),
                    lower_bound_ops: 31, // Invalid: lower > upper
                    upper_bound_ops: 30,
                },
                context,
                resolver: Arc::new(commonware_runtime::RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };

            let result: Result<AnyTest, _> = sync::sync(config).await;
            println!("{:?}", result.as_ref().err());
            assert!(matches!(
                result,
                Err(sync::Error::InvalidTarget {
                    lower_bound_pos: 31,
                    upper_bound_pos: 30,
                }),
            ));
        });
    }

    /// Test that sync works when target database has operations beyond the requested range
    /// of operations to sync.
    #[test]
    fn test_sync_subset_of_target_database() {
        const TARGET_DB_OPS: usize = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(TARGET_DB_OPS);
            // Apply all but the last operation
            apply_ops(&mut target_db, target_ops[0..TARGET_DB_OPS - 1].to_vec()).await;
            target_db.commit().await.unwrap();

            let mut hasher = test_hasher();
            let upper_bound_ops = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Add another operation after the sync range
            let final_op = &target_ops[TARGET_DB_OPS - 1];
            apply_ops(&mut target_db, vec![final_op.clone()]).await;
            target_db.commit().await.unwrap();

            // Start of the sync range is after the inactivity floor
            let config = EngineConfig {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context,
                resolver: Arc::new(RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };

            let synced_db: AnyTest = sync::sync(config).await.unwrap();

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

    // Test syncing where the sync client has some but not all of the operations in the target
    // database.
    #[test]
    fn test_sync_use_existing_db_partial_match() {
        const ORIGINAL_DB_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
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
            let mut hasher = test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1; // Up to the last operation

            // Reopen the sync database and sync it to the target database
            let target_db = Arc::new(RwLock::new(target_db));
            let config = EngineConfig {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let sync_db: AnyTest = sync::sync(config).await.unwrap();

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
    #[test]
    fn test_sync_use_existing_db_exact_match() {
        const NUM_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
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
            let mut hasher = test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1;

            // sync_db should never ask the resolver for operations
            // because it is already complete. Use a resolver that always fails
            // to ensure that it's not being used.
            let resolver = FailResolver::<sha256::Digest, sha256::Digest, sha256::Digest>::new();
            let config = EngineConfig {
                db_config: sync_config, // Use same config to access same partitions
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver,
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let sync_db: AnyTest = sync::sync(config).await.unwrap();

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
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased lower bound
            update_sender
                .send(Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound.saturating_sub(1),
                    upper_bound_ops: initial_upper_bound.saturating_add(1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::SyncTargetMovedBackward { .. })
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
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased upper bound
            update_sender
                .send(Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound.saturating_sub(1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::SyncTargetMovedBackward { .. })
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
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Apply more operations to the target database
            let more_ops = create_test_ops(1);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture final target state
            let mut hasher = test_hasher();
            let final_lower_bound = target_db.inactivity_floor_loc;
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Create client with placeholder initial target (stale compared to final target)
            let (mut update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: Some(update_receiver),
            };

            // Send target update with increased bounds
            update_sender
                .send(Target {
                    root: final_root,
                    lower_bound_ops: final_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify the synced database has the expected state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);
            assert_eq!(synced_db.op_count(), final_upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc, final_lower_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), final_lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync with invalid bounds (lower > upper)
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
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with invalid bounds (lower > upper)
            update_sender
                .send(Target {
                    root: initial_root,
                    lower_bound_ops: initial_upper_bound, // Greater than upper bound
                    upper_bound_ops: initial_lower_bound, // Less than lower bound
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(result, Err(sync::Error::InvalidTarget { .. })));

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
            let mut hasher = test_hasher();
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);

            // Create client with target that will complete immediately
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(20),
                target: Target {
                    root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Complete the sync
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Attempt to apply a target update after sync is complete to verify
            // we don't panic
            let _ = update_sender
                .send(Target {
                    // Dummy target update
                    root: sha256::Digest::from([2u8; 32]),
                    lower_bound_ops: lower_bound + 1,
                    upper_bound_ops: upper_bound + 1,
                })
                .await;

            // Verify the synced database has the expected state
            let mut hasher = test_hasher();
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
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial target and small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            // Step the client to process a batch
            let client = {
                let config = EngineConfig {
                    context: context.clone(),
                    db_config: create_test_config(context.next_u64()),
                    target: Target {
                        root: initial_root,
                        lower_bound_ops: initial_lower_bound,
                        upper_bound_ops: initial_upper_bound,
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_receiver: Some(update_receiver),
                };
                let mut client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();
                client.schedule_requests().await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
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
                let mut hasher = test_hasher();
                let new_lower_bound = db.inactivity_floor_loc;
                let new_upper_bound = db.op_count() - 1;
                let new_root = db.root(&mut hasher);

                // Send target update with new target
                update_sender
                    .send(Target {
                        root: new_root,
                        lower_bound_ops: new_lower_bound,
                        upper_bound_ops: new_upper_bound,
                    })
                    .await
                    .unwrap();

                new_root
            };

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            let mut hasher = test_hasher();
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
            let mut hasher = test_hasher();
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
            // Step the client to process a batch
            let client = {
                let config = EngineConfig {
                    context: context.clone(),
                    db_config: create_test_config(context.next_u64()),
                    target: Target {
                        root: initial_root,
                        lower_bound_ops: initial_lower_bound,
                        upper_bound_ops: initial_upper_bound,
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(2), // Very small batch size to ensure multiple batches needed
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_receiver: Some(update_receiver),
                };
                let mut client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();
                client.schedule_requests().await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal.size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Send target update with SAME lower bound but higher upper bound
            update_sender
                .send(Target {
                    root: final_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            let mut hasher = test_hasher();
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
    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count() - 1;

            // Perform sync
            let db_config = create_test_config(42);
            let context_clone = context.clone();
            let target_db = Arc::new(RwLock::new(target_db));
            let config = EngineConfig {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify initial sync worked
            let mut hasher = test_hasher();
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

    #[test_traced]
    fn test_sync_resolver_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let resolver = FailResolver::<sha256::Digest, sha256::Digest, sha256::Digest>::new();
            let target_root = sha256::Digest::from([0; 32]);

            let db_config = create_test_config(context.next_u64());
            let engine_config = EngineConfig {
                context,
                target: Target {
                    root: target_root,
                    lower_bound_ops: 0,
                    upper_bound_ops: 4,
                },
                resolver,
                apply_batch_size: 2,
                max_outstanding_requests: 2,
                fetch_batch_size: NZU64!(2),
                db_config,
                update_receiver: None,
            };

            // Attempt to sync - should fail due to resolver error
            let result: Result<AnyTest, _> = sync::sync(engine_config).await;
            assert!(result.is_err());
        });
    }
}
