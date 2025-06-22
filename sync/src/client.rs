use std::num::NonZeroU64;

use crate::resolver::Resolver;
use crate::{Error, SyncProgress};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::any::Any, adb::operation::Operation, index::Translator, mmr::verification::Proof,
};
use commonware_utils::Array;
use tracing::{debug, info};

/// Configuration for the sync client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Maximum operations to fetch per batch
    pub max_ops_per_batch: NonZeroU64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_ops_per_batch: NonZeroU64::new(1000).unwrap(),
        }
    }
}

/// Current state of the sync client
pub enum ClientState<E: Storage + Clock + Metrics, K: Array, V: Array, H: Hasher, T: Translator> {
    /// Initial state - ready to start sync
    Init {
        db: Any<E, K, V, H, T>,
        target_ops: u64,
        target_hash: H::Digest,
    },
    /// Requesting proof and operations from server
    FetchingProof {
        db: Any<E, K, V, H, T>,
        target_hash: H::Digest,
        progress: SyncProgress,
    },
    /// Applying received operations to local database
    ApplyingOperations {
        db: Any<E, K, V, H, T>,
        target_hash: H::Digest,
        proof: Proof<H>,
        operations: Vec<Operation<K, V>>,
        progress: SyncProgress,
    },
    /// Sync completed successfully
    Done {
        db: Any<E, K, V, H, T>,
        final_progress: SyncProgress,
        root_hash: H::Digest,
    },
}

/// Sync client for Any ADB
pub struct Client<E, K, V, H, T, R>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    state: Option<ClientState<E, K, V, H, T>>,
    resolver: R,
    config: ClientConfig,
    hasher: commonware_storage::mmr::hasher::Standard<H>,
}

impl<E, K, V, H, T, R> Client<E, K, V, H, T, R>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    /// Create a new sync client
    pub fn new(
        db: Any<E, K, V, H, T>,
        resolver: R,
        config: ClientConfig,
        target_ops: u64,
        target_hash: H::Digest,
    ) -> Result<Self, Error> {
        // Validate inputs
        let current_ops = db.op_count();
        if target_ops < current_ops {
            return Err(Error::InvalidTarget {
                current: current_ops,
                target: target_ops,
            });
        }

        let state = ClientState::Init {
            db,
            target_ops,
            target_hash,
        };

        Ok(Self {
            state: Some(state),
            resolver,
            config,
            hasher: commonware_storage::mmr::hasher::Standard::<H>::new(),
        })
    }

    /// Get current sync progress
    fn _progress(&self) -> Option<SyncProgress> {
        match &self.state {
            Some(ClientState::FetchingProof { progress, .. }) => Some(progress.clone()),
            Some(ClientState::ApplyingOperations { progress, .. }) => Some(progress.clone()),
            Some(ClientState::Done { final_progress, .. }) => Some(final_progress.clone()),
            _ => None,
        }
    }

    /// Process the next step in the sync process
    async fn step(&mut self) -> Result<bool, Error> {
        let current_state = self.state.take().ok_or(Error::InvalidState)?;

        match current_state {
            ClientState::Init {
                db,
                target_ops,
                target_hash,
            } => {
                let op_count = db.op_count();
                info!(op_count, target_ops, "Starting sync process");

                let progress = SyncProgress {
                    current_ops: op_count,
                    target_ops,
                    operations_applied: 0,
                    batches_processed: 0,
                };

                if op_count == target_ops {
                    // Already at exact target
                    let root_hash = db.root(&mut self.hasher);
                    if root_hash == target_hash {
                        self.state = Some(ClientState::Done {
                            db,
                            final_progress: progress,
                            root_hash,
                        });
                        return Ok(true);
                    } else {
                        return Err(Error::HashMismatch {
                            expected: Box::new(target_hash),
                            actual: Box::new(root_hash),
                        });
                    }
                } else if op_count > target_ops {
                    // We're already past the target - this shouldn't happen
                    return Err(Error::InvalidState);
                } else {
                    // We're not at the target yet, so we need to fetch more operations
                    self.state = Some(ClientState::FetchingProof {
                        db,
                        target_hash,
                        progress,
                    });
                }
                Ok(false) // Continue
            }

            ClientState::FetchingProof {
                db,
                target_hash,
                mut progress,
            } => {
                // Calculate exactly how many operations we need
                let op_count = db.op_count();
                if op_count > progress.target_ops {
                    return Err(Error::InvalidState);
                }

                let operations_needed = NonZeroU64::new(progress.target_ops - op_count).unwrap();
                let batch_size = std::cmp::min(self.config.max_ops_per_batch, operations_needed);

                debug!(
                    op_count,
                    progress.target_ops,
                    operations_needed,
                    batch_size,
                    "Fetching proof and operations"
                );

                let (proof, operations) = self.resolver.get_proof(op_count, batch_size).await?;

                // Validate that we didn't get more operations than requested
                if operations.len() as u64 > batch_size.get() {
                    return Err(Error::InvalidResolver(format!(
                        "Resolver returned {} operations but only {} were requested",
                        operations.len(),
                        batch_size.get()
                    )));
                }

                debug!(
                    operations_count = operations.len(),
                    "Received operations from resolver"
                );

                progress.batches_processed += 1;

                self.state = Some(ClientState::ApplyingOperations {
                    db,
                    target_hash,
                    proof,
                    operations,
                    progress,
                });
                Ok(false) // Continue
            }

            ClientState::ApplyingOperations {
                mut db,
                target_hash,
                proof,
                operations,
                mut progress,
            } => {
                // Verify the proof
                debug!("Verifying proof for operations");

                // Ensure we won't exceed the target after applying these operations
                let start_loc = db.op_count();
                let expected_final_ops = start_loc + operations.len() as u64;
                if expected_final_ops > progress.target_ops {
                    return Err(Error::InvalidResolver(format!(
                        "Applying {} operations from index {} would exceed target ops {}",
                        operations.len(),
                        start_loc,
                        progress.target_ops
                    )));
                }

                match Any::<E, K, V, H, T>::verify_proof(
                    &mut self.hasher,
                    &proof,
                    start_loc,
                    &operations,
                    &target_hash,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(Error::ProofVerificationFailed);
                    }
                    Err(e) => return Err(Error::ProofVerificationError(e)),
                }

                // Apply operations in batch
                debug!(
                    operations_count = operations.len(),
                    expected_final_ops, "Applying operations"
                );

                for op in operations.iter() {
                    match op {
                        Operation::Update(key, value) => {
                            db.update(key.clone(), value.clone())
                                .await
                                .map_err(Error::DatabaseError)?;
                        }
                        Operation::Deleted(key) => {
                            db.delete(key.clone()).await.map_err(Error::DatabaseError)?;
                        }
                        Operation::Commit(_) => {
                            db.commit().await.map_err(Error::DatabaseError)?;
                        }
                    }

                    progress.operations_applied += 1;
                }

                progress.current_ops = db.op_count();

                // Verify we didn't somehow exceed the target
                if progress.current_ops > progress.target_ops {
                    return Err(Error::ExceededTarget {
                        target: progress.target_ops,
                        actual: progress.current_ops,
                    });
                }

                info!(
                    current_ops = progress.current_ops,
                    target_ops = progress.target_ops,
                    operations_applied = progress.operations_applied,
                    batches_processed = progress.batches_processed,
                    completion_pct = progress.completion_percentage(),
                    "Applied operation batch"
                );

                // Check if we've reached exactly the target
                if progress.current_ops == progress.target_ops {
                    // Verify the final hash matches the target
                    let final_root = db.root(&mut self.hasher);

                    if final_root == target_hash {
                        info!(
                            final_ops = progress.current_ops,
                            operations_applied = progress.operations_applied,
                            batches_processed = progress.batches_processed,
                            "Sync completed successfully"
                        );

                        self.state = Some(ClientState::Done {
                            db,
                            final_progress: progress,
                            root_hash: final_root,
                        });
                        Ok(true) // Done
                    } else {
                        Err(Error::HashMismatch {
                            expected: Box::new(target_hash),
                            actual: Box::new(final_root),
                        })
                    }
                } else {
                    // Need more operations to reach exactly the target
                    self.state = Some(ClientState::FetchingProof {
                        db,
                        target_hash,
                        progress,
                    });
                    Ok(false) // Continue
                }
            }

            ClientState::Done { .. } => Err(Error::AlreadyComplete),
        }
    }

    /// Run the complete sync process
    pub async fn sync(&mut self) -> Result<Any<E, K, V, H, T>, Error> {
        info!("Starting complete sync process");

        loop {
            let is_done = self.step().await?;
            if is_done {
                break;
            }
        }

        // Take ownership of the state to extract the database
        match self.state.take() {
            Some(ClientState::Done {
                db,
                final_progress,
                root_hash,
            }) => {
                info!(
                    final_ops = final_progress.current_ops,
                    operations_applied = final_progress.operations_applied,
                    batches_processed = final_progress.batches_processed,
                    root_hash = root_hash.to_string(),
                    "Sync completed successfully"
                );

                Ok(db)
            }
            _ => Err(Error::InvalidState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::LocalResolver;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_storage::{
        adb::any::{Any, Config},
        index,
    };
    use commonware_utils::NZU64;
    use rand::RngCore as _;

    type TestHash = Sha256;
    type TestKey = Digest;
    type TestValue = Digest;
    type TestTranslator = index::translator::TwoCap;
    type TestAny = Any<Context, TestKey, TestValue, TestHash, TestTranslator>;
    type TestResolver = LocalResolver<Context, TestKey, TestValue, TestHash, TestTranslator>;

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> TestAny {
        let n = context.next_u64();
        let config = Config {
            mmr_journal_partition: format!("mmr_journal_{n}"),
            mmr_metadata_partition: format!("mmr_metadata_{n}"),
            mmr_items_per_blob: 1024,
            mmr_write_buffer: 64,
            log_journal_partition: format!("log_journal_{n}"),
            log_items_per_blob: 1024,
            log_write_buffer: 64,
            translator: TestTranslator::default(),
            pool: None,
        };
        TestAny::init(context, config).await.unwrap()
    }

    async fn apply_test_ops(mut db: TestAny) -> TestAny {
        // Add multiple operations
        db.update(TestHash::fill(1), TestHash::fill(1))
            .await
            .unwrap();
        db.update(TestHash::fill(2), TestHash::fill(2))
            .await
            .unwrap();
        db.commit().await.unwrap();

        db.update(TestHash::fill(3), TestHash::fill(3))
            .await
            .unwrap();
        db.delete(TestHash::fill(1)).await.unwrap();
        db.commit().await.unwrap();

        db
    }

    async fn apply_test_ops_2(mut db: TestAny) -> TestAny {
        // Add multiple operations
        db.update(TestHash::fill(1), TestHash::fill(1))
            .await
            .unwrap();
        db.update(TestHash::fill(2), TestHash::fill(2))
            .await
            .unwrap();
        db.commit().await.unwrap();

        db.update(TestHash::fill(3), TestHash::fill(3))
            .await
            .unwrap();
        db.delete(TestHash::fill(1)).await.unwrap();
        db.commit().await.unwrap();

        db.update(TestHash::fill(4), TestHash::fill(4))
            .await
            .unwrap();
        db.delete(TestHash::fill(2)).await.unwrap();
        db.commit().await.unwrap();

        db
    }

    /// Helper function to attempt sync and handle expected failures gracefully
    async fn attempt_sync(
        target_db: TestAny,
        resolver: TestResolver,
        target_ops: u64,
        target_hash: <TestHash as Hasher>::Digest,
    ) -> Result<TestAny, Error> {
        let mut client = Client::new(
            target_db,
            resolver,
            ClientConfig::default(),
            target_ops,
            target_hash,
        )?;
        client.sync().await
    }

    #[test]
    fn test_client_configuration() {
        let config = ClientConfig::default();
        assert_eq!(config.max_ops_per_batch.get(), 1000);

        let custom_config = ClientConfig {
            max_ops_per_batch: NZU64!(5),
        };
        assert_eq!(custom_config.max_ops_per_batch.get(), 5);
    }

    #[test]
    fn test_invalid_target_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let target_db = create_test_db(context.clone()).await;
            let target_db = apply_test_ops(target_db).await;
            let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
            let target_hash = target_db.root(&mut hasher);
            let sync_db = create_test_db(context.clone()).await;
            let sync_db = apply_test_ops_2(sync_db).await;

            let resolver = TestResolver::_new(sync_db);
            let result = Client::new(target_db, resolver, ClientConfig::default(), 0, target_hash);

            assert!(result.is_err());
            assert!(matches!(result.err().unwrap(), Error::InvalidTarget { .. }));
        });
    }

    // #[test]
    // fn test_client_state_management() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let (source_db, target_ops, target_hash) = apply_test_ops(context.clone()).await;
    //         let target_db = create_test_db(context).await;
    //         let resolver = TestResolver::_new(source_db);

    //         let client = Client::new(
    //             target_db,
    //             resolver,
    //             ClientConfig::default(),
    //             target_ops,
    //             target_hash,
    //         )
    //         .unwrap();

    //         // Initial state should be Some
    //         assert!(client.state.is_some());
    //         match &client.state {
    //             Some(ClientState::Init { .. }) => {}
    //             _ => panic!("Expected Init state"),
    //         }
    //     });
    // }

    #[test]
    fn test_sync_empty_to_populated() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let target_db = create_test_db(context.clone()).await;
            let target_db = apply_test_ops(target_db).await;
            let target_ops = target_db.op_count();
            let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
            let target_hash = target_db.root(&mut hasher);
            let resolver = TestResolver::_new(target_db);
            let sync_db = create_test_db(context).await;

            let result = attempt_sync(sync_db, resolver, target_ops, target_hash)
                .await
                .unwrap();
            assert_eq!(result.root(&mut hasher), target_hash);
            assert_eq!(result.op_count(), target_ops);
        });
    }

    // #[test]
    // fn test_sync_with_delete_operations() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         // Create source with delete operations
    //         let mut source_db = create_test_db(context.clone()).await;
    //         source_db
    //             .update(TestHash::fill(1u8), TestHash::fill(10u8))
    //             .await
    //             .unwrap();
    //         source_db
    //             .update(TestHash::fill(2u8), TestHash::fill(20u8))
    //             .await
    //             .unwrap();
    //         source_db.commit().await.unwrap();
    //         source_db.delete(TestHash::fill(1u8)).await.unwrap();
    //         source_db.commit().await.unwrap();

    //         let target_ops = source_db.op_count() - 1;
    //         let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
    //         let target_hash = source_db.root(&mut hasher);

    //         let target_db = create_test_db(context).await;
    //         let resolver = TestResolver::_new(source_db);

    //         let result = attempt_sync(target_db, resolver, target_ops, target_hash).await;

    //         match result {
    //             Ok(synced_db) => {
    //                 assert_eq!(synced_db.root(&mut hasher), target_hash);
    //                 assert_eq!(synced_db.op_count(), target_ops);
    //             }
    //             Err(Error::ProofVerificationFailed) => {
    //                 // Expected in test environment
    //                 assert!(false, "TODO remove");
    //             }
    //             Err(e) => panic!("Unexpected error: {:?}", e),
    //         }
    //     });
    // }

    // #[test]
    // fn test_sync_step_by_step() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let (source_db, target_ops, target_hash) = apply_test_ops(context.clone()).await;
    //         let target_db = create_test_db(context).await;
    //         let resolver = TestResolver::_new(source_db);

    //         let mut client = Client::new(
    //             target_db,
    //             resolver,
    //             ClientConfig::default(),
    //             target_ops,
    //             target_hash,
    //         )
    //         .unwrap();

    //         // Test state transitions through step execution
    //         assert!(matches!(client.state, Some(ClientState::Init { .. })));

    //         let mut steps = 0;
    //         let max_steps = 10;

    //         loop {
    //             match client.step().await {
    //                 Ok(true) => break, // Sync completed
    //                 Ok(false) => {
    //                     steps += 1;
    //                     if steps > max_steps {
    //                         panic!("Too many steps without completion");
    //                     }
    //                 }
    //                 Err(Error::ProofVerificationFailed) => break, // Expected failure
    //                 Err(e) => panic!("Unexpected error: {:?}", e),
    //             }
    //         }

    //         // Verify final state
    //         match &client.state {
    //             Some(ClientState::Done { .. }) => {
    //                 // Sync succeeded
    //             }
    //             _ => {
    //                 // Sync failed but state machine worked correctly
    //             }
    //         }
    //     });
    // }

    // #[test]
    // fn test_batch_configuration() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let (source_db, target_ops, target_hash) = apply_test_ops(context.clone()).await;
    //         let target_db = create_test_db(context).await;
    //         let resolver = TestResolver::_new(source_db);

    //         // Test with small batch size
    //         let config = ClientConfig {
    //             max_ops_per_batch: NZU64!(2),
    //         };

    //         let mut client =
    //             Client::new(target_db, resolver, config, target_ops, target_hash).unwrap();

    //         let result = client.sync().await;
    //         match result {
    //             Ok(_) => {
    //                 // Sync succeeded with small batches
    //             }
    //             Err(Error::ProofVerificationFailed) => {
    //                 // Expected in test environment
    //             }
    //             Err(e) => panic!("Unexpected error: {:?}", e),
    //         }
    //     });
    // }

    // #[test]
    // fn test_error_hash_mismatch() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let (source_db, target_ops, _) = apply_test_ops(context.clone()).await;
    //         let target_db = create_test_db(context).await;
    //         let resolver = TestResolver::_new(source_db);
    //         let wrong_hash = TestHash::fill(255u8);

    //         let result = attempt_sync(target_db, resolver, target_ops, wrong_hash).await;

    //         assert!(result.is_err());
    //         match result.err().unwrap() {
    //             Error::HashMismatch { .. } | Error::ProofVerificationFailed => {
    //                 // Both are acceptable error types for this scenario
    //             }
    //             e => panic!(
    //                 "Expected HashMismatch or ProofVerificationFailed, got: {:?}",
    //                 e
    //             ),
    //         }
    //     });
    // }
}
