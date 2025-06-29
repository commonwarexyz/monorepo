use crate::resolver::Resolver;
use crate::{Error, SyncProgress};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::any::Any, adb::operation::Operation, index::Translator, mmr::verification::Proof,
};
use commonware_utils::Array;
use std::num::NonZeroU64;
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
    FetchOps {
        db: Any<E, K, V, H, T>,
        target_hash: H::Digest,
        progress: SyncProgress,
    },
    /// Applying received operations to local database
    ApplyOps {
        db: Any<E, K, V, H, T>,
        target_hash: H::Digest,
        proof: Proof<H::Digest>,
        operations: Vec<Operation<K, V>>,
        progress: SyncProgress,
    },
    /// Sync completed successfully
    Done {
        db: Any<E, K, V, H, T>,
        progress: SyncProgress,
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
    fn _progress(&self) -> Option<&SyncProgress> {
        match &self.state {
            Some(ClientState::FetchOps { progress, .. }) => Some(progress),
            Some(ClientState::ApplyOps { progress, .. }) => Some(progress),
            Some(ClientState::Done { progress, .. }) => Some(progress),
            _ => None,
        }
    }

    /// Process the next step in the sync process
    async fn step(mut self) -> Result<Self, Error> {
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
                    batches_received: 0,
                };

                if op_count == target_ops {
                    // Already at exact target
                    let root_hash = db.root(&mut self.hasher);
                    if root_hash != target_hash {
                        return Err(Error::HashMismatch {
                            expected: Box::new(target_hash),
                            actual: Box::new(root_hash),
                        });
                    } else {
                        self.state = Some(ClientState::Done {
                            db,
                            progress,
                            root_hash,
                        });
                        Ok(self)
                    }
                } else if op_count > target_ops {
                    // We're already past the target - this shouldn't happen
                    Err(Error::InvalidState)
                } else {
                    // We're not at the target yet, so we need to fetch more operations
                    self.state = Some(ClientState::FetchOps {
                        db,
                        target_hash,
                        progress,
                    });
                    Ok(self) // Continue
                }
            }

            ClientState::FetchOps {
                db,
                target_hash,
                mut progress,
            } => {
                // Calculate exactly how many operations we need
                let op_count = db.op_count();
                let remaining_ops = progress
                    .target_ops
                    .checked_sub(op_count)
                    .and_then(NonZeroU64::new)
                    .ok_or(Error::InvalidState)?;

                let batch_size = std::cmp::min(self.config.max_ops_per_batch, remaining_ops);

                debug!(
                    op_count,
                    progress.target_ops, remaining_ops, batch_size, "Fetching proof and operations"
                );

                let (proof, operations) = self.resolver.get_proof(op_count, batch_size).await?;
                progress.batches_received += 1;

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

                self.state = Some(ClientState::ApplyOps {
                    db,
                    target_hash,
                    proof,
                    operations,
                    progress,
                });
                Ok(self) // Continue
            }

            ClientState::ApplyOps {
                mut db,
                target_hash,
                proof,
                operations,
                mut progress,
            } => {
                // Verify the proof
                debug!("Verifying proof for operations");

                // Ensure we won't exceed the target after applying these operations
                let op_count = db.op_count();
                let new_op_count = op_count + operations.len() as u64;
                if new_op_count > progress.target_ops {
                    return Err(Error::InvalidResolver(format!(
                        "Applying {} operations from index {} would exceed target ops {}",
                        operations.len(),
                        op_count,
                        progress.target_ops
                    )));
                }

                match Any::<E, K, V, H, T>::verify_proof(
                    &mut self.hasher,
                    &proof,
                    op_count,
                    &operations,
                    &target_hash,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        // TODO add retry logic
                        return Err(Error::ProofVerificationFailed);
                    }
                    Err(e) => return Err(Error::ProofVerificationError(e)),
                }

                // Apply operations in batch
                debug!(
                    operations_count = operations.len(),
                    new_op_count, "Applying operations"
                );

                for op in operations {
                    match op {
                        Operation::Update(key, value) => {
                            db.update(key, value).await.map_err(Error::DatabaseError)?;
                        }
                        Operation::Deleted(key) => {
                            db.delete(key).await.map_err(Error::DatabaseError)?;
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
                    batches_processed = progress.batches_received,
                    completion_pct = progress.completion_percentage(),
                    "Applied operation batch"
                );

                // Check if we've reached exactly the target
                if progress.current_ops == progress.target_ops {
                    // Verify the final hash matches the target
                    let root_hash = db.root(&mut self.hasher);

                    if root_hash == target_hash {
                        info!(
                            final_ops = progress.current_ops,
                            operations_applied = progress.operations_applied,
                            batches_processed = progress.batches_received,
                            "Sync completed successfully"
                        );

                        self.state = Some(ClientState::Done {
                            db,
                            progress,
                            root_hash,
                        });
                        Ok(self) // Done
                    } else {
                        Err(Error::HashMismatch {
                            expected: Box::new(target_hash),
                            actual: Box::new(root_hash),
                        })
                    }
                } else {
                    // Need more operations to reach exactly the target
                    self.state = Some(ClientState::FetchOps {
                        db,
                        target_hash,
                        progress,
                    });
                    Ok(self) // Continue
                }
            }

            ClientState::Done { .. } => Err(Error::AlreadyComplete),
        }
    }

    /// Run the complete sync process
    pub async fn sync(mut self) -> Result<Any<E, K, V, H, T>, Error> {
        info!("Starting complete sync process");

        loop {
            self = self.step().await?;
            match self.state {
                Some(ClientState::Done {
                    db,
                    progress,
                    root_hash,
                }) => {
                    info!(
                        final_ops = progress.current_ops,
                        operations_applied = progress.operations_applied,
                        batches_processed = progress.batches_received,
                        root_hash = root_hash.to_string(),
                        "Sync completed successfully"
                    );

                    return Ok(db);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{resolver::LocalResolver, sync};
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_storage::{
        adb::any::{Any, Config},
        index,
    };
    use commonware_utils::NZU64;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use test_case::test_case;

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

    // Apply n updates to the database. Some portion of the updates are deletes.
    // It's guaranteed that calling this function with n' > n will apply the same updates
    // as calling this function with n, followed by additional updates.
    // Note that we don't commit after applying the updates.
    async fn apply_test_ops(mut db: TestAny, n: usize) -> TestAny {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = TestKey::random(&mut rng);
        for i in 0..n {
            let key = TestKey::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                db.delete(prev_key).await.unwrap();
            } else {
                let value = TestValue::random(&mut rng);
                db.update(key, value).await.unwrap();
                prev_key = key;
            }
        }
        db
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

    // Test that the client returns an error if the target ops is less than the current ops.
    #[test]
    fn test_invalid_target_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let target_db = create_test_db(context.clone()).await;
            let mut target_db = apply_test_ops(target_db, 9).await;
            target_db.commit().await.unwrap();
            let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
            let target_hash = target_db.root(&mut hasher);
            let sync_db = create_test_db(context.clone()).await;
            let mut sync_db = apply_test_ops(sync_db, 10).await;
            sync_db.commit().await.unwrap();

            let resolver = TestResolver::_new(sync_db);
            let result = Client::new(target_db, resolver, ClientConfig::default(), 0, target_hash);

            assert!(result.is_err());
            assert!(matches!(result.err().unwrap(), Error::InvalidTarget { .. }));
        });
    }

    // #[test_case(0, 1, NZU64!(1))]
    // #[test_case(0, 1, NZU64!(10))]
    // #[test_case(1, 2, NZU64!(1))]
    // #[test_case(1, 2, NZU64!(10))]
    // #[test_case(0, 100, NZU64!(1))]
    #[test_case(0, 100, NZU64!(10))]
    // #[test_case(5, 100, NZU64!(1))]
    // #[test_case(5, 100, NZU64!(10))]
    // #[test_case(99, 100, NZU64!(1))]
    // #[test_case(99, 100, NZU64!(10))]
    fn test_sync(sync_db_ops: usize, target_db_ops: usize, max_ops_per_batch: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let target_db = create_test_db(context.clone()).await;
            let mut target_db = apply_test_ops(target_db, target_db_ops).await;
            target_db.commit().await.unwrap();
            let target_ops = target_db.op_count();
            let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
            let target_hash = target_db.root(&mut hasher);
            let resolver = TestResolver::_new(target_db);
            let sync_db = create_test_db(context).await;
            let sync_db = apply_test_ops(sync_db, sync_db_ops).await;
            let config = ClientConfig { max_ops_per_batch };

            let result = sync(sync_db, resolver, target_ops, target_hash, config)
                .await
                .unwrap();
            assert_eq!(result.root(&mut hasher), target_hash);
            assert_eq!(result.op_count(), target_ops);
        });
    }

    // #[test]
    // fn test_delete_me() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let target_db = create_test_db(context.clone()).await;
    //         let mut target_db = apply_test_ops(target_db, 100).await;
    //         target_db.commit().await.unwrap();
    //         let target_ops = target_db.op_count();
    //         let floor = target_db.oldest_retained_loc().unwrap();
    //         let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
    //         let target_hash = target_db.root(&mut hasher);

    //         let ops = target_db
    //             .proof(floor, NonZeroU64::new(target_ops).unwrap())
    //             .await
    //             .unwrap();
    //     });
    // }
}
