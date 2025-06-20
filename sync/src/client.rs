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
        target_index: u64,
        target_hash: H::Digest,
    },
    /// Requesting proof and operations from server
    FetchingProof {
        db: Any<E, K, V, H, T>,
        target_index: u64,
        target_hash: H::Digest,
        progress: SyncProgress,
    },
    /// Applying received operations to local database
    ApplyingOperations {
        db: Any<E, K, V, H, T>,
        target_index: u64,
        target_hash: H::Digest,
        proof: Proof<H>,
        operations: Vec<Operation<K, V>>,
        start_index: u64,
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
        target_index: u64,
        target_hash: H::Digest,
    ) -> Result<Self, Error> {
        // Validate inputs
        let current_index = db.op_count();
        if target_index < current_index {
            return Err(Error::InvalidTarget {
                current: current_index,
                target: target_index,
            });
        }

        let state = ClientState::Init {
            db,
            target_index,
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
                target_index,
                target_hash,
            } => {
                let op_count = db.op_count();
                info!(op_count, target_index, "Starting sync process");

                let progress = SyncProgress {
                    current_index: op_count,
                    target_index,
                    operations_applied: 0,
                    batches_processed: 0,
                };

                if op_count == target_index + 1 {
                    // Already at exact target (applied operations 0 through target_index inclusive)
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
                } else if op_count > target_index + 1 {
                    // We're already past the target - this shouldn't happen
                    return Err(Error::InvalidState);
                } else {
                    // We're not at the target yet, so we need to fetch more operations
                    self.state = Some(ClientState::FetchingProof {
                        db,
                        target_index,
                        target_hash,
                        progress,
                    });
                }
                Ok(false) // Continue
            }

            ClientState::FetchingProof {
                db,
                target_index,
                target_hash,
                mut progress,
            } => {
                // Calculate exactly how many operations we need
                let next_index = db.op_count();
                if next_index > target_index {
                    return Err(Error::InvalidState);
                }

                let operations_needed = NonZeroU64::new(target_index + 1 - next_index).unwrap();
                let batch_size = std::cmp::min(self.config.max_ops_per_batch, operations_needed);

                debug!(
                    next_index,
                    target_index, operations_needed, batch_size, "Fetching proof and operations"
                );

                let (proof, operations) = self.resolver.get_proof(next_index, batch_size).await?;

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
                    target_index,
                    target_hash,
                    proof,
                    operations,
                    start_index: next_index,
                    progress,
                });
                Ok(false) // Continue
            }

            ClientState::ApplyingOperations {
                mut db,
                target_index,
                target_hash,
                proof,
                operations,
                start_index,
                mut progress,
            } => {
                // Verify the proof
                let current_root = db.root(&mut self.hasher);

                debug!("Verifying proof for operations");

                match Any::<E, K, V, H, T>::verify_proof(
                    &mut self.hasher,
                    &proof,
                    start_index,
                    &operations,
                    &current_root,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(Error::ProofVerificationFailed);
                    }
                    Err(e) => return Err(Error::ProofVerificationError(e)),
                }

                // Ensure we won't exceed the target after applying these operations
                let expected_final_index = start_index + operations.len() as u64;
                if expected_final_index > target_index + 1 {
                    return Err(Error::InvalidResolver(format!(
                        "Applying {} operations from index {} would exceed target index {}",
                        operations.len(),
                        start_index,
                        target_index
                    )));
                }

                // Apply operations in batch
                debug!(
                    operations_count = operations.len(),
                    expected_final_index, "Applying operations"
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

                let new_current_index = db.op_count();
                progress.current_index = new_current_index;

                // Verify we didn't somehow exceed the target
                if new_current_index > target_index + 1 {
                    return Err(Error::ExceededTarget {
                        target: target_index,
                        actual: new_current_index,
                    });
                }

                info!(
                    current_index = new_current_index,
                    target_index,
                    operations_applied = progress.operations_applied,
                    batches_processed = progress.batches_processed,
                    completion_pct = progress.completion_percentage(),
                    "Applied operation batch"
                );

                // Check if we've reached exactly the target
                if new_current_index == target_index + 1 {
                    // Verify the final hash matches the target
                    let final_root = db.root(&mut self.hasher);

                    if final_root == target_hash {
                        info!(
                            final_index = new_current_index,
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
                        target_index,
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
                    final_index = final_progress.current_index,
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
