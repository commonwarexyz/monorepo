use crate::resolver::Resolver;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::any::Any, adb::operation::Operation, index::Translator, mmr::verification::Proof,
};
use commonware_utils::Array;
use std::fmt;
use tracing::{debug, info, warn};

mod resolver;

/// Progress information for sync operations
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub current_index: u64,
    pub target_index: u64,
    pub operations_applied: u64,
    pub batches_processed: u64,
}

impl SyncProgress {
    pub fn completion_percentage(&self) -> f64 {
        if self.target_index == 0 {
            return 100.0;
        }
        (self.current_index as f64 / self.target_index as f64 * 100.0).min(100.0)
    }

    pub fn is_complete(&self) -> bool {
        self.current_index >= self.target_index
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
        next_index: u64,
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

/// Configuration for the sync client
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum operations to fetch per batch
    pub max_ops_per_batch: u64,
    /// Maximum retries for failed operations
    pub max_retries: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_ops_per_batch: 1000,
            max_retries: 3,
        }
    }
}

/// Sync client for Any ADB
pub struct SyncClient<E, K, V, H, T, R>
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
    config: SyncConfig,
    hasher: commonware_storage::mmr::hasher::Standard<H>,
    retry_count: u32,
}

impl<E, K, V, H, T, R> SyncClient<E, K, V, H, T, R>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    /// Create a new sync client with custom configuration
    pub fn new_with_config(
        db: Any<E, K, V, H, T>,
        resolver: R,
        config: SyncConfig,
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

        if config.max_ops_per_batch == 0 {
            return Err(Error::InvalidConfig(
                "max_ops_per_batch cannot be zero".into(),
            ));
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
            retry_count: 0,
        })
    }

    /// Create a new sync client with default configuration
    pub fn new(
        db: Any<E, K, V, H, T>,
        resolver: R,
        target_index: u64,
        target_hash: H::Digest,
    ) -> Result<Self, Error> {
        Self::new_with_config(
            db,
            resolver,
            SyncConfig::default(),
            target_index,
            target_hash,
        )
    }

    /// Get current sync progress
    pub fn progress(&self) -> Option<SyncProgress> {
        match &self.state {
            Some(ClientState::FetchingProof { progress, .. }) => Some(progress.clone()),
            Some(ClientState::ApplyingOperations { progress, .. }) => Some(progress.clone()),
            Some(ClientState::Done { final_progress, .. }) => Some(final_progress.clone()),
            _ => None,
        }
    }

    /// Process the next step in the sync process
    pub async fn step(&mut self) -> Result<bool, Error> {
        let current_state = self.state.take().ok_or(Error::InvalidState)?;

        match current_state {
            ClientState::Init {
                db,
                target_index,
                target_hash,
            } => {
                let current_index = db.op_count();
                let progress = SyncProgress {
                    current_index,
                    target_index,
                    operations_applied: 0,
                    batches_processed: 0,
                };

                info!(current_index, target_index, "Starting sync process");

                if current_index >= target_index {
                    // Already at target, verify hash
                    let root_hash = db.root(&mut self.hasher);
                    if root_hash == target_hash {
                        self.state = Some(ClientState::Done {
                            db,
                            final_progress: progress,
                            root_hash,
                        });
                        return Ok(true); // Done
                    } else {
                        return Err(Error::HashMismatch {
                            expected: Box::new(target_hash),
                            actual: Box::new(root_hash),
                        });
                    }
                } else {
                    self.state = Some(ClientState::FetchingProof {
                        db,
                        target_index,
                        target_hash,
                        next_index: current_index,
                        progress,
                    });
                }
                Ok(false) // Continue
            }

            ClientState::FetchingProof {
                db,
                target_index,
                target_hash,
                next_index,
                mut progress,
            } => {
                let remaining = target_index - next_index;
                let batch_size = std::cmp::min(self.config.max_ops_per_batch, remaining);

                debug!(
                    next_index,
                    batch_size, remaining, "Fetching proof and operations"
                );

                match self.resolver.get_proof(next_index, batch_size).await {
                    Ok((proof, operations)) => {
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
                        self.retry_count = 0; // Reset retry count on success
                        Ok(false) // Continue
                    }
                    Err(e) => {
                        self.retry_count += 1;
                        if self.retry_count <= self.config.max_retries {
                            warn!(
                                retry_count = self.retry_count,
                                max_retries = self.config.max_retries,
                                error = %e,
                                "Retrying after resolver error"
                            );
                            // Put state back for retry
                            self.state = Some(ClientState::FetchingProof {
                                db,
                                target_index,
                                target_hash,
                                next_index,
                                progress,
                            });
                            Ok(false) // Retry
                        } else {
                            Err(Error::NetworkError(format!(
                                "Failed after {} retries: {}",
                                self.config.max_retries, e
                            )))
                        }
                    }
                }
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

                if !Self::verify_proof_sync(
                    &mut self.hasher,
                    &proof,
                    start_index,
                    &operations,
                    &current_root,
                )
                .await?
                {
                    return Err(Error::ProofVerificationFailed);
                }

                // Apply operations in batch
                debug!(operations_count = operations.len(), "Applying operations");

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

                info!(
                    current_index = new_current_index,
                    target_index,
                    operations_applied = progress.operations_applied,
                    batches_processed = progress.batches_processed,
                    completion_pct = progress.completion_percentage(),
                    "Applied operation batch"
                );

                // Check if we've reached the target
                if new_current_index >= target_index {
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
                    // Need more operations
                    self.state = Some(ClientState::FetchingProof {
                        db,
                        target_index,
                        target_hash,
                        next_index: new_current_index,
                        progress,
                    });
                    Ok(false) // Continue
                }
            }

            ClientState::Done { .. } => Err(Error::AlreadyComplete),
        }
    }

    /// Run the complete sync process
    pub async fn sync(&mut self) -> Result<H::Digest, Error> {
        info!("Starting complete sync process");

        loop {
            let is_done = self.step().await?;
            if is_done {
                break;
            }
        }

        match &self.state {
            Some(ClientState::Done { root_hash, .. }) => {
                info!("Sync completed successfully");
                Ok(*root_hash)
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Get reference to the current database state
    pub fn database(&self) -> Result<&Any<E, K, V, H, T>, Error> {
        match &self.state {
            Some(ClientState::Init { db, .. })
            | Some(ClientState::FetchingProof { db, .. })
            | Some(ClientState::ApplyingOperations { db, .. })
            | Some(ClientState::Done { db, .. }) => Ok(db),
            None => Err(Error::InvalidState),
        }
    }

    /// Get mutable reference to the current database state
    pub fn database_mut(&mut self) -> Result<&mut Any<E, K, V, H, T>, Error> {
        match &mut self.state {
            Some(ClientState::Init { db, .. })
            | Some(ClientState::FetchingProof { db, .. })
            | Some(ClientState::ApplyingOperations { db, .. })
            | Some(ClientState::Done { db, .. }) => Ok(db),
            None => Err(Error::InvalidState),
        }
    }

    /// Check if sync is complete
    pub fn is_done(&self) -> bool {
        matches!(self.state, Some(ClientState::Done { .. }))
    }

    /// Reset to allow retry after error
    pub fn reset(
        &mut self,
        db: Any<E, K, V, H, T>,
        target_index: u64,
        target_hash: H::Digest,
    ) -> Result<(), Error> {
        self.state = Some(ClientState::Init {
            db,
            target_index,
            target_hash,
        });
        self.retry_count = 0;
        Ok(())
    }

    // Helper method to verify proof - assumes the resolver provides valid proofs
    async fn verify_proof_sync(
        hasher: &mut commonware_storage::mmr::hasher::Standard<H>,
        proof: &Proof<H>,
        start_index: u64,
        operations: &[Operation<K, V>],
        current_root: &H::Digest,
    ) -> Result<bool, Error> {
        // Simple assumption: if the resolver provided it, we trust the proof verification
        // This can be made more sophisticated later
        Any::<E, K, V, H, T>::verify_proof(hasher, proof, start_index, operations, current_root)
            .await
            .map_err(Error::DatabaseError)
    }
}

/// Synchronization errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Network/transport error
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Database operation error
    #[error("Database error: {0}")]
    DatabaseError(commonware_storage::adb::Error),
    /// MMR error
    #[error("MMR error: {0}")]
    MmrError(commonware_storage::mmr::Error),
    /// Proof verification failed
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    /// Hash mismatch after sync
    #[error("Hash mismatch - expected {expected:?}, got {actual:?}")]
    HashMismatch {
        expected: Box<dyn fmt::Debug + Send + Sync>,
        actual: Box<dyn fmt::Debug + Send + Sync>,
    },
    /// Invalid target parameters
    #[error("Invalid target: current index {current} is already >= target index {target}")]
    InvalidTarget { current: u64, target: u64 },
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    /// Invalid client state
    #[error("Invalid client state")]
    InvalidState,
    /// Sync already completed
    #[error("Sync already completed")]
    AlreadyComplete,
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

// Simplified helper function for basic sync operations
pub async fn simple_sync<E, K, V, H, T, R>(
    db: Any<E, K, V, H, T>,
    resolver: R,
    target_index: u64,
    target_hash: H::Digest,
) -> Result<Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    let mut client = SyncClient::new(db, resolver, target_index, target_hash)?;
    client.sync().await?;

    // Extract the database from the final state
    match client.state.take() {
        Some(ClientState::Done { db, .. }) => Ok(db),
        _ => Err(Error::InvalidState),
    }
}
