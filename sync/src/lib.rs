use crate::{
    client::{Client, ClientConfig},
    resolver::Resolver,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::{any::Any, operation::Operation},
    index::Translator,
};
use commonware_utils::Array;
use std::fmt;

mod client;
mod resolver;

/// Progress information for sync operations
#[derive(Debug, Clone)]
pub struct SyncProgress<K: Array, V: Array> {
    pub operations: Vec<Operation<K, V>>,
    pub target_ops: u64,
    pub valid_batches_received: u64,
    pub invalid_batches_received: u64,
}

impl<K: Array, V: Array> SyncProgress<K, V> {
    pub fn completion_percentage(&self) -> f64 {
        if self.target_ops == 0 {
            return 100.0;
        }
        (self.operations.len() as f64 / self.target_ops as f64 * 100.0).min(100.0)
    }

    pub fn is_complete(&self) -> bool {
        self.operations.len() as u64 >= self.target_ops
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
    /// Proof verification failed
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Proof verification error: {0}")]
    ProofVerificationError(commonware_storage::adb::Error),
    /// Hash mismatch after sync
    #[error("Hash mismatch - expected {expected:?}, got {actual:?}")]
    HashMismatch {
        expected: Box<dyn fmt::Debug + Send + Sync>,
        actual: Box<dyn fmt::Debug + Send + Sync>,
    },
    /// Invalid target parameters
    #[error("Invalid target: current ops {current} is already >= target ops {target}")]
    InvalidTarget { current: u64, target: u64 },
    /// Invalid client state
    #[error("Invalid client state")]
    InvalidState,
    /// Sync already completed
    #[error("Sync already completed")]
    AlreadyComplete,
    /// Invalid resolver error
    #[error("Invalid resolver error: {0}")]
    InvalidResolver(String),
    /// Exceeded target error
    #[error("Exceeded target: target ops {target}, actual ops {actual}")]
    ExceededTarget { target: u64, actual: u64 },
}

/// Sync to the given `target_ops` and `target_hash` using the given `resolver`.
pub async fn sync<E, K, V, H, T, R>(
    resolver: R,
    target_ops: u64,
    target_hash: H::Digest,
    config: ClientConfig,
) -> Result<Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    Client::new(resolver, config, target_ops, target_hash)?
        .sync()
        .await
}
