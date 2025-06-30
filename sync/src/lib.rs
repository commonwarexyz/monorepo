use crate::{
    client::{Client, ClientConfig},
    resolver::Resolver,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{adb::any::Any, index::Translator};
use commonware_utils::Array;
use std::fmt;

mod client;
mod resolver;

/// Progress information for sync operations
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub current_ops: u64,
    pub target_ops: u64,
    pub operations_applied: u64,
    pub batches_received: u64,
}

impl SyncProgress {
    pub fn completion_percentage(&self) -> f64 {
        if self.target_ops == 0 {
            return 100.0;
        }
        (self.current_ops as f64 / self.target_ops as f64 * 100.0).min(100.0)
    }

    pub fn is_complete(&self) -> bool {
        self.current_ops >= self.target_ops
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

/// Sync `db` to the given `target_ops` and `target_hash` using the given `resolver`.
pub async fn sync<E, K, V, H, T, R>(
    db: Any<E, K, V, H, T>,
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
    Client::new(db, resolver, config, target_ops, target_hash)?
        .sync()
        .await
}
