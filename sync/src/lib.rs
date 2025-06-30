use crate::{
    client::{Client, Config},
    resolver::Resolver,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{adb::any::Any, index::Translator};
use commonware_utils::Array;
use std::fmt;

mod client;
mod resolver;

/// Synchronization errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Database operation error
    #[error("Database error: {0}")]
    GetProofFailed(commonware_storage::adb::Error),
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

/// Sync to the given database.
pub async fn sync<E, K, V, H, T, R>(
    config: Config<E, K, V, H, T, R>,
) -> Result<Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    Client::new(config)?.sync().await
}
