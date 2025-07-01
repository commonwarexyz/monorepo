use crate::{
    adb::{
        any::Any,
        sync::{
            client::{Client, Config},
            resolver::Resolver,
        },
    },
    index::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::fmt;

mod client;
mod resolver;

/// Synchronization errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Database operation error
    #[error("Database error: {0}")]
    GetProofFailed(crate::adb::Error),
    /// Hash mismatch after sync
    #[error("Hash mismatch - expected {expected:?}, got {actual:?}")]
    HashMismatch {
        expected: Box<dyn fmt::Debug + Send + Sync>,
        actual: Box<dyn fmt::Debug + Send + Sync>,
    },
    /// Invalid target parameters
    #[error("Invalid bounds: lower bound {lower_bound_pos} > upper bound {upper_bound_pos}")]
    InvalidTarget {
        lower_bound_pos: u64,
        upper_bound_pos: u64,
    },
    /// Invalid client state
    #[error("Invalid client state")]
    InvalidState,
    /// Sync already completed
    #[error("Sync already completed")]
    AlreadyComplete,
    /// Database initialization failed during sync
    #[error("Database initialization failed: {0}")]
    DatabaseInitFailed(crate::adb::Error),
    /// Maximum retries exceeded
    #[error("Maximum retries exceeded")]
    MaxRetriesExceeded,
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
