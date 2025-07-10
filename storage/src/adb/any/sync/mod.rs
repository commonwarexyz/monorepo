use crate::{
    adb::any::{
        sync::{
            client::{Client, Config},
            resolver::Resolver,
        },
        Any,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::fmt;

pub mod client;
pub mod resolver;

/// Synchronization errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    /// Error from the database
    #[error("Database error: {0}")]
    Adb(crate::adb::Error),
    /// Maximum retries exceeded
    #[error("Maximum retries exceeded")]
    MaxRetriesExceeded,
    /// Resolver error
    #[error("Resolver error: {0:?}")]
    Resolver(Box<dyn fmt::Debug + Send + Sync>),
}

/// Synchronizes a database by fetching, verifying, and applying operations from a remote source.
///
/// We repeatedly:
/// 1. Fetch operations in batches from a Resolver (i.e. a server of operations)
/// 2. Verify cryptographic proofs for each batch to ensure correctness
/// 3. Apply operations to reconstruct the database's operation log.
///
/// When the database's operation log is complete, we reconstruct the database's MMR and snapshot.
//
// TODO(#1213) Handle existing state: https://github.com/commonwarexyz/monorepo/issues/1213
// TODO(#1214) Parallelize operation fetching: https://github.com/commonwarexyz/monorepo/issues/1214
pub async fn sync<E, K, V, H, T, R>(
    config: Config<E, K, V, H, T, R>,
) -> Result<Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    Client::new(config).await?.sync().await
}
