//! Shared sync error types that can be used across different database implementations.

use crate::adb::sync::Target;
use commonware_cryptography::Digest;

/// Errors that can occur during database synchronization.
#[derive(Debug, thiserror::Error)]
pub enum Error<T, U, D>
where
    T: std::error::Error + Send + 'static,
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    /// Database error
    #[error("database error: {0}")]
    Database(T),
    /// Resolver error
    #[error("resolver error: {0:?}")]
    Resolver(U),
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: D, actual: D },
    /// Invalid target parameters
    #[error("invalid bounds: lower bound {lower_bound_pos} > upper bound {upper_bound_pos}")]
    InvalidTarget {
        lower_bound_pos: u64,
        upper_bound_pos: u64,
    },
    /// Invalid client state
    #[error("invalid client state")]
    InvalidState,
    /// Sync target root unchanged
    #[error("sync target root unchanged")]
    SyncTargetRootUnchanged,
    /// Sync target moved backward
    #[error("sync target moved backward: {old:?} -> {new:?}")]
    SyncTargetMovedBackward { old: Target<D>, new: Target<D> },
    /// Sync already completed
    #[error("sync already completed")]
    AlreadyComplete,
    /// Sync stalled - no pending fetches
    #[error("sync stalled - no pending fetches")]
    SyncStalled,
    /// Error extracting pinned nodes
    #[error("error extracting pinned nodes: {0}")]
    PinnedNodes(String),
}

impl<T, U, D> Error<T, U, D>
where
    T: std::error::Error + Send + 'static,
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    pub fn resolver(err: impl Into<U>) -> Self {
        Self::Resolver(err.into())
    }

    pub fn database(err: impl Into<T>) -> Self {
        Self::Database(err.into())
    }
}
