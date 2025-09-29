//! Shared sync error types that can be used across different database implementations.

use crate::{adb::sync::Target, mmr::Location};
use commonware_cryptography::Digest;

#[derive(Debug, thiserror::Error)]
pub enum EngineError<D: Digest> {
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: D, actual: D },
    /// Invalid target parameters
    #[error("invalid bounds: lower bound {lower_bound_pos} > upper bound {upper_bound_pos}")]
    InvalidTarget {
        lower_bound_pos: Location,
        upper_bound_pos: Location,
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

/// Errors that can occur during database synchronization.
#[derive(Debug, thiserror::Error)]
pub enum Error<U, D>
where
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    /// Database error
    #[error("database error: {0}")]
    Database(crate::adb::Error),

    /// Resolver error
    #[error("resolver error: {0:?}")]
    Resolver(U),

    /// Engine error
    #[error("engine error: {0}")]
    Engine(EngineError<D>),
}

impl<T, U, D> From<T> for Error<U, D>
where
    U: std::error::Error + Send + 'static,
    D: Digest,
    T: Into<crate::adb::Error>,
{
    fn from(err: T) -> Self {
        Self::Database(err.into())
    }
}
