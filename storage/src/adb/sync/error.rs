//! Shared sync error types that can be used across different database implementations.

use crate::adb::sync::Target;
use commonware_cryptography::Digest;

#[derive(Debug, thiserror::Error)]
pub enum EngineError<D: Digest> {
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

/// Error type for database sync operations.
/// Can represent either storage/database errors or sync engine errors.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    /// Storage or database operation failed
    #[error("storage error: {0}")]
    Storage(crate::adb::Error),

    /// Invalid target parameters
    #[error("invalid bounds: lower bound {lower_bound_pos} > upper bound {upper_bound_pos}")]
    InvalidTarget {
        lower_bound_pos: u64,
        upper_bound_pos: u64,
    },
}

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
    /// Engine error
    #[error("engine error: {0}")]
    Engine(EngineError<D>),
}

impl DatabaseError {
    pub fn storage(err: impl Into<crate::adb::Error>) -> Self {
        Self::Storage(err.into())
    }
}

impl From<crate::adb::Error> for DatabaseError {
    fn from(err: crate::adb::Error) -> Self {
        Self::Storage(err)
    }
}

impl From<crate::journal::Error> for DatabaseError {
    fn from(err: crate::journal::Error) -> Self {
        Self::Storage(crate::adb::Error::Journal(err))
    }
}

impl From<crate::mmr::Error> for DatabaseError {
    fn from(err: crate::mmr::Error) -> Self {
        Self::Storage(crate::adb::Error::Mmr(err))
    }
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

impl<U, D> From<DatabaseError> for Error<DatabaseError, U, D>
where
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    fn from(err: DatabaseError) -> Self {
        Self::Database(err)
    }
}
