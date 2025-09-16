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
pub enum DatabaseError<D: Digest> {
    /// Storage or database operation failed
    #[error("storage error: {0}")]
    Storage(crate::adb::Error),
    /// Sync engine error (invalid targets, state issues, etc.)
    #[error("engine error: {0}")]
    Engine(EngineError<D>),
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

impl<D: Digest> DatabaseError<D> {
    pub fn storage(err: impl Into<crate::adb::Error>) -> Self {
        Self::Storage(err.into())
    }

    pub fn engine(err: EngineError<D>) -> Self {
        Self::Engine(err)
    }
}

impl<D: Digest> From<EngineError<D>> for DatabaseError<D> {
    fn from(err: EngineError<D>) -> Self {
        Self::Engine(err)
    }
}

impl<D: Digest> From<crate::adb::Error> for DatabaseError<D> {
    fn from(err: crate::adb::Error) -> Self {
        Self::Storage(err)
    }
}

impl<D: Digest> From<crate::journal::Error> for DatabaseError<D> {
    fn from(err: crate::journal::Error) -> Self {
        Self::Storage(crate::adb::Error::Journal(err))
    }
}

impl<D: Digest> From<crate::mmr::Error> for DatabaseError<D> {
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

impl<U, D> From<DatabaseError<D>> for Error<DatabaseError<D>, U, D>
where
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    fn from(err: DatabaseError<D>) -> Self {
        Self::Database(err)
    }
}
