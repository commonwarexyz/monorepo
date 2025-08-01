//! Shared sync error types that can be used across different database implementations.

use std::fmt;

/// Errors that can occur during database synchronization.
#[derive(Debug, thiserror::Error)]
pub enum Error<T, U>
where
    T: std::error::Error + Send + 'static,
    U: std::error::Error + Send + 'static,
{
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch {
        expected: Box<dyn fmt::Debug + Send + Sync>,
        actual: Box<dyn fmt::Debug + Send + Sync>,
    },
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
    SyncTargetMovedBackward {
        old: Box<dyn fmt::Debug + Send + Sync>,
        new: Box<dyn fmt::Debug + Send + Sync>,
    },
    /// Sync already completed
    #[error("sync already completed")]
    AlreadyComplete,
    /// Error from the underlying database
    #[error("database error: {0}")]
    Database(T),
    /// Resolver error
    #[error("resolver error: {0:?}")]
    Resolver(U),
    /// Sync stalled - no pending fetches
    #[error("sync stalled - no pending fetches")]
    SyncStalled,
    /// Error extracting pinned nodes
    #[error("error extracting pinned nodes: {0}")]
    PinnedNodes(String),
}

impl<T, U> From<T> for Error<T, U>
where
    T: std::error::Error + Send + 'static,
    U: std::error::Error + Send + 'static,
{
    fn from(err: T) -> Self {
        Self::Database(err)
    }
}

impl<T, U> Error<T, U>
where
    T: std::error::Error + Send + 'static,
    U: std::error::Error + Send + 'static,
{
    pub fn resolver(err: U) -> Self {
        Self::Resolver(err)
    }

    pub fn database(err: T) -> Self {
        Self::Database(err)
    }

    pub fn journal<J>(err: J) -> Self
    where
        T: From<J>,
    {
        Self::Database(T::from(err))
    }
}
