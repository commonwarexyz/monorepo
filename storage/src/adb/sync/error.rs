//! Shared sync error types that can be used across different database implementations.

use std::fmt;

/// Errors that can occur during database synchronization.
/// Generic over the database-specific error type `E`.
#[derive(Debug, thiserror::Error)]
pub enum SyncError<E> {
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
    Database(E),
    /// Resolver error
    #[error("resolver error: {0:?}")]
    Resolver(Box<dyn fmt::Debug + Send + Sync>),
    /// Sync stalled - no pending fetches
    #[error("sync stalled - no pending fetches")]
    SyncStalled,
    /// Error extracting pinned nodes
    #[error("error extracting pinned nodes: {0}")]
    PinnedNodes(String),
}

impl<E> SyncError<E> {
    /// Convert a database-specific error into a sync error
    pub fn database(err: E) -> Self {
        Self::Database(err)
    }

    /// Create a resolver error
    pub fn resolver(err: impl fmt::Debug + Send + Sync + 'static) -> Self {
        Self::Resolver(Box::new(err))
    }

    /// Create a pinned nodes error
    pub fn pinned_nodes(msg: impl Into<String>) -> Self {
        Self::PinnedNodes(msg.into())
    }
}

/// Automatic conversion from database errors to sync errors
// TODO: Try to find a way to rewrite this to reduce probability of misuse
// with errors that aren't actually database errors.
impl<E> From<E> for SyncError<E>
where
    E: std::error::Error + Send + 'static,
{
    fn from(err: E) -> Self {
        Self::Database(err)
    }
}
