//! Shared sync error types that can be used across different database implementations.

use crate::{
    merkle::{Family, Location},
    qmdb::sync::Target,
};
use commonware_cryptography::Digest;

#[derive(Debug, thiserror::Error)]
pub enum EngineError<F: Family, D: Digest> {
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: D, actual: D },
    /// Compact proof did not verify against the requested root.
    #[error("compact proof failed verification")]
    InvalidProof,
    /// Compact payload leaf count did not match the requested target size.
    #[error("unexpected compact leaf count - expected {expected}, got {actual}")]
    UnexpectedLeafCount {
        expected: Location<F>,
        actual: Location<F>,
    },
    /// Compact target parameters were invalid.
    #[error("invalid compact target: {0}")]
    InvalidCompactTarget(&'static str),
    /// Invalid target parameters
    #[error("invalid bounds: lower bound {lower_bound_pos} > upper bound {upper_bound_pos}")]
    InvalidTarget {
        lower_bound_pos: Location<F>,
        upper_bound_pos: Location<F>,
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
        old: Target<F, D>,
        new: Target<F, D>,
    },
    /// Sync already completed
    #[error("sync already completed")]
    AlreadyComplete,
    /// Sync stalled - no pending fetches
    #[error("sync stalled - no pending fetches")]
    SyncStalled,
    /// Sync finish signal channel closed before finish was requested.
    #[error("sync finish signal channel closed before finish was requested")]
    FinishChannelClosed,
    /// Error extracting pinned nodes
    #[error("error extracting pinned nodes: {0}")]
    PinnedNodes(String),
}

/// Errors that can occur during database synchronization.
#[derive(Debug, thiserror::Error)]
pub enum Error<F, U, D>
where
    F: Family,
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    /// Database error
    #[error("database error: {0}")]
    Database(crate::qmdb::Error<F>),

    /// Resolver error
    #[error("resolver error: {0:?}")]
    Resolver(U),

    /// Engine error
    #[error("engine error: {0}")]
    Engine(EngineError<F, D>),
}

impl<F, T, U, D> From<T> for Error<F, U, D>
where
    F: Family,
    U: std::error::Error + Send + 'static,
    D: Digest,
    T: Into<crate::qmdb::Error<F>>,
{
    fn from(err: T) -> Self {
        Self::Database(err.into())
    }
}
