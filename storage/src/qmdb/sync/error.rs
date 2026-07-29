//! Shared sync error types that can be used across different database implementations.

use crate::{
    merkle::{Family, Location},
    qmdb::{
        self,
        sync::{Target, compact},
    },
};
use commonware_cryptography::Digest;

/// Errors a [`Source`](crate::qmdb::sync::resolver::Source) returns instead of a response.
///
/// Serving reads local storage, so these describe the source's own state, not a bad request from
/// a peer. A peer that sends something unusable is scored through
/// [`Validity`](crate::qmdb::sync::resolver::Validity) instead.
#[derive(Debug, thiserror::Error)]
pub enum ServeError<F: Family, D: Digest> {
    /// The source database failed while building the response.
    #[error("source database error: {0}")]
    Database(#[from] qmdb::Error<F>),
    /// The request named a target this source cannot serve.
    #[error("invalid target: {0}")]
    InvalidTarget(&'static str),
    /// The wrapper holding this source has no database attached right now.
    #[error("source missing")]
    MissingSource,
    /// The requested compact state is not the one this source currently holds. Compact sources
    /// serve only their latest committed state, so they cannot answer for an older root.
    #[error("stale target - requested {requested:?}, current {current:?}")]
    StaleTarget {
        requested: compact::Target<F, D>,
        current: compact::Target<F, D>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError<F: Family, D: Digest> {
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: D, actual: D },
    /// Compact proof did not verify against the requested root.
    #[error("compact proof failed verification")]
    InvalidProof,
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
