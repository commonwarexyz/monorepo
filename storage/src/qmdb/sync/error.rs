//! Shared sync error types that can be used across different database implementations.

use crate::{
    merkle::{Family, Location},
    qmdb::{self},
};
use commonware_cryptography::Digest;

/// Errors from a [`Source`](crate::qmdb::sync::source::Source) when serving a request.
#[derive(Debug, thiserror::Error)]
pub enum ServeError<F: Family> {
    /// The source database failed.
    #[error(transparent)]
    Database(#[from] qmdb::Error<F>),
    /// No database is available to serve the request.
    #[error("source missing")]
    MissingSource,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError<F: Family, D: Digest> {
    /// Hash mismatch after sync
    #[error("root digest mismatch - expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: D, actual: D },
    /// The source finished without a response that satisfies the request.
    #[error("source returned no valid response")]
    InvalidResponse,
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
    /// Sync stalled - no pending fetches
    #[error("sync stalled - no pending fetches")]
    SyncStalled,
    /// Sync finish signal channel closed before finish was requested.
    #[error("sync finish signal channel closed before finish was requested")]
    FinishChannelClosed,
}

/// Errors that can occur during database synchronization.
#[derive(Debug, thiserror::Error)]
pub enum Error<F, U, D>
where
    F: Family,
    U: std::error::Error + Send + 'static,
    D: Digest,
{
    /// The local database failed.
    #[error(transparent)]
    Database(crate::qmdb::Error<F>),

    /// The source failed to serve a request.
    #[error(transparent)]
    Source(U),

    /// The sync engine rejected the target or a response, or could not proceed.
    #[error(transparent)]
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
