//! Store plumbing shared by every role's SQLite boundary.

use thiserror::Error;

/// A commit whose durable outcome is unknown.
#[derive(Debug, Error)]
#[error("{operation} commit outcome is unknown")]
pub(crate) struct CommitUnknown {
    operation: &'static str,
    #[source]
    source: rusqlite::Error,
}

impl CommitUnknown {
    pub(crate) const fn new(operation: &'static str, source: rusqlite::Error) -> Self {
        Self { operation, source }
    }
}
