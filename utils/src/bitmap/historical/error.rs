/// Errors that can occur in Historical bitmap operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Commit numbers must be strictly monotonically increasing.
    #[error("commit number ({attempted}) <= previous commit ({previous})")]
    NonMonotonicCommit { previous: u64, attempted: u64 },

    /// Commit number u64::MAX is reserved and cannot be used.
    #[error("commit number u64::MAX is reserved and cannot be used")]
    ReservedCommitNumber,

    /// Error from the underlying Prunable bitmap.
    #[error("prunable error: {0}")]
    Prunable(#[from] crate::bitmap::prunable::Error),
}
