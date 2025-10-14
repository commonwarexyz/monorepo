/// Errors that can occur in Historical bitmap operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Commit numbers must be strictly monotonically increasing.
    #[error("commit number ({attempted}) <= previous commit ({previous})")]
    NonMonotonicCommit { previous: u64, attempted: u64 },

    /// Error from the underlying Prunable bitmap.
    #[error("prunable error: {0}")]
    Prunable(#[from] crate::bitmap::prunable::Error),
}
