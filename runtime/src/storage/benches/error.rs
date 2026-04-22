//! Error types for the storage benchmark harness.

use std::io;
use thiserror::Error;

/// Benchmark harness result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Benchmark harness error.
#[derive(Debug, Error)]
pub enum Error {
    /// Error surfaced by the runtime storage API.
    #[error(transparent)]
    Runtime(#[from] commonware_runtime::Error),

    /// Filesystem or process-local harness error.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Internal harness invariant failure.
    #[error("{0}")]
    Harness(String),
}
