//! TBD

mod disk;
use std::error;

pub use disk::Journal;

use commonware_runtime::Error as RError;
use thiserror::Error;

/// Errors that can occur when interacting with the journal.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] RError),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("blob corrupt")]
    BlobCorrupt,
}

pub struct Config {
    pub partition: String,
}
