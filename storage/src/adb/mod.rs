//! A collection of authenticated databases (ADB).

use commonware_utils::array::prefixed_u64::U64;
use thiserror::Error;

pub mod any;
pub mod operation;

/// Errors that can occur when interacting with an authenticated database.
#[derive(Error, Debug)]
pub enum Error {
    #[error("mmr error: {0}")]
    MmrError(#[from] crate::mmr::Error),
    #[error("metadata error: {0}")]
    MetadataError(#[from] crate::metadata::Error<U64>),
    #[error("journal error: {0}")]
    JournalError(#[from] crate::journal::Error),
}
