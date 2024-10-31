//! TBD

pub mod storage;

use thiserror::Error;

/// Errors that can occur when interacting with the journal.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("duplicate key found during replay")]
    DuplicateKey,
}

#[derive(Clone)]
pub struct Config {
    pub partition: String,
    pub index_key_len: u8,
}
