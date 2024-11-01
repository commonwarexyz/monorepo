//! TBD

pub mod storage;
pub mod translator;

use std::hash::Hash;
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

pub trait Translator: Clone {
    type Key: Eq + Hash + Send + Sync + Clone;

    fn transform(&self, key: &[u8]) -> Self::Key;
}

#[derive(Clone)]
pub struct Config<T: Translator> {
    pub partition: String,
    pub translator: T,
}
