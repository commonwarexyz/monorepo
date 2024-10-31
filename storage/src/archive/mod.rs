//! TBD

pub mod storage;

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

pub trait Capper {
    type Key: Eq + Hash + Send + Sync;

    fn cap(key: &[u8]) -> Self::Key;
}

struct EightCap;

impl Capper for EightCap {
    type Key = [u8; 8];

    fn cap(key: &[u8]) -> Self::Key {
        let mut capped = [0; 8];
        let len = key.len().min(8);
        capped.copy_from_slice(&key[..len]);
        capped
    }
}

#[derive(Clone)]
pub struct Config {
    pub partition: String,
}
