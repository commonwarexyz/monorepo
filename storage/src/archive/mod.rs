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

pub trait Translator: Clone {
    type Key: Eq + Hash + Send + Sync;

    fn transform(&self, key: &[u8]) -> Self::Key;
}

fn cap<const N: usize>(key: &[u8]) -> [u8; N] {
    let mut capped = [0; N];
    let len = key.len().min(N);
    capped.copy_from_slice(&key[..len]);
    capped
}

#[derive(Clone)]
struct FourCap;

impl Translator for FourCap {
    type Key = [u8; 4];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}

#[derive(Clone)]
struct EightCap;

impl Translator for EightCap {
    type Key = [u8; 8];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}

#[derive(Clone)]
pub struct Config<T: Translator> {
    pub partition: String,
    pub translator: T,
}
