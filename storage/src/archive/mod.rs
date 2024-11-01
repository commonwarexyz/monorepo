//! TBD

pub mod storage;
pub mod translator;

use prometheus_client::registry::Registry;
use std::{
    hash::Hash,
    sync::{Arc, Mutex},
};
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
    pub registry: Arc<Mutex<Registry>>,
    pub translator: T,
}
