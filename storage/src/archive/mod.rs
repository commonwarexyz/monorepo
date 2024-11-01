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

/// Configuration for `archive` storage.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Logic to transform keys into their index representation.
    ///
    /// The `Archive` assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The number of writes to buffer in a section before forcing a sync in the journal.
    ///
    /// If set to 0, the journal will be synced each time a new item is stored.
    pub pending_writes: usize,
}
