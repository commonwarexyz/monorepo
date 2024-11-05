//! TBD

mod storage;
use std::sync::{Arc, Mutex};

use prometheus_client::registry::Registry;
pub use storage::Metadata;

use thiserror::Error;

/// Errors that can occur when interacting with the journal.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("blob too large: {0}")]
    BlobTooLarge(u64),
    #[error("data too big")]
    DataTooBig,
}

/// Configuration for `Metadata` storage.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// The `commonware_runtime::Storage` partition to
    /// use for storing metadata.
    pub partition: String,
}
