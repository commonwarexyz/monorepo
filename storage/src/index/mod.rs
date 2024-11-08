//! TBD

mod storage;
pub use storage::Index;

use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("checksum mismatch: expected={0} actual={1}")]
    ChecksumMismatch(u32, u32),
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
}

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// The `commonware-runtime::Storage` partition to use
    /// for storing journal blobs.
    pub partition: String,

    /// The number of entries to keep in a given blob.
    pub entries_per_blob: u64,

    /// The size of each entry in bytes.
    pub value_size: u32,
}
