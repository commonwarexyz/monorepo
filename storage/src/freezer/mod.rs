//! A persistent storage system that provides the same interface as archive but without pruning support.
//!
//! Behind the scenes, it uses diskmap for key-value storage and diskindex for index-key mapping.
//! Key queries use the diskmap directly and index queries lookup the key in the diskindex
//! and then get the value from the diskmap.
//!
//! The diskindex manages the RMap for interval queries.

mod storage;

pub use storage::Freezer;
use thiserror::Error;

/// Errors that can occur when interacting with the freezer.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("diskmap error: {0}")]
    DiskMap(#[from] crate::diskmap::Error),
    #[error("diskindex error: {0}")]
    DiskIndex(#[from] crate::diskindex::Error),
    #[error("record corrupted")]
    RecordCorrupted,
}

/// Configuration for `Freezer` storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The `commonware-runtime::Storage` partition to use for storing the freezer.
    pub partition: String,

    /// The codec configuration to use for the value stored in the freezer.
    pub codec_config: C,

    /// The size of the write buffer to use for both diskmaps.
    pub write_buffer: usize,

    /// The size of the diskmap directory table. Should be a power of 2.
    pub directory_size: u64,

    /// The target size of each journal in the diskmap before creating a new one.
    pub target_journal_size: u64,
}
