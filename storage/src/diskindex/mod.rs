//! A disk-based index that maps contiguous indices to keys.
//!
//! `DiskIndex` maintains a flat file where each record contains a fixed-size key and CRC.
//! The file position directly corresponds to the index (no need to store index values).
//!
//! # Design
//!
//! - Each record: `[K][crc32(K)]` where K is a fixed-size key
//! - Index N is at file offset: `N * RECORD_SIZE`
//! - Simple flat file with no headers or commit pointers
//! - Maintains in-memory RMap for fast interval queries
//!
//! # Format
//!
//! Records (no header):
//! ```text
//! Record 0: [key][crc32]
//! Record 1: [key][crc32]
//! ...
//! ```

mod storage;

pub use storage::DiskIndex;
use thiserror::Error;

/// Errors that can occur when interacting with the disk index.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("invalid record: {0}")]
    InvalidRecord(u64),
}

/// Configuration for `DiskIndex` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use for storing the index.
    pub partition: String,

    /// The maximum number of items to store in each index blob.
    pub items_per_blob: u64,

    /// The size of the write buffer to use when writing to the index.
    pub write_buffer: usize,

    /// The size of the read buffer to use on restart.
    pub replay_buffer: usize,
}
