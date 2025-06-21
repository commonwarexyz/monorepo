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
    #[error("index out of bounds: {index}")]
    IndexOutOfBounds { index: u64 },
    #[error("record corrupted at index {0}")]
    RecordCorrupted(u64),
    #[error("header corrupted")]
    HeaderCorrupted,
}

/// Configuration for `DiskIndex` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use for storing the index.
    pub partition: String,

    /// The size of the write buffer for the index file.
    pub write_buffer: usize,
}
