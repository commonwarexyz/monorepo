//! A disk-based multi-map for fixed-length keys and values.
//!
//! `DiskMap` is a hash table with chaining that stores all data on disk using the Blob interface.
//! It uses a directory structure with much higher cardinality than the number of buckets to
//! provide better lookup performance.
//!
//! # Design
//!
//! The structure consists of:
//! - A directory table with `directory_size` entries, each pointing to a bucket
//! - Buckets stored as separate blobs, containing linked lists of key-value pairs
//! - A hash function that maps keys to directory entries
//!
//! The directory_size is typically much larger than the number of actual buckets,
//! allowing for better distribution and fewer collisions per bucket.
//!
//! # Format
//!
//! Directory blob format:
//! ```text
//! +---+---+---+---+---+---+---+---+
//! |     Bucket ID (u64)          |  Entry 0
//! +---+---+---+---+---+---+---+---+
//! |     Bucket ID (u64)          |  Entry 1
//! +---+---+---+---+---+---+---+---+
//! |            ...               |
//! ```
//!
//! Bucket blob format:
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! |    Key    |   Value   | Next Offset (u64) | ... |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! ```

mod storage;

pub use storage::DiskMap;
use thiserror::Error;

/// Errors that can occur when interacting with the disk map.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("invalid value length: expected {expected}, got {actual}")]
    InvalidValueLength { expected: usize, actual: usize },
    #[error("bucket corrupted at offset {0}")]
    BucketCorrupted(u64),
    #[error("directory corrupted")]
    DirectoryCorrupted,
    #[error("checksum mismatch: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch { expected: u32, actual: u32 },
}

/// Configuration for `DiskMap` storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The `commonware-runtime::Storage` partition to use for storing the disk map.
    pub partition: String,

    /// The size of the directory table. Should be a power of 2 and much larger than
    /// the expected number of buckets for better distribution.
    pub directory_size: u64,

    /// The codec configuration to use for the value stored in the disk map.
    pub codec_config: C,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: usize,
}
