mod storage;

use commonware_utils::array::U64;
pub use storage::Index;
use thiserror::Error;

/// Errors that can occur when interacting with the disk map.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error<U64>),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
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
    pub journal_partition: String,

    /// The compression algorithm to use for the journal.
    pub journal_compression: Option<u8>,

    /// The `commonware-runtime::Storage` partition to use for storing the disk map metadata.
    pub metadata_partition: String,

    /// The `commonware-runtime::Storage` partition to use for storing the disk map table.
    pub table_partition: String,

    /// The size of the table. Should be a power of 2 and much larger than
    /// the expected number of buckets for better distribution.
    pub table_size: u32,

    /// The codec configuration to use for the value stored in the disk map.
    pub codec_config: C,

    /// The size of the write buffer to use for the journal.
    pub write_buffer: usize,

    /// The target size of each journal before creating a new one.
    pub target_journal_size: u64,
}
