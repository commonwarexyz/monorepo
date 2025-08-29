use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};
use thiserror::Error;

mod storage;
pub use storage::Cache;

/// Errors that can occur when interacting with the cache.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("already pruned to: {0}")]
    AlreadyPrunedTo(u64),
    #[error("record too large")]
    RecordTooLarge,
}

/// Configuration for [Cache] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for the cache's [crate::journal] storage.
    pub partition: String,

    /// The compression level to use for the cache's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the cache.
    pub codec_config: C,

    /// The number of items per section (the granularity of pruning).
    pub items_per_section: NonZeroU64,

    /// The amount of bytes that can be buffered in a section before being written to a
    /// [commonware_runtime::Blob].
    pub write_buffer: NonZeroUsize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: NonZeroUsize,

    /// The buffer pool to use for the cache's [crate::journal] storage.
    pub buffer_pool: PoolRef,
}
