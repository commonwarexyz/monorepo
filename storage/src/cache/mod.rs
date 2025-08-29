use crate::translator::Translator;
use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};

mod storage;
pub use storage::Archive;

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// Logic to transform keys into their index representation.
    ///
    /// [Archive] assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The partition to use for the archive's [crate::journal] storage.
    pub partition: String,

    /// The compression level to use for the archive's [crate::journal] storage.
    pub compression: Option<u8>,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the archive.
    pub codec_config: C,

    /// The number of items per section (the granularity of pruning).
    pub items_per_section: NonZeroU64,

    /// The amount of bytes that can be buffered in a section before being written to a
    /// [commonware_runtime::Blob].
    pub write_buffer: NonZeroUsize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: NonZeroUsize,

    /// The buffer pool to use for the archive's [crate::journal] storage.
    pub buffer_pool: PoolRef,
}
