//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use the dbs in [crate::adb::any::fixed]
//! instead for better performance._

use crate::{
    adb::{
        operation::{Committable, Keyed},
        Error,
    },
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::journaled::Config as MmrConfig,
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use commonware_utils::Array;
use std::num::{NonZeroU64, NonZeroUsize};

pub mod ordered;
pub mod unordered;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each section of the journal.
    pub log_items_per_section: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

type Contiguous<E, O> = Journal<E, O>;

type AuthenticatedLog<E, O, H> = authenticated::Journal<E, Contiguous<E, O>, O, H>;

/// Initialize and return the authenticated log from the given config.
pub(super) async fn init_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Keyed + Committable + Codec,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: Config<T, <O as Read>::Cfg>,
) -> Result<AuthenticatedLog<E, O, H>, Error>
where
    O::Key: Array,
    O::Value: Codec,
{
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        buffer_pool: cfg.buffer_pool.clone(),
    };

    let journal_config = JournalConfig {
        partition: cfg.log_partition,
        items_per_section: cfg.log_items_per_section,
        compression: cfg.log_compression,
        codec_config: cfg.log_codec_config,
        buffer_pool: cfg.buffer_pool,
        write_buffer: cfg.log_write_buffer,
    };

    authenticated::Journal::<E, Journal<E, O>, O, H>::new(
        context.with_label("auth_log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await
    .map_err(Into::into)
}
