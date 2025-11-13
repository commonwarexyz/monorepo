//! An _Any_ authenticated database (ADB) provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [authenticated::Journal] of state-change
//! operations.
//!
//! In an Any db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::{
        operation::{Committable, Keyed},
        Error,
    },
    journal::{
        authenticated,
        contiguous::fixed::{Config as JConfig, Journal},
    },
    mmr::journaled::Config as MmrConfig,
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod ordered;
pub mod sync;
pub mod unordered;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

pub(super) type AuthenticatedLog<E, O, H> = authenticated::Journal<E, Journal<E, O>, O, H>;

/// Initialize the authenticated log from the given config, returning it along with the inactivity
/// floor specified by the last commit.
pub(crate) async fn init_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Keyed + Committable + CodecFixed<Cfg = ()>,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: Config<T>,
) -> Result<AuthenticatedLog<E, O, H>, Error> {
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        buffer_pool: cfg.buffer_pool.clone(),
    };

    let journal_config = JConfig {
        partition: cfg.log_journal_partition,
        items_per_blob: cfg.log_items_per_blob,
        write_buffer: cfg.log_write_buffer,
        buffer_pool: cfg.buffer_pool,
    };

    let log = authenticated::Journal::<E, Journal<E, O>, O, H>::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await?;

    Ok(log)
}
