//! An _Any_ authenticated database (ADB) provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [Mmr] over a log of state-change operations backed
//! by a [Journal].
//!
//! In an Any db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::{
        align_mmr_and_floored_log,
        operation::{fixed::FixedSize, Committable, Keyed},
        Error,
    },
    journal::contiguous::fixed::{Config as JConfig, Journal},
    mmr::{
        journaled::{Config as MmrConfig, Mmr},
        Location, StandardHasher,
    },
    translator::Translator,
};
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

/// Initialize an MMR and log from the given config, and return them after ensuring they are
/// aligned. The returned log will either be empty, or its last operation will be a commit floor
/// operation. The number of leaves in the MMR will be equal to the number of operations in the log.
pub(crate) async fn init_mmr_and_log<
    E: Storage + Clock + Metrics,
    O: Keyed + Committable + FixedSize,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: Config<T>,
    hasher: &mut StandardHasher<H>,
) -> Result<(Location, Mmr<E, H>, Journal<E, O>), Error> {
    let mmr = Mmr::init(
        context.with_label("mmr"),
        hasher,
        MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        },
    )
    .await?;

    let mut log: Journal<E, O> = Journal::init(
        context.with_label("log"),
        JConfig {
            partition: cfg.log_journal_partition,
            items_per_blob: cfg.log_items_per_blob,
            write_buffer: cfg.log_write_buffer,
            buffer_pool: cfg.buffer_pool,
        },
    )
    .await?;

    let (mmr, inactivity_floor_loc) = align_mmr_and_floored_log(mmr, &mut log, hasher).await?;

    Ok((inactivity_floor_loc, mmr, log))
}
