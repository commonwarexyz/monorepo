//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated with
//! a key. The submodules provide two classes of variants, one specialized for fixed-size values and
//! the other allowing variable-size values.

use crate::{
    adb::{
        operation::{Committable, Keyed},
        store::Db,
        Error,
    },
    journal::{
        authenticated,
        contiguous::fixed::{Config as JConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, mem::Clean, Location, Proof},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
};

pub mod ordered;
pub mod unordered;

/// Trait for an authenticated database (ADB) that provides succinct proofs of _any_ value ever
/// associated with a key.
pub trait AnyDb<O: Keyed, D: Digest>: Db<O::Key, O::Value> {
    fn root(&self) -> D;

    /// Returns true if there are no active keys in the database.
    fn is_empty(&self) -> bool;

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<D>, Vec<O>), Error>>;

    /// Analagous to `proof`, but with respect to the state of the database when it had
    /// `historical_size` operations.
    fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<D>, Vec<O>), Error>>;
}

/// Configuration for an `Any` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
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

/// Configuration for an `Any` authenticated db with variable-sized values.
#[derive(Clone)]
pub struct VariableConfig<T: Translator, C> {
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

    /// The number of items to put in each blob of the journal.
    pub log_items_per_blob: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

type AuthenticatedLog<E, O, H, S = Clean<DigestOf<H>>> =
    authenticated::Journal<E, Journal<E, O>, H, S>;

/// Initialize the authenticated log from the given config, returning it along with the inactivity
/// floor specified by the last commit.
pub(crate) async fn init_fixed_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Keyed + Committable + CodecFixed<Cfg = ()>,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: FixedConfig<T>,
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

    let log = AuthenticatedLog::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await?;

    Ok(log)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        adb::any::{FixedConfig, VariableConfig},
        translator::TwoCap,
    };
    use commonware_utils::{NZUsize, NZU64};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    pub(super) fn fixed_db_config(suffix: &str) -> FixedConfig<TwoCap> {
        FixedConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    pub(super) fn variable_db_config(suffix: &str) -> VariableConfig<TwoCap, ()> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }
}
