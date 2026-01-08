//! An _Any_ authenticated database provides succinct proofs of any value ever associated with a
//! key.
//!
//! The specific variants provided within this module include:
//! - Unordered: The database does not maintain or require any ordering over the key space.
//!   - Fixed-size values
//!   - Variable-size values
//! - Ordered: The database maintains a total order over active keys.
//!   - Fixed-size values
//!   - Variable-size values

use crate::{
    journal::{
        authenticated,
        contiguous::fixed::{Config as JConfig, Journal},
    },
    mmr::journaled::Config as MmrConfig,
    qmdb::{operation::Committable, Error, Merkleized},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage};
use std::num::{NonZeroU64, NonZeroUsize};

pub(crate) mod db;
mod operation;
#[cfg(any(test, feature = "test-traits"))]
pub mod states;
mod value;
pub(crate) use value::{FixedValue, ValueEncoding, VariableValue};
pub mod ordered;
pub mod unordered;

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

type AuthenticatedLog<E, O, H, S = Merkleized<H>> = authenticated::Journal<E, Journal<E, O>, H, S>;

/// Initialize the authenticated log from the given config, returning it along with the inactivity
/// floor specified by the last commit.
pub(crate) async fn init_fixed_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Committable + CodecFixed<Cfg = ()>,
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
// pub(crate) so qmdb/current can use the generic tests.
pub(crate) mod test {
    use super::*;
    use crate::{
        qmdb::any::{FixedConfig, VariableConfig},
        translator::TwoCap,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

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
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    use crate::{
        kv::Updatable,
        qmdb::{
            any::states::{CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny},
            store::MerkleizedStore,
        },
        Persistable,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};

    /// Test that merkleization state changes don't reset `steps`.
    pub(crate) async fn test_any_db_steps_not_reset<D>(db: D)
    where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = Digest, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = Digest, Error = crate::qmdb::Error>,
    {
        // Create a db with a couple keys.
        let mut db = db.into_mutable();

        assert!(db
            .create(Sha256::fill(1u8), Sha256::fill(2u8))
            .await
            .unwrap());
        assert!(db
            .create(Sha256::fill(3u8), Sha256::fill(4u8))
            .await
            .unwrap());
        let (clean_db, _) = db.commit(None).await.unwrap();
        let mut db = clean_db.into_mutable();

        // Updating an existing key should make steps non-zero.
        db.update(Sha256::fill(1u8), Sha256::fill(5u8))
            .await
            .unwrap();
        let steps = db.steps();
        assert_ne!(steps, 0);

        // Steps shouldn't change from merkleization.
        let db = db.into_merkleized().await.unwrap();
        let db = db.into_mutable();
        assert_eq!(db.steps(), steps);

        // Cleanup
        let (db, _) = db.commit(None).await.unwrap();
        let db = db.into_merkleized().await.unwrap();
        db.destroy().await.unwrap();
    }
}
