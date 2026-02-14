use super::{
    types::{AccountStore, CodeStore, Context, StorageStore},
    Error, Stores,
};
use commonware_codec::RangeCfg;
use commonware_runtime::{buffer::paged::CacheRef, Metrics as _};
use commonware_storage::{qmdb::current::VariableConfig, translator::EightCap};
use commonware_utils::{NZUsize, NZU64};

const CODE_MAX_BYTES: usize = 24_576;

/// QMDB configuration for the REVM example.
#[derive(Clone)]
pub(crate) struct QmdbConfig {
    /// Prefix used to derive the QMDB partition names.
    pub(crate) partition_prefix: String,
    /// Page cache shared by the underlying QMDB stores.
    pub(crate) page_cache: CacheRef,
}

impl QmdbConfig {
    /// Creates a new configuration for the example QMDB partitions.
    pub(crate) const fn new(partition_prefix: String, page_cache: CacheRef) -> Self {
        Self {
            partition_prefix,
            page_cache,
        }
    }
}

/// Builds a QMDB any-store config with example-appropriate defaults.
fn store_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    log_codec_config: C,
) -> VariableConfig<EightCap, C> {
    VariableConfig {
        mmr_journal_partition: format!("{prefix}-{name}-mmr"),
        mmr_metadata_partition: format!("{prefix}-{name}-mmr-meta"),
        mmr_items_per_blob: NZU64!(128),
        mmr_write_buffer: NZUsize!(1024 * 1024),
        log_partition: format!("{prefix}-{name}-log"),
        log_write_buffer: NZUsize!(1024 * 1024),
        log_compression: None,
        log_codec_config,
        log_items_per_blob: NZU64!(128),
        bitmap_metadata_partition: format!("{prefix}-{name}-bitmap-meta"),
        translator: EightCap,
        thread_pool: None,
        page_cache,
    }
}

pub(super) async fn open_stores(context: Context, config: QmdbConfig) -> Result<Stores, Error> {
    let accounts = AccountStore::init(
        context.with_label("accounts"),
        store_config(
            &config.partition_prefix,
            "accounts",
            config.page_cache.clone(),
            (),
        ),
    )
    .await?;
    let storage = StorageStore::init(
        context.with_label("storage"),
        store_config(
            &config.partition_prefix,
            "storage",
            config.page_cache.clone(),
            (),
        ),
    )
    .await?;
    let code = CodeStore::init(
        context.with_label("code"),
        store_config(
            &config.partition_prefix,
            "code",
            config.page_cache.clone(),
            (RangeCfg::new(0..=CODE_MAX_BYTES), ()),
        ),
    )
    .await?;

    Ok(Stores {
        accounts,
        storage,
        code,
    })
}
