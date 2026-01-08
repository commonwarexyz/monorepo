//! QMDB-backed storage adapter for the REVM example.
//!
//! This module wires a QMDB-backed key/value model into REVM's database
//! interfaces. QMDB provides persistence and authenticated structure, while
//! REVM executes against a synchronous in-memory overlay via `CacheDB`.
//!
//! Design at a glance:
//! - Accounts, storage, and code live in separate QMDB partitions.
//! - Reads go through `DatabaseAsyncRef` and are bridged into sync REVM calls
//!   via `WrapDatabaseAsync` (Tokio runtime required).
//! - Writes are staged in the REVM overlay and applied to QMDB in batches when
//!   the example decides a block is finalized.

mod adapter;
mod keys;
mod model;
mod persist;
mod store;

use adapter::QmdbAsyncDb;
use alloy_evm::revm::{
    database::CacheDB,
    database_interface::DBErrorMarker,
    primitives::{Address, B256, U256},
};
use commonware_codec::RangeCfg;
use commonware_runtime::{buffer::PoolRef, tokio, Metrics as _};
use commonware_storage::{
    qmdb::store::{
        db::{Config as StoreConfig, Db},
        NonDurable,
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU64};
use futures::lock::Mutex;
use std::sync::Arc;
use thiserror::Error;

use keys::{account_key, code_key, storage_key, AccountKey, CodeKey, StorageKey};
use model::{AccountRecord, StorageRecord};
use store::{apply_changes_inner, apply_genesis_inner, QmdbInner, Stores};

pub(crate) use adapter::QmdbRefDb;
pub(crate) use persist::QmdbChanges;

const CODE_MAX_BYTES: usize = 24_576;

type Context = tokio::Context;
type AccountStore = Db<Context, AccountKey, AccountRecord, EightCap>;
type StorageStore = Db<Context, StorageKey, StorageRecord, EightCap>;
type CodeStore = Db<Context, CodeKey, Vec<u8>, EightCap>;
type AccountStoreDirty = Db<Context, AccountKey, AccountRecord, EightCap, NonDurable>;
type StorageStoreDirty = Db<Context, StorageKey, StorageRecord, EightCap, NonDurable>;
type CodeStoreDirty = Db<Context, CodeKey, Vec<u8>, EightCap, NonDurable>;

/// Errors surfaced by the QMDB-backed REVM adapter.
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("qmdb error: {0}")]
    Qmdb(#[from] commonware_storage::qmdb::Error),
    #[error("missing tokio runtime for WrapDatabaseAsync")]
    MissingRuntime,
    #[error("missing code for hash {0:?}")]
    MissingCode(B256),
    #[error("qmdb store unavailable: {0}")]
    StoreUnavailable(&'static str),
}

impl DBErrorMarker for Error {}

/// QMDB configuration for the REVM example.
#[derive(Clone)]
pub(crate) struct QmdbConfig {
    /// Prefix used to derive the QMDB partition names.
    pub(crate) partition_prefix: String,
    /// Buffer pool shared by the underlying QMDB stores.
    pub(crate) buffer_pool: PoolRef,
}

impl QmdbConfig {
    /// Creates a new configuration for the example QMDB partitions.
    pub(crate) const fn new(partition_prefix: String, buffer_pool: PoolRef) -> Self {
        Self {
            partition_prefix,
            buffer_pool,
        }
    }
}

/// Owns QMDB handles and exposes a REVM database view plus persistence hooks.
#[derive(Clone)]
pub(crate) struct QmdbState {
    /// Shared QMDB handles guarded for async access.
    inner: Arc<Mutex<QmdbInner>>,
}

impl QmdbState {
    /// Initializes QMDB partitions and populates the genesis allocation.
    pub(crate) async fn init(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        let accounts = Db::init(
            context.with_label("accounts"),
            store_config(
                format!("{}-accounts", config.partition_prefix),
                config.buffer_pool.clone(),
                (),
            ),
        )
        .await?;
        let storage = Db::init(
            context.with_label("storage"),
            store_config(
                format!("{}-storage", config.partition_prefix),
                config.buffer_pool.clone(),
                (),
            ),
        )
        .await?;
        let code = Db::init(
            context.with_label("code"),
            store_config(
                format!("{}-code", config.partition_prefix),
                config.buffer_pool,
                (RangeCfg::new(0..=CODE_MAX_BYTES), ()),
            ),
        )
        .await?;

        let state = Self {
            inner: Arc::new(Mutex::new(QmdbInner::new(Stores {
                accounts,
                storage,
                code,
            }))),
        };
        state.bootstrap_genesis(genesis_alloc).await?;
        Ok(state)
    }

    /// Creates a sync REVM database view backed by the async QMDB adapter.
    ///
    /// This uses REVM's `WrapDatabaseAsync` bridge and therefore requires a
    /// Tokio runtime to be available when called.
    pub(crate) fn database(&self) -> Result<QmdbRefDb, Error> {
        let async_db = QmdbAsyncDb::new(self.inner.clone());
        let wrapped =
            alloy_evm::revm::database_interface::async_db::WrapDatabaseAsync::new(async_db)
                .ok_or(Error::MissingRuntime)?;
        Ok(QmdbRefDb {
            inner: Arc::new(wrapped),
        })
    }

    /// Persists a batch of finalized state changes into QMDB.
    ///
    /// The method stages updates with QMDB batch writers and commits once per
    /// partition, so callers can keep execution strictly in-memory and only
    /// persist at finalized block boundaries.
    ///
    /// If a write fails, the stores are left unavailable to prevent reuse
    /// after a failed mutable operation.
    pub(crate) async fn apply_changes(&self, changes: &QmdbChanges) -> Result<(), Error> {
        if changes.accounts.is_empty() {
            return Ok(());
        }

        let mut inner = self.inner.lock().await;
        let stores = inner.take_stores()?;
        let result = apply_changes_inner(stores, changes).await;
        match result {
            Ok(stores) => {
                inner.restore_stores(stores);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Writes genesis balances into the accounts partition.
    async fn bootstrap_genesis(&self, genesis_alloc: Vec<(Address, U256)>) -> Result<(), Error> {
        if genesis_alloc.is_empty() {
            return Ok(());
        }

        let mut inner = self.inner.lock().await;
        let stores = inner.take_stores()?;
        let result = apply_genesis_inner(stores, genesis_alloc).await;
        match result {
            Ok(stores) => {
                inner.restore_stores(stores);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Execution database type used by the REVM example.
pub(crate) type RevmDb = CacheDB<QmdbRefDb>;

/// Builds a QMDB store config with example-appropriate defaults.
const fn store_config<C>(
    partition: String,
    buffer_pool: PoolRef,
    log_codec_config: C,
) -> StoreConfig<EightCap, C> {
    StoreConfig {
        log_partition: partition,
        log_write_buffer: NZUsize!(1024 * 1024),
        log_compression: None,
        log_codec_config,
        log_items_per_section: NZU64!(128),
        translator: EightCap,
        buffer_pool,
    }
}
