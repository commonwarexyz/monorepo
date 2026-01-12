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
    database_interface::{async_db::WrapDatabaseAsync, DBErrorMarker},
    primitives::{keccak256, Address, B256, U256},
};
use commonware_codec::RangeCfg;
use commonware_cryptography::sha256::{Digest as QmdbDigest, Sha256 as QmdbHasher};
use commonware_runtime::{buffer::PoolRef, tokio, Metrics as _};
use commonware_storage::{
    qmdb::{
        any::{self, VariableConfig},
        NonDurable, Unmerkleized,
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU64};
use futures::lock::Mutex;
use std::sync::Arc;
use thiserror::Error;

use crate::types::StateRoot;
use keys::{account_key, code_key, storage_key, AccountKey, CodeKey, StorageKey};
use model::{AccountRecord, StorageRecord};
use store::{apply_changes_inner, apply_genesis_inner, preview_root_inner, QmdbInner, Stores};

pub(crate) use adapter::QmdbRefDb;
pub(crate) use persist::QmdbChanges;

const CODE_MAX_BYTES: usize = 24_576;
const QMDB_ROOT_NAMESPACE: &[u8] = b"_COMMONWARE_REVM_QMDB_ROOT";

type Context = tokio::Context;
type AccountStore =
    any::unordered::variable::Db<Context, AccountKey, AccountRecord, QmdbHasher, EightCap>;
type StorageStore =
    any::unordered::variable::Db<Context, StorageKey, StorageRecord, QmdbHasher, EightCap>;
type CodeStore = any::unordered::variable::Db<Context, CodeKey, Vec<u8>, QmdbHasher, EightCap>;
type AccountStoreDirty = any::unordered::variable::Db<
    Context,
    AccountKey,
    AccountRecord,
    QmdbHasher,
    EightCap,
    Unmerkleized,
    NonDurable,
>;
type StorageStoreDirty = any::unordered::variable::Db<
    Context,
    StorageKey,
    StorageRecord,
    QmdbHasher,
    EightCap,
    Unmerkleized,
    NonDurable,
>;
type CodeStoreDirty = any::unordered::variable::Db<
    Context,
    CodeKey,
    Vec<u8>,
    QmdbHasher,
    EightCap,
    Unmerkleized,
    NonDurable,
>;

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
    inner: Arc<Mutex<QmdbInner>>,
    gate: Arc<Mutex<()>>,
    context: Context,
    config: QmdbConfig,
}

impl QmdbState {
    /// Initializes QMDB partitions and populates the genesis allocation.
    pub(crate) async fn init(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        let stores = open_stores(context.clone(), config.clone()).await?;
        let state = Self {
            inner: Arc::new(Mutex::new(QmdbInner::new(stores))),
            gate: Arc::new(Mutex::new(())),
            context,
            config,
        };
        state.bootstrap_genesis(genesis_alloc).await?;
        Ok(state)
    }

    /// Creates a sync REVM database view backed by the async QMDB adapter.
    ///
    /// This uses REVM's `WrapDatabaseAsync` bridge and therefore requires a
    /// Tokio runtime to be available when called.
    pub(crate) fn database(&self) -> Result<QmdbRefDb, Error> {
        let async_db = QmdbAsyncDb::new(self.inner.clone(), self.gate.clone());
        let wrapped = WrapDatabaseAsync::new(async_db).ok_or(Error::MissingRuntime)?;
        Ok(QmdbRefDb {
            inner: Arc::new(wrapped),
        })
    }

    /// Computes the state commitment that would result from applying the changes.
    ///
    /// This does not make changes durable. The commitment is derived from the authenticated roots
    /// of the accounts, storage, and code partitions.
    pub(crate) async fn preview_root(&self, changes: QmdbChanges) -> Result<StateRoot, Error> {
        let _guard = self.gate.lock().await;
        if changes.accounts.is_empty() {
            let inner = self.inner.lock().await;
            return Ok(state_root_from_stores(inner.stores()?));
        }

        let stores = open_stores(self.context.clone(), self.config.clone()).await?;
        preview_root_inner(stores, changes).await
    }

    /// Applies state changes to QMDB and commits them to durable storage.
    ///
    /// The commitment is derived from the authenticated roots of the accounts,
    /// storage, and code partitions.
    pub(crate) async fn commit_changes(
        &self,
        changes: QmdbChanges,
    ) -> Result<StateRoot, Error> {
        let _guard = self.gate.lock().await;
        if changes.accounts.is_empty() {
            let inner = self.inner.lock().await;
            return Ok(state_root_from_stores(inner.stores()?));
        }

        let stores = open_stores(self.context.clone(), self.config.clone()).await?;
        let stores = apply_changes_inner(stores, changes).await?;
        let root = state_root_from_stores(&stores);
        let mut inner = self.inner.lock().await;
        inner.restore_stores(stores);
        Ok(root)
    }

    /// Returns the current authenticated state commitment.
    pub(crate) async fn root(&self) -> Result<StateRoot, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        Ok(state_root_from_stores(inner.stores()?))
    }

    pub(crate) async fn get_account(
        &self,
        address: Address,
    ) -> Result<Option<AccountRecord>, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        let stores = inner.stores()?;
        stores.accounts.get(&account_key(address)).await.map_err(Error::from)
    }

    pub(crate) async fn get_code(&self, code_hash: B256) -> Result<Option<Vec<u8>>, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        let stores = inner.stores()?;
        stores.code.get(&code_key(code_hash)).await.map_err(Error::from)
    }

    pub(crate) async fn get_storage(
        &self,
        address: Address,
        index: U256,
    ) -> Result<U256, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        let stores = inner.stores()?;
        let record = stores.accounts.get(&account_key(address)).await?;
        let Some(record) = record else {
            return Ok(U256::ZERO);
        };
        if !record.exists {
            return Ok(U256::ZERO);
        }
        let key = storage_key(address, record.storage_generation, index);
        let value = stores.storage.get(&key).await?;
        Ok(value.map(|entry| entry.0).unwrap_or_default())
    }

    /// Writes genesis balances into the accounts partition.
    async fn bootstrap_genesis(&self, genesis_alloc: Vec<(Address, U256)>) -> Result<(), Error> {
        let _guard = self.gate.lock().await;
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

/// Builds a QMDB any-store config with example-appropriate defaults.
fn store_config<C>(
    prefix: &str,
    name: &str,
    buffer_pool: PoolRef,
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
        translator: EightCap,
        thread_pool: None,
        buffer_pool,
    }
}

fn state_root_from_stores(stores: &Stores) -> StateRoot {
    state_root_from_roots(
        stores.accounts.root(),
        stores.storage.root(),
        stores.code.root(),
    )
}

pub(crate) fn state_root_from_roots(
    accounts: QmdbDigest,
    storage: QmdbDigest,
    code: QmdbDigest,
) -> StateRoot {
    let mut buf = Vec::with_capacity(QMDB_ROOT_NAMESPACE.len() + (32 * 3));
    buf.extend_from_slice(QMDB_ROOT_NAMESPACE);
    buf.extend_from_slice(accounts.as_ref());
    buf.extend_from_slice(storage.as_ref());
    buf.extend_from_slice(code.as_ref());
    StateRoot(keccak256(buf))
}

async fn open_stores(context: Context, config: QmdbConfig) -> Result<Stores, Error> {
    let accounts = AccountStore::init(
        context.with_label("accounts"),
        store_config(
            &config.partition_prefix,
            "accounts",
            config.buffer_pool.clone(),
            (),
        ),
    )
    .await?;
    let storage = StorageStore::init(
        context.with_label("storage"),
        store_config(
            &config.partition_prefix,
            "storage",
            config.buffer_pool.clone(),
            (),
        ),
    )
    .await?;
    let code = CodeStore::init(
        context.with_label("code"),
        store_config(
            &config.partition_prefix,
            "code",
            config.buffer_pool.clone(),
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
