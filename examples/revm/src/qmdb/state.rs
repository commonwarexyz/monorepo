use super::{
    adapter::QmdbAsyncDb,
    config::open_stores,
    store::{QmdbInner, Stores},
    Error, QmdbChangeSet, QmdbConfig, QmdbRefDb,
};
use crate::domain::StateRoot;
use alloy_evm::revm::{
    database::CacheDB,
    database_interface::async_db::WrapDatabaseAsync,
    primitives::{keccak256, Address, B256, U256},
};
use commonware_cryptography::sha256::Digest as QmdbDigest;
use futures::lock::Mutex;
use std::sync::Arc;

const QMDB_ROOT_NAMESPACE: &[u8] = b"_COMMONWARE_REVM_QMDB_ROOT";

type Context = commonware_runtime::tokio::Context;

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
    pub(crate) async fn compute_root(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let _guard = self.gate.lock().await;
        if changes.accounts.is_empty() {
            let inner = self.inner.lock().await;
            return Ok(state_root_from_stores(inner.stores()?));
        }

        let stores = open_stores(self.context.clone(), self.config.clone()).await?;
        stores.compute_root(changes).await
    }

    /// Applies state changes to QMDB and commits them to durable storage.
    ///
    /// The commitment is derived from the authenticated roots of the accounts,
    /// storage, and code partitions.
    pub(crate) async fn commit_changes(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let _guard = self.gate.lock().await;
        if changes.accounts.is_empty() {
            let inner = self.inner.lock().await;
            return Ok(state_root_from_stores(inner.stores()?));
        }

        let stores = open_stores(self.context.clone(), self.config.clone()).await?;
        let stores = stores.apply_changes(changes).await?;
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

    #[allow(dead_code)]
    pub(crate) async fn get_account(
        &self,
        address: Address,
    ) -> Result<Option<super::model::AccountRecord>, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        let stores = inner.stores()?;
        stores
            .accounts
            .get(&super::keys::account_key(address))
            .await
            .map_err(Error::from)
    }

    #[allow(dead_code)]
    pub(crate) async fn get_code(&self, code_hash: B256) -> Result<Option<Vec<u8>>, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        let stores = inner.stores()?;
        stores
            .code
            .get(&super::keys::code_key(code_hash))
            .await
            .map_err(Error::from)
    }

    #[allow(dead_code)]
    pub(crate) async fn get_storage(&self, address: Address, index: U256) -> Result<U256, Error> {
        let _guard = self.gate.lock().await;
        let inner = self.inner.lock().await;
        let stores = inner.stores()?;
        let record = stores
            .accounts
            .get(&super::keys::account_key(address))
            .await?;
        let Some(record) = record else {
            return Ok(U256::ZERO);
        };
        if !record.exists {
            return Ok(U256::ZERO);
        }
        let key = super::keys::storage_key(address, record.storage_generation, index);
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
        let result = stores.apply_genesis(genesis_alloc).await;
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
