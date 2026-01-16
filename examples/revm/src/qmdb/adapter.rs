//! REVM database adapter backed by QMDB.
//!
//! This module exposes an async database interface for QMDB and bridges it
//! into REVM's synchronous `DatabaseRef` using `WrapDatabaseAsync`. The async
//! adapter is intentionally thin so the example can rely on QMDB's internal
//! caching and batching.

use super::{
    keys::{account_key, code_key, storage_key},
    Error, QmdbInner,
};
use alloy_evm::revm::{
    database_interface::{
        async_db::{DatabaseAsyncRef, WrapDatabaseAsync},
        DatabaseRef,
    },
    primitives::{Address, Bytes, B256, KECCAK_EMPTY, U256},
    state::{AccountInfo, Bytecode},
};
use futures::lock::Mutex;
use std::sync::Arc;

/// Async QMDB view that implements `DatabaseAsyncRef` for REVM.
#[derive(Clone)]
pub(crate) struct QmdbAsyncDb {
    inner: Arc<Mutex<QmdbInner>>,
    gate: Arc<Mutex<()>>,
}

impl QmdbAsyncDb {
    /// Wraps shared QMDB state for the async REVM database bridge.
    pub(super) const fn new(inner: Arc<Mutex<QmdbInner>>, gate: Arc<Mutex<()>>) -> Self {
        Self { inner, gate }
    }
}

impl DatabaseAsyncRef for QmdbAsyncDb {
    type Error = Error;

    fn basic_async_ref(
        &self,
        address: Address,
    ) -> impl std::future::Future<Output = Result<Option<AccountInfo>, Self::Error>> + Send {
        let inner = self.inner.clone();
        let gate = self.gate.clone();
        async move {
            let _guard = gate.lock().await;
            let inner = inner.lock().await;
            let stores = inner.stores()?;
            let record = stores.accounts.get(&account_key(address)).await?;
            Ok(record.and_then(|record| record.as_info()))
        }
    }

    fn code_by_hash_async_ref(
        &self,
        code_hash: B256,
    ) -> impl std::future::Future<Output = Result<Bytecode, Self::Error>> + Send {
        let inner = self.inner.clone();
        let gate = self.gate.clone();
        async move {
            if code_hash == KECCAK_EMPTY || code_hash == B256::ZERO {
                return Ok(Bytecode::default());
            }

            let _guard = gate.lock().await;
            let inner = inner.lock().await;
            let stores = inner.stores()?;
            let code = stores.code.get(&code_key(code_hash)).await?;
            let code = code.ok_or(Error::MissingCode(code_hash))?;
            Ok(Bytecode::new_raw(Bytes::copy_from_slice(&code)))
        }
    }

    fn storage_async_ref(
        &self,
        address: Address,
        index: U256,
    ) -> impl std::future::Future<Output = Result<U256, Self::Error>> + Send {
        let inner = self.inner.clone();
        let gate = self.gate.clone();
        async move {
            let _guard = gate.lock().await;
            let inner = inner.lock().await;
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
    }

    fn block_hash_async_ref(
        &self,
        _number: u64,
    ) -> impl std::future::Future<Output = Result<B256, Self::Error>> + Send {
        std::future::ready(Ok(B256::ZERO))
    }
}

/// Sync REVM database wrapper for the async QMDB adapter.
#[derive(Clone)]
pub(crate) struct QmdbRefDb {
    pub(crate) inner: Arc<WrapDatabaseAsync<QmdbAsyncDb>>,
}

impl std::fmt::Debug for QmdbRefDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbRefDb").finish()
    }
}

impl DatabaseRef for QmdbRefDb {
    type Error = Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.inner.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash_ref(number)
    }
}
