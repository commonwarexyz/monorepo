//! QMDB-backed storage adapter for the REVM example.

use alloy_evm::revm::{
    database::CacheDB,
    database_interface::{async_db::DatabaseAsyncRef, DBErrorMarker, DatabaseRef},
    primitives::{Address, Bytes, B256, U256, KECCAK_EMPTY},
    state::{Account, AccountInfo, Bytecode, EvmState},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_runtime::{buffer::PoolRef, tokio, Metrics};
use commonware_storage::{
    qmdb::store::{Batchable as _, Store},
    translator::EightCap,
};
use commonware_utils::{sequence::FixedBytes, NZU64, NZUsize};
use futures::lock::Mutex;
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;

const CODE_MAX_BYTES: usize = 24_576;

type Context = tokio::Context;
type AccountKey = FixedBytes<20>;
type StorageKey = FixedBytes<60>;
type CodeKey = FixedBytes<32>;
type AccountStore = Store<Context, AccountKey, AccountRecord, EightCap>;
type StorageStore = Store<Context, StorageKey, StorageRecord, EightCap>;
type CodeStore = Store<Context, CodeKey, Vec<u8>, EightCap>;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("qmdb error: {0}")]
    Qmdb(#[from] commonware_storage::qmdb::Error),
    #[error("missing tokio runtime for WrapDatabaseAsync")]
    MissingRuntime,
    #[error("missing code for hash {0:?}")]
    MissingCode(B256),
}

impl DBErrorMarker for Error {}

#[derive(Clone)]
pub(crate) struct QmdbConfig {
    pub(crate) partition_prefix: String,
    pub(crate) buffer_pool: PoolRef,
}

impl QmdbConfig {
    pub(crate) fn new(partition_prefix: String, buffer_pool: PoolRef) -> Self {
        Self {
            partition_prefix,
            buffer_pool,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct QmdbChanges {
    pub(crate) accounts: BTreeMap<Address, AccountUpdate>,
}

#[derive(Clone, Debug)]
pub(crate) struct AccountUpdate {
    pub(crate) created: bool,
    pub(crate) selfdestructed: bool,
    pub(crate) nonce: u64,
    pub(crate) balance: U256,
    pub(crate) code_hash: B256,
    pub(crate) code: Option<Vec<u8>>,
    pub(crate) storage: BTreeMap<U256, U256>,
}

impl QmdbChanges {
    pub(crate) fn apply_evm_state(&mut self, state: &EvmState) {
        for (address, account) in state.iter() {
            if !account.is_touched() {
                continue;
            }
            let update = account_update_from_evm_account(account);
            match self.accounts.entry(*address) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(update);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(update);
                }
            }
        }
    }
}

impl AccountUpdate {
    fn merge(&mut self, update: AccountUpdate) {
        let AccountUpdate {
            created,
            selfdestructed,
            nonce,
            balance,
            code_hash,
            code,
            storage,
        } = update;

        if created {
            self.storage.clear();
            self.created = true;
        }

        if selfdestructed {
            self.storage.clear();
        }

        self.selfdestructed = selfdestructed;
        self.nonce = nonce;
        self.balance = balance;

        if self.code_hash != code_hash || code.is_some() {
            self.code = code;
        }
        self.code_hash = code_hash;

        if !selfdestructed {
            for (slot, value) in storage {
                self.storage.insert(slot, value);
            }
        }
    }
}

#[derive(Clone, Debug)]
struct AccountRecord {
    exists: bool,
    nonce: u64,
    balance: U256,
    code_hash: B256,
    storage_generation: u64,
}

impl AccountRecord {
    fn empty(storage_generation: u64) -> Self {
        Self {
            exists: false,
            nonce: 0,
            balance: U256::ZERO,
            code_hash: KECCAK_EMPTY,
            storage_generation,
        }
    }

    fn as_info(&self) -> Option<AccountInfo> {
        if !self.exists {
            return None;
        }
        Some(AccountInfo {
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            code: None,
        })
    }
}

impl Write for AccountRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.exists.write(buf);
        self.nonce.write(buf);
        write_u256(self.balance, buf);
        write_b256(self.code_hash, buf);
        self.storage_generation.write(buf);
    }
}

impl EncodeSize for AccountRecord {
    fn encode_size(&self) -> usize {
        self.exists.encode_size()
            + self.nonce.encode_size()
            + 32
            + 32
            + self.storage_generation.encode_size()
    }
}

impl Read for AccountRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let exists = bool::read(buf)?;
        let nonce = u64::read(buf)?;
        let balance = read_u256(buf)?;
        let code_hash = read_b256(buf)?;
        let storage_generation = u64::read(buf)?;
        Ok(Self {
            exists,
            nonce,
            balance,
            code_hash,
            storage_generation,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct StorageRecord(U256);

impl Write for StorageRecord {
    fn write(&self, buf: &mut impl BufMut) {
        write_u256(self.0, buf);
    }
}

impl EncodeSize for StorageRecord {
    fn encode_size(&self) -> usize {
        32
    }
}

impl Read for StorageRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(read_u256(buf)?))
    }
}

#[derive(Clone)]
pub(crate) struct QmdbState {
    inner: Arc<Mutex<QmdbInner>>,
}

impl QmdbState {
    pub(crate) async fn init(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        let accounts = Store::init(
            context.with_label("accounts"),
            store_config(
                format!("{}-accounts", config.partition_prefix),
                config.buffer_pool.clone(),
                (),
            ),
        )
        .await?;
        let storage = Store::init(
            context.with_label("storage"),
            store_config(
                format!("{}-storage", config.partition_prefix),
                config.buffer_pool.clone(),
                (),
            ),
        )
        .await?;
        let code = Store::init(
            context.with_label("code"),
            store_config(
                format!("{}-code", config.partition_prefix),
                config.buffer_pool,
                (RangeCfg::new(0..=CODE_MAX_BYTES), ()),
            ),
        )
        .await?;

        let state = Self {
            inner: Arc::new(Mutex::new(QmdbInner {
                accounts,
                storage,
                code,
            })),
        };
        state.bootstrap_genesis(genesis_alloc).await?;
        Ok(state)
    }

    pub(crate) fn database(&self) -> Result<QmdbRefDb, Error> {
        let async_db = QmdbAsyncDb {
            inner: self.inner.clone(),
        };
        let wrapped =
            alloy_evm::revm::database_interface::async_db::WrapDatabaseAsync::new(async_db)
                .ok_or(Error::MissingRuntime)?;
        Ok(QmdbRefDb {
            inner: Arc::new(wrapped),
        })
    }

    pub(crate) async fn apply_changes(&self, changes: &QmdbChanges) -> Result<(), Error> {
        if changes.accounts.is_empty() {
            return Ok(());
        }

        let mut inner = self.inner.lock().await;
        let (accounts_ops, storage_ops, code_ops) = {
            let mut accounts_batch = inner.accounts.start_batch();
            let mut storage_batch = inner.storage.start_batch();
            let mut code_batch = inner.code.start_batch();

            for (address, update) in changes.accounts.iter() {
                let account_key = account_key(*address);
                let existing = inner.accounts.get(&account_key).await?;
                let base_generation = existing
                    .as_ref()
                    .map(|record| record.storage_generation)
                    .unwrap_or(0);

                let storage_generation = if update.created || update.selfdestructed {
                    base_generation.saturating_add(1)
                } else {
                    base_generation
                };

                let record = if update.selfdestructed {
                    AccountRecord::empty(storage_generation)
                } else {
                    AccountRecord {
                        exists: true,
                        nonce: update.nonce,
                        balance: update.balance,
                        code_hash: update.code_hash,
                        storage_generation,
                    }
                };
                accounts_batch.update(account_key, record).await?;

                if update.selfdestructed {
                    continue;
                }

                if let Some(code) = update.code.as_ref() {
                    if !code.is_empty() && update.code_hash != KECCAK_EMPTY {
                        code_batch
                            .update(code_key(update.code_hash), code.clone())
                            .await?;
                    }
                }

                for (slot, value) in update.storage.iter() {
                    let key = storage_key(*address, storage_generation, *slot);
                    if value.is_zero() {
                        storage_batch.delete_unchecked(key).await?;
                    } else {
                        storage_batch.update(key, StorageRecord(*value)).await?;
                    }
                }
            }

            (
                accounts_batch.into_iter().collect::<Vec<_>>(),
                storage_batch.into_iter().collect::<Vec<_>>(),
                code_batch.into_iter().collect::<Vec<_>>(),
            )
        };

        inner
            .accounts
            .write_batch(accounts_ops.into_iter())
            .await?;
        inner
            .storage
            .write_batch(storage_ops.into_iter())
            .await?;
        inner.code.write_batch(code_ops.into_iter()).await?;
        inner.accounts.commit(None).await?;
        inner.storage.commit(None).await?;
        inner.code.commit(None).await?;
        Ok(())
    }

    async fn bootstrap_genesis(
        &self,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<(), Error> {
        if genesis_alloc.is_empty() {
            return Ok(());
        }

        let mut inner = self.inner.lock().await;
        let batch_ops = {
            let mut batch = inner.accounts.start_batch();
            for (address, balance) in genesis_alloc {
                let record = AccountRecord {
                    exists: true,
                    nonce: 0,
                    balance,
                    code_hash: KECCAK_EMPTY,
                    storage_generation: 0,
                };
                batch.update(account_key(address), record).await?;
            }
            batch.into_iter().collect::<Vec<_>>()
        };
        inner.accounts.write_batch(batch_ops.into_iter()).await?;
        inner.accounts.commit(None).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct QmdbAsyncDb {
    inner: Arc<Mutex<QmdbInner>>,
}

impl DatabaseAsyncRef for QmdbAsyncDb {
    type Error = Error;

    fn basic_async_ref(
        &self,
        address: Address,
    ) -> impl std::future::Future<Output = Result<Option<AccountInfo>, Self::Error>> + Send {
        let inner = self.inner.clone();
        async move {
            let inner = inner.lock().await;
            let record = inner.accounts.get(&account_key(address)).await?;
            Ok(record.and_then(|record| record.as_info()))
        }
    }

    fn code_by_hash_async_ref(
        &self,
        code_hash: B256,
    ) -> impl std::future::Future<Output = Result<Bytecode, Self::Error>> + Send {
        let inner = self.inner.clone();
        async move {
            if code_hash == KECCAK_EMPTY || code_hash == B256::ZERO {
                return Ok(Bytecode::default());
            }

            let inner = inner.lock().await;
            let code = inner.code.get(&code_key(code_hash)).await?;
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
        async move {
            let inner = inner.lock().await;
            let record = inner.accounts.get(&account_key(address)).await?;
            let Some(record) = record else {
                return Ok(U256::ZERO);
            };
            if !record.exists {
                return Ok(U256::ZERO);
            }
            let key = storage_key(address, record.storage_generation, index);
            let value = inner.storage.get(&key).await?;
            Ok(value.map(|entry| entry.0).unwrap_or_default())
        }
    }

    fn block_hash_async_ref(
        &self,
        _number: u64,
    ) -> impl std::future::Future<Output = Result<B256, Self::Error>> + Send {
        async move { Ok(B256::ZERO) }
    }
}

#[derive(Clone)]
pub(crate) struct QmdbRefDb {
    inner: Arc<alloy_evm::revm::database_interface::async_db::WrapDatabaseAsync<QmdbAsyncDb>>,
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

pub(crate) type RevmDb = CacheDB<QmdbRefDb>;

struct QmdbInner {
    accounts: AccountStore,
    storage: StorageStore,
    code: CodeStore,
}

fn account_update_from_evm_account(account: &Account) -> AccountUpdate {
    let mut storage = BTreeMap::new();
    for (slot, slot_value) in account.changed_storage_slots() {
        storage.insert(*slot, slot_value.present_value());
    }

    let code = account
        .info
        .code
        .as_ref()
        .map(|code| code.original_byte_slice().to_vec());
    let code_hash = if account.info.code_hash == B256::ZERO {
        KECCAK_EMPTY
    } else {
        account.info.code_hash
    };

    AccountUpdate {
        created: account.is_created(),
        selfdestructed: account.is_selfdestructed(),
        nonce: account.info.nonce,
        balance: account.info.balance,
        code_hash,
        code,
        storage,
    }
}

fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

fn code_key(hash: B256) -> CodeKey {
    CodeKey::new(hash.0)
}

fn storage_key(address: Address, generation: u64, slot: U256) -> StorageKey {
    let mut out = [0u8; 60];
    out[..20].copy_from_slice(address.as_slice());
    out[20..28].copy_from_slice(&generation.to_be_bytes());
    out[28..60].copy_from_slice(&slot.to_be_bytes::<32>());
    StorageKey::new(out)
}

fn write_u256(value: U256, buf: &mut impl BufMut) {
    buf.put_slice(&value.to_be_bytes::<32>());
}

fn read_u256(buf: &mut impl Buf) -> Result<U256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(U256::from_be_bytes(out))
}

fn write_b256(value: B256, buf: &mut impl BufMut) {
    buf.put_slice(value.as_slice());
}

fn read_b256(buf: &mut impl Buf) -> Result<B256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(B256::from(out))
}

fn store_config<C>(
    partition: String,
    buffer_pool: PoolRef,
    log_codec_config: C,
) -> commonware_storage::qmdb::store::Config<EightCap, C> {
    commonware_storage::qmdb::store::Config {
        log_partition: partition,
        log_write_buffer: NZUsize!(1024 * 1024),
        log_compression: None,
        log_codec_config,
        log_items_per_section: NZU64!(128),
        translator: EightCap,
        buffer_pool,
    }
}
