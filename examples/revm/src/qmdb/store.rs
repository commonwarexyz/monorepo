//! QMDB store plumbing for the REVM example.
//!
//! This module keeps the store ownership and update flow separate from the
//! public-facing API so `mod.rs` stays focused on the example entry points.

use super::{
    account_key, code_key, storage_key, AccountRecord, AccountStore, AccountStoreDirty, CodeStore,
    CodeStoreDirty, Error, QmdbChanges, StorageRecord, StorageStore, StorageStoreDirty,
};
use alloy_evm::revm::primitives::{Address, KECCAK_EMPTY, U256};
use commonware_storage::kv::{Batchable as _, Updatable as _};

/// Durable QMDB stores backing the example state.
pub(crate) struct Stores {
    /// Account metadata keyed by address.
    pub(crate) accounts: AccountStore,
    /// Storage slots keyed by address, generation, and slot.
    pub(crate) storage: StorageStore,
    /// Contract bytecode keyed by code hash.
    pub(crate) code: CodeStore,
}

/// Dirty QMDB stores used while applying updates.
struct DirtyStores {
    accounts: AccountStoreDirty,
    storage: StorageStoreDirty,
    code: CodeStoreDirty,
}

/// Batched updates prepared for QMDB writes.
struct StoreBatches {
    accounts: Vec<(super::AccountKey, Option<AccountRecord>)>,
    storage: Vec<(super::StorageKey, Option<StorageRecord>)>,
    code: Vec<(super::CodeKey, Option<Vec<u8>>)>,
}

impl Stores {
    /// Transitions durable stores into their non-durable update state.
    fn into_dirty(self) -> DirtyStores {
        DirtyStores {
            accounts: self.accounts.into_dirty(),
            storage: self.storage.into_dirty(),
            code: self.code.into_dirty(),
        }
    }
}

impl DirtyStores {
    /// Commits all dirty stores and returns them in durable form.
    async fn commit(self) -> Result<Stores, Error> {
        let (accounts, _) = self.accounts.commit(None).await?;
        let (storage, _) = self.storage.commit(None).await?;
        let (code, _) = self.code.commit(None).await?;
        Ok(Stores {
            accounts,
            storage,
            code,
        })
    }
}

/// Slot that temporarily yields ownership of the QMDB stores during updates.
pub(crate) struct StoresSlot(Option<Stores>);

impl StoresSlot {
    /// Creates a new slot holding initialized stores.
    pub(crate) const fn new(stores: Stores) -> Self {
        Self(Some(stores))
    }

    /// Returns a shared reference to the stores, if available.
    pub(crate) fn get(&self) -> Result<&Stores, Error> {
        self.0
            .as_ref()
            .ok_or(Error::StoreUnavailable("stores unavailable"))
    }

    /// Takes ownership of the stores while an update is in progress.
    pub(crate) fn take(&mut self) -> Result<Stores, Error> {
        self.0
            .take()
            .ok_or(Error::StoreUnavailable("stores unavailable"))
    }

    /// Restores the stores after a successful update.
    pub(crate) fn restore(&mut self, stores: Stores) {
        self.0 = Some(stores);
    }
}

pub(crate) struct QmdbInner {
    /// Store ownership state for QMDB partitions.
    stores: StoresSlot,
}

impl QmdbInner {
    /// Wraps initialized stores for shared access.
    pub(crate) const fn new(stores: Stores) -> Self {
        Self {
            stores: StoresSlot::new(stores),
        }
    }

    /// Returns a shared reference to the stores, if available.
    pub(crate) fn stores(&self) -> Result<&Stores, Error> {
        self.stores.get()
    }

    /// Takes ownership of the stores for an update.
    pub(crate) fn take_stores(&mut self) -> Result<Stores, Error> {
        self.stores.take()
    }

    /// Restores stores after a successful update.
    pub(crate) fn restore_stores(&mut self, stores: Stores) {
        self.stores.restore(stores);
    }
}

/// Applies a finalized change set and returns updated durable stores.
pub(crate) async fn apply_changes_inner(
    stores: Stores,
    changes: &QmdbChanges,
) -> Result<Stores, Error> {
    let mut dirty = stores.into_dirty();
    let batches = build_batches(&dirty, changes).await?;
    write_batches(&mut dirty, batches).await?;
    dirty.commit().await
}

/// Applies the genesis allocation to a fresh store set.
pub(crate) async fn apply_genesis_inner(
    stores: Stores,
    genesis_alloc: Vec<(Address, U256)>,
) -> Result<Stores, Error> {
    let Stores {
        accounts,
        storage,
        code,
    } = stores;
    let mut accounts = accounts.into_dirty();
    let batch_ops = {
        let mut batch = accounts.start_batch();
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
    accounts.write_batch(batch_ops.into_iter()).await?;
    let (accounts, _) = accounts.commit(None).await?;
    Ok(Stores {
        accounts,
        storage,
        code,
    })
}

/// Builds batched QMDB operations from a finalized change set.
async fn build_batches(stores: &DirtyStores, changes: &QmdbChanges) -> Result<StoreBatches, Error> {
    let mut accounts_batch = stores.accounts.start_batch();
    let mut storage_batch = stores.storage.start_batch();
    let mut code_batch = stores.code.start_batch();

    for (address, update) in changes.accounts.iter() {
        let account_key = account_key(*address);
        let existing = stores.accounts.get(&account_key).await?;
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

    Ok(StoreBatches {
        accounts: accounts_batch.into_iter().collect(),
        storage: storage_batch.into_iter().collect(),
        code: code_batch.into_iter().collect(),
    })
}

/// Writes batches to the dirty stores before commit.
async fn write_batches(stores: &mut DirtyStores, batches: StoreBatches) -> Result<(), Error> {
    stores
        .accounts
        .write_batch(batches.accounts.into_iter())
        .await?;
    stores
        .storage
        .write_batch(batches.storage.into_iter())
        .await?;
    stores.code.write_batch(batches.code.into_iter()).await?;
    Ok(())
}
