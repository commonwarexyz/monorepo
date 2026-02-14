//! QMDB store plumbing for the REVM example.
//!
//! This module keeps the store ownership and update flow separate from the
//! public-facing API so `mod.rs` stays focused on the example entry points.

use super::{
    keys::{account_key, code_key, storage_key, AccountKey, CodeKey, StorageKey},
    model::{AccountRecord, StorageRecord},
    state_root_from_roots, AccountStore, AccountStoreDirty, CodeStore, CodeStoreDirty, Error,
    QmdbChangeSet, StorageStore, StorageStoreDirty,
};
use crate::domain::StateRoot;
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
pub(super) struct DirtyStores {
    pub(super) accounts: AccountStoreDirty,
    pub(super) storage: StorageStoreDirty,
    pub(super) code: CodeStoreDirty,
}

/// Batched updates prepared for QMDB writes.
pub(super) struct StoreBatches {
    pub(super) accounts: Vec<(AccountKey, Option<AccountRecord>)>,
    pub(super) storage: Vec<(StorageKey, Option<StorageRecord>)>,
    pub(super) code: Vec<(CodeKey, Option<Vec<u8>>)>,
}

/// Slot that temporarily yields ownership of the QMDB stores during updates.
pub(super) struct StoresSlot(Option<Stores>);

impl StoresSlot {
    /// Creates a new slot holding initialized stores.
    pub(super) const fn new(stores: Stores) -> Self {
        Self(Some(stores))
    }

    /// Returns a shared reference to the stores, if available.
    pub(super) fn get(&self) -> Result<&Stores, Error> {
        self.0
            .as_ref()
            .ok_or(Error::StoreUnavailable("stores unavailable"))
    }

    /// Takes ownership of the stores while an update is in progress.
    pub(super) fn take(&mut self) -> Result<Stores, Error> {
        self.0
            .take()
            .ok_or(Error::StoreUnavailable("stores unavailable"))
    }

    /// Restores the stores after a successful update.
    pub(super) fn restore(&mut self, stores: Stores) {
        self.0 = Some(stores);
    }
}

/// Shared QMDB store state guarded by the async mutex in `QmdbState`.
pub(crate) struct QmdbInner {
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

impl Stores {
    /// Transitions durable stores into their non-durable update state.
    pub(super) fn into_dirty(self) -> DirtyStores {
        DirtyStores {
            accounts: self.accounts.into_mutable(),
            storage: self.storage.into_mutable(),
            code: self.code.into_mutable(),
        }
    }

    /// Applies a finalized change set and returns updated durable stores.
    pub(crate) async fn apply_changes(self, changes: QmdbChangeSet) -> Result<Self, Error> {
        let dirty = self.into_dirty();
        let (mut dirty, batches) = dirty.build_batches(changes).await?;
        dirty.apply_batches(batches).await?;
        dirty.commit().await
    }

    /// Applies the genesis allocation to a fresh store set.
    pub(crate) async fn apply_genesis(
        self,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        let Self {
            accounts,
            storage,
            code,
        } = self;
        let mut accounts = accounts.into_mutable();
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
        let accounts = accounts.into_merkleized().await?;
        Ok(Self {
            accounts,
            storage,
            code,
        })
    }

    /// Computes the state commitment after applying changes without committing durability.
    pub(crate) async fn compute_root(self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let dirty = self.into_dirty();
        let (mut dirty, batches) = dirty.build_batches(changes).await?;
        dirty.apply_batches(batches).await?;

        let accounts = dirty.accounts.into_merkleized().await?;
        let storage = dirty.storage.into_merkleized().await?;
        let code = dirty.code.into_merkleized().await?;
        Ok(state_root_from_roots(
            accounts.root(),
            storage.root(),
            code.root(),
        ))
    }
}

impl DirtyStores {
    /// Builds batched QMDB operations from a finalized change set.
    ///
    /// Takes ownership of `DirtyStores` and `QmdbChangeSet` to avoid holding references
    /// across await points, which would trigger RPITIT cross-crate Send bound issues.
    ///
    /// The function is structured to:
    /// 1. Pre-fetch all existing account data (async lookups complete before batch building)
    /// 2. Build all batch operations synchronously without await in the loop
    pub(super) async fn build_batches(
        self,
        changes: QmdbChangeSet,
    ) -> Result<(Self, StoreBatches), Error> {
        // Prefetch existing account records to avoid await points during batch assembly.
        let stores = self;
        // Convert changes to owned Vec to avoid holding BTreeMap iterator across await
        let account_updates: Vec<_> = changes.accounts.into_iter().collect();

        // Extract just the addresses for pre-fetching (owned, not borrowed)
        let addresses: Vec<_> = account_updates.iter().map(|(addr, _)| *addr).collect();

        // Pre-fetch all existing account records we need (complete all async ops first)
        let mut existing_accounts = Vec::with_capacity(addresses.len());
        for address in addresses {
            let key = account_key(address);
            let existing = stores.accounts.get(&key).await?;
            existing_accounts.push(existing);
        }

        // Now build batches synchronously - no await points in this section
        let mut accounts_batch = stores.accounts.start_batch();
        let mut storage_batch = stores.storage.start_batch();
        let mut code_batch = stores.code.start_batch();

        // Collect all batch operations into vecs
        let mut account_ops = Vec::new();
        let mut storage_ops = Vec::new();
        let mut code_ops = Vec::new();

        for ((address, update), existing) in account_updates.into_iter().zip(existing_accounts) {
            let account_key = account_key(address);
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
            account_ops.push((account_key, Some(record)));

            if update.selfdestructed {
                continue;
            }

            if let Some(code) = update.code.as_ref() {
                if !code.is_empty() && update.code_hash != KECCAK_EMPTY {
                    code_ops.push((code_key(update.code_hash), Some(code.clone())));
                }
            }

            // Convert storage iteration to owned Vec to avoid borrow
            let storage_slots: Vec<_> = update.storage.into_iter().collect();
            for (slot, value) in storage_slots {
                let key = storage_key(address, storage_generation, slot);
                if value.is_zero() {
                    storage_ops.push((key, None));
                } else {
                    storage_ops.push((key, Some(StorageRecord(value))));
                }
            }
        }

        // Apply all batch operations (these may await but don't hold iterator borrows)
        for (key, value) in account_ops {
            if let Some(v) = value {
                accounts_batch.update(key, v).await?;
            }
        }
        for (key, value) in storage_ops {
            if let Some(v) = value {
                storage_batch.update(key, v).await?;
            } else {
                storage_batch.delete_unchecked(key).await?;
            }
        }
        for (key, value) in code_ops {
            if let Some(v) = value {
                code_batch.update(key, v).await?;
            }
        }

        let batches = StoreBatches {
            accounts: accounts_batch.into_iter().collect(),
            storage: storage_batch.into_iter().collect(),
            code: code_batch.into_iter().collect(),
        };
        Ok((stores, batches))
    }

    /// Writes batches to the dirty stores before commit.
    pub(super) async fn apply_batches(&mut self, batches: StoreBatches) -> Result<(), Error> {
        self.accounts
            .write_batch(batches.accounts.into_iter())
            .await?;
        self.storage
            .write_batch(batches.storage.into_iter())
            .await?;
        self.code.write_batch(batches.code.into_iter()).await?;
        Ok(())
    }

    /// Commits all dirty stores and returns them in durable form.
    pub(super) async fn commit(self) -> Result<Stores, Error> {
        let (accounts, _) = self.accounts.commit(None).await?;
        let accounts = accounts.into_merkleized().await?;
        let (storage, _) = self.storage.commit(None).await?;
        let storage = storage.into_merkleized().await?;
        let (code, _) = self.code.commit(None).await?;
        let code = code.into_merkleized().await?;
        Ok(Stores {
            accounts,
            storage,
            code,
        })
    }
}
