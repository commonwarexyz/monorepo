//! QMDB change tracking and merge helpers.
//!
//! The execution layer builds `QmdbChangeSet` from REVM diffs, and the QMDB layer
//! applies them to the underlying stores. Merging semantics are important:
//! - later updates override earlier ones,
//! - account recreation bumps storage generation, effectively clearing old slots,
//! - selfdestruct clears storage and deletes the account record.

use alloy_evm::revm::primitives::{Address, B256, U256};
use std::collections::BTreeMap;

/// Aggregated changes to be persisted into QMDB.
#[derive(Clone, Debug, Default)]
pub(crate) struct QmdbChangeSet {
    /// Per-address updates collected from the REVM overlay.
    pub(crate) accounts: BTreeMap<Address, AccountUpdate>,
}

/// Per-account changes derived from REVM state.
#[derive(Clone, Debug)]
pub(crate) struct AccountUpdate {
    /// True if the account was created during execution.
    pub(crate) created: bool,
    /// True if the account was selfdestructed during execution.
    pub(crate) selfdestructed: bool,
    /// Updated nonce value.
    pub(crate) nonce: u64,
    /// Updated balance value.
    pub(crate) balance: U256,
    /// Code hash after execution.
    pub(crate) code_hash: B256,
    /// Code bytes if a new code blob was deployed or changed.
    pub(crate) code: Option<Vec<u8>>,
    /// Updated storage slots (slot -> value).
    pub(crate) storage: BTreeMap<U256, U256>,
}

impl QmdbChangeSet {
    /// Merges updates from a later block into the current change set.
    ///
    /// This is used when combining unpersisted ancestor deltas with the current
    /// block's delta during root computation and commit preparation.
    pub(crate) fn merge(&mut self, other: Self) {
        for (address, update) in other.accounts {
            match self.accounts.entry(address) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(update);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(update);
                }
            }
        }
    }

    /// Applies a per-account update into the change set.
    ///
    /// If the account already has pending updates, this merges them using the
    /// same semantics as `merge`.
    pub(crate) fn apply_update(&mut self, address: Address, update: AccountUpdate) {
        match self.accounts.entry(address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(update);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().merge(update);
            }
        }
    }
}

impl AccountUpdate {
    /// Merges an update from later execution into the current view.
    ///
    /// Merge rules:
    /// - `created` clears prior storage and marks the account as created.
    /// - `selfdestructed` clears storage and marks the account as deleted.
    /// - nonce/balance always take the latest values.
    /// - code is replaced if the hash changes or new code bytes are present.
    /// - storage writes are applied last unless the account was selfdestructed.
    fn merge(&mut self, update: Self) {
        let Self {
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
