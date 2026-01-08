//! QMDB change tracking and diff application helpers.
//!
//! The REVM overlay produces an `EvmState` after execution. This module turns
//! those updates into QMDB-friendly batches that can be persisted at finalized
//! block boundaries.

use alloy_evm::revm::{
    primitives::{Address, B256, KECCAK_EMPTY, U256},
    state::{Account, EvmState},
};
use std::collections::BTreeMap;

/// Aggregated changes to be persisted into QMDB.
#[derive(Clone, Debug, Default)]
pub(crate) struct QmdbChanges {
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

impl QmdbChanges {
    /// Applies the touched accounts from an `EvmState` into the change set.
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
    /// Merges an update from later execution into the current view.
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

/// Builds an account update from the REVM account record.
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
