//! QMDB change tracking and diff application helpers.

use alloy_evm::revm::{
    primitives::{Address, B256, KECCAK_EMPTY, U256},
    state::{Account, EvmState},
};
use std::collections::BTreeMap;

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
