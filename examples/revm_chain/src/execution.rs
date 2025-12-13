use crate::commitment::{commit_state_root, AccountChange, StateChanges};
use crate::types::{StateRoot, Tx};
use alloy_evm::{eth::EthEvmBuilder, Database as AlloyDatabase, Evm, EvmEnv};
use alloy_evm::revm::{
    context::TxEnv,
    context_interface::result::ResultAndState,
    primitives::TxKind,
    state::{Account, EvmState},
    DatabaseCommit,
};
use anyhow::Context as _;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub state_root: StateRoot,
    pub tx_changes: Vec<StateChanges>,
}

pub fn execute_txs<DB>(
    db: DB,
    env: EvmEnv,
    prev_root: StateRoot,
    txs: &[Tx],
) -> anyhow::Result<(DB, ExecutionOutcome)>
where
    DB: AlloyDatabase + DatabaseCommit,
{
    let mut evm = EthEvmBuilder::new(db, env).build();

    let mut state_root = prev_root;
    let mut tx_changes = Vec::with_capacity(txs.len());

    for tx in txs {
        let chain_id = evm.chain_id();
        let tx_env = tx_env_from_db(evm.db_mut(), tx, chain_id)
            .context("build tx env")?;

        let ResultAndState { result: _, state } = evm.transact_raw(tx_env).context("execute tx")?;

        let changes = state_changes_from_evm_state(&state);
        state_root = commit_state_root(state_root, &changes);

        evm.db_mut().commit(state);
        tx_changes.push(changes);
    }

    let (db, _) = evm.finish();
    Ok((db, ExecutionOutcome { state_root, tx_changes }))
}

fn tx_env_from_db<DB>(db: &mut DB, tx: &Tx, chain_id: u64) -> anyhow::Result<TxEnv>
where
    DB: AlloyDatabase,
{
    let nonce = match db.basic(tx.from).context("read sender account")? {
        Some(info) => info.nonce,
        None => 0,
    };

    let mut tx_env = TxEnv::default();
    tx_env.caller = tx.from;
    tx_env.kind = TxKind::Call(tx.to);
    tx_env.value = tx.value;
    tx_env.gas_limit = tx.gas_limit;
    tx_env.data = tx.data.clone();
    tx_env.nonce = nonce;
    tx_env.chain_id = Some(chain_id);
    tx_env.gas_price = 0;
    tx_env.gas_priority_fee = None;

    Ok(tx_env)
}

fn state_changes_from_evm_state(state: &EvmState) -> StateChanges {
    let mut changes = StateChanges::default();
    for (address, account) in state.iter() {
        if !account.is_touched() {
            continue;
        }
        changes.accounts.insert(*address, account_change_from_evm_account(account));
    }
    changes
}

fn account_change_from_evm_account(account: &Account) -> AccountChange {
    let mut storage = BTreeMap::new();
    for (slot, slot_value) in account.changed_storage_slots() {
        storage.insert(*slot, slot_value.present_value());
    }

    AccountChange {
        touched: account.is_touched(),
        created: account.is_created(),
        selfdestructed: account.is_selfdestructed(),
        nonce: account.info.nonce,
        balance: account.info.balance,
        code_hash: account.info.code_hash,
        storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::commit_state_root;
    use alloy_evm::EvmEnv;
    use alloy_evm::revm::{
        database::InMemoryDB,
        primitives::{Address, B256, Bytes, U256},
        state::AccountInfo,
        Database as _,
    };

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    #[test]
    fn test_execute_single_transfer() {
        let from = addr(0x11);
        let to = addr(0x22);

        let mut db = InMemoryDB::default();
        db.insert_account_info(
            from,
            AccountInfo {
                balance: U256::from(1_000_000u64),
                nonce: 0,
                ..Default::default()
            },
        );

        let tx = Tx {
            from,
            to,
            value: U256::from(100u64),
            gas_limit: 21_000,
            data: Bytes::new(),
        };

        let prev_root = StateRoot(B256::ZERO);
        let (mut db, outcome) =
            execute_txs(db, test_env(1, B256::from([7u8; 32])), prev_root, &[tx]).unwrap();

        assert_eq!(outcome.tx_changes.len(), 1);
        assert!(!outcome.tx_changes[0].is_empty());
        assert_eq!(
            outcome.state_root,
            commit_state_root(prev_root, &outcome.tx_changes[0])
        );

        let from_info = db.basic(from).unwrap().unwrap();
        let to_info = db.basic(to).unwrap().unwrap();
        assert_eq!(from_info.balance, U256::from(1_000_000u64 - 100));
        assert_eq!(from_info.nonce, 1);
        assert_eq!(to_info.balance, U256::from(100u64));
        assert_eq!(to_info.nonce, 0);
    }

    fn test_env(height: u64, prevrandao: B256) -> EvmEnv {
        let mut env: EvmEnv = EvmEnv::default();
        env.cfg_env.chain_id = 1337;
        env.block_env.number = U256::from(height);
        env.block_env.timestamp = U256::from(height);
        env.block_env.prevrandao = Some(prevrandao);
        env
    }
}
