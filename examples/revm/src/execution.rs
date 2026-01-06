//! EVM execution for the example chain.
//!
//! This module uses `alloy-evm` as the integration layer above `revm` and keeps the execution
//! backend generic over the `Database + DatabaseCommit` seam.
//!
//! The example also installs a small precompile that returns `block.prevrandao` (EIP-4399), which
//! is sourced from the threshold-simplex seed.

use crate::{
    commitment::{commit_state_root, AccountChange, StateChanges},
    qmdb::QmdbChanges,
    types::{StateRoot, Tx},
};
use alloy_evm::{
    eth::EthEvmBuilder,
    precompiles::{DynPrecompile, PrecompilesMap},
    revm::{
        context::TxEnv,
        context_interface::result::ResultAndState,
        precompile::{PrecompileId, PrecompileOutput, PrecompileSpecId, Precompiles},
        primitives::{Address, Bytes, TxKind, B256, U256},
        state::{Account, EvmState},
        DatabaseCommit,
    },
    Database as AlloyDatabase, Evm, EvmEnv,
};
use anyhow::Context as _;
use std::collections::BTreeMap;

/// Example chain id used by the simulation.
pub const CHAIN_ID: u64 = 1337;
pub const SEED_PRECOMPILE_ADDRESS_BYTES: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF,
];

/// Address of the example "seed" precompile.
pub fn seed_precompile_address() -> Address {
    Address::from(SEED_PRECOMPILE_ADDRESS_BYTES)
}

/// Build an `EvmEnv` for a given block height and `prevrandao`.
pub fn evm_env(height: u64, prevrandao: B256) -> EvmEnv {
    let mut env: EvmEnv = EvmEnv::default();
    env.cfg_env.chain_id = CHAIN_ID;
    env.block_env.number = U256::from(height);
    env.block_env.timestamp = U256::from(height);
    env.block_env.prevrandao = Some(prevrandao);
    env
}

#[derive(Debug, Clone)]
/// Result of executing a batch of transactions.
pub struct ExecutionOutcome {
    /// Rolling state commitment after applying the batch.
    pub state_root: StateRoot,
    /// Canonical per-transaction state deltas used to compute `state_root`.
    pub tx_changes: Vec<StateChanges>,
    /// Per-account changes used to persist finalized blocks to QMDB.
    pub qmdb_changes: QmdbChanges,
}

/// Execute a batch of transactions and commit them to the provided DB.
///
/// Notes:
/// - Uses `transact_raw` so the state diff is available to compute the rolling `state_root`
///   *before* committing the changes.
/// - Commits the diff into the DB after updating the rolling root.
pub fn execute_txs<DB>(
    db: DB,
    env: EvmEnv,
    prev_root: StateRoot,
    txs: &[Tx],
) -> anyhow::Result<(DB, ExecutionOutcome)>
where
    DB: AlloyDatabase + DatabaseCommit,
{
    let spec = env.cfg_env.spec;
    let precompiles = precompiles_with_seed(spec);
    let mut evm = EthEvmBuilder::new(db, env).precompiles(precompiles).build();
    let chain_id = evm.chain_id();

    let mut state_root = prev_root;
    let mut tx_changes = Vec::with_capacity(txs.len());
    let mut qmdb_changes = QmdbChanges::default();

    for tx in txs {
        let tx_env = tx_env_from_db(evm.db_mut(), tx, chain_id).context("build tx env")?;

        let ResultAndState { result: _, state } = evm.transact_raw(tx_env).context("execute tx")?;

        let changes = state_changes_from_evm_state(&state);
        qmdb_changes.apply_evm_state(&state);
        state_root = commit_state_root(state_root, &changes);

        evm.db_mut().commit(state);
        tx_changes.push(changes);
    }

    let (db, _) = evm.finish();
    Ok((
        db,
        ExecutionOutcome {
            state_root,
            tx_changes,
            qmdb_changes,
        },
    ))
}

fn precompiles_with_seed(spec: alloy_evm::revm::primitives::hardfork::SpecId) -> PrecompilesMap {
    let mut precompiles =
        PrecompilesMap::from_static(Precompiles::new(PrecompileSpecId::from_spec_id(spec)));

    let address = seed_precompile_address();
    // This precompile is stateful (not pure) because it depends on the current block env.
    precompiles.apply_precompile(&address, |_| {
        Some(DynPrecompile::new_stateful(
            PrecompileId::Custom("commonware_seed".into()),
            |input| {
                use alloy_evm::revm::context_interface::Block as _;
                let seed = input
                    .internals
                    .block_env()
                    .prevrandao()
                    .unwrap_or(B256::ZERO);
                Ok(PrecompileOutput::new(
                    0,
                    Bytes::copy_from_slice(seed.as_slice()),
                ))
            },
        ))
    });

    precompiles
}

fn tx_env_from_db<DB>(db: &mut DB, tx: &Tx, chain_id: u64) -> anyhow::Result<TxEnv>
where
    DB: AlloyDatabase,
{
    let nonce = match db.basic(tx.from).context("read sender account")? {
        Some(info) => info.nonce,
        None => 0,
    };

    Ok(TxEnv {
        caller: tx.from,
        kind: TxKind::Call(tx.to),
        value: tx.value,
        gas_limit: tx.gas_limit,
        data: tx.data.clone(),
        nonce,
        chain_id: Some(chain_id),
        gas_price: 0,
        gas_priority_fee: None,
        ..Default::default()
    })
}

fn state_changes_from_evm_state(state: &EvmState) -> StateChanges {
    let mut changes = StateChanges::default();
    for (address, account) in state.iter() {
        if !account.is_touched() {
            continue;
        }
        changes
            .accounts
            .insert(*address, account_change_from_evm_account(account));
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
    use alloy_evm::revm::{
        database::InMemoryDB,
        primitives::{Address, Bytes, B256, U256},
        state::AccountInfo,
        Database as _,
    };

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn fund(db: &mut InMemoryDB, address: Address, balance: U256, nonce: u64) {
        db.insert_account_info(
            address,
            AccountInfo {
                balance,
                nonce,
                ..Default::default()
            },
        );
    }

    fn nonce(db: &mut InMemoryDB, address: Address) -> u64 {
        db.basic(address)
            .unwrap()
            .map(|info| info.nonce)
            .unwrap_or(0)
    }

    #[test]
    fn test_execute_single_transfer() {
        // Prepare
        let sender = addr(0x11);
        let recipient = addr(0x22);
        let seed = B256::from([7u8; 32]);
        let height = 1;
        let prev_root = StateRoot(B256::ZERO);
        let mut db = InMemoryDB::default();
        fund(
            &mut db,
            sender,
            U256::from(1_000_000u64),
            /* nonce */ 0,
        );
        let tx = Tx {
            from: sender,
            to: recipient,
            value: U256::from(100),
            gas_limit: 21_000,
            data: Bytes::new(),
        };

        // Execute
        let (mut db, outcome) = execute_txs(db, evm_env(height, seed), prev_root, &[tx]).unwrap();

        // Assert (outcome)
        assert_eq!(outcome.tx_changes.len(), 1);
        assert!(!outcome.tx_changes[0].is_empty());
        assert_eq!(
            outcome.state_root,
            commit_state_root(prev_root, &outcome.tx_changes[0])
        );

        // Assert (state)
        let sender_info = db.basic(sender).unwrap().unwrap();
        let recipient_info = db.basic(recipient).unwrap().unwrap();
        assert_eq!(sender_info.balance, U256::from(1_000_000u64 - 100));
        assert_eq!(sender_info.nonce, 1);
        assert_eq!(recipient_info.balance, U256::from(100u64));
        assert_eq!(recipient_info.nonce, 0);
    }

    #[test]
    fn test_seed_precompile_returns_block_prevrandao() {
        use alloy_evm::revm::context_interface::result::ExecutionResult;

        // Prepare
        let caller = addr(0x11);
        let seed = B256::from([7u8; 32]);
        let height = 1;
        let mut db = InMemoryDB::default();
        fund(
            &mut db,
            caller,
            U256::from(1_000_000u64),
            /* nonce */ 0,
        );

        let env = evm_env(height, seed);
        let spec = env.cfg_env.spec;
        let precompiles = precompiles_with_seed(spec);
        let mut evm = EthEvmBuilder::new(db, env).precompiles(precompiles).build();

        let tx = Tx {
            from: caller,
            to: seed_precompile_address(),
            value: U256::ZERO,
            gas_limit: 100_000,
            data: Bytes::new(),
        };

        // Execute
        let chain_id = evm.chain_id();
        let tx_env = tx_env_from_db(evm.db_mut(), &tx, chain_id).unwrap();
        let ResultAndState { result, state: _ } = evm.transact_raw(tx_env).unwrap();

        // Assert
        match result {
            ExecutionResult::Success { output, .. } => {
                assert_eq!(output.into_data().as_ref(), seed.as_slice());
            }
            other => panic!("unexpected execution result: {other:?}"),
        }
    }

    #[test]
    fn test_contract_can_read_seed_precompile() {
        use alloy_evm::revm::context_interface::result::{ExecutionResult, Output};

        // Prepare
        let caller = addr(0x11);
        let seed = B256::from([9u8; 32]);
        let height = 1;
        let mut db = InMemoryDB::default();
        fund(
            &mut db,
            caller,
            U256::from(1_000_000u64),
            /* nonce */ 0,
        );

        let env = evm_env(height, seed);
        let spec = env.cfg_env.spec;
        let precompiles = precompiles_with_seed(spec);
        let mut evm = EthEvmBuilder::new(db, env).precompiles(precompiles).build();

        let runtime = seed_reader_runtime();
        let init = seed_reader_init(&runtime);

        // Execute (deploy contract)
        let create_nonce = nonce(evm.db_mut(), caller);

        let create = TxEnv {
            caller,
            kind: TxKind::Create,
            value: U256::ZERO,
            gas_limit: 500_000,
            data: init,
            nonce: create_nonce,
            chain_id: Some(evm.chain_id()),
            gas_price: 0,
            gas_priority_fee: None,
            ..Default::default()
        };

        let ResultAndState {
            result: create_result,
            state: create_state,
        } = evm.transact_raw(create).unwrap();
        let deployed = match create_result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(address)),
                ..
            } => address,
            other => panic!("unexpected create result: {other:?}"),
        };
        evm.db_mut().commit(create_state);

        // Execute (call deployed contract)
        let call_nonce = nonce(evm.db_mut(), caller);

        let call = TxEnv {
            caller,
            kind: TxKind::Call(deployed),
            value: U256::ZERO,
            gas_limit: 200_000,
            data: Bytes::new(),
            nonce: call_nonce,
            chain_id: Some(evm.chain_id()),
            gas_price: 0,
            gas_priority_fee: None,
            ..Default::default()
        };

        let ResultAndState {
            result: call_result,
            state: _,
        } = evm.transact_raw(call).unwrap();

        // Assert
        match call_result {
            ExecutionResult::Success { output, .. } => {
                assert_eq!(output.into_data().as_ref(), seed.as_slice());
            }
            other => panic!("unexpected call result: {other:?}"),
        }
    }

    fn seed_reader_runtime() -> Bytes {
        // Runtime program:
        // - STATICCALL seed precompile with no calldata
        // - return exactly 32 bytes from memory[0..32)
        let address = seed_precompile_address();

        let mut bytecode = Vec::new();
        bytecode.extend_from_slice(&[0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73]);
        bytecode.extend_from_slice(address.as_slice());
        bytecode.extend_from_slice(&[0x61, 0xFF, 0xFF, 0xFA, 0x50, 0x60, 0x20, 0x60, 0x00, 0xF3]);

        Bytes::from(bytecode)
    }

    fn seed_reader_init(runtime: &Bytes) -> Bytes {
        // Init program:
        // - copy runtime to memory[0..len)
        // - return it as the deployed code
        let runtime_len = u8::try_from(runtime.len()).expect("runtime too large");
        let runtime_offset = 12u8;

        let mut init = Vec::new();
        init.extend_from_slice(&[
            0x60,
            runtime_len,
            0x60,
            runtime_offset,
            0x60,
            0x00,
            0x39,
            0x60,
            runtime_len,
            0x60,
            0x00,
            0xF3,
        ]);
        init.extend_from_slice(runtime.as_ref());
        Bytes::from(init)
    }
}
