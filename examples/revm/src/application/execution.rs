//! EVM execution for the example chain.
//!
//! This module uses `alloy-evm` as the integration layer above `revm` and keeps the execution
//! backend generic over the `Database + DatabaseCommit` seam.
//!
//! The example also installs a small precompile that returns `block.prevrandao` (EIP-4399), which
//! is sourced from the threshold-simplex seed.

use crate::{
    domain::{AccountChange, StateChanges, Tx},
    qmdb::{AccountUpdate, QmdbChangeSet},
};
use alloy_evm::{
    eth::EthEvmBuilder,
    precompiles::{DynPrecompile, PrecompilesMap},
    revm::{
        context::TxEnv,
        context_interface::result::ResultAndState,
        precompile::{PrecompileId, PrecompileOutput, PrecompileSpecId, Precompiles},
        primitives::{hardfork::SpecId, Address, Bytes, TxKind, B256, KECCAK_EMPTY, U256},
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

pub(crate) fn precompiles_with_seed(spec: SpecId) -> PrecompilesMap {
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

pub(crate) fn tx_env_from_db<DB>(db: &mut DB, tx: &Tx, chain_id: u64) -> anyhow::Result<TxEnv>
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

#[derive(Debug, Clone)]
/// Result of executing a batch of transactions.
pub struct ExecutionOutcome {
    /// Canonical per-transaction state deltas observed during execution.
    pub tx_changes: Vec<StateChanges>,
    /// Per-account changes used to persist finalized blocks to QMDB.
    pub(crate) qmdb_changes: QmdbChangeSet,
}

/// Execute a batch of transactions and commit them to the provided DB.
///
/// Notes:
/// - Uses `transact_raw` so the state diff is available for downstream processing.
/// - Commits the diff into the DB after each transaction.
/// - Returns an error if a transaction reverts or halts.
pub fn execute_txs<DB>(db: DB, env: EvmEnv, txs: &[Tx]) -> anyhow::Result<(DB, ExecutionOutcome)>
where
    DB: AlloyDatabase + DatabaseCommit,
{
    let spec = env.cfg_env.spec;
    let precompiles = precompiles_with_seed(spec);
    let mut evm = EthEvmBuilder::new(db, env).precompiles(precompiles).build();
    let chain_id = evm.chain_id();

    let mut tx_changes = Vec::with_capacity(txs.len());
    let mut qmdb_changes = QmdbChangeSet::default();

    for tx in txs {
        let tx_env = tx_env_from_db(evm.db_mut(), tx, chain_id).context("build tx env")?;

        let ResultAndState { result, state } = evm.transact_raw(tx_env).context("execute tx")?;
        if !result.is_success() {
            return Err(anyhow::anyhow!("tx execution failed: {result:?}"));
        }

        let changes = state_changes_from_evm_state(&state);
        apply_evm_state_to_qmdb_changes(&mut qmdb_changes, &state);
        evm.db_mut().commit(state);
        tx_changes.push(changes);
    }

    let (db, _) = evm.finish();
    Ok((
        db,
        ExecutionOutcome {
            tx_changes,
            qmdb_changes,
        },
    ))
}

pub(crate) fn state_changes_from_evm_state(state: &EvmState) -> StateChanges {
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

pub(crate) fn apply_evm_state_to_qmdb_changes(changes: &mut QmdbChangeSet, state: &EvmState) {
    // Translate REVM's per-tx diff into a persistence-oriented QMDB delta.
    for (address, account) in state.iter() {
        if !account.is_touched() {
            continue;
        }
        let update = account_update_from_evm_account(account);
        changes.apply_update(*address, update);
    }
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

#[cfg(test)]
mod tests {
    use super::{
        evm_env, execute_txs, precompiles_with_seed, seed_precompile_address, tx_env_from_db,
    };
    use crate::domain::Tx;
    use alloy_evm::{
        eth::EthEvmBuilder,
        revm::{
            database::InMemoryDB,
            primitives::{Address, Bytes, B256, U256},
            state::AccountInfo,
            Database as _, DatabaseCommit as _,
        },
        Evm as _,
    };

    const HEIGHT: u64 = 1;
    const INITIAL_BALANCE: u64 = 1_000_000;
    const INITIAL_NONCE: u64 = 0;
    const TRANSFER_AMOUNT: u64 = 100;
    const GAS_LIMIT_TRANSFER: u64 = 21_000;
    const GAS_LIMIT_PRECOMPILE: u64 = 100_000;
    const GAS_LIMIT_CREATE: u64 = 500_000;
    const GAS_LIMIT_CALL: u64 = 200_000;
    const STATICCALL_GAS: u16 = 0xFFFF;
    const SEED_A_BYTES: [u8; 32] = [7u8; 32];
    const SEED_B_BYTES: [u8; 32] = [9u8; 32];
    const SENDER_BYTE: u8 = 0x11;
    const RECIPIENT_BYTE: u8 = 0x22;
    const SEED_OUTPUT_LEN: u8 = 32;
    const INIT_RUNTIME_OFFSET: u8 = 14;

    fn address_from_byte(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn fund_account(db: &mut InMemoryDB, address: Address, balance: u64, nonce: u64) {
        db.insert_account_info(
            address,
            AccountInfo {
                balance: U256::from(balance),
                nonce,
                ..Default::default()
            },
        );
    }

    fn account_nonce(db: &mut InMemoryDB, address: Address) -> u64 {
        db.basic(address)
            .unwrap()
            .map(|info| info.nonce)
            .unwrap_or(0)
    }

    fn transfer_tx(from: Address, to: Address, value: u64) -> Tx {
        Tx {
            from,
            to,
            value: U256::from(value),
            gas_limit: GAS_LIMIT_TRANSFER,
            data: Bytes::new(),
        }
    }

    fn build_seeded_evm(
        db: InMemoryDB,
        height: u64,
        seed: B256,
    ) -> alloy_evm::eth::EthEvm<
        InMemoryDB,
        alloy_evm::revm::inspector::NoOpInspector,
        alloy_evm::precompiles::PrecompilesMap,
    > {
        let env = evm_env(height, seed);
        let precompiles = precompiles_with_seed(env.cfg_env.spec);
        EthEvmBuilder::new(db, env).precompiles(precompiles).build()
    }

    #[test]
    fn execute_txs_transfers_value_and_increments_nonce() {
        // Arrange
        let sender = address_from_byte(SENDER_BYTE);
        let recipient = address_from_byte(RECIPIENT_BYTE);
        let seed = B256::from(SEED_A_BYTES);
        let mut db = InMemoryDB::default();
        fund_account(&mut db, sender, INITIAL_BALANCE, INITIAL_NONCE);
        let tx = transfer_tx(sender, recipient, TRANSFER_AMOUNT);

        // Act
        let (mut db, outcome) =
            execute_txs(db, evm_env(HEIGHT, seed), &[tx]).expect("execute transfer");

        // Assert
        assert_eq!(outcome.tx_changes.len(), 1);
        assert!(!outcome.tx_changes[0].is_empty());
        let sender_info = db.basic(sender).unwrap().unwrap();
        let recipient_info = db.basic(recipient).unwrap().unwrap();
        assert_eq!(
            sender_info.balance,
            U256::from(INITIAL_BALANCE - TRANSFER_AMOUNT)
        );
        assert_eq!(sender_info.nonce, 1);
        assert_eq!(recipient_info.balance, U256::from(TRANSFER_AMOUNT));
        assert_eq!(recipient_info.nonce, 0);
    }

    #[test]
    fn seed_precompile_returns_block_prevrandao() {
        use alloy_evm::revm::context_interface::result::ExecutionResult;

        // Arrange
        let caller = address_from_byte(SENDER_BYTE);
        let seed = B256::from(SEED_A_BYTES);
        let mut db = InMemoryDB::default();
        fund_account(&mut db, caller, INITIAL_BALANCE, INITIAL_NONCE);
        let mut evm = build_seeded_evm(db, HEIGHT, seed);
        let tx = Tx {
            from: caller,
            to: seed_precompile_address(),
            value: U256::ZERO,
            gas_limit: GAS_LIMIT_PRECOMPILE,
            data: Bytes::new(),
        };

        // Act
        let chain_id = evm.chain_id();
        let tx_env = tx_env_from_db(evm.db_mut(), &tx, chain_id).unwrap();
        let revm::context_interface::result::ResultAndState { result, state: _ } =
            evm.transact_raw(tx_env).unwrap();

        // Assert
        match result {
            ExecutionResult::Success { output, .. } => {
                assert_eq!(output.into_data().as_ref(), seed.as_slice());
            }
            other => panic!("unexpected execution result: {other:?}"),
        }
    }

    #[test]
    fn seed_reader_contract_reads_precompile_value() {
        use alloy_evm::revm::context_interface::result::{ExecutionResult, Output};

        // Arrange
        let caller = address_from_byte(SENDER_BYTE);
        let seed = B256::from(SEED_B_BYTES);
        let mut db = InMemoryDB::default();
        fund_account(&mut db, caller, INITIAL_BALANCE, INITIAL_NONCE);
        let mut evm = build_seeded_evm(db, HEIGHT, seed);

        let runtime = seed_reader_runtime();
        let init = seed_reader_init(&runtime);

        // Act (deploy contract)
        let create_nonce = account_nonce(evm.db_mut(), caller);

        let create = alloy_evm::revm::context::TxEnv {
            caller,
            kind: alloy_evm::revm::primitives::TxKind::Create,
            value: U256::ZERO,
            gas_limit: GAS_LIMIT_CREATE,
            data: init,
            nonce: create_nonce,
            chain_id: Some(evm.chain_id()),
            gas_price: 0,
            gas_priority_fee: None,
            ..Default::default()
        };

        let alloy_evm::revm::context_interface::result::ResultAndState {
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

        // Act (call deployed contract)
        let call_nonce = account_nonce(evm.db_mut(), caller);

        let call = alloy_evm::revm::context::TxEnv {
            caller,
            kind: alloy_evm::revm::primitives::TxKind::Call(deployed),
            value: U256::ZERO,
            gas_limit: GAS_LIMIT_CALL,
            data: Bytes::new(),
            nonce: call_nonce,
            chain_id: Some(evm.chain_id()),
            gas_price: 0,
            gas_priority_fee: None,
            ..Default::default()
        };

        let alloy_evm::revm::context_interface::result::ResultAndState {
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
        bytecode.extend_from_slice(&[
            0x60,
            SEED_OUTPUT_LEN,
            0x60,
            0x00,
            0x60,
            0x00,
            0x60,
            0x00,
            0x73,
        ]);
        bytecode.extend_from_slice(address.as_slice());
        bytecode.extend_from_slice(&[0x61]);
        bytecode.extend_from_slice(&STATICCALL_GAS.to_be_bytes());
        bytecode.extend_from_slice(&[0xFA, 0x50, 0x60, SEED_OUTPUT_LEN, 0x60, 0x00, 0xF3]);

        Bytes::from(bytecode)
    }

    fn seed_reader_init(runtime: &Bytes) -> Bytes {
        // Init program:
        // - copy runtime to memory[0..len)
        // - return memory[0..len)
        let runtime_len = runtime.len() as u16;
        let mut bytecode = Vec::new();
        bytecode.extend_from_slice(&[0x61]);
        bytecode.extend_from_slice(&runtime_len.to_be_bytes());
        bytecode.extend_from_slice(&[0x60, INIT_RUNTIME_OFFSET, 0x60, 0x00, 0x39, 0x61]);
        bytecode.extend_from_slice(&runtime_len.to_be_bytes());
        bytecode.extend_from_slice(&[0x60, 0x00, 0xf3]);
        bytecode.extend_from_slice(runtime.as_ref());
        Bytes::from(bytecode)
    }
}
