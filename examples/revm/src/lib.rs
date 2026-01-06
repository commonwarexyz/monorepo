//! REVM-based example chain driven by threshold-simplex.
//!
//! This example uses `alloy-evm` as the integration layer above `revm` and keeps the execution
//! backend generic over the database trait boundary (`Database` + `DatabaseCommit`).

mod application;
mod commitment;
mod execution;
mod qmdb;
mod sim;
mod types;

pub use commitment::{commit_state_root, StateChanges};
pub use execution::{
    evm_env, execute_txs, seed_precompile_address, ExecutionOutcome, CHAIN_ID,
    SEED_PRECOMPILE_ADDRESS_BYTES,
};
pub use sim::{simulate, SimConfig, SimOutcome};
pub use types::{block_id, Block, BlockId, StateRoot, Tx, TxId};

pub type ConsensusDigest = commonware_cryptography::sha256::Digest;
pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub(crate) type FinalizationEvent = (u32, ConsensusDigest);
