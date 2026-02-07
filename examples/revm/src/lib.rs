//! REVM-based example chain driven by threshold-simplex.
//!
//! This example uses `alloy-evm` as the integration layer above `revm` and keeps the execution
//! backend generic over the database trait boundary (`Database` + `DatabaseCommit`).

mod application;
mod domain;
mod qmdb;
mod simulation;

pub use application::execution::{
    evm_env, execute_txs, seed_precompile_address, ExecutionOutcome, CHAIN_ID,
    SEED_PRECOMPILE_ADDRESS_BYTES,
};
pub use domain::{
    block_id, AccountChange, Block, BlockCfg, BlockContext, BlockId, BootstrapConfig, StateChanges,
    StateChangesCfg, StateRoot, Tx, TxCfg, TxId,
};
pub use simulation::{simulate, SimConfig, SimOutcome};

pub type ConsensusDigest = commonware_cryptography::sha256::Digest;
pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub(crate) type FinalizationEvent = (u32, ConsensusDigest);
