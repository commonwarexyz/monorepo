//! REVM-based example chain driven by threshold-simplex.
//!
//! This example uses `alloy-evm` as the integration layer above `revm` and keeps the execution
//! backend generic over the database trait boundary (`Database` + `DatabaseCommit`).

mod commitment;
mod consensus;
mod application;
mod execution;
mod sim;
mod types;

pub use commitment::{commit_state_root, StateChanges};
pub use consensus::{ConsensusDigest, PublicKey};
pub use execution::{evm_env, execute_txs, ExecutionOutcome, CHAIN_ID};
pub use sim::{simulate, SimConfig, SimOutcome};
pub use types::{block_id, Block, BlockId, StateRoot, Tx, TxId};
