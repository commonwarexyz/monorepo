//! Domain model types and commitment helpers for the REVM example.

mod commitment;
mod events;
mod types;

pub use commitment::{commit_state_root, AccountChange, StateChanges, StateChangesCfg};
pub(crate) use events::{LedgerEvent, LedgerEvents};
pub use types::{block_id, Block, BlockCfg, BlockId, BootstrapConfig, StateRoot, Tx, TxCfg, TxId};
