//! Domain model types and deterministic state-change helpers for the REVM example.

mod commitment;
mod events;
mod types;

pub use commitment::{AccountChange, StateChanges, StateChangesCfg};
pub(crate) use events::{LedgerEvent, LedgerEvents};
pub(crate) use types::genesis_context;
pub use types::{
    block_id, Block, BlockCfg, BlockContext, BlockId, BootstrapConfig, StateRoot, Tx, TxCfg, TxId,
};
