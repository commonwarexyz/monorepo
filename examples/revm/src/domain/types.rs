//! Canonical types and encodings for the example chain.
//!
//! The example uses `commonware-codec` for deterministic, bounded decoding of untrusted bytes.
//!
//! - `BlockId` is `keccak256(Encode(Block))`.
//! - Consensus orders `ConsensusDigest = sha256(BlockId)` (the block's `Committable`).
//! - `StateRoot` is a 32-byte commitment over merkleized, non-durable QMDB partition roots.

use alloy_evm::revm::primitives::{Address, U256};

mod block;
mod ids;
mod tx;

#[cfg(test)]
mod tests;

pub type BlockContext =
    commonware_consensus::simplex::types::Context<crate::ConsensusDigest, crate::PublicKey>;

pub(crate) use block::genesis_context;
pub use block::{block_id, Block, BlockCfg};
pub use ids::{BlockId, StateRoot, TxId};
pub use tx::{Tx, TxCfg};

#[derive(Clone, Debug)]
/// Genesis allocation plus bootstrap transactions applied before consensus starts.
///
/// # Examples
/// ```no_run
/// use alloy_evm::revm::primitives::{Address, Bytes, U256};
/// use commonware_revm::{BootstrapConfig, Tx};
///
/// let from = Address::from([0x11u8; 20]);
/// let to = Address::from([0x22u8; 20]);
/// let tx = Tx {
///     from,
///     to,
///     value: U256::from(100u64),
///     gas_limit: 21_000,
///     data: Bytes::new(),
/// };
/// let bootstrap = BootstrapConfig::new(vec![(from, U256::from(1_000_000u64))], vec![tx]);
/// # let _ = bootstrap;
/// ```
pub struct BootstrapConfig {
    /// Genesis allocation applied before consensus starts.
    pub genesis_alloc: Vec<(Address, U256)>,
    /// Transactions to submit before consensus starts.
    pub bootstrap_txs: Vec<Tx>,
}

impl BootstrapConfig {
    pub const fn new(genesis_alloc: Vec<(Address, U256)>, bootstrap_txs: Vec<Tx>) -> Self {
        Self {
            genesis_alloc,
            bootstrap_txs,
        }
    }
}
