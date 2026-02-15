//! Deterministic demo scenario for the simulation.
//!
//! The example chain "prefunds" two addresses and injects a single transfer at height 1.

use alloy_evm::revm::primitives::{Address, Bytes as EvmBytes, U256};

#[derive(Clone, Debug)]
pub(super) struct DemoTransfer {
    pub(super) from: Address,
    pub(super) to: Address,
    pub(super) alloc: Vec<(Address, U256)>,
    pub(super) tx: crate::Tx,
    pub(super) expected_from: U256,
    pub(super) expected_to: U256,
}

impl DemoTransfer {
    pub(super) fn new() -> Self {
        let from = Address::from([0x11u8; 20]);
        let to = Address::from([0x22u8; 20]);
        let tx = crate::Tx {
            from,
            to,
            value: U256::from(100u64),
            gas_limit: 21_000,
            data: EvmBytes::new(),
        };

        Self {
            from,
            to,
            alloc: vec![(from, U256::from(1_000_000u64)), (to, U256::ZERO)],
            tx,
            expected_from: U256::from(1_000_000u64 - 100),
            expected_to: U256::from(100u64),
        }
    }
}
