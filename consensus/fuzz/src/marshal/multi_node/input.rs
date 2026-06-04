//! Libfuzzer-facing input for the marshal liveness targets.
//!
//! This samples the axes the marshal liveness harness actually uses, without
//! spending corpus bytes on unrelated simplex modes.

use crate::{
    strategy::StrategyChoice,
    utils::{Partition, SetPartition},
};
use arbitrary::Arbitrary;
use commonware_consensus::{marshal::mocks::harness::BLOCKS_PER_EPOCH, simplex::ForwardingPolicy};

const MIN_REQUIRED: u64 = 1;
const MAX_REQUIRED: u64 = BLOCKS_PER_EPOCH.get() - 1;

#[derive(Debug, Clone)]
pub struct MarshalLivenessInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub degraded_network: bool,
    pub partition: Partition,
    pub strategy: StrategyChoice,
    pub forwarding: ForwardingPolicy,
}

impl Arbitrary<'_> for MarshalLivenessInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let partition = match u.int_in_range(0..=99)? {
            0..=49 => Partition::Connected,
            _ => Partition::Static(SetPartition::n4(u.int_in_range(1..=14)?)),
        };

        let degraded_network = partition == Partition::Connected && u.int_in_range(0..=9)? == 0;
        let required_containers = u.int_in_range(MIN_REQUIRED..=MAX_REQUIRED)?;

        let strategy = match u.int_in_range(0..=9)? {
            0 => StrategyChoice::AnyScope,
            1 => {
                let fault_rounds_bound = u.int_in_range(1..=required_containers)?;
                let min_fault_rounds = crate::MIN_NUMBER_OF_FAULTS.min(fault_rounds_bound);
                let max_fault_rounds =
                    (fault_rounds_bound / crate::FAULT_INJECTION_RATIO).max(min_fault_rounds);
                let fault_rounds = u.int_in_range(min_fault_rounds..=max_fault_rounds)?;
                StrategyChoice::FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                }
            }
            _ => {
                let fault_rounds_bound = u.int_in_range(1..=required_containers)?;
                let min_fault_rounds = crate::MIN_NUMBER_OF_FAULTS.min(fault_rounds_bound);
                let max_fault_rounds =
                    (fault_rounds_bound / crate::FAULT_INJECTION_RATIO).max(min_fault_rounds);
                let fault_rounds = u.int_in_range(min_fault_rounds..=max_fault_rounds)?;
                StrategyChoice::SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                }
            }
        };

        let forwarding = match u.int_in_range(0..=2)? {
            0 => ForwardingPolicy::Disabled,
            1 => ForwardingPolicy::SilentVoters,
            _ => ForwardingPolicy::SilentLeader,
        };

        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = u.bytes(remaining)?.to_vec();

        Ok(Self {
            raw_bytes,
            required_containers,
            degraded_network,
            partition,
            strategy,
            forwarding,
        })
    }
}
