//! Libfuzzer-facing input for the marshal liveness targets.
//!
//! This samples the axes the marshal liveness harness actually uses, without
//! spending corpus bytes on unrelated simplex modes.

use super::MAX_REQUIRED;
use crate::{
    strategy::{HeaderMutation, StrategyChoice},
    utils::{Partition, SetPartition},
};
use arbitrary::Arbitrary;
use commonware_consensus::simplex::ForwardingPolicy;

const MIN_REQUIRED: u64 = 1;
const MAX_TWINS_ROUNDS: u8 = 6;
const MAX_TWINS_TRAILING_BLOCKS: u8 = 3;

fn sample_fault_rounds(
    u: &mut arbitrary::Unstructured<'_>,
    required_containers: u64,
) -> arbitrary::Result<(u64, u64)> {
    let fault_rounds_bound = u.int_in_range(1..=required_containers)?;
    let min_fault_rounds = crate::MIN_NUMBER_OF_FAULTS.min(fault_rounds_bound);
    let max_fault_rounds =
        (fault_rounds_bound / crate::FAULT_INJECTION_RATIO).max(min_fault_rounds);
    let fault_rounds = u.int_in_range(min_fault_rounds..=max_fault_rounds)?;
    Ok((fault_rounds, fault_rounds_bound))
}

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
                let (fault_rounds, fault_rounds_bound) =
                    sample_fault_rounds(u, required_containers)?;
                StrategyChoice::FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                }
            }
            _ => {
                let (fault_rounds, fault_rounds_bound) =
                    sample_fault_rounds(u, required_containers)?;
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

/// Input for the end-to-end standard-marshal Twins mutator.
#[derive(Debug, Clone)]
pub struct MarshalTwinsInput {
    /// Byte tape used by the deterministic runtime and scenario sampler.
    pub raw_bytes: Vec<u8>,
    /// Number of adversarial Twins rounds before the synchronous suffix.
    pub rounds: u8,
    /// Selects one fixed-Byzantine case from the sampled scenario set.
    pub case_selector: u8,
    /// Repeat one partition pattern across the adversarial prefix.
    pub sustained: bool,
    /// Byzantine message mutation strategy used by the secondary twin.
    pub strategy: StrategyChoice,
    /// Number of honest blocks required after the adversarial prefix.
    pub trailing_blocks: u8,
    /// Simplex forwarding policy used by every engine.
    pub forwarding: ForwardingPolicy,
}

impl Arbitrary<'_> for MarshalTwinsInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let rounds = u.int_in_range(1..=MAX_TWINS_ROUNDS)?;
        let case_selector = u.arbitrary()?;
        let sustained = u.arbitrary()?;
        let strategy = match u.int_in_range(0..=9)? {
            0 => StrategyChoice::AnyScope,
            1 => {
                let (fault_rounds, fault_rounds_bound) = sample_fault_rounds(u, rounds.into())?;
                StrategyChoice::FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                }
            }
            2 => {
                let (fault_rounds, fault_rounds_bound) = sample_fault_rounds(u, rounds.into())?;
                StrategyChoice::SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                }
            }
            // Header-scoped equivocation is this target's primary quarry. Keep
            // the known previous-parent attack heavily weighted while allowing
            // the campaign to explore other payload-preserving parent choices.
            _ => {
                let (fault_rounds, fault_rounds_bound) = sample_fault_rounds(u, rounds.into())?;
                let mutation = match u.int_in_range(0..=9)? {
                    0 => HeaderMutation::LastFinalizedParent,
                    1 => HeaderMutation::BeforeLastNotarizedParent,
                    _ => HeaderMutation::PreviousParent,
                };
                StrategyChoice::HeaderScope {
                    fault_rounds,
                    fault_rounds_bound,
                    mutation,
                }
            }
        };
        let trailing_blocks = u.int_in_range(1..=MAX_TWINS_TRAILING_BLOCKS)?;
        let forwarding = match u.int_in_range(0..=2)? {
            0 => ForwardingPolicy::Disabled,
            1 => ForwardingPolicy::SilentVoters,
            _ => ForwardingPolicy::SilentLeader,
        };
        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self {
            raw_bytes,
            rounds,
            case_selector,
            sustained,
            strategy,
            trailing_blocks,
            forwarding,
        })
    }
}
