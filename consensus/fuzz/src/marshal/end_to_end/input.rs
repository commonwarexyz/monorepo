//! Libfuzzer-facing input for the marshal liveness targets.
//!
//! This samples the axes the marshal liveness harness actually uses, without
//! spending corpus bytes on unrelated simplex modes.

use super::{
    MAX_REQUIRED,
    scenario::{
        DropRule, MAX_ACTIONS, MAX_ADVANCE_MILLIS, MAX_LATENCY_MILLIS, PreGstAction, Role,
        ScenarioTemplate,
    },
};
use crate::{
    network::ByzantinePolicy,
    strategy::{HeaderMutation, StrategyChoice},
    utils::{Partition, SetPartition},
};
use arbitrary::Arbitrary;
use commonware_consensus::simplex::ForwardingPolicy;

const MIN_REQUIRED: u64 = 1;
pub(super) const MAX_TWINS_ROUNDS: u8 = 6;
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
pub struct MarshalDisrupterInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub degraded_network: bool,
    pub partition: Partition,
    pub strategy: StrategyChoice,
    pub forwarding: ForwardingPolicy,
}

impl Arbitrary<'_> for MarshalDisrupterInput {
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

fn role(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Role> {
    Ok(match u.int_in_range(0..=3)? {
        0 => Role::HolderA,
        1 => Role::Byzantine,
        2 => Role::HolderB,
        _ => Role::Victim,
    })
}

fn drop_rule(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<DropRule> {
    Ok(if u.int_in_range(0..=1)? == 0 {
        DropRule::HolderNotarizeSplit
    } else {
        DropRule::VictimNotarizationRebroadcast
    })
}

fn pre_gst_action(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<PreGstAction> {
    Ok(match u.int_in_range(0..=99)? {
        0..=29 => PreGstAction::AdvanceTime(u.int_in_range(0..=MAX_ADVANCE_MILLIS)?),
        30..=49 => PreGstAction::RemoveLink {
            from: role(u)?,
            to: role(u)?,
        },
        50..=74 => PreGstAction::SetLink {
            from: role(u)?,
            to: role(u)?,
            latency_ms: u.int_in_range(0..=MAX_LATENCY_MILLIS)?,
        },
        75..=87 => PreGstAction::EnableDrop(drop_rule(u)?),
        _ => PreGstAction::DisableDrop(drop_rule(u)?),
    })
}

/// Structured fuzz input for the Standard Marshal notarization/block-split
/// harness.
///
/// The template and the byzantine omissions are weighted so a minimal input
/// selects the split notarization/block wedge with every omission armed and no
/// generated action; larger inputs reshape the pre-GST topology, latency, drop
/// rules, byzantine behaviour and attack timing around it.
#[derive(Debug, Clone)]
pub struct NotarizationBlockSplitScenarioInput {
    /// Byte tape used by the deterministic runtime and the application's fault
    /// sampler.
    pub raw_bytes: Vec<u8>,
    /// The scripted scenario the pre-GST program starts from.
    pub template: ScenarioTemplate,
    /// Generated pre-GST steps, spliced into the template's stages.
    pub actions: Vec<PreGstAction>,
    /// Which of the byzantine node's omissions are armed.
    pub byzantine_policy: ByzantinePolicy,
    /// Simplex forwarding policy used by every engine.
    pub forwarding: ForwardingPolicy,
}

impl Arbitrary<'_> for NotarizationBlockSplitScenarioInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // The split-notarization wedge is this target's primary quarry, so it
        // stays the default and the heavily weighted template.
        let template = match u.int_in_range(0..=9)? {
            0..=6 => ScenarioTemplate::SplitNotarization,
            7..=8 => ScenarioTemplate::Connected,
            _ => ScenarioTemplate::Partitioned,
        };

        let action_count = u.int_in_range(0..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            actions.push(pre_gst_action(u)?);
        }

        // Every omission stays armed unless the input turns it off, so the
        // known attack survives mutation of the surrounding axes.
        let mut omission = || u.int_in_range(0..=9).map(|sample| sample != 9);
        let byzantine_policy = ByzantinePolicy {
            omit_future_notarize_votes: omission()?,
            ignore_inbound_notarize_votes: omission()?,
            omit_certificate_announcements: omission()?,
            omit_notarized_responses: omission()?,
        };

        // The attack needs the most aggressive forwarding policy to mean
        // anything: every correct node that certifies the attack view pushes
        // its block to the peers that did not vote for it, the victim included.
        let forwarding = match u.int_in_range(0..=9)? {
            0..=7 => ForwardingPolicy::SilentVoters,
            8 => ForwardingPolicy::SilentLeader,
            _ => ForwardingPolicy::Disabled,
        };

        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = u.bytes(remaining)?.to_vec();

        Ok(Self {
            raw_bytes,
            template,
            actions,
            byzantine_policy,
            forwarding,
        })
    }
}

/// Input for the end-to-end marshal Twins mutators.
#[derive(Debug, Clone)]
pub struct MarshalTwinsInput {
    /// Byte tape used by the deterministic runtime and scenario sampler.
    ///
    /// General Twins targets reserve the final byte for stack selection.
    /// Focused regression targets use the complete tape.
    pub raw_bytes: Vec<u8>,
    /// Number of adversarial Twins rounds before the synchronous suffix.
    pub rounds: u8,
    /// Selects one case from the sampled Twins scenario set.
    pub case_selector: u16,
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
