//! Libfuzzer-facing input for the scenario-based marshal target.
//!
//! A minimal input selects the first scenario in the adversarial `N4F1C3` config
//! with a connected network; larger inputs pick other scenarios, the honest
//! `N4F0C4` config, and reshape the pre-GST topology, byzantine strategy, and
//! forwarding around them.

use crate::{
    Configuration, N4F0C4, N4F1C3,
    utils::{Partition, SetPartition},
};
use arbitrary::Arbitrary;
use commonware_consensus::{marshal::mocks::harness::BLOCKS_PER_EPOCH, simplex::ForwardingPolicy};

const MIN_REQUIRED: u64 = 1;
/// Highest fresh block height this single-epoch harness can require.
const MAX_REQUIRED: u64 = BLOCKS_PER_EPOCH.get() - 1;

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

/// The concrete scenario a run replays as its prefix.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioKind {
    MissingCandidate,
    FinalizationWithoutBlock,
    SubscribeBeforeBlock,
    SameHeightDifferentViews,
    PendingFloorAnchor,
    ByzantineParentEquivocation,
    ConflictingVerifyNoCertPoison,
    EquivocatedBlockPersists,
    ConflictingProposalsBothAck,
    HeightLieParentFetch,
    InternalMissingFinalizedBlock,
    MultipleTrailingGaps,
    LargePendingTip,
    FloorRepairsGapAfterAnchor,
    NewerFloorSupersedesOlder,
    DeferredCertifyFallback,
    FirstBlockFetchesGenesisParent,
}

/// How the byzantine leader disseminates its attack-view block on channels 2 + 3.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockFault {
    /// Announce a notarize but never gossip the block.
    Omit,
    /// Gossip the block to every honest node but one (which must fetch it).
    Partition,
    /// Gossip two conflicting blocks to disjoint honest sets.
    Equivocate,
}

/// How the byzantine node answers marshal backfill requests on channel 1.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillFault {
    /// Accept requests but never answer them.
    Withhold,
    /// Answer with a protocol error, forcing an immediate re-fetch.
    ServeError,
    /// Answer notarized-block requests with a well-formed quorum notarization over
    /// an unavailable payload paired with a mismatched block: verifies as a
    /// certificate but is rejected on the commitment check, and never finalizable.
    Poison,
}

/// The byzantine node's behavior on the consensus channels (vote 3, cert 4,
/// resolver 5): `Corrupt` runs the Simplex disrupter; `Silent` leaves the
/// channels dead (crash-silence), so inbound traffic is discarded and the node
/// emits nothing beyond the dissemination-layer leader announce.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusMutation {
    Corrupt,
    Silent,
}

/// Independently-enabled per-layer faults for the adversary: a
/// dissemination-layer disrupter on channels 1 + 2 (always run) and a
/// Simplex-layer Disrupter on channels 3/4/5, run only under
/// [`ConsensusMutation::Corrupt`] (a `SmallScope` whose density is set by the
/// run's `fault_rounds`/`fault_rounds_bound`); `Silent` leaves those channels
/// dead.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    /// Block-dissemination fault on channels 2 + 3.
    pub block_fault: BlockFault,
    /// Backfill fault on channel 1.
    pub backfill: BackfillFault,
    /// Consensus mutation on channels 3/4/5.
    pub consensus: ConsensusMutation,
}

#[derive(Debug, Clone)]
pub struct MarshalScenarioPrefixInput {
    pub raw_bytes: Vec<u8>,
    pub scenario: ScenarioKind,
    /// The cluster configuration: `N4F0C4` (honest) or `N4F1C3` (node 0 byzantine).
    pub config: Configuration,
    pub fault_plan: FaultPlan,
    /// Fault-density parameters for the Simplex disrupter's `SmallScope` (wrapped
    /// by `LiveScope` so it faults live views above the floor).
    pub fault_rounds: u64,
    pub fault_rounds_bound: u64,
    pub required_containers: u64,
    pub degraded_network: bool,
    pub partition: Partition,
    pub forwarding: ForwardingPolicy,
}

impl Arbitrary<'_> for MarshalScenarioPrefixInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let scenario = ScenarioKind::arbitrary(u)?;
        let config = match u.int_in_range(0..=1)? {
            0 => N4F1C3,
            _ => N4F0C4,
        };
        let fault_plan = FaultPlan::arbitrary(u)?;

        let partition = match u.int_in_range(0..=99)? {
            0..=49 => Partition::Connected,
            _ => Partition::Static(SetPartition::n4(u.int_in_range(1..=14)?)),
        };
        let degraded_network = partition == Partition::Connected && u.int_in_range(0..=9)? == 0;
        let required_containers = u.int_in_range(MIN_REQUIRED..=MAX_REQUIRED)?;

        let (fault_rounds, fault_rounds_bound) = sample_fault_rounds(u, required_containers)?;

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
            scenario,
            config,
            fault_plan,
            fault_rounds,
            fault_rounds_bound,
            required_containers,
            degraded_network,
            partition,
            forwarding,
        })
    }
}
