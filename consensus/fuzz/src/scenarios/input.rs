//! Libfuzzer-facing input for the scenario-based marshal target.
//!
//! A minimal input selects the scenario in the adversarial `N4F1C3` config
//! with a connected network; larger inputs pick the honest `N4F0C4` config and
//! reshape the pre-GST topology, byzantine strategy, and forwarding around it.

use crate::{
    Configuration, N4F0C4, N4F1C3,
    utils::{Partition, SetPartition},
};
use arbitrary::Arbitrary;
use commonware_consensus::{marshal::mocks::harness::BLOCKS_PER_EPOCH, simplex::ForwardPolicy};

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

/// The concrete scenario a run replays as its prefix. Each variant names an
/// authoritative `consensus/src/marshal` test it faithfully reproduces.
#[derive(Arbitrary, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioKind {
    /// `test_standard_certify_missing_candidate_fetches_by_round`, composed
    /// with the engines through certification recovery from a seeded voter
    /// journal (see `scenarios.rs`).
    StandardCertifyMissingCandidateFetchesByRound,
    /// `test_standard_certify_first_block_fetches_genesis_parent`: the
    /// verified height-1 candidate certifies against the genesis parent with
    /// no fetch, and the engines start bare from the genesis floor
    /// (see `scenarios.rs`).
    StandardCertifyFirstBlockFetchesGenesisParent,
    /// `test_standard_verify_height_lie_parent_fetch_is_round_bound`: the
    /// victim verifies a height-lying child whose parent fetch must be bound
    /// to the parent's round, never derived from the claimed height, and the
    /// engines start bare from the genesis floor with that fetch still
    /// outstanding (see `scenarios.rs`).
    StandardVerifyHeightLieParentFetchIsRoundBound,
    /// `test_standard_certify_bumps_notarized_fetch_for_pending_verify`: a
    /// `verify` still pending when `certify` arrives is taken as certify's
    /// gate, and certify bumps exactly one round-bound notarized fetch that
    /// resolves through the armed delivery; the engines recover the
    /// fabricated notarization from their seeded voter journals
    /// (see `scenarios.rs`).
    StandardCertifyBumpsNotarizedFetchForPendingVerify,
    /// `test_standard_verify_missing_candidate_waits_without_fetching`: a
    /// `verify` of an unknown digest waits locally and issues no fetch at
    /// all, and dropping the verify receiver cancels the wait without
    /// converting it into a fetch; the engines start bare from the genesis
    /// floor with the fetch multiset explicitly empty (see `scenarios.rs`).
    StandardVerifyMissingCandidateWaitsWithoutFetching,
    /// `test_standard_get_block_by_height_and_latest`: the victim finalizes
    /// three blocks through the proposed-then-finalized flow, each height and
    /// the latest query map to its block, and the engines start from the
    /// height-3 finalized floor with no fetch issued (see `scenarios.rs`).
    StandardGetBlockByHeightAndLatest,
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
    pub forwarding: ForwardPolicy,
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
            0 => ForwardPolicy::Disabled,
            1 => ForwardPolicy::SilentVoters,
            _ => ForwardPolicy::SilentLeader,
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
