//! Twins framework scenario generator and executor helpers.
//!
//! This module follows the testing architecture from
//! [Twins: BFT Systems Made Robust](https://arxiv.org/pdf/2004.10617):
//! 1. Generate partition scenarios.
//! 2. Combine partitions with leader assignments per round.
//! 3. Arrange those round choices into full multi-round scenarios.
//! 4. Execute each scenario across compromised-node assignments.
//!
//! Scenarios are generated in a canonical unlabeled form instead of by
//! enumerating every participant relabeling. The generator tracks participant
//! symmetry classes as `cells`, where each cell is a group of participants that
//! have been indistinguishable across all attack rounds generated so far.
//! Advancing one round refines those cells by splitting each group according to
//! the role its members take in the new round.
//!
//! `cases()` can then either emit those canonical scenarios directly or map each
//! one onto a concrete participant permutation derived from the case seed,
//! depending on [`Framework::relabel`]. In both modes, cases are cross-producted
//! with concrete compromised-node sets. That keeps the scenario budget focused
//! on distinct shapes while still allowing concrete player assignments to be
//! exercised when desired.

use crate::{
    simplex::elector::{Config as ElectorConfig, Elector as Elected},
    types::{Participant, Round, View},
};
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::simulated::SplitTarget;
use commonware_utils::{ordered::Set, rng::mix64, test_rng_seeded};
use rand::{rngs::StdRng, Rng};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

/// Keeps case seeds off the raw framework seed, including the `(0, 0)` fixed point.
const CASE_SEED_DOMAIN: u64 = 0x8f36_d01c_4ea8_9b27;
/// Separates compromised-set sampling from scenario generation.
const COMPROMISED_SET_DOMAIN: u64 = 0x0000_0000_dead_beef;
/// Separates participant relabeling from the raw case seed stream.
const RELABEL_ASSIGNMENT_DOMAIN: u64 = 0x0000_0000_a11c_e55e;

/// Per-round adversarial setting from the Twins framework.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoundScenario {
    // Participant index chosen to lead this round.
    leader: usize,
    // Bitmasks selecting which participant indices each twin half can reach.
    primary_mask: u64,
    secondary_mask: u64,
}

impl RoundScenario {
    /// Returns the designated leader index for this round scenario.
    pub const fn leader(self) -> usize {
        self.leader
    }
}

/// Multi-round scenario from the Twins framework.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scenario {
    rounds: Vec<RoundScenario>,
}

impl Scenario {
    /// Returns the round scenarios in this scenario.
    pub fn rounds(&self) -> &[RoundScenario] {
        &self.rounds
    }

    /// Returns recipients for each twin half at a given view.
    ///
    /// Views after the configured adversarial rounds use full synchrony
    /// (`all -> all`) to model eventual synchrony for liveness checks.
    pub fn partitions<P: Clone>(&self, view: View, participants: &[P]) -> (Vec<P>, Vec<P>) {
        let idx = view.get().saturating_sub(1) as usize;
        if let Some(round) = self.rounds.get(idx) {
            return masks_to_partitions(round.primary_mask, round.secondary_mask, participants);
        }
        (participants.to_vec(), participants.to_vec())
    }

    /// Routes a message from sender to the correct twin half at a given view.
    ///
    /// Unlike [`partitions`](Self::partitions), this avoids allocating temporary
    /// Vecs by comparing bitmasks directly for inbound twin traffic.
    pub fn route<P: PartialEq>(&self, view: View, sender: &P, participants: &[P]) -> SplitTarget {
        let idx = view.get().saturating_sub(1) as usize;
        if let Some(round) = self.rounds.get(idx) {
            let sender_idx = participants
                .iter()
                .position(|participant| participant == sender)
                .expect("sender missing from runtime participant list");
            let bit = 1u64 << sender_idx;
            let in_primary = (round.primary_mask & bit) != 0;
            let in_secondary = (round.secondary_mask & bit) != 0;
            return match (in_primary, in_secondary) {
                (true, true) => SplitTarget::Both,
                (true, false) => SplitTarget::Primary,
                (false, true) => SplitTarget::Secondary,
                (false, false) => SplitTarget::None,
            };
        }
        // After attack rounds, both halves see everyone.
        SplitTarget::Both
    }
}

/// Routes a sender according to explicit primary and secondary groups.
fn route_with_groups<P: PartialEq>(sender: &P, primary: &[P], secondary: &[P]) -> SplitTarget {
    let in_primary = primary.contains(sender);
    let in_secondary = secondary.contains(sender);
    match (in_primary, in_secondary) {
        (true, true) => SplitTarget::Both,
        (true, false) => SplitTarget::Primary,
        (false, true) => SplitTarget::Secondary,
        (false, false) => SplitTarget::None,
    }
}

/// Splits participants at index `view % n`.
pub fn view_partitions<P: Clone>(view: View, participants: &[P]) -> (Vec<P>, Vec<P>) {
    let split = (view.get() as usize) % participants.len();
    let (primary, secondary) = participants.split_at(split);
    (primary.to_vec(), secondary.to_vec())
}

/// Routes a sender according to [`view_partitions`].
pub fn view_route<P: Clone + PartialEq>(view: View, sender: &P, participants: &[P]) -> SplitTarget {
    let (primary, secondary) = view_partitions(view, participants);
    route_with_groups(sender, &primary, &secondary)
}

/// Twins leader-election config that follows scripted scenario leaders before
/// delegating to a fallback elector.
#[derive(Clone, Debug)]
pub struct Elector<C> {
    fallback: C,
    round_leaders: Arc<[Participant]>,
}

impl<C: Default> Default for Elector<C> {
    fn default() -> Self {
        Self {
            fallback: C::default(),
            round_leaders: Arc::from(Vec::new()),
        }
    }
}

impl<C> Elector<C> {
    /// Create a twins elector from a scenario and fallback elector.
    pub fn new(fallback: C, scenario: &Scenario, participants: usize) -> Self {
        let round_leaders: Vec<_> = scenario
            .rounds()
            .iter()
            .map(|round| {
                assert!(
                    round.leader() < participants,
                    "scenario leader out of bounds"
                );
                Participant::new(round.leader() as u32)
            })
            .collect();
        Self {
            fallback,
            round_leaders: Arc::from(round_leaders),
        }
    }
}

/// Initialized twins leader elector built from [`Elector`].
#[derive(Clone, Debug)]
pub struct ElectorState<E> {
    fallback: E,
    round_leaders: Arc<[Participant]>,
}

impl<S, C> ElectorConfig<S> for Elector<C>
where
    S: Scheme,
    C: ElectorConfig<S>,
{
    type Elector = ElectorState<C::Elector>;

    fn build(self, participants: &Set<S::PublicKey>) -> Self::Elector {
        ElectorState {
            fallback: self.fallback.build(participants),
            round_leaders: self.round_leaders,
        }
    }
}

impl<S, E> Elected<S> for ElectorState<E>
where
    S: Scheme,
    E: Elected<S>,
{
    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant {
        let idx = round.view().get().saturating_sub(1) as usize;
        if let Some(&leader) = self.round_leaders.get(idx) {
            return leader;
        }

        // After the scripted attack prefix, intentionally resume the caller's
        // fallback elector rather than forcing an honest-only suffix. Twins
        // campaigns should not prevent the protocol from timing out in
        // later views (if a twin is elected).
        self.fallback.elect(round, certificate)
    }
}

/// Framework configuration for generating Twins cases.
#[derive(Clone, Copy, Debug)]
pub struct Framework {
    /// Number of participants in the network.
    pub participants: usize,
    /// Number of compromised participants.
    pub faults: usize,
    /// Number of adversarial rounds before synchronous suffix.
    pub rounds: usize,
    /// Maximum number of partitions to use while generating partition scenarios.
    pub max_partitions: usize,
    /// Maximum number of generated scenarios.
    pub max_scenarios: usize,
    /// Maximum number of generated compromised-node sets.
    pub max_compromised_sets: usize,
    /// Whether to relabel canonical scenarios onto concrete participant
    /// permutations before emitting executable cases.
    pub relabel: bool,
}

/// Executable case from the Twins framework.
#[derive(Clone, Debug)]
pub struct Case {
    /// Compromised participant indices for this case.
    pub compromised: Vec<usize>,
    /// Multi-round scenario for this case.
    pub scenario: Scenario,
    /// Deterministic seed used for this case.
    pub seed: u64,
}

/// Generate executable Twins cases from framework parameters.
///
/// Scenario generation first collapses participant relabelings into canonical
/// unlabeled scenario shapes. Depending on [`Framework::relabel`], each case
/// then either emits that canonical shape directly or deterministically
/// relabels it onto a concrete participant permutation before combining it
/// with a concrete compromised-node assignment.
pub fn cases(seed: u64, framework: Framework) -> Vec<Case> {
    assert!(framework.participants > 1, "participants must be > 1");
    assert!(
        framework.participants <= u64::BITS as usize,
        "participants must fit in u64 masks"
    );
    assert!(framework.faults > 0, "faults must be > 0");
    assert!(
        framework.faults < framework.participants,
        "faults must be less than participants"
    );
    assert!(framework.rounds > 0, "rounds must be > 0");
    assert!(framework.max_partitions > 1, "max_partitions must be > 1");
    assert!(
        framework.max_partitions <= framework.participants,
        "max_partitions must be <= participants"
    );
    assert!(framework.max_scenarios > 0, "max_scenarios must be > 0");
    assert!(
        framework.max_compromised_sets > 0,
        "max_compromised_sets must be > 0"
    );

    let scenarios = generate_scenarios(
        seed,
        framework.participants,
        framework.rounds,
        framework.max_partitions,
        framework.max_scenarios,
    );
    let compromised = compromised_sets(
        seed ^ COMPROMISED_SET_DOMAIN,
        framework.participants,
        framework.faults,
        framework.max_compromised_sets,
    );

    let mut out = Vec::new();
    for (compromised_idx, compromised) in compromised.iter().enumerate() {
        for (scenario_idx, scenario) in scenarios.iter().enumerate() {
            let case_seed = derive_case_seed(seed, compromised_idx, scenario_idx, scenarios.len());
            out.push(Case {
                compromised: compromised.clone(),
                scenario: if framework.relabel {
                    let permutation = assignment_from_seed(
                        case_seed ^ RELABEL_ASSIGNMENT_DOMAIN,
                        framework.participants,
                    );
                    permute_scenario(scenario, &permutation)
                } else {
                    scenario.clone()
                },
                seed: case_seed,
            });
        }
    }
    out
}

/// Materializes the participants selected by a bitmask.
fn partition_for_mask<P: Clone>(mask: u64, participants: &[P]) -> Vec<P> {
    let mut group = Vec::new();
    for (idx, participant) in participants.iter().enumerate() {
        if (mask & (1u64 << idx)) != 0 {
            group.push(participant.clone());
        }
    }
    group
}

/// Converts twins routing bitmasks into concrete participant groups.
fn masks_to_partitions<P: Clone>(
    primary_mask: u64,
    secondary_mask: u64,
    participants: &[P],
) -> (Vec<P>, Vec<P>) {
    let primary = partition_for_mask(primary_mask, participants);
    let secondary = partition_for_mask(secondary_mask, participants);
    (primary, secondary)
}

/// Applies a participant permutation to a routing bitmask.
fn permute_mask(mask: u64, permutation: &[usize]) -> u64 {
    let mut permuted = 0u64;
    for (participant, &mapped) in permutation.iter().enumerate() {
        if (mask & (1u64 << participant)) != 0 {
            permuted |= 1u64 << mapped;
        }
    }
    permuted
}

/// Applies a participant permutation to every round in a scenario.
fn permute_scenario(scenario: &Scenario, permutation: &[usize]) -> Scenario {
    assert!(
        scenario
            .rounds
            .iter()
            .all(|round| round.leader < permutation.len()),
        "permutation must cover the scenario participants"
    );
    Scenario {
        rounds: scenario
            .rounds
            .iter()
            .map(|round| RoundScenario {
                leader: permutation[round.leader],
                primary_mask: permute_mask(round.primary_mask, permutation),
                secondary_mask: permute_mask(round.secondary_mask, permutation),
            })
            .collect(),
    }
}

/// Derives a deterministic participant permutation from a case seed.
fn assignment_from_seed(seed: u64, n: usize) -> Vec<usize> {
    let mut rng = test_rng_seeded(seed);
    let mut assignment: Vec<_> = (0..n).collect();
    for idx in (1..n).rev() {
        assignment.swap(idx, rng.gen_range(0..=idx));
    }
    assignment
}

/// Returns a contiguous bitmask range `[start, start + len)`.
const fn range_mask(start: usize, len: usize) -> u64 {
    if len == 0 {
        return 0;
    }
    (((1u128 << len) - 1) << start) as u64
}

/// Converts cell sizes into contiguous index ranges.
fn cells_to_ranges(cells: &[usize]) -> Vec<(usize, usize)> {
    let mut start = 0usize;
    cells
        .iter()
        .copied()
        .map(|size| {
            let range = (start, size);
            start += size;
            range
        })
        .collect()
}

/// Enumerates all canonical next-round refinements from the current cell state.
fn next_round_transitions(
    cells: &[usize],
    max_partitions: usize,
) -> Vec<(RoundScenario, Vec<usize>)> {
    // Accumulated state for a round where the secondary partition differs:
    // the masks built so far, whether any secondary members exist, and leader.
    #[derive(Clone, Copy)]
    struct SecondaryState {
        primary_mask: u64,
        secondary_mask: u64,
        secondary_total: usize,
        leader: Option<usize>,
    }

    /// Refines cells for a round where primary and secondary coincide.
    fn no_secondary(
        ranges: &[(usize, usize)],
        leader_cell: usize,
        cell_idx: usize,
        primary_mask: u64,
        leader: Option<usize>,
        next_cells: &mut Vec<usize>,
        out: &mut Vec<(RoundScenario, Vec<usize>)>,
    ) {
        if cell_idx == ranges.len() {
            // Primary and secondary coincide in this branch, so the round is
            // fully described by a single mask.
            out.push((
                RoundScenario {
                    leader: leader.expect("leader cell should assign a leader"),
                    primary_mask,
                    secondary_mask: primary_mask,
                },
                next_cells.clone(),
            ));
            return;
        }

        let (start, size) = ranges[cell_idx];
        // The designated leader must be isolated into its own singleton cell,
        // so the leader's source cell can contribute at most `size - 1`
        // non-leader members to the ordinary partition buckets.
        let max_outside = if cell_idx == leader_cell {
            size - 1
        } else {
            size
        };
        for outside in 0..=max_outside {
            // Within a cell we keep participants contiguous in canonical role
            // order: excluded from both partitions first, then shared by both
            // halves, and finally the leader singleton (if this is the leader
            // cell). `next_cells` records those refined cell sizes.
            let both = if cell_idx == leader_cell {
                size - outside - 1
            } else {
                size - outside
            };

            if outside > 0 {
                next_cells.push(outside);
            }
            if both > 0 {
                next_cells.push(both);
            }

            let mut next_primary = primary_mask | range_mask(start + outside, both);
            let mut next_leader = leader;
            if cell_idx == leader_cell {
                // Place the leader at the end of its refined block so later
                // rounds can distinguish it from the rest of the cell.
                let leader_idx = start + outside + both;
                next_primary |= 1u64 << leader_idx;
                next_cells.push(1);
                next_leader = Some(leader_idx);
            }

            no_secondary(
                ranges,
                leader_cell,
                cell_idx + 1,
                next_primary,
                next_leader,
                next_cells,
                out,
            );

            // Backtrack in reverse push order before exploring the next split.
            if cell_idx == leader_cell {
                next_cells.pop();
            }
            if both > 0 {
                next_cells.pop();
            }
            if outside > 0 {
                next_cells.pop();
            }
        }
    }

    /// Refines cells for a round with a distinct secondary partition.
    fn with_secondary(
        ranges: &[(usize, usize)],
        max_partitions: usize,
        leader_cell: usize,
        cell_idx: usize,
        state: SecondaryState,
        next_cells: &mut Vec<usize>,
        out: &mut Vec<(RoundScenario, Vec<usize>)>,
    ) {
        if cell_idx == ranges.len() {
            if state.secondary_total == 0 {
                // A zero-sized secondary partition is already emitted by
                // `no_secondary`, so skipping it here avoids duplicates.
                return;
            }
            out.push((
                RoundScenario {
                    leader: state.leader.expect("leader cell should assign a leader"),
                    primary_mask: state.primary_mask,
                    secondary_mask: state.secondary_mask,
                },
                next_cells.clone(),
            ));
            return;
        }

        let (start, size) = ranges[cell_idx];
        let has_leader = cell_idx == leader_cell;
        let available = if has_leader { size - 1 } else { size };
        // `max_partitions == 2` forbids an "outside both halves" bucket, so the
        // cell may only split between secondary and primary in that mode.
        let outside_range = if max_partitions == 2 {
            0..=0
        } else {
            0..=available
        };

        for outside in outside_range {
            let remaining = available - outside;
            for secondary in 0..=remaining {
                // The canonical contiguous layout for a refined cell is:
                // outside -> secondary-only -> primary-only -> leader.
                let primary = remaining - secondary;

                if outside > 0 {
                    next_cells.push(outside);
                }
                if secondary > 0 {
                    next_cells.push(secondary);
                }
                if primary > 0 {
                    next_cells.push(primary);
                }

                let next_secondary = state.secondary_mask | range_mask(start + outside, secondary);
                let next_primary =
                    state.primary_mask | range_mask(start + outside + secondary, primary);
                let mut next_leader = state.leader;
                if has_leader {
                    // As in `no_secondary`, keep the leader as a singleton at
                    // the tail of its source cell's refined block. Enumerate
                    // both twin-half assignments so the leader may be isolated
                    // with either partition when the halves differ.
                    let leader_idx = start + outside + secondary + primary;
                    next_cells.push(1);
                    next_leader = Some(leader_idx);

                    for leader_in_primary in [true, false] {
                        let leader_bit = 1u64 << leader_idx;
                        with_secondary(
                            ranges,
                            max_partitions,
                            leader_cell,
                            cell_idx + 1,
                            SecondaryState {
                                primary_mask: if leader_in_primary {
                                    next_primary | leader_bit
                                } else {
                                    next_primary
                                },
                                secondary_mask: if leader_in_primary {
                                    next_secondary
                                } else {
                                    next_secondary | leader_bit
                                },
                                secondary_total: state.secondary_total
                                    + secondary
                                    + usize::from(!leader_in_primary),
                                leader: next_leader,
                            },
                            next_cells,
                            out,
                        );
                    }

                    next_cells.pop();
                    if primary > 0 {
                        next_cells.pop();
                    }
                    if secondary > 0 {
                        next_cells.pop();
                    }
                    if outside > 0 {
                        next_cells.pop();
                    }
                    continue;
                }

                with_secondary(
                    ranges,
                    max_partitions,
                    leader_cell,
                    cell_idx + 1,
                    SecondaryState {
                        primary_mask: next_primary,
                        secondary_mask: next_secondary,
                        secondary_total: state.secondary_total + secondary,
                        leader: next_leader,
                    },
                    next_cells,
                    out,
                );

                // Undo the refined cells before trying the next allocation.
                if has_leader {
                    next_cells.pop();
                }
                if primary > 0 {
                    next_cells.pop();
                }
                if secondary > 0 {
                    next_cells.pop();
                }
                if outside > 0 {
                    next_cells.pop();
                }
            }
        }
    }

    let ranges = cells_to_ranges(cells);
    let mut out = Vec::new();
    for leader_cell in 0..cells.len() {
        // Any current symmetry cell may supply the next leader. Enumerate the
        // no-secondary and with-secondary cases separately to keep the output
        // canonical and duplicate-free.
        let mut next_cells = Vec::new();
        no_secondary(&ranges, leader_cell, 0, 0, None, &mut next_cells, &mut out);
        let mut next_cells = Vec::new();
        with_secondary(
            &ranges,
            max_partitions.min(3),
            leader_cell,
            0,
            SecondaryState {
                primary_mask: 0,
                secondary_mask: 0,
                secondary_total: 0,
                leader: None,
            },
            &mut next_cells,
            &mut out,
        );
    }
    out
}

/// Counts canonical scenario suffixes reachable from a cell state.
fn canonical_scenario_count(
    cells: &[usize],
    rounds: usize,
    max_partitions: usize,
    memo: &mut HashMap<(Vec<usize>, usize), Option<u128>>,
) -> Option<u128> {
    if rounds == 0 {
        return Some(1);
    }
    let key = (cells.to_vec(), rounds);
    if let Some(cached) = memo.get(&key) {
        return *cached;
    }

    let result = (|| {
        let mut total = 0u128;
        for (_, next_cells) in next_round_transitions(cells, max_partitions) {
            let suffix = canonical_scenario_count(&next_cells, rounds - 1, max_partitions, memo)?;
            total = total.checked_add(suffix)?;
        }
        Some(total)
    })();
    memo.insert(key, result);
    result
}

/// Reconstructs the canonical scenario at a given lexicographic rank.
fn canonical_scenario_from_rank(
    cells: &[usize],
    rounds: usize,
    max_partitions: usize,
    mut rank: u128,
    memo: &mut HashMap<(Vec<usize>, usize), Option<u128>>,
) -> Scenario {
    if rounds == 0 {
        return Scenario { rounds: Vec::new() };
    }

    for (round, next_cells) in next_round_transitions(cells, max_partitions) {
        let suffix = canonical_scenario_count(&next_cells, rounds - 1, max_partitions, memo)
            .expect("canonical scenario count should fit in u128");
        if rank < suffix {
            let mut scenario =
                canonical_scenario_from_rank(&next_cells, rounds - 1, max_partitions, rank, memo);
            scenario.rounds.insert(0, round);
            return scenario;
        }
        rank -= suffix;
    }
    unreachable!("canonical scenario rank out of bounds")
}

/// Counts `k`-subsets of an `n`-element set without overflow.
fn combination_count(n: usize, k: usize) -> Option<u128> {
    if k > n {
        return Some(0);
    }
    let k = k.min(n - k);
    let mut total = 1u128;
    for i in 0..k {
        total = total.checked_mul((n - k + i + 1) as u128)?;
        total /= (i + 1) as u128;
    }
    Some(total)
}

/// Reconstructs the lexicographically ranked `k`-subset of `[0, n)`.
fn combination_from_rank(n: usize, k: usize, mut rank: u128) -> Vec<usize> {
    let mut set = Vec::with_capacity(k);
    let mut start = 0usize;
    for remaining in (1..=k).rev() {
        for candidate in start..=(n - remaining) {
            let suffix = combination_count(n - candidate - 1, remaining - 1)
                .expect("suffix count should fit in u128");
            if rank < suffix {
                set.push(candidate);
                start = candidate + 1;
                break;
            }
            rank -= suffix;
        }
    }
    set
}

/// Derives a stable seed for a `(compromised set, scenario)` pair.
fn derive_case_seed(
    seed: u64,
    compromised_idx: usize,
    scenario_idx: usize,
    scenarios: usize,
) -> u64 {
    let case_idx = compromised_idx
        .checked_mul(scenarios)
        .and_then(|offset| offset.checked_add(scenario_idx))
        .expect("case index overflow");
    mix64(seed ^ u64::try_from(case_idx).expect("case index should fit in u64") ^ CASE_SEED_DOMAIN)
}

/// Samples unique indices without replacement from `[0, total)`.
fn sample_unique_indices(rng: &mut StdRng, total: u128, samples: usize) -> Vec<u128> {
    assert!(
        (samples as u128) <= total,
        "cannot sample more unique indices than total domain size"
    );
    if samples == 0 {
        return Vec::new();
    }

    // Floyd's algorithm samples without replacement in O(samples) time with no retry loop.
    let mut sampled = Vec::with_capacity(samples);
    let mut seen = HashSet::with_capacity(samples);
    for idx in (total - samples as u128)..total {
        let candidate = rng.gen_range(0..=idx);
        if seen.insert(candidate) {
            sampled.push(candidate);
        } else {
            let inserted = seen.insert(idx);
            debug_assert!(inserted, "tail index should be unique in Floyd sampling");
            sampled.push(idx);
        }
    }
    sampled
}

/// Generates canonical scenarios subject to the framework bounds.
fn generate_scenarios(
    seed: u64,
    n: usize,
    rounds: usize,
    max_partitions: usize,
    max_scenarios: usize,
) -> Vec<Scenario> {
    let mut rng = test_rng_seeded(seed);
    let mut memo = HashMap::new();
    let initial_cells = vec![n];
    if let Some(total) =
        canonical_scenario_count(&initial_cells, rounds, max_partitions.min(3), &mut memo)
    {
        if total <= max_scenarios as u128 {
            return (0..total)
                .map(|idx| {
                    canonical_scenario_from_rank(
                        &initial_cells,
                        rounds,
                        max_partitions.min(3),
                        idx,
                        &mut memo,
                    )
                })
                .collect();
        }

        return sample_unique_indices(&mut rng, total, max_scenarios)
            .into_iter()
            .map(|idx| {
                canonical_scenario_from_rank(
                    &initial_cells,
                    rounds,
                    max_partitions.min(3),
                    idx,
                    &mut memo,
                )
            })
            .collect();
    }

    // Extremely large canonical spaces can overflow counts; sample directly
    // from the canonical transition graph while enforcing uniqueness. This
    // path treats `max_scenarios` as an upper bound, since concentrated random
    // walks may not discover that many distinct scenarios within the attempt
    // budget even when the canonical space is much larger.
    let max_attempts = max_scenarios.saturating_mul(1024).max(4096);
    sample_scenarios_fallback(
        &mut rng,
        &initial_cells,
        rounds,
        max_partitions.min(3),
        max_scenarios,
        max_attempts,
    )
}

/// Samples unique scenarios from the canonical transition graph without using counts.
fn sample_scenarios_fallback(
    rng: &mut StdRng,
    initial_cells: &[usize],
    rounds: usize,
    max_partitions: usize,
    max_scenarios: usize,
    max_attempts: usize,
) -> Vec<Scenario> {
    let mut scenarios = BTreeSet::new();
    let mut attempts = 0usize;
    while scenarios.len() < max_scenarios && attempts < max_attempts {
        attempts += 1;
        let mut cells = initial_cells.to_vec();
        let mut scenario = Scenario {
            rounds: Vec::with_capacity(rounds),
        };
        for _ in 0..rounds {
            let transitions = next_round_transitions(&cells, max_partitions);
            let idx = rng.gen_range(0..transitions.len());
            let (round, next_cells) = transitions[idx].clone();
            scenario.rounds.push(round);
            cells = next_cells;
        }
        scenarios.insert(scenario);
    }
    scenarios.into_iter().collect()
}

/// Generates concrete compromised-node assignments subject to the framework bounds.
fn compromised_sets(seed: u64, n: usize, faults: usize, max_sets: usize) -> Vec<Vec<usize>> {
    /// Recursively enumerates all `remaining`-subsets starting at `start`.
    fn choose(
        start: usize,
        n: usize,
        remaining: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            out.push(current.clone());
            return;
        }
        for idx in start..=(n - remaining) {
            current.push(idx);
            choose(idx + 1, n, remaining - 1, current, out);
            current.pop();
        }
    }

    let total = combination_count(n, faults).expect("combination count should fit in u128");
    if total <= max_sets as u128 {
        let mut all = Vec::with_capacity(total as usize);
        choose(0, n, faults, &mut Vec::new(), &mut all);
        return all;
    }

    let mut rng = test_rng_seeded(seed);
    sample_unique_indices(&mut rng, total, max_sets)
        .into_iter()
        .map(|idx| combination_from_rank(n, faults, idx))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            elector::{Config as ElectorConfig, RoundRobin},
            scheme::ed25519,
        },
        types::Epoch,
    };
    use commonware_cryptography::{ed25519::PrivateKey, Sha256, Signer};
    use commonware_utils::ordered::Set;

    fn scenario(rounds: &[(usize, u64, u64)]) -> Scenario {
        Scenario {
            rounds: rounds
                .iter()
                .map(|&(leader, primary_mask, secondary_mask)| RoundScenario {
                    leader,
                    primary_mask,
                    secondary_mask,
                })
                .collect(),
        }
    }

    fn case_tuples(cases: &[Case]) -> Vec<(Vec<usize>, Scenario, u64)> {
        cases
            .iter()
            .map(|case| (case.compromised.clone(), case.scenario.clone(), case.seed))
            .collect()
    }

    #[test]
    fn cases_cover_all_compromised_nodes_for_n5_f1() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_partitions: 3,
            max_scenarios: 3,
            max_compromised_sets: 5,
            relabel: true,
        };
        let cases = cases(0, framework);
        let compromised: HashSet<_> = cases.iter().map(|case| case.compromised[0]).collect();
        assert_eq!(compromised, HashSet::from([0, 1, 2, 3, 4]));
    }

    #[test]
    fn generated_cases_are_deterministic() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_partitions: 3,
            max_scenarios: 4,
            max_compromised_sets: 5,
            relabel: true,
        };
        let first = cases(42, framework);
        let second = cases(42, framework);
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.compromised, b.compromised);
            assert_eq!(a.scenario, b.scenario);
            assert_eq!(a.seed, b.seed);
        }
    }

    #[test]
    fn case_seeds_do_not_collide_for_large_scenario_indices() {
        let seed = 42;
        let scenarios = 65_537;
        let first = derive_case_seed(seed, 0, 65_536, scenarios);
        let second = derive_case_seed(seed, 1, 0, scenarios);
        assert_ne!(first, second);
    }

    #[test]
    fn first_case_seed_differs_from_framework_seed() {
        let seed = 0;
        assert_ne!(derive_case_seed(seed, 0, 0, 1), seed);
    }

    #[test]
    fn generated_scenarios_include_leaders_visible_only_to_secondary() {
        let scenarios = generate_scenarios(0, 3, 1, 2, usize::MAX);
        assert!(scenarios.iter().any(|scenario| {
            let round = scenario.rounds[0];
            let leader_bit = 1u64 << round.leader;
            (round.primary_mask & leader_bit) == 0 && (round.secondary_mask & leader_bit) != 0
        }));
    }

    #[test]
    fn unique_index_sampling_handles_near_full_ranges() {
        let total = 100_000u128;
        let samples = 99_999usize;
        let mut rng = test_rng_seeded(9);
        let sampled = sample_unique_indices(&mut rng, total, samples);
        assert_eq!(sampled.len(), samples);
        assert_eq!(
            sampled.iter().copied().collect::<HashSet<_>>().len(),
            samples
        );
        assert!(sampled.into_iter().all(|idx| idx < total));
    }

    #[test]
    fn route_selects_correct_half() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 0,
                primary_mask: 0b0011,
                secondary_mask: 0b1100,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();
        assert_eq!(
            scenario.route(View::new(1), &0, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &1, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &2, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            scenario.route(View::new(1), &3, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn scenarios_fall_back_to_synchrony_after_attack_rounds() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 0,
                primary_mask: 0b0011,
                secondary_mask: 0b1100,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();
        let (primary, secondary) = scenario.partitions(View::new(2), &participants);
        assert_eq!(primary, participants);
        assert_eq!(secondary, participants);
    }

    #[test]
    fn generated_scenarios_respect_max_scenarios_bound() {
        let scenarios = generate_scenarios(7, 5, 4, 3, 3);
        assert_eq!(scenarios.len(), 3);
    }

    #[test]
    fn generated_scenarios_fallback_sampling_is_bounded() {
        let scenarios = generate_scenarios(5, 4, 40, 3, 8);
        assert!(!scenarios.is_empty());
        assert!(scenarios.len() <= 8);
    }

    #[test]
    fn fallback_sampling_returns_partial_results_when_attempt_budget_is_exhausted() {
        let mut rng = test_rng_seeded(0);
        let scenarios = sample_scenarios_fallback(&mut rng, &[4], 40, 3, 8, 1);
        assert_eq!(scenarios.len(), 1);
    }

    #[test]
    fn canonical_scenario_count_caches_overflow_results() {
        let initial_cells = vec![4];
        let mut memo = HashMap::new();
        assert_eq!(
            canonical_scenario_count(&initial_cells, 40, 3, &mut memo),
            None
        );
        assert_eq!(memo.get(&(initial_cells, 40)), Some(&None));
    }

    #[test]
    fn pruned_scenarios_vary_across_round_positions() {
        let scenarios = generate_scenarios(11, 5, 3, 3, 32);
        for round in 0..3 {
            let unique: HashSet<_> = scenarios
                .iter()
                .map(|scenario| scenario.rounds[round])
                .collect();
            assert!(
                unique.len() > 1,
                "round index {round} should vary under deterministic pruning"
            );
        }
    }

    #[test]
    fn cases_relabel_generated_scenarios_across_compromised_assignments() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_partitions: 3,
            max_scenarios: 1,
            max_compromised_sets: 5,
            relabel: true,
        };
        let cases = cases(7, framework);
        let concrete: HashSet<_> = cases.iter().map(|case| case.scenario.clone()).collect();
        assert!(concrete.len() > 1);
    }

    #[test]
    fn cases_reuse_generated_scenarios_without_relabeling() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_partitions: 3,
            max_scenarios: 1,
            max_compromised_sets: 5,
            relabel: false,
        };
        let cases = cases(7, framework);
        let concrete: HashSet<_> = cases.iter().map(|case| case.scenario.clone()).collect();
        assert_eq!(concrete.len(), 1);
    }

    #[test]
    #[should_panic(expected = "participants must fit in u64 masks")]
    fn cases_reject_frameworks_that_exceed_mask_width() {
        let _ = cases(
            0,
            Framework {
                participants: (u64::BITS as usize) + 1,
                faults: 1,
                rounds: 1,
                max_partitions: 2,
                max_scenarios: 1,
                max_compromised_sets: 1,
                relabel: false,
            },
        );
    }

    #[test]
    fn small_two_way_cases_match_expected() {
        let cases = cases(
            0,
            Framework {
                participants: 3,
                faults: 1,
                rounds: 1,
                max_partitions: 2,
                max_scenarios: usize::MAX,
                max_compromised_sets: usize::MAX,
                relabel: true,
            },
        );
        assert_eq!(
            case_tuples(&cases),
            vec![
                (vec![0], scenario(&[(1, 7, 7)]), 2170739273462938283),
                (vec![0], scenario(&[(2, 6, 6)]), 4465124358439419799),
                (vec![0], scenario(&[(1, 2, 2)]), 8002959681992535999),
                (vec![0], scenario(&[(1, 5, 2)]), 6108070350708085049),
                (vec![0], scenario(&[(1, 3, 4)]), 9989874130994336479),
                (vec![0], scenario(&[(2, 2, 5)]), 10325517022425501071),
                (vec![0], scenario(&[(1, 2, 5)]), 18117611283088466541),
                (vec![0], scenario(&[(1, 0, 7)]), 5679428222510952296),
                (vec![1], scenario(&[(1, 7, 7)]), 1472286416061459289),
                (vec![1], scenario(&[(1, 3, 3)]), 13499682107543998298),
                (vec![1], scenario(&[(1, 2, 2)]), 4136269653119000327),
                (vec![1], scenario(&[(1, 5, 2)]), 6929273731067172831),
                (vec![1], scenario(&[(1, 3, 4)]), 10007311085265012729),
                (vec![1], scenario(&[(2, 1, 6)]), 4458826077016808784),
                (vec![1], scenario(&[(2, 4, 3)]), 15937942260472093875),
                (vec![1], scenario(&[(1, 0, 7)]), 14820960278153147396),
                (vec![2], scenario(&[(0, 7, 7)]), 11179427316405893828),
                (vec![2], scenario(&[(1, 3, 3)]), 10131263269842774556),
                (vec![2], scenario(&[(2, 4, 4)]), 9128492615816103125),
                (vec![2], scenario(&[(1, 5, 2)]), 2928794839749781711),
                (vec![2], scenario(&[(1, 6, 1)]), 3392439396611310632),
                (vec![2], scenario(&[(2, 1, 6)]), 7533739392812329049),
                (vec![2], scenario(&[(2, 4, 3)]), 13228754465217521794),
                (vec![2], scenario(&[(2, 0, 7)]), 8857000381058704332),
            ]
        );
    }

    #[test]
    fn small_three_way_cases_match_expected() {
        let cases = cases(
            0,
            Framework {
                participants: 3,
                faults: 1,
                rounds: 1,
                max_partitions: 3,
                max_scenarios: usize::MAX,
                max_compromised_sets: usize::MAX,
                relabel: true,
            },
        );
        assert_eq!(
            case_tuples(&cases),
            vec![
                (vec![0], scenario(&[(1, 7, 7)]), 2170739273462938283),
                (vec![0], scenario(&[(2, 6, 6)]), 4465124358439419799),
                (vec![0], scenario(&[(1, 2, 2)]), 8002959681992535999),
                (vec![0], scenario(&[(1, 5, 2)]), 6108070350708085049),
                (vec![0], scenario(&[(1, 3, 4)]), 9989874130994336479),
                (vec![0], scenario(&[(2, 2, 5)]), 10325517022425501071),
                (vec![0], scenario(&[(1, 2, 5)]), 18117611283088466541),
                (vec![0], scenario(&[(1, 0, 7)]), 5679428222510952296),
                (vec![0], scenario(&[(1, 4, 2)]), 1472286416061459289),
                (vec![0], scenario(&[(1, 2, 1)]), 13499682107543998298),
                (vec![0], scenario(&[(1, 0, 6)]), 4136269653119000327),
                (vec![0], scenario(&[(1, 0, 2)]), 6929273731067172831),
                (vec![1], scenario(&[(1, 7, 7)]), 10007311085265012729),
                (vec![1], scenario(&[(2, 5, 5)]), 4458826077016808784),
                (vec![1], scenario(&[(2, 4, 4)]), 15937942260472093875),
                (vec![1], scenario(&[(1, 5, 2)]), 14820960278153147396),
                (vec![1], scenario(&[(0, 5, 2)]), 11179427316405893828),
                (vec![1], scenario(&[(1, 1, 6)]), 10131263269842774556),
                (vec![1], scenario(&[(2, 4, 3)]), 9128492615816103125),
                (vec![1], scenario(&[(1, 0, 7)]), 2928794839749781711),
                (vec![1], scenario(&[(1, 4, 2)]), 3392439396611310632),
                (vec![1], scenario(&[(2, 4, 1)]), 7533739392812329049),
                (vec![1], scenario(&[(2, 0, 6)]), 13228754465217521794),
                (vec![1], scenario(&[(2, 0, 4)]), 8857000381058704332),
                (vec![2], scenario(&[(0, 7, 7)]), 18274429830946313084),
                (vec![2], scenario(&[(2, 6, 6)]), 11084478744584418441),
                (vec![2], scenario(&[(2, 4, 4)]), 11686864087075984732),
                (vec![2], scenario(&[(0, 6, 1)]), 1543352670129978634),
                (vec![2], scenario(&[(2, 6, 1)]), 3022581153672932472),
                (vec![2], scenario(&[(0, 4, 3)]), 192248451665106653),
                (vec![2], scenario(&[(1, 2, 5)]), 11870905462056970452),
                (vec![2], scenario(&[(1, 0, 7)]), 10791667775650329745),
                (vec![2], scenario(&[(0, 4, 1)]), 10991605233820999680),
                (vec![2], scenario(&[(1, 2, 1)]), 9903328472526535128),
                (vec![2], scenario(&[(1, 0, 6)]), 922995990465865764),
                (vec![2], scenario(&[(0, 0, 1)]), 3263032590923257502),
            ]
        );
    }

    #[test]
    fn route_returns_none_for_participants_outside_selected_partitions() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 0,
                primary_mask: 0b0001,
                secondary_mask: 0b0010,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();
        assert_eq!(
            scenario.route(View::new(1), &2, &participants),
            SplitTarget::None
        );
    }

    #[test]
    #[should_panic(expected = "sender missing from runtime participant list")]
    fn route_panics_when_sender_is_missing_from_participants() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 0,
                primary_mask: 0b0001,
                secondary_mask: 0b0010,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();
        let _ = scenario.route(View::new(1), &99, &participants);
    }

    #[test]
    fn twins_elector_uses_scenario_leaders_then_fallback_suffix() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_partitions: 3,
            max_scenarios: 1,
            max_compromised_sets: 1,
            relabel: true,
        };
        let case = cases(0, framework)
            .into_iter()
            .next()
            .expect("expected at least one generated twins case");
        let participants: Vec<_> = (0..framework.participants as u64)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        let participants = Set::try_from(participants).expect("participants should be unique");
        let twins = <Elector<RoundRobin<Sha256>> as ElectorConfig<ed25519::Scheme>>::build(
            Elector::new(
                RoundRobin::<Sha256>::default(),
                &case.scenario,
                framework.participants,
            ),
            &participants,
        );
        let fallback = <RoundRobin<Sha256> as ElectorConfig<ed25519::Scheme>>::build(
            RoundRobin::<Sha256>::default(),
            &participants,
        );

        for (round_idx, round_scenario) in case.scenario.rounds().iter().enumerate() {
            let round = Round::new(Epoch::new(0), View::new((round_idx as u64) + 1));
            assert_eq!(
                twins.elect(round, None),
                Participant::new(round_scenario.leader() as u32),
                "unexpected leader in scripted attack round"
            );
        }

        for view in (framework.rounds as u64 + 1)..=20 {
            let round = Round::new(Epoch::new(333), View::new(view));
            assert_eq!(twins.elect(round, None), fallback.elect(round, None));
        }
    }

    #[test]
    fn compromised_set_sampling_handles_large_combination_spaces() {
        let sets = compromised_sets(9, 30, 10, 3);
        assert_eq!(sets.len(), 3);

        let unique: HashSet<_> = sets.iter().cloned().collect();
        assert_eq!(unique.len(), sets.len());
        for set in sets {
            assert_eq!(set.len(), 10);
            assert!(set.windows(2).all(|window| window[0] < window[1]));
        }
    }
}
