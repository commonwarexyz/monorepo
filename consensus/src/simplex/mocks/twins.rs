//! Twins framework scenario generator and executor helpers.
//!
//! This module follows the testing architecture from
//! [Twins: BFT Systems Made Robust](https://arxiv.org/pdf/2004.10617):
//! 1. Generate partition scenarios.
//! 2. Combine partitions with leader choices per round.
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
//! The full enumeration approach guarantees that every case within a campaign
//! is structurally distinct -- no duplicate (scenario, compromised-assignment)
//! pairs are ever emitted. For each canonical scenario, `cases()` computes the
//! residual symmetry cells and generates only the unique compromised-node
//! assignments: two assignments that differ only in which members of a cell
//! are chosen are equivalent and collapsed to a single representative. When the
//! case space exceeds `max_cases`, scenarios are sampled without replacement.

use crate::{
    simplex::elector::{Config as ElectorConfig, Elector as Elected},
    types::{Participant, Round, View},
};
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::simulated::SplitTarget;
use commonware_utils::ordered::Set;
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

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
///
/// Each canonical scenario tracks residual symmetry cells -- participants that
/// were treated identically across all rounds. Two compromised-node assignments
/// that differ only in which members of a symmetry cell are compromised produce
/// identical test behavior, so the framework generates only one representative
/// per equivalence class. This keeps the case budget focused on structurally
/// distinct attack configurations.
///
/// The total case count is the sum, over generated scenarios, of the number of
/// symmetry-unique compromised assignments for that scenario's residual cells.
/// [`Framework::max_cases`] caps the total.
#[derive(Clone, Copy, Debug)]
pub struct Framework {
    /// Number of participants in the network.
    pub participants: usize,
    /// Number of compromised participants.
    pub faults: usize,
    /// Number of adversarial rounds before synchronous suffix.
    pub rounds: usize,
    /// Upper bound on the total number of emitted cases (scenario x
    /// compromised-assignment pairs). When the full case space exceeds this
    /// budget, scenarios are sampled to fit.
    pub max_cases: usize,
}

/// Executable case from the Twins framework.
#[derive(Clone, Debug)]
pub struct Case {
    /// Compromised participant indices for this case.
    pub compromised: Vec<usize>,
    /// Multi-round scenario for this case.
    pub scenario: Scenario,
}

/// Generate executable Twins cases from framework parameters.
///
/// The full enumeration approach guarantees no duplicate cases within a
/// campaign. For each canonical scenario, the generator computes the residual
/// symmetry cells and emits only the structurally unique compromised-node
/// assignments. When the total exceeds [`Framework::max_cases`], scenarios
/// are sampled without replacement so every emitted case is distinct.
pub fn cases(rng: &mut impl Rng, framework: Framework) -> Vec<Case> {
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
    assert!(framework.max_cases > 0, "max_cases must be > 0");

    let scenarios = generate_scenarios(
        rng,
        framework.participants,
        framework.rounds,
        framework.max_cases,
    );

    let mut out = Vec::new();
    for (scenario, residual_cells) in &scenarios {
        let compromised_sets = compromised_sets_for_cells(residual_cells, framework.faults);
        for compromised in compromised_sets {
            out.push(Case {
                compromised,
                scenario: scenario.clone(),
            });
            if out.len() >= framework.max_cases {
                return out;
            }
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
///
/// Each round splits participants into up to 3 groups: outside both
/// partitions, primary-only, and secondary-only.
fn next_round_transitions(cells: &[usize]) -> Vec<(RoundScenario, Vec<usize>)> {
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
        let outside_range = 0..=available;

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
                    // both twin-half placements so the leader may be isolated
                    // with either partition when the halves differ.
                    let leader_idx = start + outside + secondary + primary;
                    next_cells.push(1);
                    next_leader = Some(leader_idx);

                    for leader_in_primary in [true, false] {
                        let leader_bit = 1u64 << leader_idx;
                        with_secondary(
                            ranges,
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

/// Generates compromised-node assignments that are unique modulo residual
/// symmetry cells.
///
/// Two assignments are equivalent if one can be obtained from the other by
/// permuting participants within the same cell. This function emits exactly
/// one canonical representative per equivalence class by always picking the
/// first indices from each cell.
fn compromised_sets_for_cells(cells: &[usize], faults: usize) -> Vec<Vec<usize>> {
    let ranges = cells_to_ranges(cells);
    let mut result = Vec::new();
    let mut current = Vec::new();
    allocate_faults(&ranges, 0, faults, &mut current, &mut result);
    result
}

/// Recursively allocates `remaining` faults across cells starting at
/// `cell_idx`, picking the first `take` indices from each cell as the
/// canonical representative.
fn allocate_faults(
    ranges: &[(usize, usize)],
    cell_idx: usize,
    remaining: usize,
    current: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if remaining == 0 {
        result.push(current.clone());
        return;
    }
    if cell_idx >= ranges.len() {
        return;
    }
    let (start, size) = ranges[cell_idx];
    let remaining_capacity: usize = ranges[cell_idx..].iter().map(|(_, s)| *s).sum();
    if remaining > remaining_capacity {
        return;
    }
    let max_from_this = remaining.min(size);
    for take in 0..=max_from_this {
        for i in 0..take {
            current.push(start + i);
        }
        allocate_faults(ranges, cell_idx + 1, remaining - take, current, result);
        for _ in 0..take {
            current.pop();
        }
    }
}

/// Counts compromised assignments unique modulo residual symmetry cells.
#[cfg(test)]
fn compromised_count_for_cells(cells: &[usize], faults: usize) -> usize {
    fn count(ranges: &[(usize, usize)], idx: usize, remaining: usize) -> usize {
        if remaining == 0 {
            return 1;
        }
        if idx >= ranges.len() {
            return 0;
        }
        let (_, size) = ranges[idx];
        let remaining_capacity: usize = ranges[idx..].iter().map(|(_, s)| *s).sum();
        if remaining > remaining_capacity {
            return 0;
        }
        let mut total = 0;
        for take in 0..=remaining.min(size) {
            total += count(ranges, idx + 1, remaining - take);
        }
        total
    }
    let ranges = cells_to_ranges(cells);
    count(&ranges, 0, faults)
}

/// Counts canonical scenario suffixes reachable from a cell state.
fn canonical_scenario_count(
    cells: &[usize],
    rounds: usize,
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
        for (_, next_cells) in next_round_transitions(cells) {
            let suffix = canonical_scenario_count(&next_cells, rounds - 1, memo)?;
            total = total.checked_add(suffix)?;
        }
        Some(total)
    })();
    memo.insert(key, result);
    result
}

/// Reconstructs the canonical scenario and residual cells at a given
/// lexicographic rank.
fn canonical_scenario_from_rank(
    cells: &[usize],
    rounds: usize,
    mut rank: u128,
    memo: &mut HashMap<(Vec<usize>, usize), Option<u128>>,
) -> (Scenario, Vec<usize>) {
    if rounds == 0 {
        return (Scenario { rounds: Vec::new() }, cells.to_vec());
    }

    for (round, next_cells) in next_round_transitions(cells) {
        let suffix = canonical_scenario_count(&next_cells, rounds - 1, memo)
            .expect("canonical scenario count should fit in u128");
        if rank < suffix {
            let (mut scenario, residual) =
                canonical_scenario_from_rank(&next_cells, rounds - 1, rank, memo);
            scenario.rounds.insert(0, round);
            return (scenario, residual);
        }
        rank -= suffix;
    }
    unreachable!("canonical scenario rank out of bounds")
}

/// Samples unique indices without replacement from `[0, total)`.
fn sample_unique_indices(rng: &mut impl Rng, total: u128, samples: usize) -> Vec<u128> {
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

/// Generates canonical scenarios with their residual symmetry cells, subject
/// to the framework bounds.
///
/// `max_cases` is used to derive an internal scenario budget: we generate
/// scenarios until the cumulative case count (scenarios x their per-scenario
/// compromised assignments) would exceed the budget.
fn generate_scenarios(
    rng: &mut impl Rng,
    n: usize,
    rounds: usize,
    max_cases: usize,
) -> Vec<(Scenario, Vec<usize>)> {
    let mut memo = HashMap::new();
    let initial_cells = vec![n];
    if let Some(total) = canonical_scenario_count(&initial_cells, rounds, &mut memo) {
        if total <= max_cases as u128 {
            return (0..total)
                .map(|idx| canonical_scenario_from_rank(&initial_cells, rounds, idx, &mut memo))
                .collect();
        }

        return sample_unique_indices(rng, total, max_cases)
            .into_iter()
            .map(|idx| canonical_scenario_from_rank(&initial_cells, rounds, idx, &mut memo))
            .collect();
    }

    let max_attempts = max_cases.saturating_mul(1024).max(4096);
    sample_scenarios_fallback(rng, &initial_cells, rounds, max_cases, max_attempts)
}

/// Samples unique scenarios with residual cells from the canonical transition
/// graph without using counts.
fn sample_scenarios_fallback(
    rng: &mut impl Rng,
    initial_cells: &[usize],
    rounds: usize,
    max_scenarios: usize,
    max_attempts: usize,
) -> Vec<(Scenario, Vec<usize>)> {
    let mut scenarios = BTreeMap::new();
    let mut attempts = 0usize;
    while scenarios.len() < max_scenarios && attempts < max_attempts {
        attempts += 1;
        let mut cells = initial_cells.to_vec();
        let mut scenario = Scenario {
            rounds: Vec::with_capacity(rounds),
        };
        for _ in 0..rounds {
            let transitions = next_round_transitions(&cells);
            let idx = rng.gen_range(0..transitions.len());
            let (round, next_cells) = transitions[idx].clone();
            scenario.rounds.push(round);
            cells = next_cells;
        }
        scenarios.entry(scenario).or_insert(cells);
    }
    scenarios.into_iter().collect()
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
    use commonware_utils::{ordered::Set, test_rng, test_rng_seeded};

    #[test]
    fn generated_cases_are_deterministic() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_cases: 50,
        };
        let first = cases(&mut test_rng(), framework);
        let second = cases(&mut test_rng(), framework);
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.compromised, b.compromised);
            assert_eq!(a.scenario, b.scenario);
        }
    }

    #[test]
    fn generated_scenarios_include_leaders_visible_only_to_secondary() {
        let scenarios = generate_scenarios(&mut test_rng(), 3, 1, usize::MAX);
        assert!(scenarios.iter().any(|(scenario, _)| {
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
    fn generated_scenarios_respect_max_bound() {
        let scenarios = generate_scenarios(&mut test_rng(), 5, 4, 3);
        assert_eq!(scenarios.len(), 3);
    }

    #[test]
    fn generated_scenarios_fallback_sampling_is_bounded() {
        let scenarios = generate_scenarios(&mut test_rng(), 4, 40, 8);
        assert!(!scenarios.is_empty());
        assert!(scenarios.len() <= 8);
    }

    #[test]
    fn fallback_sampling_returns_partial_results_when_attempt_budget_is_exhausted() {
        let mut rng = test_rng();
        let scenarios = sample_scenarios_fallback(&mut rng, &[4], 40, 8, 1);
        assert_eq!(scenarios.len(), 1);
    }

    #[test]
    fn canonical_scenario_count_caches_overflow_results() {
        let initial_cells = vec![4];
        let mut memo = HashMap::new();
        assert_eq!(
            canonical_scenario_count(&initial_cells, 40, &mut memo),
            None
        );
        assert_eq!(memo.get(&(initial_cells, 40)), Some(&None));
    }

    #[test]
    fn pruned_scenarios_vary_across_round_positions() {
        let scenarios = generate_scenarios(&mut test_rng(), 5, 3, 32);
        for round in 0..3 {
            let unique: HashSet<_> = scenarios
                .iter()
                .map(|(scenario, _)| scenario.rounds[round])
                .collect();
            assert!(
                unique.len() > 1,
                "round index {round} should vary under deterministic pruning"
            );
        }
    }

    #[test]
    fn compromised_sets_collapse_symmetry_cells() {
        // All 3 participants in one cell: only 1 unique compromised set for f=1
        assert_eq!(compromised_sets_for_cells(&[3], 1).len(), 1);
        assert_eq!(compromised_sets_for_cells(&[3], 1), vec![vec![0]]);

        // Cells [2, 1]: two unique compromised sets for f=1
        let sets = compromised_sets_for_cells(&[2, 1], 1);
        assert_eq!(sets, vec![vec![2], vec![0]]);

        // All singletons [1, 1, 1]: 3 unique compromised sets for f=1
        let sets = compromised_sets_for_cells(&[1, 1, 1], 1);
        assert_eq!(sets, vec![vec![2], vec![1], vec![0]]);
    }

    #[test]
    fn compromised_sets_multi_fault() {
        // Cells [3, 2], f=2: allocate across cells
        let sets = compromised_sets_for_cells(&[3, 2], 2);
        // take=0 from cell0, take=2 from cell1 -> [3, 4]
        // take=1 from cell0, take=1 from cell1 -> [0, 3]
        // take=2 from cell0, take=0 from cell1 -> [0, 1]
        assert_eq!(sets, vec![vec![3, 4], vec![0, 3], vec![0, 1]]);
    }

    #[test]
    fn compromised_count_matches_enumeration() {
        for cells in &[vec![5], vec![3, 2], vec![2, 2, 1], vec![1, 1, 1, 1, 1]] {
            for faults in 1..=cells.iter().sum::<usize>().min(3) {
                assert_eq!(
                    compromised_count_for_cells(cells, faults),
                    compromised_sets_for_cells(cells, faults).len(),
                    "mismatch for cells={cells:?}, faults={faults}"
                );
            }
        }
    }

    #[test]
    fn cases_fewer_than_naive_cross_product() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 1,
            max_cases: usize::MAX,
        };
        let all_cases = cases(&mut test_rng(), framework);
        let scenarios = generate_scenarios(&mut test_rng(), 5, 1, usize::MAX);
        // Naive cross-product would be scenarios * C(5,1) = scenarios * 5.
        // Symmetry-aware should produce fewer.
        let naive = scenarios.len() * 5;
        assert!(
            all_cases.len() < naive,
            "got {} cases but naive would be {naive}",
            all_cases.len()
        );
    }

    #[test]
    fn max_cases_caps_output() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,

            max_cases: 10,
        };
        let result = cases(&mut test_rng(), framework);
        assert!(result.len() <= 10);
    }

    #[test]
    #[should_panic(expected = "participants must fit in u64 masks")]
    fn cases_reject_frameworks_that_exceed_mask_width() {
        let _ = cases(
            &mut test_rng(),
            Framework {
                participants: (u64::BITS as usize) + 1,
                faults: 1,
                rounds: 1,
                max_cases: 1,
            },
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
            max_cases: 1,
        };
        let case = cases(&mut test_rng(), framework)
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
}
