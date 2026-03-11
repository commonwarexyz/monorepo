//! Twins framework scenario generator and executor helpers.
//!
//! This module follows the testing architecture from
//! [Twins: BFT Systems Made Robust](https://arxiv.org/pdf/2004.10617):
//! 1. Generate primary/secondary recipient-set scenarios.
//! 2. Combine those sets with leader choices per round.
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
//!
//! These recipient sets are not required to be disjoint. A participant may
//! appear in both masks for a round, meaning both twin halves can exchange
//! messages with that participant identity in that view.

use crate::{
    simplex::elector::{Config as ElectorConfig, Elector as Elected},
    types::{Participant, Round, View},
};
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::simulated::SplitTarget;
use commonware_utils::ordered::Set;
use rand::{seq::SliceRandom, Rng};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Per-round adversarial setting from the Twins framework.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoundScenario {
    // Participant index chosen to lead this round.
    leader: usize,
    // Bitmasks selecting which participant identities each twin half can
    // exchange messages with. The masks may overlap.
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

    /// Returns recipient sets for each twin half at a given view.
    ///
    /// These sets are not required to be disjoint: if the same participant
    /// appears in both, both twin halves may exchange messages with that
    /// participant in the given view.
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
    /// Vecs by comparing bitmasks directly for inbound twin traffic. When a
    /// sender appears in both masks, this returns [`SplitTarget::Both`].
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

/// Routes a sender according to explicit primary and secondary recipient sets.
fn route_with_groups<P: PartialEq>(sender: &P, primary: &[P], secondary: &[P]) -> SplitTarget {
    let in_primary = primary.contains(sender);
    let in_secondary = secondary.contains(sender);
    match (in_primary, in_secondary) {
        (true, true) => SplitTarget::Both,
        (true, false) => SplitTarget::Primary,
        (false, true) => SplitTarget::Secondary,
        (false, false) => panic!("sender not in any partition"),
    }
}

/// Returns the strict disjoint split at index `view % n`.
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

/// Controls how multi-round scenarios are constructed.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Each round gets independently chosen primary and secondary recipient
    /// sets and a leader.
    Sampled,
    /// A single 1-round recipient-set pattern is repeated across all rounds,
    /// modeling a persistent adversarial split.
    Sustained,
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
/// [`Framework::max_cases`] caps the total emitted cases; the full scenario
/// space must fit within this budget (panics otherwise).
#[derive(Clone, Copy, Debug)]
pub struct Framework {
    /// Number of participants in the network.
    pub participants: usize,
    /// Number of compromised participants.
    pub faults: usize,
    /// Number of adversarial rounds before synchronous suffix.
    pub rounds: usize,
    /// How multi-round scenarios are constructed.
    pub mode: Mode,
    /// Upper bound on the total number of emitted cases (scenario x
    /// compromised-assignment pairs). Also used to cap the number of
    /// scenarios enumerated (since each scenario produces >= 1 case).
    /// When the scenario space exceeds this, scenarios are sampled
    /// uniformly without replacement; the resulting cases are then
    /// shuffled and truncated to this budget.
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

    let scenarios = match framework.mode {
        Mode::Sampled => generate_scenarios(
            rng,
            framework.participants,
            framework.rounds,
            framework.max_cases,
        ),
        Mode::Sustained => {
            // Generate 1-round scenarios and repeat across all rounds.
            // The 1-round residual cells are valid here because applying
            // the same recipient-set pattern repeatedly never distinguishes
            // participants that were indistinguishable after the first round.
            let single_round =
                generate_scenarios(rng, framework.participants, 1, framework.max_cases);
            single_round
                .into_iter()
                .map(|(s, cells)| {
                    let scenario = Scenario {
                        rounds: vec![s.rounds[0]; framework.rounds],
                    };
                    (scenario, cells)
                })
                .collect()
        }
    };

    let mut result: Vec<Case> = scenarios
        .iter()
        .flat_map(|(scenario, residual_cells)| {
            compromised_sets_for_cells(residual_cells, framework.faults)
                .into_iter()
                .map(move |compromised| Case {
                    compromised,
                    scenario: scenario.clone(),
                })
        })
        .collect();
    result.shuffle(rng);
    result.truncate(framework.max_cases);
    result
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

/// Converts twins routing bitmasks into concrete recipient sets.
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
/// Each round refines participants into up to 4 non-leader placements relative
/// to the primary and secondary recipient sets: outside both, shared by both
/// halves, primary-only, and secondary-only. The chosen leader is then
/// isolated into its own singleton cell and may be visible to either half or
/// both halves.
fn next_round_transitions(cells: &[usize]) -> Vec<(RoundScenario, Vec<usize>)> {
    // Accumulated state for a round where the secondary recipient set differs:
    // the masks built so far and leader.
    #[derive(Clone, Copy)]
    struct SecondaryState {
        primary_mask: u64,
        secondary_mask: u64,
        leader: Option<usize>,
    }

    const LEADER_PLACEMENTS: &[(bool, bool)] = &[(true, false), (false, true), (true, true)];

    fn push_nonzero_cells(next_cells: &mut Vec<usize>, sizes: [usize; 4]) {
        for size in sizes {
            if size > 0 {
                next_cells.push(size);
            }
        }
    }

    /// Refines cells for a round where both halves have identical recipient
    /// sets.
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
            // fully described by a single recipient mask.
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
        // non-leader members to the ordinary recipient-set buckets.
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

    /// Refines cells for a round where the halves have distinct recipient
    /// sets.
    fn with_secondary(
        ranges: &[(usize, usize)],
        leader_cell: usize,
        cell_idx: usize,
        state: SecondaryState,
        next_cells: &mut Vec<usize>,
        out: &mut Vec<(RoundScenario, Vec<usize>)>,
    ) {
        if cell_idx == ranges.len() {
            if state.primary_mask == state.secondary_mask {
                // Equal recipient masks are already emitted by
                // `no_secondary`, so skipping them here avoids duplicates.
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
            let remaining_after_outside = available - outside;
            for both in 0..=remaining_after_outside {
                let remaining = remaining_after_outside - both;
                for secondary in 0..=remaining {
                    // The canonical contiguous layout for a refined cell is:
                    // outside -> both-halves -> secondary-only -> primary-only
                    // -> leader.
                    let primary = remaining - secondary;
                    let checkpoint = next_cells.len();
                    push_nonzero_cells(next_cells, [outside, both, secondary, primary]);

                    let shared_mask = range_mask(start + outside, both);
                    let next_secondary = state.secondary_mask
                        | shared_mask
                        | range_mask(start + outside + both, secondary);
                    let next_primary = state.primary_mask
                        | shared_mask
                        | range_mask(start + outside + both + secondary, primary);
                    if has_leader {
                        // As in `no_secondary`, keep the leader as a singleton
                        // at the tail of its source cell's refined block.
                        // Enumerate all distinct twin-half placements so the
                        // leader may be isolated with either recipient set or
                        // bridge both halves when the masks differ.
                        let leader_idx = start + outside + both + secondary + primary;
                        next_cells.push(1);
                        for &(leader_in_primary, leader_in_secondary) in LEADER_PLACEMENTS {
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
                                    secondary_mask: if leader_in_secondary {
                                        next_secondary | leader_bit
                                    } else {
                                        next_secondary
                                    },
                                    leader: Some(leader_idx),
                                },
                                next_cells,
                                out,
                            );
                        }
                    } else {
                        with_secondary(
                            ranges,
                            leader_cell,
                            cell_idx + 1,
                            SecondaryState {
                                primary_mask: next_primary,
                                secondary_mask: next_secondary,
                                leader: state.leader,
                            },
                            next_cells,
                            out,
                        );
                    }
                    next_cells.truncate(checkpoint);
                }
            }
        }
    }

    let ranges = cells_to_ranges(cells);
    let mut out = Vec::new();
    for leader_cell in 0..cells.len() {
        // Any current symmetry cell may supply the next leader. Enumerate the
        // equal-recipient-set and split-recipient-set cases separately to keep
        // the output canonical and duplicate-free.
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

    // Floyd's algorithm: O(samples) time, no retry loop.
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

/// Enumerates canonical scenarios with their residual symmetry cells.
///
/// Returns all scenarios when the space fits within `max_scenarios`;
/// otherwise samples `max_scenarios` without replacement. Panics if the
/// scenario space overflows u128 and cannot be sampled.
fn generate_scenarios(
    rng: &mut impl Rng,
    n: usize,
    rounds: usize,
    max_scenarios: usize,
) -> Vec<(Scenario, Vec<usize>)> {
    let mut memo = HashMap::new();
    let initial_cells = vec![n];
    let total = canonical_scenario_count(&initial_cells, rounds, &mut memo)
        .expect("scenario space overflows u128; reduce rounds or participants");
    if total <= max_scenarios as u128 {
        return (0..total)
            .map(|idx| canonical_scenario_from_rank(&initial_cells, rounds, idx, &mut memo))
            .collect();
    }
    sample_unique_indices(rng, total, max_scenarios)
        .into_iter()
        .map(|idx| canonical_scenario_from_rank(&initial_cells, rounds, idx, &mut memo))
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
    use commonware_utils::{ordered::Set, test_rng, test_rng_seeded};
    use std::collections::HashSet;

    fn expected_single_round_transitions(n: usize) -> HashSet<(RoundScenario, Vec<usize>)> {
        let mut out = HashSet::new();

        for outside in 0..n {
            let both = n - outside - 1;
            let leader = outside + both;
            let leader_bit = 1u64 << leader;
            let mask = range_mask(outside, both) | leader_bit;

            let mut cells = Vec::new();
            if outside > 0 {
                cells.push(outside);
            }
            if both > 0 {
                cells.push(both);
            }
            cells.push(1);

            out.insert((
                RoundScenario {
                    leader,
                    primary_mask: mask,
                    secondary_mask: mask,
                },
                cells,
            ));
        }

        for outside in 0..n {
            let remaining_after_outside = n - outside - 1;
            for both in 0..=remaining_after_outside {
                let remaining = remaining_after_outside - both;
                for secondary in 0..=remaining {
                    let primary = remaining - secondary;
                    let leader = outside + both + secondary + primary;
                    let leader_bit = 1u64 << leader;
                    let shared_mask = range_mask(outside, both);
                    let secondary_mask = shared_mask | range_mask(outside + both, secondary);
                    let primary_mask =
                        shared_mask | range_mask(outside + both + secondary, primary);

                    let mut cells = Vec::new();
                    if outside > 0 {
                        cells.push(outside);
                    }
                    if both > 0 {
                        cells.push(both);
                    }
                    if secondary > 0 {
                        cells.push(secondary);
                    }
                    if primary > 0 {
                        cells.push(primary);
                    }
                    cells.push(1);

                    out.insert((
                        RoundScenario {
                            leader,
                            primary_mask: primary_mask | leader_bit,
                            secondary_mask,
                        },
                        cells.clone(),
                    ));
                    out.insert((
                        RoundScenario {
                            leader,
                            primary_mask,
                            secondary_mask: secondary_mask | leader_bit,
                        },
                        cells.clone(),
                    ));
                    out.insert((
                        RoundScenario {
                            leader,
                            primary_mask: primary_mask | leader_bit,
                            secondary_mask: secondary_mask | leader_bit,
                        },
                        cells,
                    ));
                }
            }
        }

        out
    }

    #[test]
    fn generated_cases_are_deterministic() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            mode: Mode::Sampled,
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
    fn generated_scenarios_include_shared_non_leaders_in_split_rounds() {
        let scenarios = generate_scenarios(&mut test_rng(), 5, 1, usize::MAX);
        assert!(scenarios.iter().any(|(scenario, _)| {
            let round = scenario.rounds[0];
            let leader_bit = 1u64 << round.leader;
            let shared_non_leaders = (round.primary_mask & round.secondary_mask) & !leader_bit;
            let primary_only = round.primary_mask & !round.secondary_mask;
            let secondary_only = round.secondary_mask & !round.primary_mask;
            shared_non_leaders != 0 && primary_only != 0 && secondary_only != 0
        }));
    }

    #[test]
    fn generated_scenarios_include_shared_non_leaders_when_only_leader_splits_halves() {
        let scenarios = generate_scenarios(&mut test_rng(), 4, 1, usize::MAX);
        assert!(scenarios.iter().any(|(scenario, _)| {
            let round = scenario.rounds[0];
            let leader_bit = 1u64 << round.leader;
            let shared_non_leaders = (round.primary_mask & round.secondary_mask) & !leader_bit;
            let primary_only_non_leaders =
                (round.primary_mask & !round.secondary_mask) & !leader_bit;
            let secondary_only_non_leaders =
                (round.secondary_mask & !round.primary_mask) & !leader_bit;
            shared_non_leaders != 0
                && primary_only_non_leaders == 0
                && secondary_only_non_leaders == 0
                && round.primary_mask != round.secondary_mask
        }));
    }

    #[test]
    fn generated_single_round_scenarios_match_expected_canonical_space() {
        let generated: HashSet<_> = generate_scenarios(&mut test_rng(), 4, 1, usize::MAX)
            .into_iter()
            .map(|(scenario, cells)| (scenario.rounds[0], cells))
            .collect();
        assert_eq!(generated, expected_single_round_transitions(4));
    }

    #[test]
    fn scripted_partitions_preserve_participant_order_and_overlap() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 3,
                primary_mask: 0b1011,
                secondary_mask: 0b0110,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();
        let (primary, secondary) = scenario.partitions(View::new(1), &participants);

        assert_eq!(primary, vec![0, 1, 3]);
        assert_eq!(secondary, vec![1, 2]);
    }

    #[test]
    fn route_with_groups_covers_reachable_split_targets() {
        let primary = vec![1u32, 2];
        let secondary = vec![2u32, 3];

        assert_eq!(
            route_with_groups(&2, &primary, &secondary),
            SplitTarget::Both
        );
        assert_eq!(
            route_with_groups(&1, &primary, &secondary),
            SplitTarget::Primary
        );
        assert_eq!(
            route_with_groups(&3, &primary, &secondary),
            SplitTarget::Secondary
        );
    }

    #[test]
    #[should_panic(expected = "sender not in any partition")]
    fn route_with_groups_panics_when_sender_is_missing() {
        let primary = vec![1u32, 2];
        let secondary = vec![2u32, 3];

        let _ = route_with_groups(&0, &primary, &secondary);
    }

    #[test]
    fn view_helpers_follow_modulo_split() {
        let participants: Vec<u32> = (0..4).collect();

        assert_eq!(
            view_partitions(View::new(1), &participants),
            (vec![0], vec![1, 2, 3])
        );
        assert_eq!(
            view_partitions(View::new(4), &participants),
            (Vec::<u32>::new(), participants.clone())
        );
        assert_eq!(
            view_route(View::new(1), &0, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            view_route(View::new(1), &3, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            view_route(View::new(4), &0, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn route_supports_shared_non_leaders_in_split_rounds() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 4,
                primary_mask: 0b11010,
                secondary_mask: 0b00110,
            }],
        };
        let participants: Vec<u32> = (0..5).collect();
        assert_eq!(
            scenario.route(View::new(1), &0, &participants),
            SplitTarget::None
        );
        assert_eq!(
            scenario.route(View::new(1), &1, &participants),
            SplitTarget::Both
        );
        assert_eq!(
            scenario.route(View::new(1), &2, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            scenario.route(View::new(1), &3, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            scenario.route(View::new(1), &4, &participants),
            SplitTarget::Primary
        );
    }

    #[test]
    fn leader_visible_to_both_halves_preserves_partitions_and_route() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 3,
                primary_mask: 0b1010,
                secondary_mask: 0b1100,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();
        let (primary, secondary) = scenario.partitions(View::new(1), &participants);

        assert_eq!(primary, vec![1, 3]);
        assert_eq!(secondary, vec![2, 3]);
        assert_eq!(
            scenario.route(View::new(1), &3, &participants),
            SplitTarget::Both
        );
    }

    #[test]
    fn generated_split_round_leaders_belong_to_at_least_one_half() {
        let scenarios = generate_scenarios(&mut test_rng(), 4, 2, usize::MAX);
        for (scenario, _) in scenarios {
            for round in scenario.rounds {
                if round.primary_mask == round.secondary_mask {
                    continue;
                }
                let leader_bit = 1u64 << round.leader;
                let leader_in_primary = (round.primary_mask & leader_bit) != 0;
                let leader_in_secondary = (round.secondary_mask & leader_bit) != 0;
                assert!(leader_in_primary || leader_in_secondary);
            }
        }
    }

    #[test]
    fn generated_split_rounds_include_leaders_visible_to_both_halves() {
        let scenarios = generate_scenarios(&mut test_rng(), 4, 1, usize::MAX);
        assert!(scenarios.iter().any(|(scenario, _)| {
            let round = scenario.rounds[0];
            if round.primary_mask == round.secondary_mask {
                return false;
            }
            let leader_bit = 1u64 << round.leader;
            (round.primary_mask & leader_bit) != 0 && (round.secondary_mask & leader_bit) != 0
        }));
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
    fn route_returns_both_after_scripted_rounds() {
        let scenario = Scenario {
            rounds: vec![RoundScenario {
                leader: 0,
                primary_mask: 0b0011,
                secondary_mask: 0b1100,
            }],
        };
        let participants: Vec<u32> = (0..4).collect();

        for participant in &participants {
            assert_eq!(
                scenario.route(View::new(2), participant, &participants),
                SplitTarget::Both
            );
        }
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
    fn sustained_cases_repeat_single_round() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            mode: Mode::Sustained,
            max_cases: 50,
        };
        let all = cases(&mut test_rng(), framework);
        assert!(!all.is_empty());
        for case in &all {
            let rounds = case.scenario.rounds();
            assert_eq!(rounds.len(), 3);
            assert_eq!(rounds[0], rounds[1]);
            assert_eq!(rounds[1], rounds[2]);
        }
    }

    #[test]
    #[should_panic(expected = "scenario space overflows u128")]
    fn cases_panic_on_scenario_overflow() {
        let _ = cases(
            &mut test_rng(),
            Framework {
                participants: 4,
                faults: 1,
                rounds: 40,
                mode: Mode::Sampled,
                max_cases: 1,
            },
        );
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
    fn cases_fewer_than_naive_cross_product() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 1,
            mode: Mode::Sampled,
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
    #[should_panic(expected = "participants must fit in u64 masks")]
    fn cases_reject_frameworks_that_exceed_mask_width() {
        let _ = cases(
            &mut test_rng(),
            Framework {
                participants: (u64::BITS as usize) + 1,
                faults: 1,
                rounds: 1,
                mode: Mode::Sampled,
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
            mode: Mode::Sampled,
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
