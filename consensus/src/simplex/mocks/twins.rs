//! Twins framework scenario generator and executor helpers.
//!
//! This module follows the testing architecture from
//! [Twins: BFT Systems Made Robust](https://arxiv.org/pdf/2004.10617):
//! 1. Generate partition scenarios.
//! 2. Combine partitions with leader assignments per round.
//! 3. Arrange those round choices into full multi-round scenarios.
//! 4. Execute each scenario across compromised-node assignments.

use crate::{
    simplex::elector::{Config as ElectorConfig, Elector as Elected},
    types::{Participant, Round, View},
};
use commonware_cryptography::{certificate::Scheme, PublicKey};
use commonware_p2p::{
    simulated::{SplitOrigin, SplitTarget},
    Recipients,
};
use commonware_runtime::IoBuf;
use commonware_utils::{ordered::Set, test_rng_seeded};
use rand::{rngs::StdRng, Rng};
use std::{collections::HashSet, sync::Arc};

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
#[derive(Clone, Debug, Eq, PartialEq)]
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
                .position(|participant| participant == sender);
            assert!(
                sender_idx.is_some(),
                "sender missing from runtime participant list"
            );
            let Some(sender_idx) = sender_idx else {
                return SplitTarget::None;
            };
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

/// Drop resolver sends for twins.
///
/// Twins currently model resolver connectivity as unavailable under partition.
pub fn blackhole_resolver_forwarder<P: PublicKey>(
    _: SplitOrigin,
    _: &Recipients<P>,
    _: &IoBuf,
) -> Option<Recipients<P>> {
    None
}

/// Drop resolver receives for twins.
///
/// Twins currently model resolver connectivity as unavailable under partition.
pub fn blackhole_resolver_router<P: PublicKey>(_: &(P, IoBuf)) -> SplitTarget {
    SplitTarget::None
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
pub fn cases(seed: u64, framework: Framework) -> Vec<Case> {
    assert!(framework.participants > 1, "participants must be > 1");
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
        seed ^ 0xDEAD_BEEF,
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
                scenario: scenario.clone(),
                seed: case_seed,
            });
        }
    }
    out
}

fn partition_for_mask<P: Clone>(mask: u64, participants: &[P]) -> Vec<P> {
    let mut group = Vec::new();
    for (idx, participant) in participants.iter().enumerate() {
        if (mask & (1u64 << idx)) != 0 {
            group.push(participant.clone());
        }
    }
    group
}

fn masks_to_partitions<P: Clone>(
    primary_mask: u64,
    secondary_mask: u64,
    participants: &[P],
) -> (Vec<P>, Vec<P>) {
    let primary = partition_for_mask(primary_mask, participants);
    let secondary = partition_for_mask(secondary_mask, participants);
    (primary, secondary)
}

fn checked_pow(base: u128, exp: usize) -> Option<u128> {
    let mut total = 1u128;
    for _ in 0..exp {
        total = total.checked_mul(base)?;
    }
    Some(total)
}

fn round_scenario_count(n: usize, max_partitions: usize) -> u128 {
    assert!(n > 1, "n must be > 1");
    assert!(
        n < u64::BITS as usize,
        "mask representation supports fewer than 64 participants"
    );
    assert!(max_partitions > 1, "max_partitions must be > 1");
    assert!(
        max_partitions <= n,
        "max_partitions must be less than or equal to n"
    );

    // Round scenarios only observe the leader's partition, the secondary
    // partition, and whether any participants remain outside those groups.
    let effective_partitions = max_partitions.min(3);
    let per_leader = if effective_partitions == 2 {
        (1u128 << n) - 1
    } else {
        checked_pow(3, n - 1).expect("round scenario count overflow")
    };
    (n as u128)
        .checked_mul(per_leader)
        .expect("round scenario count overflow")
}

fn round_scenario(n: usize, max_partitions: usize, idx: u128) -> RoundScenario {
    let total = round_scenario_count(n, max_partitions);
    assert!(idx < total, "round scenario index out of bounds");

    let effective_partitions = max_partitions.min(3);
    let per_leader = if effective_partitions == 2 {
        (1u128 << n) - 1
    } else {
        checked_pow(3, n - 1).expect("round scenario count overflow")
    };

    let leader = usize::try_from(idx / per_leader).expect("leader index should fit in usize");
    let mut local = idx % per_leader;
    let leader_bit = 1u64 << leader;
    let mut primary_mask = leader_bit;

    if effective_partitions == 2 {
        let same_partition = 1u128 << (n - 1);
        if local < same_partition {
            for participant in 0..n {
                if participant == leader {
                    continue;
                }
                if (local & 1) == 0 {
                    primary_mask |= 1u64 << participant;
                }
                local >>= 1;
            }
            return RoundScenario {
                leader,
                primary_mask,
                secondary_mask: primary_mask,
            };
        }

        let mut assignment = (local - same_partition) + 1;
        let mut secondary_mask = 0u64;
        for participant in 0..n {
            if participant == leader {
                continue;
            }
            if (assignment & 1) == 0 {
                primary_mask |= 1u64 << participant;
            } else {
                secondary_mask |= 1u64 << participant;
            }
            assignment >>= 1;
        }
        return RoundScenario {
            leader,
            primary_mask,
            secondary_mask,
        };
    }

    let mut secondary_mask = 0u64;
    let mut saw_secondary = false;
    for participant in 0..n {
        if participant == leader {
            continue;
        }
        match local % 3 {
            0 => primary_mask |= 1u64 << participant,
            1 => {
                saw_secondary = true;
                secondary_mask |= 1u64 << participant;
            }
            2 => {}
            _ => unreachable!("ternary digit must be in range"),
        }
        local /= 3;
    }
    RoundScenario {
        leader,
        primary_mask,
        secondary_mask: if saw_secondary {
            secondary_mask
        } else {
            primary_mask
        },
    }
}

#[cfg(test)]
fn round_scenarios(n: usize, max_partitions: usize) -> Vec<RoundScenario> {
    let total = round_scenario_count(n, max_partitions);
    let total = usize::try_from(total).expect("too many round scenarios to materialize");
    (0..total)
        .map(|idx| round_scenario(n, max_partitions, idx as u128))
        .collect()
}

fn index_to_round_scenarios(
    mut idx: u128,
    base: u128,
    rounds: usize,
    n: usize,
    max_partitions: usize,
) -> Vec<RoundScenario> {
    let mut digits = vec![0u128; rounds];
    for digit in digits.iter_mut().rev() {
        *digit = idx % base;
        idx /= base;
    }
    digits
        .into_iter()
        .map(|digit| round_scenario(n, max_partitions, digit))
        .collect()
}

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
    seed ^ u64::try_from(case_idx).expect("case index should fit in u64")
}

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

fn generate_scenarios(
    seed: u64,
    n: usize,
    rounds: usize,
    max_partitions: usize,
    max_scenarios: usize,
) -> Vec<Scenario> {
    let mut rng = test_rng_seeded(seed);
    let base = round_scenario_count(n, max_partitions);
    if let Some(total) = checked_pow(base, rounds) {
        if total <= max_scenarios as u128 {
            return (0..total)
                .map(|idx| Scenario {
                    rounds: index_to_round_scenarios(idx, base, rounds, n, max_partitions),
                })
                .collect();
        }

        // Deterministically sample unique arrangement indices instead of taking
        // a lexicographic prefix, while keeping generation bounded by
        // `max_scenarios`.
        return sample_unique_indices(&mut rng, total as u128, max_scenarios)
            .into_iter()
            .map(|idx| Scenario {
                rounds: index_to_round_scenarios(idx, base, rounds, n, max_partitions),
            })
            .collect();
    }

    // Extremely large spaces can overflow arrangement counts; sample directly
    // from the per-round option product while enforcing uniqueness.
    let mut scenarios = Vec::with_capacity(max_scenarios);
    let mut seen = HashSet::new();
    let max_attempts = max_scenarios.saturating_mul(64).max(1024);
    let mut attempts = 0usize;
    while scenarios.len() < max_scenarios && attempts < max_attempts {
        attempts += 1;
        let digits: Vec<u128> = (0..rounds).map(|_| rng.gen_range(0..base)).collect();
        if seen.insert(digits.clone()) {
            scenarios.push(Scenario {
                rounds: digits
                    .into_iter()
                    .map(|digit| round_scenario(n, max_partitions, digit))
                    .collect(),
            });
        }
    }
    assert_eq!(
        scenarios.len(),
        max_scenarios,
        "failed to sample enough unique scenarios in fallback path"
    );
    scenarios
}

fn compromised_sets(seed: u64, n: usize, faults: usize, max_sets: usize) -> Vec<Vec<usize>> {
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

    #[test]
    fn cases_cover_all_compromised_nodes_for_n5_f1() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            max_partitions: 3,
            max_scenarios: 3,
            max_compromised_sets: 5,
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
        assert_eq!(scenarios.len(), 8);
    }

    #[test]
    fn round_scenarios_expand_with_additional_partition_counts() {
        let two_way = round_scenarios(5, 2);
        let up_to_three_way = round_scenarios(5, 3);
        assert!(up_to_three_way.len() > two_way.len());
    }

    #[test]
    fn generated_scenarios_cover_full_permutation_space_when_unbounded() {
        // n=3 with up to two-way partitions now includes full broadcast, so
        // there are 21 round options. Over 2 rounds, the full arrangement
        // count is 21^2 = 441.
        let scenarios = generate_scenarios(0, 3, 2, 2, 1000);
        assert_eq!(scenarios.len(), 441);
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
    fn round_scenarios_include_full_broadcast() {
        let full = (1u64 << 5) - 1;
        assert!(round_scenarios(5, 3)
            .into_iter()
            .any(|round| { round.primary_mask == full && round.secondary_mask == full }));
    }

    #[test]
    fn round_scenarios_cover_all_leaders() {
        let leaders: HashSet<_> = round_scenarios(10, 3)
            .into_iter()
            .map(|round| round.leader())
            .collect();
        assert_eq!(leaders, (0..10).collect());
    }

    #[test]
    fn round_scenarios_saturate_after_three_partitions() {
        assert_eq!(round_scenarios(6, 3), round_scenarios(6, 6));
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
