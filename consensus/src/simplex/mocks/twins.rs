//! Twins framework scenario generator and executor helpers.
//!
//! This module follows the testing architecture from
//! [Twins: BFT Systems Made Robust](https://arxiv.org/pdf/2004.10617):
//! 1. Generate partition scenarios.
//! 2. Combine partitions with leader assignments per round.
//! 3. Arrange those round choices into full multi-round scenarios.
//! 4. Execute each scenario across compromised-node assignments.

use crate::types::View;
use commonware_p2p::simulated::SplitTarget;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeSet, HashSet};

/// Per-round adversarial setting from the Twins framework.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoundScenario {
    leader: usize,
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
    pub fn route<P: Clone + PartialEq>(
        &self,
        view: View,
        sender: &P,
        participants: &[P],
    ) -> SplitTarget {
        let (primary, secondary) = self.partitions(view, participants);
        route_with_groups(sender, &primary, &secondary)
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

/// Splits participants by `view % n` to mirror the legacy twins `View` strategy.
pub fn view_partitions<P: Clone>(view: View, participants: &[P]) -> (Vec<P>, Vec<P>) {
    let split = (view.get() as usize) % participants.len();
    let (primary, secondary) = participants.split_at(split);
    (primary.to_vec(), secondary.to_vec())
}

/// Routes a sender using the legacy twins `View` strategy.
pub fn view_route<P: Clone + PartialEq>(view: View, sender: &P, participants: &[P]) -> SplitTarget {
    let (primary, secondary) = view_partitions(view, participants);
    route_with_groups(sender, &primary, &secondary)
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
            let case_seed = seed ^ ((compromised_idx as u64) << 32) ^ ((scenario_idx as u64) << 16);
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

fn partition_scenarios(n: usize, max_partitions: usize) -> Vec<Vec<usize>> {
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

    fn generate(
        idx: usize,
        n: usize,
        used: usize,
        max_partitions: usize,
        current: &mut [usize],
        out: &mut Vec<Vec<usize>>,
    ) {
        if idx == n {
            if used > 1 {
                out.push(current.to_vec());
            }
            return;
        }
        for partition in 0..used {
            current[idx] = partition;
            generate(idx + 1, n, used, max_partitions, current, out);
        }
        if used < max_partitions {
            current[idx] = used;
            generate(idx + 1, n, used + 1, max_partitions, current, out);
        }
    }

    let mut out = Vec::new();
    let mut current = vec![0usize; n];
    generate(1, n, 1, max_partitions, &mut current, &mut out);
    out
}

fn round_scenarios(n: usize, max_partitions: usize) -> Vec<RoundScenario> {
    let partitions = partition_scenarios(n, max_partitions);
    let mut scenarios = BTreeSet::new();

    for partition in partitions.iter() {
        let partition_count = partition.iter().copied().max().unwrap_or(0) + 1;
        let mut masks = vec![0u64; partition_count];
        for (participant_idx, partition_idx) in partition.iter().copied().enumerate() {
            masks[partition_idx] |= 1u64 << participant_idx;
        }

        for (leader, primary_idx) in partition.iter().copied().enumerate() {
            for secondary_idx in 0..partition_count {
                scenarios.insert(RoundScenario {
                    leader,
                    primary_mask: masks[primary_idx],
                    secondary_mask: masks[secondary_idx],
                });
            }
        }
    }

    scenarios.into_iter().collect()
}

fn index_to_round_scenarios(
    mut idx: usize,
    base: usize,
    rounds: usize,
    options: &[RoundScenario],
) -> Vec<RoundScenario> {
    let mut digits = vec![0usize; rounds];
    for digit in digits.iter_mut().rev() {
        *digit = idx % base;
        idx /= base;
    }
    digits.into_iter().map(|digit| options[digit]).collect()
}

fn arrangement_count(base: usize, rounds: usize) -> Option<usize> {
    let mut total = 1usize;
    for _ in 0..rounds {
        total = total.checked_mul(base)?;
    }
    Some(total)
}

fn generate_scenarios(
    seed: u64,
    n: usize,
    rounds: usize,
    max_partitions: usize,
    max_scenarios: usize,
) -> Vec<Scenario> {
    let options = round_scenarios(n, max_partitions);
    if options.is_empty() {
        return Vec::new();
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let base = options.len();
    if let Some(total) = arrangement_count(base, rounds) {
        if total <= max_scenarios {
            return (0..total)
                .map(|idx| Scenario {
                    rounds: index_to_round_scenarios(idx, base, rounds, &options),
                })
                .collect();
        }

        // Deterministically prune by sampling unique arrangement indices instead
        // of taking a lexicographic prefix.
        let mut seen = HashSet::new();
        let mut sampled = Vec::with_capacity(max_scenarios);
        while sampled.len() < max_scenarios {
            let idx = rng.gen_range(0..total);
            if seen.insert(idx) {
                sampled.push(idx);
            }
        }
        return sampled
            .into_iter()
            .map(|idx| Scenario {
                rounds: index_to_round_scenarios(idx, base, rounds, &options),
            })
            .collect();
    }

    // Extremely large spaces can overflow arrangement counts; sample directly
    // from the per-round option product while enforcing uniqueness.
    let mut scenarios = Vec::with_capacity(max_scenarios);
    let mut seen = HashSet::new();
    while scenarios.len() < max_scenarios {
        let digits: Vec<usize> = (0..rounds).map(|_| rng.gen_range(0..base)).collect();
        if seen.insert(digits.clone()) {
            scenarios.push(Scenario {
                rounds: digits.into_iter().map(|digit| options[digit]).collect(),
            });
        }
    }
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

    let mut all = Vec::new();
    choose(0, n, faults, &mut Vec::new(), &mut all);
    if all.len() <= max_sets {
        return all;
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let mut picked = HashSet::new();
    let mut sampled = Vec::new();
    while sampled.len() < max_sets {
        let idx = rng.gen_range(0..all.len());
        if picked.insert(idx) {
            sampled.push(all[idx].clone());
        }
    }
    sampled
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn round_scenarios_expand_with_additional_partition_counts() {
        let two_way = round_scenarios(5, 2);
        let up_to_three_way = round_scenarios(5, 3);
        assert!(up_to_three_way.len() > two_way.len());
    }

    #[test]
    fn generated_scenarios_cover_full_permutation_space_when_unbounded() {
        // n=3 with up to two-way partitions has 18 round options.
        // Over 2 rounds, full permutation count is 18^2 = 324.
        let scenarios = generate_scenarios(0, 3, 2, 2, 1000);
        assert_eq!(scenarios.len(), 324);
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
}
