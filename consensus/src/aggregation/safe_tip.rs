use crate::types::Height;
use commonware_cryptography::PublicKey;
use commonware_utils::{N3f1, ordered::Committee};
use std::{
    collections::{BTreeMap, HashMap, btree_map::Entry},
    ops::Bound::{Excluded, Unbounded},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tip {
    height: Height,
    weight: u64,
}

/// Tracks the greatest height reported by more than the maximum faulty weight.
pub struct SafeTip<P: PublicKey> {
    tips: HashMap<P, Tip>,
    /// Total committee weight at each reported height.
    heights: BTreeMap<Height, u64>,
    /// Greatest height reported by more than the maximum faulty weight.
    safe: Height,
    /// Total committee weight strictly above `safe`.
    above_safe: u64,
    max_fault_weight: u64,
}

impl<P: PublicKey> Default for SafeTip<P> {
    fn default() -> Self {
        Self {
            tips: HashMap::new(),
            heights: BTreeMap::new(),
            safe: Height::zero(),
            above_safe: 0,
            max_fault_weight: 0,
        }
    }
}

impl<P: PublicKey> SafeTip<P> {
    /// Initializes an instance with the given committee.
    pub fn init(&mut self, committee: &Committee<P>) {
        self.tips.clear();
        self.reconcile(committee);
    }

    /// Updates the committee, preserving retained participants' heights.
    pub fn reconcile(&mut self, committee: &Committee<P>) {
        let tips = committee
            .iter()
            .zip(committee.weights())
            .map(|(participant, &weight)| {
                let height = self
                    .tips
                    .get(participant)
                    .map_or(Height::zero(), |tip| tip.height);
                (participant.clone(), Tip { height, weight })
            })
            .collect::<HashMap<_, _>>();

        let mut heights = BTreeMap::new();
        for tip in tips.values() {
            let weight = heights.entry(tip.height).or_insert(0u64);
            *weight = weight
                .checked_add(tip.weight)
                .expect("height weight overflow");
        }

        let max_fault_weight = committee.max_fault_weight::<N3f1>();
        let mut above_safe = 0u64;
        let safe = heights
            .iter()
            .rev()
            .find_map(|(&height, &weight)| {
                if above_safe
                    .checked_add(weight)
                    .expect("height weight overflow")
                    > max_fault_weight
                {
                    return Some(height);
                }
                above_safe = above_safe
                    .checked_add(weight)
                    .expect("height weight overflow");
                None
            })
            .expect("empty committee");

        self.tips = tips;
        self.heights = heights;
        self.safe = safe;
        self.above_safe = above_safe;
        self.max_fault_weight = max_fault_weight;
    }

    /// Updates a participant's tip, returning its previous height.
    ///
    /// Returns `None` for an unknown participant or a non-increasing update.
    pub fn update(&mut self, public_key: P, new: Height) -> Option<Height> {
        let &Tip {
            height: old,
            weight,
        } = self.tips.get(&public_key)?;
        if old >= new {
            return None;
        }

        self.tips.insert(
            public_key,
            Tip {
                height: new,
                weight,
            },
        );

        match self.heights.entry(old) {
            Entry::Occupied(mut entry) => {
                let remaining = entry
                    .get()
                    .checked_sub(weight)
                    .expect("insufficient height weight");
                if remaining == 0 {
                    entry.remove();
                } else {
                    *entry.get_mut() = remaining;
                }
            }
            Entry::Vacant(_) => panic!("cannot remove missing height weight"),
        }
        let new_weight = self.heights.entry(new).or_insert(0);
        *new_weight = new_weight
            .checked_add(weight)
            .expect("height weight overflow");

        if old <= self.safe && new > self.safe {
            self.above_safe = self
                .above_safe
                .checked_add(weight)
                .expect("height weight overflow");
        }
        while self.above_safe > self.max_fault_weight {
            let (&next, &weight) = self
                .heights
                .range((Excluded(self.safe), Unbounded))
                .next()
                .expect("weight above safe height must have a reported height");
            self.safe = next;
            self.above_safe = self
                .above_safe
                .checked_sub(weight)
                .expect("height weight underflow");
        }
        Some(old)
    }

    /// Returns the greatest height reached by weight greater than `f`.
    pub const fn get(&self) -> Height {
        self.safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{TryCollect, test_rng};
    use rand::RngExt as _;

    fn key(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn committee(entries: &[(u64, u64)]) -> Committee<PublicKey> {
        entries
            .iter()
            .map(|&(seed, weight)| (key(seed), weight))
            .try_collect()
            .unwrap()
    }

    fn setup(entries: &[(u64, u64)]) -> (SafeTip<PublicKey>, Committee<PublicKey>) {
        let committee = committee(entries);
        let mut safe_tip = SafeTip::default();
        safe_tip.init(&committee);
        (safe_tip, committee)
    }

    fn oracle(committee: &Committee<PublicKey>, heights: &HashMap<PublicKey, Height>) -> Height {
        let f = committee.max_fault_weight::<N3f1>();
        heights
            .values()
            .copied()
            .filter(|&candidate| {
                committee
                    .iter()
                    .zip(committee.weights())
                    .filter(|(participant, _)| heights[*participant] >= candidate)
                    .fold(0u64, |weight, (_, participant_weight)| {
                        weight.checked_add(*participant_weight).unwrap()
                    })
                    > f
            })
            .max()
            .unwrap()
    }

    fn assert_invariants(safe_tip: &SafeTip<PublicKey>) {
        let expected = safe_tip.tips.values().map(|tip| tip.weight).sum::<u64>();
        assert_eq!(safe_tip.heights.values().sum::<u64>(), expected);
        assert!(safe_tip.heights.values().all(|&weight| weight > 0));
        assert_eq!(
            safe_tip
                .heights
                .range((Excluded(safe_tip.safe), Unbounded))
                .map(|(_, weight)| weight)
                .sum::<u64>(),
            safe_tip.above_safe
        );
    }

    #[test]
    fn uniform_weights_match_count_based_safe_tip() {
        for count in 1..=8 {
            let entries = (1..=count).map(|seed| (seed, 1)).collect::<Vec<_>>();
            let (mut safe_tip, committee) = setup(&entries);
            let mut heights = committee
                .iter()
                .cloned()
                .map(|participant| (participant, Height::zero()))
                .collect::<HashMap<_, _>>();

            for (index, participant) in committee.iter().cloned().enumerate() {
                let height = Height::new((index + 1) as u64);
                safe_tip.update(participant.clone(), height);
                heights.insert(participant, height);
                assert_eq!(safe_tip.get(), oracle(&committee, &heights));
            }
        }
    }

    #[test]
    fn participant_weight_can_span_the_safe_tip_boundary() {
        let (mut safe_tip, committee) = setup(&[(1, 5), (2, 2), (3, 1)]);
        let heavy = committee
            .iter()
            .find(|participant| committee.weights()[committee.position(participant).unwrap()] == 5)
            .unwrap()
            .clone();

        safe_tip.update(heavy, Height::new(10));

        assert_eq!(safe_tip.get(), Height::new(10));
        assert_eq!(safe_tip.heights[&Height::new(10)], 5);
    }

    #[test]
    fn weighted_safety_uses_weight_strictly_greater_than_f() {
        let (mut safe_tip, committee) = setup(&[(1, 3), (2, 2), (3, 2)]);
        let mut by_weight = committee
            .iter()
            .cloned()
            .zip(committee.weights().iter().copied())
            .collect::<Vec<_>>();
        by_weight.sort_by_key(|(_, weight)| *weight);

        safe_tip.update(by_weight[0].0.clone(), Height::new(100));
        assert_eq!(safe_tip.get(), Height::zero());
        safe_tip.update(by_weight[2].0.clone(), Height::new(20));
        assert_eq!(safe_tip.get(), Height::new(20));
    }

    #[test]
    fn reconcile_applies_weight_changes_without_losing_heights() {
        let (mut safe_tip, old) = setup(&[(1, 1), (2, 1), (3, 1), (4, 1)]);
        for (index, participant) in old.iter().cloned().enumerate() {
            safe_tip.update(participant, Height::new((index + 1) as u64 * 10));
        }
        let highest = old.iter().last().unwrap().clone();
        let changed = old
            .iter()
            .map(|participant| {
                (
                    participant.clone(),
                    if participant == &highest { 4 } else { 1 },
                )
            })
            .try_collect::<Committee<_>>()
            .unwrap();

        safe_tip.reconcile(&changed);

        assert_eq!(safe_tip.tips[&highest].height, Height::new(40));
        assert_eq!(safe_tip.tips[&highest].weight, 4);
        assert_eq!(safe_tip.get(), Height::new(40));
    }

    #[test]
    fn reconcile_supports_committee_size_changes() {
        let (mut safe_tip, old) = setup(&[(1, 1), (2, 1), (3, 1), (4, 1)]);
        for participant in old.iter().cloned() {
            safe_tip.update(participant, Height::new(10));
        }
        let retained = old.iter().skip(2).cloned().collect::<Vec<_>>();
        let smaller = vec![
            (retained[0].clone(), 1),
            (retained[1].clone(), 1),
            (key(5), 2),
        ]
        .try_into()
        .unwrap();

        safe_tip.reconcile(&smaller);

        assert_eq!(safe_tip.tips[&retained[0]].height, Height::new(10));
        assert_eq!(safe_tip.tips[&retained[1]].height, Height::new(10));
        assert_eq!(safe_tip.tips[&key(5)].height, Height::zero());
        assert_eq!(safe_tip.get(), Height::new(10));

        let larger = vec![
            (retained[0].clone(), 1),
            (retained[1].clone(), 1),
            (key(5), 2),
            (key(6), 4),
            (key(7), 4),
        ]
        .try_into()
        .unwrap();
        safe_tip.reconcile(&larger);

        assert_eq!(safe_tip.tips[&retained[0]].height, Height::new(10));
        assert_eq!(safe_tip.tips[&retained[1]].height, Height::new(10));
        assert_eq!(safe_tip.tips[&key(5)].height, Height::zero());
        assert_eq!(safe_tip.tips[&key(6)].height, Height::zero());
        assert_eq!(safe_tip.tips[&key(7)].height, Height::zero());
        assert_eq!(safe_tip.get(), Height::zero());
    }

    #[test]
    fn zero_fault_weight_tracks_the_highest_tip() {
        let (mut safe_tip, committee) = setup(&[(1, 1), (2, 1), (3, 1)]);
        assert_eq!(safe_tip.max_fault_weight, 0);

        safe_tip.update(committee[0].clone(), Height::new(4));
        safe_tip.update(committee[1].clone(), Height::new(9));
        assert_eq!(safe_tip.get(), Height::new(9));
    }

    #[test]
    fn rejects_unknown_and_non_increasing_updates() {
        let (mut safe_tip, committee) = setup(&[(1, 1), (2, 1), (3, 1), (4, 1)]);
        assert_eq!(safe_tip.update(key(99), Height::new(1)), None);
        assert_eq!(
            safe_tip.update(committee[0].clone(), Height::new(5)),
            Some(Height::zero())
        );
        assert_eq!(safe_tip.update(committee[0].clone(), Height::new(5)), None);
        assert_eq!(safe_tip.update(committee[0].clone(), Height::new(4)), None);
    }

    #[test]
    fn matches_small_brute_force_oracle() {
        let (mut safe_tip, committee) = setup(&[(1, 1), (2, 2), (3, 3)]);
        let participants = committee.iter().cloned().collect::<Vec<_>>();
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        for first in 0..=3 {
            for second in 0..=3 {
                for third in 0..=3 {
                    let values = [first, second, third];
                    let mut heights = HashMap::new();
                    for (participant, &value) in participants.iter().zip(&values) {
                        let height = Height::new(value);
                        heights.insert(participant.clone(), height);
                    }

                    for order in orders {
                        safe_tip.init(&committee);
                        for index in order {
                            let value = values[index];
                            if value > 0 {
                                safe_tip.update(participants[index].clone(), Height::new(value));
                            }
                        }
                        assert_eq!(safe_tip.get(), oracle(&committee, &heights));
                        assert_invariants(&safe_tip);
                    }
                }
            }
        }
    }

    #[test]
    fn randomized_updates_and_reconciles_match_oracle() {
        let mut rng = test_rng();
        let entries = (1..=32)
            .map(|seed| (seed, rng.random_range(1..=20)))
            .collect::<Vec<_>>();
        let (mut safe_tip, mut committee) = setup(&entries);
        let mut heights = committee
            .iter()
            .cloned()
            .map(|participant| (participant, Height::zero()))
            .collect::<HashMap<_, _>>();

        for step in 0..500 {
            if step > 0 && step % 100 == 0 {
                let (start, count) = match step {
                    100 => (1, 24),
                    200 => (1, 40),
                    300 => (9, 32),
                    _ => (1, 36),
                };
                let entries = (start..start + count)
                    .map(|seed| (seed, rng.random_range(1..=20)))
                    .collect::<Vec<_>>();
                let next = self::committee(&entries);
                heights = next
                    .iter()
                    .cloned()
                    .map(|participant| {
                        let height = heights
                            .get(&participant)
                            .copied()
                            .unwrap_or_else(Height::zero);
                        (participant, height)
                    })
                    .collect();
                safe_tip.reconcile(&next);
                committee = next;
            } else {
                let index = rng.random_range(0..committee.len());
                let participant = committee[index].clone();
                let old = heights[&participant];
                let new = Height::new(old.get() + rng.random_range(1..=25));
                assert_eq!(safe_tip.update(participant.clone(), new), Some(old));
                heights.insert(participant, new);
            }

            assert_eq!(safe_tip.get(), oracle(&committee, &heights));
            assert_invariants(&safe_tip);
        }
    }
}
