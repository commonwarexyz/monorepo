use crate::types::Height;
use commonware_cryptography::PublicKey;
use commonware_utils::{N3f1, ordered::Committee};
use std::{
    cmp::Ordering,
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tip {
    height: Height,
    weight: u64,
}

/// Tracks the greatest height reported by more than the maximum faulty weight.
pub struct SafeTip<P: PublicKey> {
    tips: HashMap<P, Tip>,
    heights: WeightedHeights,
    max_fault_weight: u64,
}

impl<P: PublicKey> Default for SafeTip<P> {
    fn default() -> Self {
        Self {
            tips: HashMap::new(),
            heights: WeightedHeights::default(),
            max_fault_weight: 0,
        }
    }
}

impl<P: PublicKey> SafeTip<P> {
    /// Initializes an instance with the given committee.
    pub fn init(&mut self, committee: &Committee<P>) {
        let max_fault_weight = committee.max_fault_weight::<N3f1>();
        self.tips = committee
            .iter()
            .zip(committee.weights())
            .map(|(participant, &weight)| {
                (
                    participant.clone(),
                    Tip {
                        height: Height::zero(),
                        weight,
                    },
                )
            })
            .collect();
        self.heights = WeightedHeights::default();
        self.heights.add(Height::zero(), committee.total_weight());
        self.max_fault_weight = max_fault_weight;
    }

    /// Updates the committee, preserving retained participants' heights.
    ///
    /// # Panics
    ///
    /// Panics if the new committee does not have the same participant count.
    pub fn reconcile(&mut self, committee: &Committee<P>) {
        assert_eq!(
            committee.len(),
            self.tips.len(),
            "committee participant count mismatch"
        );

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

        let mut heights = WeightedHeights::default();
        for tip in tips.values() {
            heights.add(tip.height, tip.weight);
        }

        self.tips = tips;
        self.heights = heights;
        self.max_fault_weight = committee.max_fault_weight::<N3f1>();
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

        self.heights.remove(old, weight);
        self.heights.add(new, weight);
        Some(old)
    }

    /// Returns the greatest height reached by weight greater than `f`.
    pub fn get(&self) -> Height {
        self.heights
            .nth_highest(
                self.max_fault_weight
                    .checked_add(1)
                    .expect("fault weight cannot reach u64::MAX"),
            )
            .expect("empty committee")
    }
}

#[derive(Default)]
struct WeightedHeights {
    root: Option<Box<Node>>,
    hasher: RandomState,
}

impl WeightedHeights {
    fn add(&mut self, height: Height, weight: u64) {
        assert!(weight > 0, "height weight must be positive");
        let priority = self.hasher.hash_one(height);
        self.root = Some(Node::insert(self.root.take(), height, weight, priority));
    }

    fn remove(&mut self, height: Height, weight: u64) {
        assert!(weight > 0, "height weight must be positive");
        self.root = Node::remove(self.root.take(), height, weight);
    }

    fn nth_highest(&self, weight: u64) -> Option<Height> {
        self.root
            .as_deref()
            .and_then(|root| root.nth_highest(weight))
    }
}

struct Node {
    height: Height,
    weight: u64,
    subtree_weight: u64,
    priority: u64,
    left: Option<Box<Self>>,
    right: Option<Box<Self>>,
}

impl Node {
    fn new(height: Height, weight: u64, priority: u64) -> Box<Self> {
        Box::new(Self {
            height,
            weight,
            subtree_weight: weight,
            priority,
            left: None,
            right: None,
        })
    }

    fn subtree_weight(node: &Option<Box<Self>>) -> u64 {
        node.as_ref().map_or(0, |node| node.subtree_weight)
    }

    fn refresh(&mut self) {
        self.subtree_weight = Self::subtree_weight(&self.left)
            .checked_add(self.weight)
            .and_then(|weight| weight.checked_add(Self::subtree_weight(&self.right)))
            .expect("height weight overflow");
    }

    fn higher_priority_than(&self, other: &Self) -> bool {
        (self.priority, self.height) > (other.priority, other.height)
    }

    fn insert(root: Option<Box<Self>>, height: Height, weight: u64, priority: u64) -> Box<Self> {
        let Some(mut root) = root else {
            return Self::new(height, weight, priority);
        };

        match height.cmp(&root.height) {
            Ordering::Less => {
                root.left = Some(Self::insert(root.left.take(), height, weight, priority));
                if root
                    .left
                    .as_ref()
                    .is_some_and(|left| left.higher_priority_than(&root))
                {
                    return Self::rotate_right(root);
                }
            }
            Ordering::Greater => {
                root.right = Some(Self::insert(root.right.take(), height, weight, priority));
                if root
                    .right
                    .as_ref()
                    .is_some_and(|right| right.higher_priority_than(&root))
                {
                    return Self::rotate_left(root);
                }
            }
            Ordering::Equal => {
                root.weight = root
                    .weight
                    .checked_add(weight)
                    .expect("height weight overflow");
            }
        }
        root.refresh();
        root
    }

    fn remove(root: Option<Box<Self>>, height: Height, weight: u64) -> Option<Box<Self>> {
        let mut root = root.expect("cannot remove missing height weight");
        match height.cmp(&root.height) {
            Ordering::Less => root.left = Self::remove(root.left.take(), height, weight),
            Ordering::Greater => root.right = Self::remove(root.right.take(), height, weight),
            Ordering::Equal => {
                root.weight = root
                    .weight
                    .checked_sub(weight)
                    .expect("insufficient height weight");
                if root.weight == 0 {
                    return Self::merge(root.left, root.right);
                }
            }
        }
        root.refresh();
        Some(root)
    }

    fn merge(left: Option<Box<Self>>, right: Option<Box<Self>>) -> Option<Box<Self>> {
        match (left, right) {
            (None, right) => right,
            (left, None) => left,
            (Some(mut left), Some(mut right)) => {
                if left.higher_priority_than(&right) {
                    left.right = Self::merge(left.right.take(), Some(right));
                    left.refresh();
                    Some(left)
                } else {
                    right.left = Self::merge(Some(left), right.left.take());
                    right.refresh();
                    Some(right)
                }
            }
        }
    }

    fn rotate_left(mut root: Box<Self>) -> Box<Self> {
        let mut pivot = root.right.take().expect("missing right child");
        root.right = pivot.left.take();
        root.refresh();
        pivot.left = Some(root);
        pivot.refresh();
        pivot
    }

    fn rotate_right(mut root: Box<Self>) -> Box<Self> {
        let mut pivot = root.left.take().expect("missing left child");
        root.left = pivot.right.take();
        root.refresh();
        pivot.right = Some(root);
        pivot.refresh();
        pivot
    }

    fn nth_highest(&self, weight: u64) -> Option<Height> {
        if weight == 0 || weight > self.subtree_weight {
            return None;
        }

        let right_weight = Self::subtree_weight(&self.right);
        if weight <= right_weight {
            return self.right.as_deref()?.nth_highest(weight);
        }
        let weight = weight.checked_sub(right_weight).expect("weight underflow");
        if weight <= self.weight {
            return Some(self.height);
        }
        self.left
            .as_deref()?
            .nth_highest(weight.checked_sub(self.weight).expect("weight underflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::TryCollect;

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

    fn assert_weight(safe_tip: &SafeTip<PublicKey>) {
        let expected = safe_tip.tips.values().map(|tip| tip.weight).sum::<u64>();
        assert_eq!(
            safe_tip
                .heights
                .root
                .as_ref()
                .map_or(0, |root| root.subtree_weight),
            expected
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
        assert_eq!(safe_tip.heights.nth_highest(2), Some(Height::new(10)));
        assert_eq!(safe_tip.heights.nth_highest(3), Some(Height::new(10)));
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
    fn reconcile_replaces_members_at_height_zero() {
        let (mut safe_tip, old) = setup(&[(1, 1), (2, 1), (3, 1), (4, 1)]);
        for participant in old.iter().cloned() {
            safe_tip.update(participant, Height::new(10));
        }
        let retained = old.iter().skip(2).cloned().collect::<Vec<_>>();
        let replacement = vec![
            (retained[0].clone(), 1),
            (retained[1].clone(), 1),
            (key(5), 1),
            (key(6), 1),
        ]
        .try_into()
        .unwrap();

        safe_tip.reconcile(&replacement);

        assert_eq!(safe_tip.tips[&retained[0]].height, Height::new(10));
        assert_eq!(safe_tip.tips[&retained[1]].height, Height::new(10));
        assert_eq!(safe_tip.tips[&key(5)].height, Height::zero());
        assert_eq!(safe_tip.tips[&key(6)].height, Height::zero());
        assert_eq!(safe_tip.get(), Height::new(10));
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
                        assert_weight(&safe_tip);
                    }
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "committee participant count mismatch")]
    fn reconcile_requires_same_participant_count() {
        let (mut safe_tip, _) = setup(&[(1, 1), (2, 1), (3, 1), (4, 1)]);
        safe_tip.reconcile(&committee(&[(1, 1), (2, 1), (3, 1)]));
    }
}
