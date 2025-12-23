//! Helpers for implementing [Twins: BFT Systems Made Robust](https://arxiv.org/abs/2004.10617).

use crate::types::View;
use commonware_p2p::simulated::SplitTarget;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};

/// Partition strategy for twins.
///
/// Determines how participants are split between twin instances at each view.
#[derive(Clone, Copy)]
pub enum Strategy {
    /// Split changes based on view number: `view % n` determines the split point.
    View,

    /// Fixed split at a specific index.
    Fixed(usize),

    /// Both twins send to everyone and receive from everyone (maximum equivocation).
    Broadcast,

    /// One twin sends only to the specified participant index, the other sends to everyone else.
    Isolate(usize),

    /// Randomly shuffle participants using view as RNG seed, then split at a random index.
    Shuffle,
}

impl Strategy {
    /// Returns which participants each twin communicates with.
    pub fn partitions<P: Clone>(self, view: View, participants: &[P]) -> (Vec<P>, Vec<P>) {
        let n = participants.len();
        match self {
            Self::View => {
                let split = view.get() as usize % n;
                let (primary, secondary) = participants.split_at(split);
                (primary.to_vec(), secondary.to_vec())
            }
            Self::Fixed(split) => {
                let (primary, secondary) = participants.split_at(split);
                (primary.to_vec(), secondary.to_vec())
            }
            Self::Broadcast => (participants.to_vec(), participants.to_vec()),
            Self::Isolate(idx) => (
                vec![participants[idx].clone()],
                participants
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != idx)
                    .map(|(_, p)| p.clone())
                    .collect(),
            ),
            Self::Shuffle => {
                let mut rng = StdRng::seed_from_u64(view.get());
                let mut shuffled: Vec<_> = participants.to_vec();
                shuffled.shuffle(&mut rng);
                let split = rng.gen_range(0..n);
                let (primary, secondary) = shuffled.split_at(split);
                (primary.to_vec(), secondary.to_vec())
            }
        }
    }

    /// Determines which twin should receive a message from a given sender at a given view.
    pub fn route<P: Clone + PartialEq>(
        self,
        view: View,
        sender: &P,
        participants: &[P],
    ) -> SplitTarget {
        let (primary, secondary) = self.partitions(view, participants);
        let in_primary = primary.contains(sender);
        let in_secondary = secondary.contains(sender);
        match (in_primary, in_secondary) {
            (true, true) => SplitTarget::Both,
            (true, false) => SplitTarget::Primary,
            (false, true) => SplitTarget::Secondary,
            (false, false) => panic!("sender not in any partition"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_twin_partition_view_split_varies_by_view() {
        let participants: Vec<u32> = (0..5).collect();

        // View 0: split at 0 % 5 = 0 -> primary gets [], secondary gets [0,1,2,3,4]
        let (primary, secondary) = Strategy::View.partitions(View::new(0), &participants);
        assert!(primary.is_empty());
        assert_eq!(secondary, vec![0, 1, 2, 3, 4]);

        // View 1: split at 1 % 5 = 1 -> primary gets [0], secondary gets [1,2,3,4]
        let (primary, secondary) = Strategy::View.partitions(View::new(1), &participants);
        assert_eq!(primary, vec![0]);
        assert_eq!(secondary, vec![1, 2, 3, 4]);

        // View 2: split at 2 % 5 = 2 -> primary gets [0,1], secondary gets [2,3,4]
        let (primary, secondary) = Strategy::View.partitions(View::new(2), &participants);
        assert_eq!(primary, vec![0, 1]);
        assert_eq!(secondary, vec![2, 3, 4]);

        // View 5: split at 5 % 5 = 0 -> wraps back
        let (primary, secondary) = Strategy::View.partitions(View::new(5), &participants);
        assert!(primary.is_empty());
        assert_eq!(secondary, vec![0, 1, 2, 3, 4]);

        // View 7: split at 7 % 5 = 2
        let (primary, secondary) = Strategy::View.partitions(View::new(7), &participants);
        assert_eq!(primary, vec![0, 1]);
        assert_eq!(secondary, vec![2, 3, 4]);
    }

    #[test]
    fn test_twin_partition_fixed_constant_split() {
        let participants: Vec<u32> = (0..5).collect();

        // Fixed split at index 2: primary gets [0,1], secondary gets [2,3,4]
        let partition = Strategy::Fixed(2);

        // Split should be the same regardless of view
        for view in [0, 1, 5, 100] {
            let (primary, secondary) = partition.partitions(View::new(view), &participants);
            assert_eq!(primary, vec![0, 1]);
            assert_eq!(secondary, vec![2, 3, 4]);
        }

        // Fixed at 0: primary gets [], secondary gets all
        let (primary, secondary) = Strategy::Fixed(0).partitions(View::new(0), &participants);
        assert!(primary.is_empty());
        assert_eq!(secondary, vec![0, 1, 2, 3, 4]);

        // Fixed at 5: primary gets all, secondary gets []
        let (primary, secondary) = Strategy::Fixed(5).partitions(View::new(0), &participants);
        assert_eq!(primary, vec![0, 1, 2, 3, 4]);
        assert!(secondary.is_empty());
    }

    #[test]
    fn test_twin_partition_broadcast_both_get_all() {
        let participants: Vec<u32> = (0..5).collect();

        // Both twins should get all participants regardless of view
        for view in [0, 1, 5, 100] {
            let (primary, secondary) =
                Strategy::Broadcast.partitions(View::new(view), &participants);
            assert_eq!(primary, vec![0, 1, 2, 3, 4]);
            assert_eq!(secondary, vec![0, 1, 2, 3, 4]);
        }
    }

    #[test]
    fn test_twin_partition_isolate_single_vs_rest() {
        let participants: Vec<u32> = (0..5).collect();

        // Isolate(2): primary gets only [2], secondary gets everyone else [0,1,3,4]
        let partition = Strategy::Isolate(2);

        // Should be constant across views
        for view in [0, 1, 5, 100] {
            let (primary, secondary) = partition.partitions(View::new(view), &participants);
            assert_eq!(primary, vec![2]);
            assert_eq!(secondary, vec![0, 1, 3, 4]);
        }

        // Isolate(0): primary gets [0], secondary gets [1,2,3,4]
        let (primary, secondary) = Strategy::Isolate(0).partitions(View::new(0), &participants);
        assert_eq!(primary, vec![0]);
        assert_eq!(secondary, vec![1, 2, 3, 4]);

        // Isolate(4): primary gets [4], secondary gets [0,1,2,3]
        let (primary, secondary) = Strategy::Isolate(4).partitions(View::new(0), &participants);
        assert_eq!(primary, vec![4]);
        assert_eq!(secondary, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_twin_partition_route_view() {
        let participants: Vec<u32> = (0..5).collect();
        let partition = Strategy::View;

        // View 2: split at 2 -> primary talks to [0,1], secondary talks to [2,3,4]
        // Sender 0 is in primary's set, so route to Primary
        assert_eq!(
            partition.route(View::new(2), &0, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            partition.route(View::new(2), &1, &participants),
            SplitTarget::Primary
        );
        // Sender 2,3,4 are in secondary's set, so route to Secondary
        assert_eq!(
            partition.route(View::new(2), &2, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            partition.route(View::new(2), &4, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn test_twin_partition_route_fixed() {
        let participants: Vec<u32> = (0..5).collect();
        let partition = Strategy::Fixed(3);

        // Fixed at 3: primary talks to [0,1,2], secondary talks to [3,4]
        assert_eq!(
            partition.route(View::new(0), &0, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            partition.route(View::new(0), &2, &participants),
            SplitTarget::Primary
        );
        assert_eq!(
            partition.route(View::new(0), &3, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            partition.route(View::new(0), &4, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn test_twin_partition_route_broadcast() {
        let participants: Vec<u32> = (0..5).collect();
        let partition = Strategy::Broadcast;

        // Both twins talk to everyone, so all senders route to Both
        for sender in &participants {
            assert_eq!(
                partition.route(View::new(0), sender, &participants),
                SplitTarget::Both
            );
        }
    }

    #[test]
    fn test_twin_partition_route_isolate() {
        let participants: Vec<u32> = (0..5).collect();
        let partition = Strategy::Isolate(2);

        // Isolate(2): primary talks to [2], secondary talks to [0,1,3,4]
        // Sender 2 is in primary's set only -> Primary
        assert_eq!(
            partition.route(View::new(0), &2, &participants),
            SplitTarget::Primary
        );
        // Sender 0,1,3,4 are in secondary's set only -> Secondary
        assert_eq!(
            partition.route(View::new(0), &0, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            partition.route(View::new(0), &1, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            partition.route(View::new(0), &3, &participants),
            SplitTarget::Secondary
        );
        assert_eq!(
            partition.route(View::new(0), &4, &participants),
            SplitTarget::Secondary
        );
    }

    #[test]
    fn test_twin_partition_shuffle_deterministic() {
        let participants: Vec<u32> = (0..5).collect();

        // Same view should always produce the same result
        let (primary_1, secondary_1) = Strategy::Shuffle.partitions(View::new(42), &participants);
        let (primary_2, secondary_2) = Strategy::Shuffle.partitions(View::new(42), &participants);
        assert_eq!(primary_1, primary_2);
        assert_eq!(secondary_1, secondary_2);
    }

    #[test]
    fn test_twin_partition_shuffle_varies_by_view() {
        let participants: Vec<u32> = (0..50).collect();

        // Different views should produce different results (with high probability)
        let (primary_0, secondary_0) = Strategy::Shuffle.partitions(View::new(0), &participants);
        let (primary_1, secondary_1) = Strategy::Shuffle.partitions(View::new(1), &participants);
        let (primary_2, secondary_2) = Strategy::Shuffle.partitions(View::new(2), &participants);

        // Check that at least some are different (extremely unlikely to be identical)
        let all_same = primary_0 == primary_1
            && primary_1 == primary_2
            && secondary_0 == secondary_1
            && secondary_1 == secondary_2;
        assert!(!all_same, "shuffle should vary by view");
    }

    #[test]
    fn test_twin_partition_shuffle_covers_all_participants() {
        let participants: Vec<u32> = (0..5).collect();

        for view in [0, 1, 5, 42, 100] {
            let (primary, secondary) = Strategy::Shuffle.partitions(View::new(view), &participants);

            // Combined should contain all participants exactly once
            let mut combined: Vec<_> = primary.iter().chain(secondary.iter()).copied().collect();
            combined.sort();
            assert_eq!(combined, participants);
        }
    }

    #[test]
    fn test_twin_partition_shuffle_route() {
        let participants: Vec<u32> = (0..5).collect();
        let partition = Strategy::Shuffle;

        // For a given view, each participant should route to exactly one of Primary or Secondary
        for view in [0, 1, 5, 42] {
            let (primary, secondary) = partition.partitions(View::new(view), &participants);
            for p in &participants {
                let target = partition.route(View::new(view), p, &participants);
                let in_primary = primary.contains(p);
                let in_secondary = secondary.contains(p);

                // Should be in exactly one partition
                assert!(
                    in_primary ^ in_secondary,
                    "participant should be in exactly one partition"
                );

                // Route should match partition membership
                if in_primary {
                    assert_eq!(target, SplitTarget::Primary);
                } else {
                    assert_eq!(target, SplitTarget::Secondary);
                }
            }
        }
    }
}
