//! Commitments this node certified.

use crate::types::Height;
use std::collections::BTreeSet;

/// Commitments of proposals this node certified, and ancestors of them,
/// indexed by height and commitment.
///
/// A certified block arrives bound to its commitment, and its certification,
/// by this node or by the honest validators consensus required, checked its
/// embedded parent commitment against a root-bound parent. So recording a
/// certified block also records its parent, and a block fetched under this
/// knowledge extends it to that block's parent. Entries at or below the
/// finalized tip are pruned and cannot be reinserted.
///
/// Both indexes contain the same pairs. Height order limits retirement to expired
/// pairs, while commitment order provides logarithmic lookup by full commitment.
pub(super) struct Certified<C: Ord + Copy> {
    by_height: BTreeSet<(Height, C)>,
    by_commitment: BTreeSet<(C, Height)>,
    min: Height,
}

impl<C: Ord + Copy> Certified<C> {
    pub(super) const fn new() -> Self {
        Self {
            by_height: BTreeSet::new(),
            by_commitment: BTreeSet::new(),
            min: Height::new(1),
        }
    }

    /// Records `commitment` at `height` as certified unless below the retention minimum.
    pub(super) fn insert(&mut self, height: Height, commitment: C) {
        if height < self.min {
            return;
        }
        self.by_height.insert((height, commitment));
        self.by_commitment.insert((commitment, height));
    }

    /// Returns true when `commitment` at `height` is known certified.
    pub(super) fn contains(&self, height: Height, commitment: &C) -> bool {
        self.by_height.contains(&(height, *commitment))
    }

    /// Returns the least retained height of an exact certified commitment.
    pub(super) fn height(&self, commitment: &C) -> Option<Height> {
        self.by_commitment
            .range((*commitment, Height::zero())..=(*commitment, Height::new(u64::MAX)))
            .next()
            .map(|(_, height)| *height)
    }

    /// Retains entries at or above `min` and rejects future inserts below it.
    /// The retention minimum never decreases.
    pub(super) fn retain(&mut self, min: Height) {
        if min <= self.min {
            return;
        }
        self.min = min;
        while self
            .by_height
            .first()
            .is_some_and(|(height, _)| *height < min)
        {
            let (height, commitment) = self.by_height.pop_first().expect("expired pair exists");
            self.by_commitment.remove(&(commitment, height));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Change::{Insert, Retain};
    use std::{cell::Cell, cmp::Ordering, collections::BTreeMap};

    enum Change {
        Insert(u64, u64),
        Retain(u64),
    }

    thread_local! {
        static COMPARISONS: Cell<usize> = const { Cell::new(0) };
    }

    #[derive(Clone, Copy, Debug, Eq)]
    struct Counted(u64);

    impl PartialEq for Counted {
        fn eq(&self, other: &Self) -> bool {
            COMPARISONS.with(|count| count.set(count.get() + 1));
            self.0 == other.0
        }
    }

    impl Ord for Counted {
        fn cmp(&self, other: &Self) -> Ordering {
            COMPARISONS.with(|count| count.set(count.get() + 1));
            self.0.cmp(&other.0)
        }
    }

    impl PartialOrd for Counted {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    fn lookup_comparisons(size: u64) -> [usize; 2] {
        let mut certified = Certified::new();
        for key in 0..size {
            certified.insert(Height::new(key + 1), Counted(key));
        }

        COMPARISONS.with(|count| count.set(0));
        for key in size..2 * size {
            assert_eq!(certified.height(&Counted(key)), None);
        }
        let absent = COMPARISONS.with(Cell::get);

        COMPARISONS.with(|count| count.set(0));
        for index in 0..size {
            // An odd stride visits every key in these power-of-two populations.
            let key = index * 513 % size;
            assert_eq!(certified.height(&Counted(key)), Some(Height::new(key + 1)));
        }
        [absent, COMPARISONS.with(Cell::get)]
    }

    #[test]
    fn exact_lookup_does_not_scan_retained_heights() {
        let small = lookup_comparisons(1024);
        let large = lookup_comparisons(2048);
        for (size, counts) in [(1024, small), (2048, large)] {
            for (kind, comparisons) in ["absent", "present"].into_iter().zip(counts) {
                assert!(
                    comparisons <= 64 * size,
                    "{kind} lookup comparison budget exceeded: size={size}, comparisons={comparisons}, small={small:?}, large={large:?}",
                );
            }
        }
        for (small, large) in small.into_iter().zip(large) {
            assert!(
                large <= 3 * small,
                "doubling population: {small} -> {large}"
            );
        }
    }

    #[test]
    fn relation_preserves_forks_and_monotone_retention() {
        let mut certified = Certified::new();
        let mut reference = BTreeMap::<Height, BTreeSet<u64>>::new();
        let mut min = Height::new(1);
        for change in [
            Insert(0, 0),
            Insert(5, 1),
            Insert(7, 1),
            Insert(5, 1),
            Insert(5, 2),
            Insert(6, 0),
            Insert(u64::MAX, u64::MAX),
            Insert(u64::MAX - 1, u64::MAX - 1),
            Retain(6),
            Retain(4),
            Insert(5, 1),
            Insert(6, 2),
            Retain(7),
            Retain(u64::MAX),
            Retain(0),
            Insert(u64::MAX - 1, 0),
            Insert(u64::MAX, 0),
        ] {
            match change {
                Insert(height, key) => {
                    let height = Height::new(height);
                    certified.insert(height, key);
                    if height >= min {
                        reference.entry(height).or_default().insert(key);
                    }
                }
                Retain(height) => {
                    min = min.max(Height::new(height));
                    certified.retain(Height::new(height));
                    reference.retain(|height, _| *height >= min);
                }
            }

            let pairs: BTreeSet<_> = reference
                .iter()
                .flat_map(|(height, keys)| keys.iter().map(move |key| (*height, *key)))
                .collect();
            assert_eq!(certified.by_height, pairs);
            assert_eq!(
                certified.by_commitment,
                pairs.iter().map(|(height, key)| (*key, *height)).collect(),
            );

            for key in [0, 1, 2, 3, u64::MAX - 2, u64::MAX - 1, u64::MAX] {
                let expected = reference
                    .iter()
                    .find_map(|(height, keys)| keys.contains(&key).then_some(*height));
                assert_eq!(certified.height(&key), expected, "key={key}");
                for height in [0, 1, 4, 5, 6, 7, u64::MAX - 1, u64::MAX] {
                    let height = Height::new(height);
                    let expected = reference
                        .get(&height)
                        .is_some_and(|keys| keys.contains(&key));
                    assert_eq!(certified.contains(height, &key), expected, "{height}/{key}");
                }
            }
        }
    }
}
