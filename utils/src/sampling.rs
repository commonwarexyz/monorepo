//! Random sampling with weights.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use rand::{Rng, RngExt as _};

/// A collection of weights at fixed indices supporting proportional random draws and updates.
///
/// Construction takes `O(n)` time and space. Sampling and changing a weight take `O(log n)` time.
/// Zero-weight entries are never sampled. Draws use only integer arithmetic, so a fixed sequence
/// of weights and random input is reproducible across platforms.
///
/// # Examples
///
/// ```
/// use commonware_utils::sampling::WeightedIndex;
/// use rand::{SeedableRng, rngs::StdRng};
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let mut weights = WeightedIndex::new([0, 5]);
/// assert_eq!(weights.sample(&mut rng), Some(1));
/// assert_eq!(weights.update(1, |weight| weight * 2), 5);
/// assert_eq!(weights.weight(1), 10);
/// weights.set(1, 0);
/// assert_eq!(weights.sample(&mut rng), None);
/// ```
pub struct WeightedIndex {
    /// Weights in index order.
    weights: Vec<u64>,
    /// Fenwick tree in which entry `i` holds the sum of `weights[i & (i + 1)..=i]`.
    tree: Vec<u128>,
    /// Sum of all weights.
    total: u128,
}

impl WeightedIndex {
    /// Builds an index over `weights`, preserving their order.
    pub fn new(weights: impl IntoIterator<Item = u64>) -> Self {
        let weights: Vec<_> = weights.into_iter().collect();
        let mut tree: Vec<_> = weights.iter().copied().map(u128::from).collect();
        let total = tree.iter().sum();

        // Each entry's range lies inside its parent's range, so one forward pass builds the tree.
        for index in 0..tree.len() {
            let parent = index | (index + 1);
            if parent < tree.len() {
                tree[parent] += tree[index];
            }
        }
        Self {
            weights,
            tree,
            total,
        }
    }

    /// Returns the sum of all weights.
    pub const fn total(&self) -> u128 {
        self.total
    }

    /// Returns the weight at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    pub fn weight(&self, index: usize) -> u64 {
        self.weights[index]
    }

    /// Replaces the weight at `index`, returning its previous value.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    pub fn set(&mut self, index: usize, weight: u64) -> u64 {
        self.update(index, |_| weight)
    }

    /// Applies `f` to the weight at `index`, returning its previous value.
    /// Returning the same weight skips the update.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds, before invoking `f`. If `f` panics, `self` is unchanged.
    pub fn update(&mut self, index: usize, f: impl FnOnce(u64) -> u64) -> u64 {
        // Evaluate the callback before changing any state. Unchanged weights need no tree walk.
        let entry = &mut self.weights[index];
        let previous = *entry;
        let weight = f(previous);
        if weight == previous {
            return previous;
        }
        *entry = weight;

        // Every Fenwick entry whose range contains `index` trades the old weight for the new one.
        let old = u128::from(previous);
        let new = u128::from(weight);
        self.total = self.total - old + new;
        let mut node = index;
        while node < self.tree.len() {
            self.tree[node] = self.tree[node] - old + new;
            node |= node + 1;
        }
        previous
    }

    /// Draws an index with probability proportional to its weight.
    ///
    /// Returns `None` without consuming randomness when the total weight is zero.
    pub fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<usize> {
        (self.total != 0).then(|| self.locate(rng.random_range(0..self.total)))
    }

    fn locate(&self, mut draw: u128) -> usize {
        // Descend the Fenwick tree to the first index whose cumulative weight exceeds the draw.
        let mut index = 0;
        let mut step = 1usize << self.tree.len().ilog2();
        while step != 0 {
            let next = index + step;
            if next <= self.tree.len() && self.tree[next - 1] <= draw {
                draw -= self.tree[next - 1];
                index = next;
            }
            step >>= 1;
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Number of deterministic draws used for distribution checks.
    const DRAWS: usize = 2_000;

    /// Asserts that `index` holds `weights` and that every positive weight's cumulative
    /// interval locates its own position.
    fn assert_intervals(index: &WeightedIndex, weights: &[u64]) {
        assert_eq!(index.weights, weights);
        let mut start = 0;
        for (position, &weight) in weights.iter().enumerate() {
            let end = start + u128::from(weight);
            if weight != 0 {
                assert_eq!(index.locate(start), position);
                assert_eq!(index.locate(end - 1), position);
            }
            start = end;
        }
        assert_eq!(index.total(), start);
    }

    #[test]
    fn weighted_index_updates_match_intervals() {
        let mut rng = TestRng::new(0);
        for len in [
            0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129,
        ] {
            let mut weights: Vec<_> = (0..len).map(|i| [0, 1, u64::MAX][i % 3]).collect();
            let mut index = WeightedIndex::new(weights.iter().copied());
            assert_intervals(&index, &weights);
            for _ in 0..64 {
                if weights.is_empty() {
                    break;
                }
                let position = rng.random_range(0..weights.len());
                let weight = [0, 1, u64::MAX, rng.random()][rng.random_range(0..4)];
                assert_eq!(index.set(position, weight), weights[position]);
                weights[position] = weight;
                assert_intervals(&index, &weights);
            }
        }
    }

    #[test]
    fn weighted_index_update_uses_current_weight() {
        // Derive a replacement from the current weight and observe one callback invocation.
        let mut index = WeightedIndex::new([0, 7, u64::MAX]);
        let mut calls = 0;
        let previous = index.update(1, |weight| {
            calls += 1;
            weight * 2
        });
        assert_eq!(previous, 7);
        assert_eq!(calls, 1);
        assert_intervals(&index, &[0, 14, u64::MAX]);

        // Identity updates preserve every interval, including zero and maximum weights.
        for (position, weight) in [0, 14, u64::MAX].into_iter().enumerate() {
            assert_eq!(index.update(position, core::convert::identity), weight);
        }
        assert_intervals(&index, &[0, 14, u64::MAX]);

        // Moving entries between zero and positive weight must update the cumulative sums.
        assert_eq!(index.update(2, |_| 0), u64::MAX);
        assert_eq!(index.update(0, |weight| weight + 1), 0);
        assert_intervals(&index, &[1, 14, 0]);
    }

    #[test]
    fn weighted_index_update_panics_preserve_index() {
        // Bounds checks must reject invalid positions before invoking the callback.
        for weights in [vec![], vec![0, 7, u64::MAX]] {
            let mut index = WeightedIndex::new(weights.iter().copied());
            for position in [weights.len(), usize::MAX] {
                let mut called = false;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    index.update(position, |_| {
                        called = true;
                        1
                    });
                }));
                assert!(result.is_err());
                assert!(!called);
                assert_intervals(&index, &weights);
            }
        }

        // A callback panic must leave both weights and cumulative sums intact.
        let mut index = WeightedIndex::new([0, 7, u64::MAX]);
        let result = catch_unwind(AssertUnwindSafe(|| {
            index.update(1, |_| panic!("callback must not return"));
        }));
        assert!(result.is_err());
        assert_intervals(&index, &[0, 7, u64::MAX]);
    }

    #[test]
    fn weighted_index_zero_total_does_not_draw() {
        let mut rng = TestRng::new(0);
        let mut reference = TestRng::new(0);
        for weights in [vec![], vec![0], vec![0; 65]] {
            assert_eq!(WeightedIndex::new(weights).sample(&mut rng), None);
        }
        assert_eq!(rng.random::<[u64; 4]>(), reference.random::<[u64; 4]>());
        let mut index = WeightedIndex::new([0, 7, 0]);
        assert_eq!(index.sample(&mut rng), Some(1));
        index.set(1, 0);
        assert_eq!(index.sample(&mut rng), None);
    }

    /// Counts how often each index is sampled over `DRAWS` draws, one seed per draw.
    fn sample_counts<const N: usize>(weights: [u64; N]) -> [usize; N] {
        let index = WeightedIndex::new(weights);
        let mut counts = [0; N];
        for seed in 0..DRAWS as u64 {
            counts[index.sample(&mut TestRng::new(seed)).unwrap()] += 1;
        }
        counts
    }

    #[test]
    fn weighted_index_prefers_heavier_weights() {
        let counts = sample_counts([0, 9, 1, 0]);
        assert_eq!(counts[0], 0);
        assert_eq!(counts[3], 0);
        assert!(
            (DRAWS * 85 / 100..DRAWS * 95 / 100).contains(&counts[1]),
            "{counts:?}"
        );
    }

    #[test]
    fn weighted_index_equal_weights_are_uniform() {
        let counts = sample_counts([7, 7, 7]);
        for count in counts {
            assert!((DRAWS / 4..DRAWS * 5 / 12).contains(&count), "{counts:?}");
        }
    }
}
