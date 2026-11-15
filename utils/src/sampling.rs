//! Random sampling with weights.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use rand::{Rng, RngExt as _};

/// A collection of weights at fixed indices supporting proportional and uniform draws and updates.
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
    /// Number of positive weights in each Fenwick entry's range.
    counts: Vec<usize>,
    /// Sum of all weights.
    total: u128,
    /// Number of positive weights.
    positive: usize,
}

impl WeightedIndex {
    /// Builds an index over `weights`, preserving their order.
    pub fn new(weights: impl IntoIterator<Item = u64>) -> Self {
        let weights: Vec<_> = weights.into_iter().collect();
        let mut tree: Vec<_> = weights.iter().copied().map(u128::from).collect();
        let mut counts: Vec<_> = weights
            .iter()
            .map(|&weight| usize::from(weight != 0))
            .collect();
        let total = tree.iter().sum();
        let positive = counts.iter().sum();

        // Each entry's range lies inside its parent's range, so one forward pass builds the tree.
        for index in 0..tree.len() {
            let parent = index | (index + 1);
            if parent < tree.len() {
                tree[parent] += tree[index];
                counts[parent] += counts[index];
            }
        }
        Self {
            weights,
            tree,
            counts,
            total,
            positive,
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
        let was_positive = usize::from(previous != 0);
        let is_positive = usize::from(weight != 0);
        self.total = self.total - old + new;
        self.positive = self.positive - was_positive + is_positive;
        let mut node = index;
        while node < self.tree.len() {
            self.tree[node] = self.tree[node] - old + new;
            if was_positive != is_positive {
                self.counts[node] = self.counts[node] - was_positive + is_positive;
            }
            node |= node + 1;
        }
        previous
    }

    /// Draws an index with probability proportional to its weight.
    ///
    /// Returns `None` without consuming randomness when the total weight is zero.
    pub fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<usize> {
        (self.total != 0).then(|| self.locate::<false>(rng.random_range(0..self.total)))
    }

    /// Draws uniformly from the indices with positive weight.
    ///
    /// Returns `None` without consuming randomness when all weights are zero.
    pub fn sample_uniform<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<usize> {
        (self.positive != 0)
            .then(|| self.locate::<true>(rng.random_range(0..self.positive as u128)))
    }

    /// Starts a sequence of draws that can choose each positive-weight index at most once.
    ///
    /// Dropping the sequence restores all weights, including during unwinding. Construction takes
    /// constant time without allocating. Each draw takes amortized `O(log n)` time, and `k` draws
    /// use `O(k)` space. Stopping after the first draw leaves the index unchanged and needs no
    /// restoration.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_utils::sampling::WeightedIndex;
    /// use rand::{SeedableRng, rngs::StdRng};
    ///
    /// let mut rng = StdRng::seed_from_u64(0);
    /// let mut weights = WeightedIndex::new([0, 5, 3]);
    /// {
    ///     let mut draws = weights.without_replacement();
    ///     let first = draws.sample(&mut rng).unwrap();
    ///     let second = draws.sample_uniform(&mut rng).unwrap();
    ///     assert_ne!(first, second);
    ///     assert!(draws.is_empty());
    /// }
    /// assert_eq!(weights.total(), 8);
    /// ```
    pub const fn without_replacement(&mut self) -> WithoutReplacement<'_> {
        WithoutReplacement {
            pool: Pool::Borrowed {
                index: self,
                excluded: Vec::new(),
            },
            previous: None,
        }
    }

    /// Consumes this index for draws that can choose each positive-weight index at most once.
    ///
    /// Construction takes constant time without allocating. Each draw takes `O(log n)` time and
    /// constant extra space, because a consumed index is never restored.
    pub const fn into_without_replacement(self) -> WithoutReplacement<'static> {
        WithoutReplacement {
            pool: Pool::Owned(self),
            previous: None,
        }
    }

    fn locate<const UNIFORM: bool>(&self, mut draw: u128) -> usize {
        // Descend to the first index whose cumulative weight or positive count exceeds the draw.
        let mut index = 0;
        let mut step = 1usize << self.tree.len().ilog2();
        while step != 0 {
            let next = index + step;
            if next <= self.tree.len() {
                let sum = if UNIFORM {
                    self.counts[next - 1] as u128
                } else {
                    self.tree[next - 1]
                };
                if sum <= draw {
                    draw -= sum;
                    index = next;
                }
            }
            step >>= 1;
        }
        index
    }
}

/// Storage for a without-replacement sequence.
enum Pool<'a> {
    /// A borrowed index and the weights to restore when the sequence ends.
    Borrowed {
        index: &'a mut WeightedIndex,
        excluded: Vec<(usize, u64)>,
    },
    /// An index discarded when the sequence ends.
    Owned(WeightedIndex),
}

/// Draws from a [`WeightedIndex`] without repeating an index.
///
/// Weighted and uniform draws share the same exclusions. Dropping a sequence over a borrowed index
/// restores its original weights in `O(k log n)` time, where `k` is the number of draws after the
/// first. A sequence that owns its index discards it.
pub struct WithoutReplacement<'a> {
    /// Index and any weights needed for restoration.
    pool: Pool<'a>,
    /// Last draw, excluded only if another draw is requested.
    previous: Option<usize>,
}

impl WithoutReplacement<'_> {
    /// Returns whether every positive-weight index has been drawn.
    pub fn is_empty(&self) -> bool {
        let index = match &self.pool {
            Pool::Borrowed { index, .. } => &**index,
            Pool::Owned(index) => index,
        };
        index.positive == usize::from(self.previous.is_some())
    }

    /// Draws proportionally to the remaining weights, excluding all previous draws.
    ///
    /// Returns `None` without consuming randomness when no indices remain.
    pub fn sample<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<usize> {
        self.draw::<false, R>(rng)
    }

    /// Draws uniformly from the remaining positive-weight indices.
    ///
    /// Returns `None` without consuming randomness when no indices remain.
    pub fn sample_uniform<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<usize> {
        self.draw::<true, R>(rng)
    }

    fn draw<const UNIFORM: bool, R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let (index, excluded) = match &mut self.pool {
            Pool::Borrowed { index, excluded } => (&mut **index, Some(excluded)),
            Pool::Owned(index) => (index, None),
        };

        // Delay mutation and allocation until a later draw needs the previous entry excluded.
        if let Some(previous) = self.previous {
            if let Some(excluded) = excluded {
                excluded.push((previous, index.weight(previous)));
            }
            self.previous = None;
            index.set(previous, 0);
        }
        self.previous = if UNIFORM {
            index.sample_uniform(rng)
        } else {
            index.sample(rng)
        };
        self.previous
    }
}

impl Drop for WithoutReplacement<'_> {
    fn drop(&mut self) {
        if let Pool::Borrowed { index, excluded } = &mut self.pool {
            for &(position, weight) in excluded.iter() {
                index.set(position, weight);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Number of deterministic draws used for distribution checks.
    const DRAWS: usize = 2_000;

    /// Asserts that `index` holds `weights` and that every weighted interval and uniform rank
    /// locates its own position.
    fn assert_intervals(index: &WeightedIndex, weights: &[u64]) {
        assert_eq!(index.weights, weights);
        let mut start = 0;
        let mut positive = 0;
        for (position, &weight) in weights.iter().enumerate() {
            let end = start + u128::from(weight);
            if weight != 0 {
                assert_eq!(index.locate::<false>(start), position);
                assert_eq!(index.locate::<false>(end - 1), position);
                assert_eq!(index.locate::<true>(positive as u128), position);
                positive += 1;
            }
            start = end;
        }
        assert_eq!(index.total(), start);
        assert_eq!(index.positive, positive);
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
            let mut index = WeightedIndex::new(weights);
            assert_eq!(index.sample(&mut rng), None);
            assert_eq!(index.sample_uniform(&mut rng), None);
            let mut draws = index.without_replacement();
            assert!(draws.is_empty());
            assert_eq!(draws.sample(&mut rng), None);
            assert_eq!(draws.sample_uniform(&mut rng), None);
        }
        assert_eq!(rng.random::<[u64; 4]>(), reference.random::<[u64; 4]>());
        let mut index = WeightedIndex::new([0, 7, 0]);
        assert_eq!(index.sample(&mut rng), Some(1));
        index.set(1, 0);
        assert_eq!(index.sample(&mut rng), None);
    }

    #[test]
    fn uniform_draws_match_unit_weights() {
        for weights in [vec![0, 1, 0], vec![u64::MAX, 0, 1, 7], vec![9; 65]] {
            let index = WeightedIndex::new(weights.iter().copied());
            let uniform = WeightedIndex::new(weights.iter().map(|&weight| u64::from(weight != 0)));
            let mut rng = TestRng::new(0);
            let mut reference = TestRng::new(0);
            for _ in 0..DRAWS {
                assert_eq!(
                    index.sample_uniform(&mut rng),
                    uniform.sample(&mut reference)
                );
            }
            assert_eq!(rng.random::<[u64; 4]>(), reference.random::<[u64; 4]>());
        }
    }

    /// Checks a sequence against independently excluded weighted and unit-weight indices.
    /// `mode` 0 draws by weight, 1 draws uniformly, and 2 alternates, starting by weight.
    fn assert_without_replacement(
        mut draws: WithoutReplacement<'_>,
        weights: &[u64],
        stop_after: usize,
        mode: usize,
    ) {
        let mut weighted = WeightedIndex::new(weights.iter().copied());
        let mut uniform = WeightedIndex::new(weights.iter().map(|&weight| u64::from(weight != 0)));
        let mut rng = TestRng::new(0);
        let mut reference = TestRng::new(0);
        for step in 0..stop_after {
            assert!(!draws.is_empty());
            let (actual, expected) = if mode == 1 || (mode == 2 && step % 2 == 1) {
                (
                    draws.sample_uniform(&mut rng),
                    uniform.sample(&mut reference),
                )
            } else {
                (draws.sample(&mut rng), weighted.sample(&mut reference))
            };
            assert_eq!(actual, expected);
            let selected = expected.unwrap();
            weighted.set(selected, 0);
            uniform.set(selected, 0);
        }
        assert_eq!(draws.is_empty(), weighted.total() == 0);
        if draws.is_empty() {
            assert_eq!(draws.sample(&mut rng), None);
            assert_eq!(draws.sample_uniform(&mut rng), None);
        }
        assert_eq!(rng.random::<[u64; 4]>(), reference.random::<[u64; 4]>());
    }

    #[test]
    fn without_replacement_matches_exclusion_and_restores_weights() {
        for weights in [
            vec![],
            vec![0, 0],
            vec![0, 1, 0],
            vec![u64::MAX, 1, 0, 7, u64::MAX],
            vec![1; 65],
        ] {
            let positive = weights.iter().filter(|&&weight| weight != 0).count();
            for stop_after in 0..=positive {
                for mode in 0..3 {
                    let mut index = WeightedIndex::new(weights.iter().copied());
                    assert_without_replacement(
                        index.without_replacement(),
                        &weights,
                        stop_after,
                        mode,
                    );
                    assert_intervals(&index, &weights);
                    assert_without_replacement(
                        index.into_without_replacement(),
                        &weights,
                        stop_after,
                        mode,
                    );
                }
            }
        }
    }

    #[test]
    fn without_replacement_restores_weights_on_unwind() {
        let weights = [u64::MAX, 1, 0, 7];
        let mut index = WeightedIndex::new(weights);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut draws = index.without_replacement();
            let mut rng = TestRng::new(0);
            assert!(draws.sample(&mut rng).is_some());
            assert!(draws.sample_uniform(&mut rng).is_some());
            panic!("unwind with an unfinished selection");
        }));
        assert!(result.is_err());
        assert_intervals(&index, &weights);
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
