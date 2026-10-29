//! Random sampling with weights.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use rand::{Rng, RngExt as _};

/// Orders `items` by weighted sampling without replacement.
///
/// Each position is filled by drawing one of the remaining items with probability proportional
/// to its weight, so heavier items tend to come first while every item can appear at any
/// position. Items with zero weight are drawn only once no positive weight remains, and then in
/// uniformly random order. Draws consume only integer samples from `rng`, so the same random
/// sequence yields the same order on every platform.
///
/// Runs in `O(n^2)` time, which suits the small collections it is meant for, such as a peer set.
///
/// # Examples
///
/// ```
/// use commonware_utils::sampling::weighted_shuffle;
/// use rand::{SeedableRng, rngs::StdRng};
///
/// let mut rng = StdRng::seed_from_u64(0);
/// let order = weighted_shuffle(&mut rng, [("rare", 1), ("common", 99)]);
/// assert_eq!(order.len(), 2);
/// ```
pub fn weighted_shuffle<T, R: Rng + ?Sized>(
    rng: &mut R,
    items: impl IntoIterator<Item = (T, u64)>,
) -> Vec<T> {
    let mut remaining: Vec<(T, u64)> = items.into_iter().collect();
    let mut total: u128 = remaining
        .iter()
        .map(|(_, weight)| u128::from(*weight))
        .sum();
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let index = if total == 0 {
            rng.random_range(0..remaining.len())
        } else {
            let mut draw = rng.random_range(0..total);
            remaining
                .iter()
                .position(|(_, weight)| {
                    let weight = u128::from(*weight);
                    if draw < weight {
                        return true;
                    }
                    draw -= weight;
                    false
                })
                .expect("draw is below the total weight")
        };
        let (item, weight) = remaining.swap_remove(index);
        total -= u128::from(weight);
        ordered.push(item);
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;

    const DRAWS: usize = 2_000;

    /// Counts how often each item is drawn first over [`DRAWS`] shuffles, one seed per shuffle.
    fn first_picks<const N: usize>(items: [(char, u64); N]) -> [usize; N] {
        let mut picks = [0; N];
        for seed in 0..DRAWS as u64 {
            let first = weighted_shuffle(&mut TestRng::new(seed), items)[0];
            picks[items.iter().position(|(item, _)| *item == first).unwrap()] += 1;
        }
        picks
    }

    #[test]
    fn permutes_items() {
        let items = [('a', 5), ('b', 0), ('c', 1), ('d', u64::MAX), ('e', 3)];
        for seed in 0..100 {
            let mut order = weighted_shuffle(&mut TestRng::new(seed), items);
            assert_eq!(order.len(), items.len());
            order.sort_unstable();
            assert_eq!(order, ['a', 'b', 'c', 'd', 'e']);
        }
    }

    #[test]
    fn handles_empty_and_single() {
        let mut rng = TestRng::new(0);
        let empty: Vec<char> = weighted_shuffle(&mut rng, []);
        assert!(empty.is_empty());
        assert_eq!(weighted_shuffle(&mut rng, [('a', 0)]), ['a']);
        assert_eq!(weighted_shuffle(&mut rng, [('a', 7)]), ['a']);
    }

    #[test]
    fn same_seed_same_order() {
        let items = [('a', 1), ('b', 2), ('c', 3), ('d', 4)];
        for seed in 0..20 {
            let first = weighted_shuffle(&mut TestRng::new(seed), items);
            let second = weighted_shuffle(&mut TestRng::new(seed), items);
            assert_eq!(first, second);
        }
    }

    #[test]
    fn heavier_items_lead() {
        let [heavy, light] = first_picks([('h', 9), ('l', 1)]);
        assert!(
            (DRAWS * 85 / 100..DRAWS * 95 / 100).contains(&heavy),
            "{heavy} {light}"
        );
    }

    #[test]
    fn equal_weights_are_uniform() {
        let picks = first_picks([('a', 0), ('b', 0), ('c', 0)]);
        for count in picks {
            assert!((DRAWS / 4..DRAWS * 5 / 12).contains(&count), "{picks:?}");
        }
        let picks = first_picks([('a', 7), ('b', 7), ('c', 7)]);
        for count in picks {
            assert!((DRAWS / 4..DRAWS * 5 / 12).contains(&count), "{picks:?}");
        }
    }

    #[test]
    fn zero_weights_come_last_in_random_order() {
        let items = [('z', 0), ('a', 5), ('y', 0), ('b', 3)];
        let mut tail_orders = [0usize; 2];
        for seed in 0..200 {
            let order = weighted_shuffle(&mut TestRng::new(seed), items);
            assert!(
                order[..2].contains(&'a') && order[..2].contains(&'b'),
                "{order:?}"
            );
            tail_orders[usize::from(order[2] == 'y')] += 1;
        }
        assert!(
            tail_orders.iter().all(|&count| count > 50),
            "{tail_orders:?}"
        );
    }
}
