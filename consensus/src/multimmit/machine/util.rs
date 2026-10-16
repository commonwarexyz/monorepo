//! Collection helpers shared by the machine's partitions.

use std::collections::{BTreeMap, BTreeSet};

/// One bounded prefix of resumable work: the items it processed, whether the work finished, and
/// what the prefix produced.
pub(crate) struct Drive<T> {
    pub(crate) processed: usize,
    pub(crate) complete: bool,
    pub(crate) output: T,
}

impl<T> Drive<T> {
    /// Returns a drive that finished after `processed` items.
    pub(crate) const fn done(processed: usize, output: T) -> Self {
        Self {
            processed,
            complete: true,
            output,
        }
    }
}

/// Removes the ordered prefix selected by `retired`, stopping at the first retained key.
/// The predicate must select a contiguous prefix of the map's key order.
pub(crate) fn drain_prefix<K: Ord, V>(
    entries: &mut BTreeMap<K, V>,
    mut retired: impl FnMut(&K) -> bool,
) -> impl Iterator<Item = (K, V)> {
    std::iter::from_fn(move || {
        if entries
            .first_key_value()
            .is_some_and(|(key, _)| retired(key))
        {
            entries.pop_first()
        } else {
            None
        }
    })
}

/// Removes `value` from the set indexed by `key` and drops the set once it is empty.
///
/// Returns whether the set was dropped, so callers can react to the last removal.
pub(super) fn remove_indexed<K: Ord, V: Ord>(
    map: &mut BTreeMap<K, BTreeSet<V>>,
    key: &K,
    value: &V,
) -> bool {
    let Some(values) = map.get_mut(key) else {
        return false;
    };
    values.remove(value);
    if !values.is_empty() {
        return false;
    }
    map.remove(key);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::View;

    #[test]
    fn retirement_prefix_skips_the_live_suffix() {
        for live in [8, 16_384] {
            let mut entries = (0..live).map(|key| (key, key)).collect::<BTreeMap<_, _>>();
            let mut expected = entries.clone();
            let mut full_checks = 0;
            expected.retain(|key, _| {
                full_checks += 1;
                *key > 3
            });
            let mut prefix_checks = 0;
            let removed = drain_prefix(&mut entries, |key| {
                prefix_checks += 1;
                *key <= 3
            })
            .collect::<Vec<_>>();
            assert_eq!(entries, expected);
            assert_eq!(removed, [(0, 0), (1, 1), (2, 2), (3, 3)]);
            assert_eq!(prefix_checks, 5);
            assert_eq!(full_checks, live);
            assert!(prefix_checks < full_checks);
        }
    }

    #[test]
    fn retirement_prefix_handles_boundaries_and_compound_keys() {
        let mut entries = BTreeMap::from([
            ((View::zero(), 0), 0),
            ((View::new(1), 0), 1),
            ((View::new(1), 1), 2),
            ((View::new(u64::MAX), 0), 3),
        ]);
        assert_eq!(
            drain_prefix(&mut entries, |(view, _)| *view <= View::zero()).count(),
            1
        );
        assert_eq!(
            drain_prefix(&mut entries, |(view, _)| *view <= View::zero()).count(),
            0
        );
        assert_eq!(
            drain_prefix(&mut entries, |(view, _)| *view <= View::new(1)).count(),
            2
        );
        assert_eq!(
            drain_prefix(&mut entries, |(view, _)| *view <= View::new(u64::MAX)).count(),
            1
        );
        assert_eq!(drain_prefix(&mut entries, |_| true).count(), 0);
    }

    #[test]
    fn remove_indexed_drops_only_emptied_sets() {
        let mut map = BTreeMap::from([(1, BTreeSet::from([10, 11])), (2, BTreeSet::from([20]))]);

        assert!(!remove_indexed(&mut map, &1, &10));
        assert_eq!(map[&1], BTreeSet::from([11]));
        assert!(!remove_indexed(&mut map, &1, &12));
        assert!(!remove_indexed(&mut map, &3, &30));

        assert!(remove_indexed(&mut map, &2, &20));
        assert!(!map.contains_key(&2));
        assert!(remove_indexed(&mut map, &1, &11));
        assert!(map.is_empty());
    }
}
