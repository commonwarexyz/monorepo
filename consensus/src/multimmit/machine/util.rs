//! Collection helpers shared by the machine's partitions.

use super::verification::Observation;
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

    /// Returns a drive that exhausted its budget after `processed` items.
    pub(crate) const fn yielded(processed: usize, output: T) -> Self {
        Self {
            processed,
            complete: false,
            output,
        }
    }
}

impl<T: Default> Drive<T> {
    /// Returns a drive that had nothing to do.
    pub(crate) fn idle() -> Self {
        Self::done(0, T::default())
    }
}

/// Items held inline while there is exactly one, and in a vector beyond that.
pub(crate) enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    /// Returns the items in insertion order.
    pub(crate) fn as_slice(&self) -> &[T] {
        match self {
            Self::One(item) => core::slice::from_ref(item),
            Self::Many(items) => items,
        }
    }

    /// Returns the items in insertion order, mutably.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            Self::One(item) => core::slice::from_mut(item),
            Self::Many(items) => items,
        }
    }

    /// Appends `item`.
    pub(crate) fn push(&mut self, item: T) {
        *self = match core::mem::replace(self, Self::Many(Vec::new())) {
            Self::One(first) => Self::Many(vec![first, item]),
            Self::Many(mut items) => {
                items.push(item);
                Self::Many(items)
            }
        };
    }

    /// Maps every item in order, stopping at the first error.
    pub(crate) fn try_map<U, E>(
        self,
        mut map: impl FnMut(T) -> Result<U, E>,
    ) -> Result<OneOrMany<U>, E> {
        Ok(match self {
            Self::One(item) => OneOrMany::One(map(item)?),
            Self::Many(items) => {
                OneOrMany::Many(items.into_iter().map(map).collect::<Result<_, _>>()?)
            }
        })
    }
}

/// A record and the earliest observation of it.
#[derive(Clone, Debug)]
pub(crate) struct Observed<T> {
    pub(crate) observation: Observation,
    pub(crate) value: T,
}

/// Keyed records in ascending `(observation, key)` order, each held at the earliest observation
/// of its key.
#[derive(Clone, Debug)]
pub(crate) struct ObservedList<K, R> {
    entries: Vec<(K, Observed<R>)>,
}

impl<K, R> Default for ObservedList<K, R> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<K: Copy + Ord, R> ObservedList<K, R> {
    /// Records `key` at `observation`.
    ///
    /// A new key holds the record `make` builds. A held key keeps its record and moves to the
    /// earlier of its two observations. Returns the key's record.
    pub(crate) fn upsert_min(
        &mut self,
        key: K,
        observation: Observation,
        make: impl FnOnce() -> R,
    ) -> &mut R {
        let index = match self.position(key) {
            None => {
                let index = self.insertion_point(observation, key);
                self.entries.insert(
                    index,
                    (
                        key,
                        Observed {
                            observation,
                            value: make(),
                        },
                    ),
                );
                index
            }
            Some(index) if self.entries[index].1.observation > observation => {
                let (key, mut record) = self.entries.remove(index);
                record.observation = observation;
                let index = self.insertion_point(observation, key);
                self.entries.insert(index, (key, record));
                index
            }
            Some(index) => index,
        };
        &mut self.entries[index].1.value
    }

    /// Returns the earliest record and its key.
    pub(crate) fn first(&self) -> Option<(K, &Observed<R>)> {
        self.entries.first().map(|(key, record)| (*key, record))
    }

    /// Returns every record and its key in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (K, &Observed<R>)> {
        self.entries.iter().map(|(key, record)| (*key, record))
    }

    /// Removes the record held for `key`.
    pub(crate) fn remove(&mut self, key: K) -> Option<Observed<R>> {
        let index = self.position(key)?;
        Some(self.entries.remove(index).1)
    }

    /// Returns how many records are held.
    pub(crate) const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no record is held.
    pub(crate) const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn position(&self, key: K) -> Option<usize> {
        self.entries.iter().position(|(held, _)| *held == key)
    }

    fn insertion_point(&self, observation: Observation, key: K) -> usize {
        self.entries
            .partition_point(|(held, record)| (record.observation, *held) < (observation, key))
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

/// Removes the ordered prefix selected by `retired` without yielding it.
/// The predicate must select a contiguous prefix of the map's key order.
pub(crate) fn retire_prefix<K: Ord, V>(
    entries: &mut BTreeMap<K, V>,
    retired: impl FnMut(&K) -> bool,
) {
    drain_prefix(entries, retired).for_each(drop);
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

    fn keys<R>(list: &ObservedList<u8, R>) -> Vec<(u8, u64, u32)> {
        list.iter()
            .map(|(key, record)| (key, record.observation.cohort(), record.observation.index()))
            .collect()
    }

    #[test]
    fn observed_list_keeps_earliest_observation_in_order() {
        let mut list = ObservedList::default();
        assert_eq!(*list.upsert_min(3, Observation::new(5, 0), || "c"), "c");
        assert_eq!(*list.upsert_min(1, Observation::new(7, 0), || "a"), "a");
        assert_eq!(*list.upsert_min(2, Observation::new(5, 0), || "b"), "b");
        // Equal observations order by key.
        assert_eq!(keys(&list), [(2, 5, 0), (3, 5, 0), (1, 7, 0)]);

        // A later observation leaves the record in place.
        assert_eq!(
            *list.upsert_min(2, Observation::new(9, 0), || unreachable!()),
            "b"
        );
        assert_eq!(keys(&list), [(2, 5, 0), (3, 5, 0), (1, 7, 0)]);

        // An earlier observation moves the record and keeps its value.
        assert_eq!(
            *list.upsert_min(1, Observation::new(4, 1), || unreachable!()),
            "a"
        );
        assert_eq!(keys(&list), [(1, 4, 1), (2, 5, 0), (3, 5, 0)]);
        let (key, first) = list.first().expect("records are held");
        assert_eq!((key, first.value), (1, "a"));

        *list.upsert_min(3, Observation::new(5, 0), || unreachable!()) = "d";
        assert_eq!(list.remove(3).map(|record| record.value), Some("d"));
        assert!(list.remove(3).is_none());
        assert_eq!(list.len(), 2);
        list.remove(1);
        list.remove(2);
        assert!(list.is_empty());
    }

    #[test]
    fn one_or_many_preserves_insertion_order() {
        let mut items = OneOrMany::One(1);
        assert_eq!(items.as_slice(), [1]);
        items.push(2);
        items.push(3);
        assert_eq!(items.as_slice(), [1, 2, 3]);
        items.as_mut_slice()[0] = 4;
        let doubled = items.try_map(|item| Ok::<_, ()>(item * 2)).unwrap();
        assert_eq!(doubled.as_slice(), [8, 4, 6]);
    }

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
