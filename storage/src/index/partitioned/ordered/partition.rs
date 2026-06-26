//! Storage for a single partition of a partitioned index.
//!
//! A partition holds the values for all translated keys that share a key prefix, stored as sorted
//! struct-of-arrays: parallel `keys`/`vals` vectors ordered by translated key. Storing keys and
//! values contiguously (rather than in a per-entry map node) is what makes the partitioned index
//! memory-efficient at scale.
//!
//! Multiple values for the same translated key (collisions, or repeated inserts) form a contiguous
//! run of equal keys. Collisions are rare for well-distributed translated keys, so most runs have
//! length one. Within a run the newest value is first (lowest index), matching the iteration order
//! of the non-partitioned index.

use std::ops::Range;

/// A single partition's values as sorted parallel arrays keyed by translated key.
pub(super) struct Partition<K, V> {
    /// Translated keys in ascending order. Equal keys are adjacent (a value run).
    keys: Vec<K>,
    /// Values, aligned with `keys`: `vals[i]` belongs to `keys[i]`.
    vals: Vec<V>,
}

impl<K, V> Default for Partition<K, V> {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            vals: Vec::new(),
        }
    }
}

impl<K: Ord + Copy, V> Partition<K, V> {
    /// Whether the partition holds no entries.
    pub(super) const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The number of stored entries (values, counting collisions).
    pub(super) const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Move every entry out of the partition, leaving it empty, returning one `(key, values)` pair
    /// per distinct key with its values newest-first.
    pub(super) fn drain_runs(&mut self) -> Vec<(K, Vec<V>)> {
        // Each run is already stored newest-first (lowest index), so taking its values in array
        // order preserves that ordering.
        let keys = std::mem::take(&mut self.keys);
        let vals = std::mem::take(&mut self.vals);
        let mut vals = vals.into_iter();
        let mut runs = Vec::new();
        let mut i = 0;
        while i < keys.len() {
            let key = keys[i];
            let mut j = i + 1;
            while j < keys.len() && keys[j] == key {
                j += 1;
            }
            runs.push((key, vals.by_ref().take(j - i).collect()));
            i = j;
        }
        runs
    }

    /// Index of the first entry whose key is `>= key` (the start of `key`'s run, or its insertion
    /// point if absent).
    fn lower_bound(&self, key: &K) -> usize {
        self.keys.partition_point(|k| k < key)
    }

    /// The half-open `[idx, end)` index range of the run of entries equal to `keys[idx]`, given
    /// that `idx` is known to be the run's start (scans forward only).
    fn run_starting_at(&self, idx: usize) -> Range<usize> {
        let key = self.keys[idx];
        let mut end = idx + 1;
        while end < self.keys.len() && self.keys[end] == key {
            end += 1;
        }
        idx..end
    }

    /// The half-open `[start, idx + 1)` index range of the run of entries equal to `keys[idx]`,
    /// given that `idx` is known to be the run's end (scans backward only).
    fn run_ending_at(&self, idx: usize) -> Range<usize> {
        let key = self.keys[idx];
        let mut start = idx;
        while start > 0 && self.keys[start - 1] == key {
            start -= 1;
        }
        start..idx + 1
    }

    /// The half-open `[start, end)` index range of the run of entries equal to `key` (empty if the
    /// key is absent).
    pub(super) fn run_range(&self, key: &K) -> Range<usize> {
        let start = self.lower_bound(key);
        if self.keys.get(start) != Some(key) {
            return start..start;
        }
        let mut end = start + 1;
        while end < self.keys.len() && self.keys[end] == *key {
            end += 1;
        }
        start..end
    }

    /// The values associated with `key`, newest first (empty if absent).
    pub(super) fn values(&self, key: &K) -> &[V] {
        &self.vals[self.run_range(key)]
    }

    /// The value at array index `idx`.
    pub(super) fn value_at(&self, idx: usize) -> &V {
        &self.vals[idx]
    }

    /// Insert `(key, value)` at array index `idx`. The caller must pass an `idx` that keeps `keys`
    /// sorted (i.e. within or adjacent to `key`'s run).
    pub(super) fn insert_at(&mut self, idx: usize, key: K, value: V) {
        self.keys.insert(idx, key);
        self.vals.insert(idx, value);
    }

    /// Remove the entry at array index `idx`, returning its value.
    pub(super) fn remove(&mut self, idx: usize) -> V {
        self.keys.remove(idx);
        self.vals.remove(idx)
    }

    /// Remove every entry in the array range `range` (a whole key's run).
    pub(super) fn remove_run(&mut self, range: Range<usize>) {
        self.keys.drain(range.clone());
        self.vals.drain(range);
    }

    /// Overwrite the value at array index `idx`.
    pub(super) fn set(&mut self, idx: usize, value: V) {
        self.vals[idx] = value;
    }

    /// The values of the lexicographically smallest key, newest first (None if the partition is
    /// empty).
    pub(super) fn first_values(&self) -> Option<&[V]> {
        if self.keys.is_empty() {
            return None;
        }
        Some(&self.vals[self.run_starting_at(0)])
    }

    /// The values of the lexicographically largest key, newest first (None if the partition is
    /// empty).
    pub(super) fn last_values(&self) -> Option<&[V]> {
        let last = self.keys.len().checked_sub(1)?;
        Some(&self.vals[self.run_ending_at(last)])
    }

    /// The values of the smallest key strictly greater than `key`, newest first (None if no such
    /// key exists).
    pub(super) fn next_values_after(&self, key: &K) -> Option<&[V]> {
        let idx = self.keys.partition_point(|k| *k <= *key);
        if idx >= self.keys.len() {
            return None;
        }
        Some(&self.vals[self.run_starting_at(idx)])
    }

    /// The values of the largest key strictly less than `key`, newest first (None if no such key
    /// exists).
    pub(super) fn prev_values_before(&self, key: &K) -> Option<&[V]> {
        let prev = self.lower_bound(key).checked_sub(1)?;
        Some(&self.vals[self.run_ending_at(prev)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Insert `value` as the newest value for `key`, keeping the arrays sorted. The production hot
    /// path instead reuses the run it already computed (`insert_at(run.start, ..)`) to avoid a
    /// second `lower_bound`; this helper keeps the tests concise.
    fn insert<K: Ord + Copy, V>(p: &mut Partition<K, V>, key: K, value: V) {
        p.insert_at(p.lower_bound(&key), key, value);
    }

    #[test]
    fn test_partition_empty() {
        let p = Partition::<u16, u64>::default();
        assert_eq!(p.values(&5), &[] as &[u64]);
        assert_eq!(p.run_range(&5), 0..0);
        assert!(p.first_values().is_none());
        assert!(p.last_values().is_none());
        assert!(p.next_values_after(&5).is_none());
        assert!(p.prev_values_before(&5).is_none());
    }

    #[test]
    fn test_partition_sorted_insert() {
        let mut p = Partition::<u16, u64>::default();
        // Insert out of order; the arrays stay sorted by key.
        for (k, v) in [(30u16, 300u64), (10, 100), (20, 200)] {
            insert(&mut p, k, v);
        }
        assert_eq!(p.keys, vec![10, 20, 30]);
        assert_eq!(p.vals, vec![100, 200, 300]);
        assert_eq!(p.first_values(), Some(&[100u64] as &[u64]));
        assert_eq!(p.last_values(), Some(&[300u64] as &[u64]));
        assert_eq!(p.values(&20), &[200]);
        assert_eq!(p.values(&25), &[] as &[u64]);
    }

    #[test]
    fn test_partition_navigation() {
        let mut p = Partition::<u16, u64>::default();
        for (k, v) in [(10u16, 100u64), (20, 200), (20, 222), (30, 300)] {
            insert(&mut p, k, v);
        }
        // next strictly-greater key.
        assert_eq!(p.next_values_after(&5), Some(&[100u64] as &[u64]));
        assert_eq!(p.next_values_after(&10), Some(&[222u64, 200] as &[u64])); // run, newest first
        assert_eq!(p.next_values_after(&20), Some(&[300u64] as &[u64]));
        assert!(p.next_values_after(&30).is_none());
        // prev strictly-less key.
        assert!(p.prev_values_before(&10).is_none());
        assert_eq!(p.prev_values_before(&20), Some(&[100u64] as &[u64]));
        assert_eq!(p.prev_values_before(&25), Some(&[222u64, 200] as &[u64]));
        assert_eq!(p.prev_values_before(&999), Some(&[300u64] as &[u64]));
    }

    #[test]
    fn test_partition_collision_run_newest_first() {
        let mut p = Partition::<u16, u64>::default();
        insert(&mut p, 10, 1);
        insert(&mut p, 20, 2);
        // Three values collide on key 10; newest is first within the run.
        insert(&mut p, 10, 11);
        insert(&mut p, 10, 111);
        assert_eq!(p.values(&10), &[111, 11, 1]);
        assert_eq!(p.values(&20), &[2]);
        // Keys remain sorted with the run adjacent.
        assert_eq!(p.keys, vec![10, 10, 10, 20]);
        assert_eq!(p.run_range(&10), 0..3);
        assert_eq!(p.run_range(&20), 3..4);
    }

    #[test]
    fn test_partition_remove_keeps_alignment() {
        let mut p = Partition::<u16, u64>::default();
        for (k, v) in [(10u16, 1u64), (10, 11), (20, 2)] {
            insert(&mut p, k, v);
        }
        // keys=[10,10,20] vals=[11,1,2]; remove the older value of key 10 (index 1).
        let removed = p.remove(1);
        assert_eq!(removed, 1);
        assert_eq!(p.keys, vec![10, 20]);
        assert_eq!(p.vals, vec![11, 2]);
        assert_eq!(p.values(&10), &[11]);
    }

    #[test]
    fn test_partition_set() {
        let mut p = Partition::<u16, u64>::default();
        insert(&mut p, 10, 1);
        p.set(0, 99);
        assert_eq!(p.values(&10), &[99]);
    }

    #[test]
    fn test_partition_drain_runs() {
        let mut p = Partition::<u16, u64>::default();
        // Two runs: key 10 with three values (newest-first 111, 11, 1), key 20 with one.
        for (k, v) in [(10u16, 1u64), (20, 2), (10, 11), (10, 111)] {
            insert(&mut p, k, v);
        }
        assert_eq!(p.len(), 4);
        let runs = p.drain_runs();
        // One pair per distinct key, ascending, values newest-first.
        assert_eq!(runs, vec![(10, vec![111, 11, 1]), (20, vec![2])]);
        // The partition is left empty.
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }
}
