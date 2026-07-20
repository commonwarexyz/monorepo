//! Solver-friendly ordered containers substituted for the volume's
//! `BTreeMap`/`BTreeSet` under Kani.
//!
//! Symbolic execution of the std BTree containers exhausts CBMC: the
//! node-splitting tree surgery behind two symbolic-key inserts alone
//! blows past the solver's memory budget. [`VecMap`] and [`VecSet`] are
//! sorted-Vec substitutes with linear scans that solve the same shapes in
//! seconds, so `cargo kani` builds swap them in for the volume's ordered
//! containers through the `OrderedMap`/`OrderedSet` aliases in the module
//! root (the loom pattern: substitute the primitive under a cfg, keep the
//! algorithm identical). Production and test builds are untouched — the
//! aliases resolve to the std containers whenever `kani` is not set.
//!
//! # Trust argument
//!
//! A proof over a substituted container checks "the algorithm over an
//! equivalent container", not the exact container production runs.
//! Equivalence is enforced by the differential tests below: long
//! randomized op sequences drive each substitute against its BTree
//! original over the full mirrored API (including range queries in both
//! directions, `split_off`, and `retain`), asserting identical observable
//! results after every op.
//!
//! # Maintenance contract
//!
//! The substitutes mirror exactly the BTree API subset the volume uses on
//! aliased containers. A new BTree method used on one of them must be
//! mirrored here (with differential coverage) or `cargo kani` fails to
//! compile.

// Under Kani only the methods reached from non-test volume code are live
// (the rest serve test-only callers and the differential tests).
#![cfg_attr(kani, allow(dead_code))]

use std::{
    fmt, iter,
    ops::{Bound, RangeBounds},
    slice, vec,
};

// The iterators are concrete `Map`s of slice iterators over nameable fn
// pointers, not `impl Trait`: an opaque return type is treated as possibly
// carrying drop glue, which keeps scrutinee temporaries borrowed to the
// end of an `if let` where the std BTree iterators (no `Drop`) release
// early — call sites borrow-check identically only with concrete types.

/// The `(&K, &V)` view of a stored entry.
type EntryRefs<'a, K, V> = fn(&'a (K, V)) -> (&'a K, &'a V);

/// The `(&K, &mut V)` view of a stored entry.
type EntryMuts<'a, K, V> = fn(&'a mut (K, V)) -> (&'a K, &'a mut V);

/// A borrowed key.
type KeyRef<'a, K, V> = fn(&'a (K, V)) -> &'a K;

/// A borrowed value.
type ValueRef<'a, K, V> = fn(&'a (K, V)) -> &'a V;

/// A mutably borrowed value.
type ValueMut<'a, K, V> = fn(&'a mut (K, V)) -> &'a mut V;

/// An entry's value, owned.
type IntoValue<K, V> = fn((K, V)) -> V;

/// The borrowed-entry iterator (`BTreeMap::iter`'s shape).
type Iter<'a, K, V> = iter::Map<slice::Iter<'a, (K, V)>, EntryRefs<'a, K, V>>;

/// The mutable-entry iterator (`BTreeMap::range_mut`'s shape).
type IterMut<'a, K, V> = iter::Map<slice::IterMut<'a, (K, V)>, EntryMuts<'a, K, V>>;

/// The borrowed-key iterator (`BTreeSet::iter`'s shape).
type SetIter<'a, K> = iter::Map<slice::Iter<'a, (K, ())>, KeyRef<'a, K, ()>>;

/// Borrow an entry's key and value.
const fn entry_refs<K, V>(entry: &(K, V)) -> (&K, &V) {
    (&entry.0, &entry.1)
}

/// Borrow an entry's key and, mutably, its value.
const fn entry_muts<K, V>(entry: &mut (K, V)) -> (&K, &mut V) {
    (&entry.0, &mut entry.1)
}

/// A `BTreeMap` substitute over a sorted `Vec`, mirroring the API subset
/// the volume uses (see the module docs).
pub(super) struct VecMap<K, V> {
    /// Entries sorted by key, keys unique.
    entries: Vec<(K, V)>,
}

impl<K: Ord, V> VecMap<K, V> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Index of the first entry whose key is `>= key` (linear scan: data-
    /// independent loop structure keeps the solver's formula small).
    fn lower_bound(&self, key: &K) -> usize {
        let mut i = 0;
        while i < self.entries.len() && self.entries[i].0 < *key {
            i += 1;
        }
        i
    }

    /// Index of the first entry whose key is `> key`.
    fn upper_bound(&self, key: &K) -> usize {
        let mut i = 0;
        while i < self.entries.len() && self.entries[i].0 <= *key {
            i += 1;
        }
        i
    }

    /// `Ok(index)` of `key`, or `Err` of its order-preserving insertion
    /// index.
    fn position(&self, key: &K) -> Result<usize, usize> {
        let at = self.lower_bound(key);
        if at < self.entries.len() && self.entries[at].0 == *key {
            Ok(at)
        } else {
            Err(at)
        }
    }

    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.position(key).ok().map(|i| &self.entries[i].1)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.position(key).ok().map(|i| &mut self.entries[i].1)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.position(key).is_ok()
    }

    /// Insert `value` at `key`, returning the previous value (the
    /// original key is kept on replacement, as with `BTreeMap`).
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.position(&key) {
            Ok(i) => Some(std::mem::replace(&mut self.entries[i].1, value)),
            Err(i) => {
                self.entries.insert(i, (key, value));
                None
            }
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.position(key).ok().map(|i| self.entries.remove(i).1)
    }

    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.entries.first().map(entry_refs)
    }

    /// The entries in ascending key order.
    pub fn iter(&self) -> Iter<'_, K, V> {
        let refs: EntryRefs<'_, K, V> = entry_refs;
        self.entries.iter().map(refs)
    }

    pub fn keys(&self) -> iter::Map<slice::Iter<'_, (K, V)>, KeyRef<'_, K, V>> {
        let key: KeyRef<'_, K, V> = |entry| &entry.0;
        self.entries.iter().map(key)
    }

    pub fn values(&self) -> iter::Map<slice::Iter<'_, (K, V)>, ValueRef<'_, K, V>> {
        let value: ValueRef<'_, K, V> = |entry| &entry.1;
        self.entries.iter().map(value)
    }

    pub fn values_mut(&mut self) -> iter::Map<slice::IterMut<'_, (K, V)>, ValueMut<'_, K, V>> {
        let value: ValueMut<'_, K, V> = |entry| &mut entry.1;
        self.entries.iter_mut().map(value)
    }

    pub fn into_values(self) -> iter::Map<vec::IntoIter<(K, V)>, IntoValue<K, V>> {
        let value: IntoValue<K, V> = |entry| entry.1;
        self.entries.into_iter().map(value)
    }

    /// The entries with keys in `range`, in ascending key order.
    ///
    /// Panics like `BTreeMap::range`: on a range whose start is greater
    /// than its end, or one with equal and both-excluded bounds.
    pub fn range<R: RangeBounds<K>>(&self, range: R) -> Iter<'_, K, V> {
        let (lo, hi) = self.subrange(&range);
        let refs: EntryRefs<'_, K, V> = entry_refs;
        self.entries[lo..hi].iter().map(refs)
    }

    /// [`Self::range`] with mutable values.
    pub fn range_mut<R: RangeBounds<K>>(&mut self, range: R) -> IterMut<'_, K, V> {
        let (lo, hi) = self.subrange(&range);
        let muts: EntryMuts<'_, K, V> = entry_muts;
        self.entries[lo..hi].iter_mut().map(muts)
    }

    /// The half-open entry-index window `range` covers, panicking on the
    /// ranges `BTreeMap::range` rejects.
    fn subrange<R: RangeBounds<K>>(&self, range: &R) -> (usize, usize) {
        match (range.start_bound(), range.end_bound()) {
            (Bound::Excluded(s), Bound::Excluded(e)) if s == e => {
                panic!("range start and end are equal and both are excluded")
            }
            (Bound::Included(s) | Bound::Excluded(s), Bound::Included(e) | Bound::Excluded(e))
                if s > e =>
            {
                panic!("range start is greater than range end")
            }
            _ => {}
        }
        let lo = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(key) => self.lower_bound(key),
            Bound::Excluded(key) => self.upper_bound(key),
        };
        let hi = match range.end_bound() {
            Bound::Unbounded => self.entries.len(),
            Bound::Included(key) => self.upper_bound(key),
            Bound::Excluded(key) => self.lower_bound(key),
        };
        (lo, hi)
    }

    /// Split the map: `self` keeps the keys below `key`, the returned map
    /// holds the keys at and above it.
    pub fn split_off(&mut self, key: &K) -> Self {
        let at = self.lower_bound(key);
        // A plain push loop: collecting through a size hint reserves
        // symbolic capacity, which bloats the solver's memory model.
        let mut tail = Vec::new();
        for entry in self.entries.drain(at..) {
            tail.push(entry);
        }
        Self { entries: tail }
    }

    /// Keep only the entries `keep` accepts, visited in ascending key
    /// order.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let mut kept = 0;
        for i in 0..self.entries.len() {
            let entry = &mut self.entries[i];
            if keep(&entry.0, &mut entry.1) {
                // Kept entries slide left over the dropped ones, so the
                // ascending order is preserved.
                self.entries.swap(kept, i);
                kept += 1;
            }
        }
        self.entries.truncate(kept);
    }
}

impl<K, V> Default for VecMap<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for VecMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(entry_refs))
            .finish()
    }
}

impl<K, V> IntoIterator for VecMap<K, V> {
    type Item = (K, V);
    type IntoIter = vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a VecMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        let refs: EntryRefs<'a, K, V> = entry_refs;
        self.entries.iter().map(refs)
    }
}

/// A `BTreeSet` substitute over [`VecMap`], mirroring the API subset the
/// volume uses (std's own layering: `BTreeSet` wraps `BTreeMap<T, ()>`).
pub(super) struct VecSet<K> {
    map: VecMap<K, ()>,
}

impl<K: Ord> VecSet<K> {
    pub const fn new() -> Self {
        Self { map: VecMap::new() }
    }

    pub const fn len(&self) -> usize {
        self.map.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Insert `key`, returning whether it was newly inserted.
    pub fn insert(&mut self, key: K) -> bool {
        self.map.insert(key, ()).is_none()
    }

    /// Remove `key`, returning whether it was present.
    pub fn remove(&mut self, key: &K) -> bool {
        self.map.remove(key).is_some()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn first(&self) -> Option<&K> {
        self.map.first_key_value().map(|(key, _)| key)
    }

    /// The keys in ascending order.
    pub fn iter(&self) -> SetIter<'_, K> {
        self.map.keys()
    }

    /// The keys in `range`, ascending (panics as [`VecMap::range`] does).
    pub fn range<R: RangeBounds<K>>(&self, range: R) -> SetIter<'_, K> {
        let (lo, hi) = self.map.subrange(&range);
        let key: KeyRef<'_, K, ()> = |entry| &entry.0;
        self.map.entries[lo..hi].iter().map(key)
    }

    /// Split the set: `self` keeps the keys below `key`, the returned set
    /// holds the keys at and above it.
    pub fn split_off(&mut self, key: &K) -> Self {
        Self {
            map: self.map.split_off(key),
        }
    }

    /// Keep only the keys `keep` accepts, visited in ascending order.
    pub fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        self.map.retain(|key, ()| keep(key));
    }
}

impl<K> Default for VecSet<K> {
    fn default() -> Self {
        Self {
            map: VecMap::default(),
        }
    }
}

impl<K: fmt::Debug> fmt::Debug for VecSet<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.map.entries.iter().map(|entry| &entry.0))
            .finish()
    }
}

/// Extract the key from an owned set entry (nameable for the owned
/// [`IntoIterator`] impl).
type SetKey<K> = fn((K, ())) -> K;

impl<K> IntoIterator for VecSet<K> {
    type Item = K;
    type IntoIter = iter::Map<vec::IntoIter<(K, ())>, SetKey<K>>;

    fn into_iter(self) -> Self::IntoIter {
        let key: SetKey<K> = |(key, ())| key;
        self.map.into_iter().map(key)
    }
}

impl<'a, K> IntoIterator for &'a VecSet<K> {
    type Item = &'a K;
    type IntoIter = SetIter<'a, K>;

    fn into_iter(self) -> Self::IntoIter {
        let key: KeyRef<'a, K, ()> = |entry| &entry.0;
        self.map.entries.iter().map(key)
    }
}

// The swap's in-tree smoke test (run via `just kani`): the exact shape
// that exhausted the solver's memory over `BTreeMap` — two symbolic-key
// inserts — plus the floor-descent observation every runs-map walk
// performs, proven cheap over the substitute.
#[cfg(kani)]
mod verification {
    use super::VecMap;

    /// Two symbolic-key inserts read back exactly, and the ordered floor
    /// descent (`range(..=hi).next_back()`) finds the largest key.
    #[kani::proof]
    #[kani::unwind(6)]
    fn vecmap_symbolic_inserts() {
        let mut map: VecMap<u64, u64> = VecMap::new();
        let (k1, v1): (u64, u64) = (kani::any(), kani::any());
        let (k2, v2): (u64, u64) = (kani::any(), kani::any());
        map.insert(k1, v1);
        map.insert(k2, v2);
        assert_eq!(map.get(&k2), Some(&v2));
        if k1 != k2 {
            assert_eq!(map.get(&k1), Some(&v1));
        }
        let hi = k1.max(k2);
        let floor = map.range(..=hi).next_back().expect("nonempty");
        assert_eq!((*floor.0, *floor.1), (hi, *map.get(&hi).expect("present")));
    }
}

#[cfg(test)]
mod tests {
    use super::{VecMap, VecSet};
    use commonware_utils::TestRng;
    use rand::RngExt as _;
    use std::{
        collections::{BTreeMap, BTreeSet},
        ops::Bound,
    };

    /// Key domain, small enough that inserts, removes, and range bounds
    /// collide constantly.
    const KEYS: u64 = 48;
    /// Ops per seed.
    const OPS: usize = 4_000;
    /// Independent differential runs.
    const SEEDS: u64 = 8;

    /// A random valid range: ordered endpoints, any bound kinds, skipping
    /// the equal-and-both-excluded shape both containers reject.
    fn any_range(rng: &mut TestRng) -> (Bound<u64>, Bound<u64>) {
        loop {
            let a = rng.random_range(0..=KEYS);
            let b = rng.random_range(0..=KEYS);
            let (lo, hi) = (a.min(b), a.max(b));
            let start = match rng.random_range(0..3u8) {
                0 => Bound::Included(lo),
                1 => Bound::Excluded(lo),
                _ => Bound::Unbounded,
            };
            let end = match rng.random_range(0..3u8) {
                0 => Bound::Included(hi),
                1 => Bound::Excluded(hi),
                _ => Bound::Unbounded,
            };
            match (start, end) {
                (Bound::Excluded(s), Bound::Excluded(e)) if s == e => continue,
                _ => return (start, end),
            }
        }
    }

    /// Assert every borrowed observation matches the model.
    fn assert_map_equiv(map: &VecMap<u64, u64>, model: &BTreeMap<u64, u64>) {
        assert_eq!(map.len(), model.len());
        assert_eq!(map.is_empty(), model.is_empty());
        assert_eq!(map.first_key_value(), model.first_key_value());
        assert!(map.iter().eq(model.iter()), "iter diverged");
        assert!(map.iter().rev().eq(model.iter().rev()), "rev diverged");
        assert!(map.keys().eq(model.keys()), "keys diverged");
        assert!(map.values().eq(model.values()), "values diverged");
        assert!(map.into_iter().eq(model), "borrowed IntoIterator diverged");
        assert_eq!(format!("{map:?}"), format!("{model:?}"), "Debug diverged");
    }

    /// Assert every borrowed observation matches the model.
    fn assert_set_equiv(set: &VecSet<u64>, model: &BTreeSet<u64>) {
        assert_eq!(set.len(), model.len());
        assert_eq!(set.is_empty(), model.is_empty());
        assert_eq!(set.first(), model.first());
        assert!(set.iter().eq(model.iter()), "iter diverged");
        assert!(set.iter().rev().eq(model.iter().rev()), "rev diverged");
        assert!(set.into_iter().eq(model), "borrowed IntoIterator diverged");
        assert_eq!(format!("{set:?}"), format!("{model:?}"), "Debug diverged");
    }

    #[test]
    fn test_vecmap_differential() {
        for seed in 0..SEEDS {
            let mut rng = TestRng::new(seed);
            let mut map: VecMap<u64, u64> = VecMap::new();
            let mut model: BTreeMap<u64, u64> = BTreeMap::new();
            for _ in 0..OPS {
                let key = rng.random_range(0..KEYS);
                match rng.random_range(0..16u8) {
                    0..=4 => {
                        let value = rng.random_range(0..u64::MAX);
                        assert_eq!(map.insert(key, value), model.insert(key, value));
                    }
                    5..=6 => {
                        assert_eq!(map.remove(&key), model.remove(&key));
                    }
                    7 => {
                        assert_eq!(map.get(&key), model.get(&key));
                        assert_eq!(map.contains_key(&key), model.contains_key(&key));
                        if let Some(value) = map.get_mut(&key) {
                            *value = value.wrapping_add(1);
                        }
                        if let Some(value) = model.get_mut(&key) {
                            *value = value.wrapping_add(1);
                        }
                    }
                    8 => {
                        let range = any_range(&mut rng);
                        assert!(map.range(range).eq(model.range(range)), "range diverged");
                    }
                    9 => {
                        let range = any_range(&mut rng);
                        assert!(
                            map.range(range).rev().eq(model.range(range).rev()),
                            "range rev diverged"
                        );
                    }
                    10 => {
                        let range = any_range(&mut rng);
                        let delta = rng.random_range(0..u64::MAX);
                        let mut touched = 0;
                        for (_, value) in map.range_mut(range) {
                            *value = value.wrapping_add(delta);
                            touched += 1;
                        }
                        let mut model_touched = 0;
                        for (_, value) in model.range_mut(range) {
                            *value = value.wrapping_add(delta);
                            model_touched += 1;
                        }
                        assert_eq!(touched, model_touched);
                    }
                    11 => {
                        let at = rng.random_range(0..=KEYS);
                        let tail = map.split_off(&at);
                        let model_tail = model.split_off(&at);
                        assert_map_equiv(&tail, &model_tail);
                        // Owned iteration over the split halves also pins
                        // `into_values` and the owned `IntoIterator`.
                        if rng.random_range(0..2u8) == 0 {
                            assert!(tail.into_values().eq(model_tail.into_values()));
                        } else {
                            assert!(tail.into_iter().eq(model_tail));
                        }
                    }
                    12 => {
                        // Also pins the ascending visit order.
                        let modulus = rng.random_range(2..5u64);
                        let mut seen = Vec::new();
                        map.retain(|&k, value| {
                            seen.push(k);
                            *value % modulus != 0
                        });
                        let mut model_seen = Vec::new();
                        model.retain(|&k, value| {
                            model_seen.push(k);
                            *value % modulus != 0
                        });
                        assert_eq!(seen, model_seen, "retain visit order diverged");
                    }
                    13 => {
                        let delta = rng.random_range(0..u64::MAX);
                        for value in map.values_mut() {
                            *value = value.wrapping_add(delta);
                        }
                        for value in model.values_mut() {
                            *value = value.wrapping_add(delta);
                        }
                    }
                    14 => {
                        // The floor/ceiling descents the volume leans on.
                        assert_eq!(
                            map.range(..=key).next_back(),
                            model.range(..=key).next_back()
                        );
                        assert_eq!(map.range(key..).next(), model.range(key..).next());
                    }
                    _ => {
                        map.clear();
                        model.clear();
                    }
                }
                assert_map_equiv(&map, &model);
            }
            assert!(map.into_iter().eq(model), "owned IntoIterator diverged");
        }
    }

    #[test]
    fn test_vecset_differential() {
        for seed in 0..SEEDS {
            let mut rng = TestRng::new(seed);
            let mut set: VecSet<u64> = VecSet::new();
            let mut model: BTreeSet<u64> = BTreeSet::new();
            for _ in 0..OPS {
                let key = rng.random_range(0..KEYS);
                match rng.random_range(0..16u8) {
                    0..=5 => {
                        assert_eq!(set.insert(key), model.insert(key));
                    }
                    6..=8 => {
                        assert_eq!(set.remove(&key), model.remove(&key));
                    }
                    9 => {
                        assert_eq!(set.contains(&key), model.contains(&key));
                    }
                    10..=11 => {
                        let range = any_range(&mut rng);
                        assert!(set.range(range).eq(model.range(range)), "range diverged");
                        assert!(
                            set.range(range).rev().eq(model.range(range).rev()),
                            "range rev diverged"
                        );
                        assert_eq!(set.range(range).count(), model.range(range).count());
                    }
                    12 => {
                        let at = rng.random_range(0..=KEYS);
                        let tail = set.split_off(&at);
                        let model_tail = model.split_off(&at);
                        assert_set_equiv(&tail, &model_tail);
                        assert!(tail.into_iter().eq(model_tail));
                    }
                    13 => {
                        // Also pins the ascending visit order.
                        let modulus = rng.random_range(2..5u64);
                        let mut seen = Vec::new();
                        set.retain(|&k| {
                            seen.push(k);
                            k % modulus != 0
                        });
                        let mut model_seen = Vec::new();
                        model.retain(|&k| {
                            model_seen.push(k);
                            k % modulus != 0
                        });
                        assert_eq!(seen, model_seen, "retain visit order diverged");
                    }
                    14 => {
                        assert_eq!(
                            set.range(..=key).next_back(),
                            model.range(..=key).next_back()
                        );
                        assert_eq!(set.range(key..).next(), model.range(key..).next());
                    }
                    _ => {
                        set.clear();
                        model.clear();
                    }
                }
                assert_set_equiv(&set, &model);
            }
            assert!(set.into_iter().eq(model), "owned IntoIterator diverged");
        }
    }

    #[test]
    #[should_panic(expected = "range start is greater than range end")]
    fn test_range_rejects_inverted_bounds() {
        let map: VecMap<u64, u64> = VecMap::new();
        let _ = map.range((Bound::Included(3u64), Bound::Included(1)));
    }

    #[test]
    #[should_panic(expected = "range start and end are equal and both are excluded")]
    fn test_range_rejects_doubly_excluded_point() {
        let map: VecMap<u64, u64> = VecMap::new();
        let _ = map.range((Bound::Excluded(1u64), Bound::Excluded(1u64)));
    }
}
