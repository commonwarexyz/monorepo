//! A memory-efficient index that uses an unordered map internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

use crate::{
    index::{
        Cursor as CursorTrait, Unordered,
        storage::{Cursor as CursorImpl, IndexEntry, Overflow, Values, push_displaced},
    },
    translator::Translator,
};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};
use std::collections::{
    HashMap,
    hash_map::{Entry, OccupiedEntry, VacantEntry},
};

/// Implementation of [IndexEntry] for [OccupiedEntry].
impl<K: Send + Sync, V: Send + Sync> IndexEntry<V> for OccupiedEntry<'_, K, V> {
    type Key = K;

    fn key(&self) -> &K {
        OccupiedEntry::key(self)
    }

    fn get_mut(&mut self) -> &mut V {
        self.get_mut()
    }

    fn remove(self) {
        OccupiedEntry::remove(self);
    }
}

/// A [crate::index::Cursor] over the values associated with a translated key.
pub type Cursor<'a, K, V, S> = CursorImpl<'a, K, V, OccupiedEntry<'a, K, V>, S>;

/// A memory-efficient index that uses an unordered map internally to map translated keys to
/// arbitrary values.
///
/// Each translated key maps directly to its most recently inserted value. Conflicting values (from
/// key collisions or repeated insertions) live in a separate overflow map, keeping the common
/// (collision-free) case compact.
pub struct Index<T: Translator, V: Send + Sync> {
    translator: T,
    map: HashMap<T::Key, V, T>,
    overflow: Overflow<T::Key, V, T>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Send + Sync> Index<T, V> {
    /// Create a new entry in the index.
    fn create(keys: &Gauge, items: &Gauge, vacant: VacantEntry<'_, T::Key, V>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(v);
    }

    /// Create a new index with the given translator and metrics registry. The maps start without
    /// capacity and grow as needed, so unused indices (e.g. empty partitions) cost no memory.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        Self {
            translator: translator.clone(),
            overflow: HashMap::with_hasher(translator.clone()),
            map: HashMap::with_hasher(translator),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    /// Create an empty index with this index's translator and metric handles. Parallel
    /// snapshot-build workers use it for their partition slots.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn empty(&self) -> Self {
        Self {
            translator: self.translator.clone(),
            overflow: HashMap::with_hasher(self.translator.clone()),
            map: HashMap::with_hasher(self.translator.clone()),
            keys: self.keys.clone(),
            items: self.items.clone(),
            pruned: self.pruned.clone(),
        }
    }

    /// Move `other`'s contents into self, which must be empty. Wholesale moves are what let
    /// [`Self::empty`] build-worker slots install without re-inserting each entry.
    /// Metrics need no adjustment, since `other` updated self's handles directly.
    ///
    /// # Panics
    ///
    /// Panics if self is not empty.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn absorb(&mut self, other: Self) {
        assert!(
            self.map.is_empty() && self.overflow.is_empty(),
            "absorb target must be empty"
        );
        self.map = other.map;
        self.overflow = other.overflow;
    }

    /// Visit every value held by the index (inline and overflow), in unspecified order.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn for_each_value(&self, mut f: impl FnMut(&V)) {
        for v in self.map.values() {
            f(v);
        }
        for chain in self.overflow.values() {
            for v in chain {
                f(v);
            }
        }
    }

    /// Retain only the values, across all keys, for which `should_retain` returns `true`, calling
    /// it once per value, then shrink each map, and any overflow chain left under a quarter full,
    /// to fit twice its remaining entries, so memory and later calls track the index's size rather
    /// than its peak.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn retain_all(&mut self, mut should_retain: impl FnMut(&V) -> bool) {
        let mut removed_items = 0;
        let mut removed_keys = 0;

        // Filter the overflow chains first, so a dropped inline value can be replaced by a
        // retained overflow value.
        for chain in self.overflow.values_mut() {
            let len = chain.len();
            chain.retain(&mut should_retain);
            removed_items += len - chain.len();

            // `Vec::shrink_to` reallocates whenever capacity exceeds its bound, so only a chain
            // left under a quarter full shrinks, to twice its remaining entries.
            if chain.capacity() > chain.len() * 4 {
                chain.shrink_to(chain.len() * 2);
            }
        }

        self.map.retain(|k, head| {
            if should_retain(head) {
                return true;
            }
            removed_items += 1;

            // Promote the newest overflow value, matching the order a cursor delete leaves.
            let Some(newest) = self.overflow.get_mut(k).and_then(Vec::pop) else {
                removed_keys += 1;
                return false;
            };
            *head = newest;
            true
        });
        self.overflow.retain(|_, chain| !chain.is_empty());

        // `shrink_to` checks the real bucket count, which `capacity()` understates after removals.
        self.map.shrink_to(self.map.len() * 2);
        self.overflow.shrink_to(self.overflow.len() * 2);

        self.keys.dec_by(removed_keys);
        self.items.dec_by(removed_items as i64);
        self.pruned.inc_by(removed_items as u64);
    }
}

impl<T: Translator, V: Send + Sync> super::Factory for Index<T, V> {
    type Translator = T;

    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Send + Sync> Unordered for Index<T, V> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V, T>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a
    where
        V: 'a,
    {
        let k = self.translator.transform(key);
        Values::new(self.map.get(&k), &self.overflow, k)
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => Some(Cursor::<'_, T::Key, V, T>::new(
                entry,
                &mut self.overflow,
                &self.keys,
                &self.items,
                &self.pruned,
            )),
            Entry::Vacant(_) => None,
        }
    }

    fn get_mut_or_insert<'a>(&'a mut self, key: &[u8], value: V) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => Some(Cursor::<'_, T::Key, V, T>::new(
                entry,
                &mut self.overflow,
                &self.keys,
                &self.items,
                &self.pruned,
            )),
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, value);
                None
            }
        }
    }

    fn insert(&mut self, key: &[u8], v: V) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut entry) => {
                // The newest value is stored inline; the displaced value joins the end of the
                // overflow chain.
                let old = std::mem::replace(entry.get_mut(), v);
                push_displaced(&mut self.overflow, k, old);
                self.items.inc();
            }
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, v);
            }
        }
    }

    fn insert_and_retain(
        &mut self,
        key: &[u8],
        value: V,
        mut should_retain: impl FnMut(&V) -> bool,
    ) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(mut entry) => {
                // Optimized fast path for the common case of no overflow chain.
                #[allow(clippy::map_entry)]
                if !self.overflow.contains_key(&k) {
                    match (should_retain(entry.get()), should_retain(&value)) {
                        // Keep both, with the new value placed at the end of the overflow chain.
                        (true, true) => {
                            self.overflow.insert(k, vec![value]);
                            self.items.inc();
                        }
                        // Drop the existing value, keep the new one: replace in place.
                        (false, true) => {
                            *entry.get_mut() = value;
                            self.pruned.inc();
                        }
                        // Drop both: remove the key entirely.
                        (false, false) => {
                            entry.remove();
                            self.keys.dec();
                            self.items.dec();
                            self.pruned.inc();
                        }
                        // Keep the existing value, drop the new one: nothing to do.
                        (true, false) => {}
                    }
                    return;
                }

                // Slow path: the key has conflicting values; walk them with a cursor.
                let mut cursor = Cursor::<'_, T::Key, V, T>::new(
                    entry,
                    &mut self.overflow,
                    &self.keys,
                    &self.items,
                    &self.pruned,
                );

                // Drop anything that should not be retained.
                cursor.retain(&mut should_retain);

                // Add the new value only if it should be retained.
                if should_retain(&value) {
                    cursor.insert(value);
                }
            }
            Entry::Vacant(entry) => {
                // Create the entry only if the value should be retained.
                if should_retain(&value) {
                    Self::create(&self.keys, &self.items, entry, value);
                }
            }
        }
    }

    fn remove(&mut self, key: &[u8]) {
        let k = self.translator.transform(key);
        if self.map.remove(&k).is_some() {
            // To ensure metrics are accurate, account for all conflicting values in the chain.
            self.keys.dec();
            self.items.dec();
            self.pruned.inc();
            if !self.overflow.is_empty()
                && let Some(chain) = self.overflow.remove(&k)
            {
                self.items.dec_by(chain.len() as i64);
                self.pruned.inc_by(chain.len() as u64);
            }
        }
    }

    #[cfg(test)]
    fn keys(&self) -> usize {
        self.keys.get() as usize
    }

    #[cfg(test)]
    fn items(&self) -> usize {
        self.items.get() as usize
    }

    #[cfg(test)]
    fn pruned(&self) -> usize {
        self.pruned.get() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::{EightCap, TwoCap};
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::GOLDEN_RATIO;

    fn values(index: &Index<TwoCap, u64>, key: &[u8]) -> Vec<u64> {
        index.get(key).copied().collect()
    }

    #[test_traced]
    fn test_retain_all_keeps_newest_first() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = Index::new(context, TwoCap);
            for v in 1..=3 {
                index.insert(b"aa", v);
            }
            index.insert(b"bb", 4);
            index.insert(b"cc", 5);
            index.insert(b"cc", 6);
            for v in 7..=10 {
                index.insert(b"dd", v);
            }

            // Each value is tested once. Survivors stay newest first, including where a retained
            // overflow value is promoted.
            let mut calls = 0;
            index.retain_all(|v| {
                calls += 1;
                matches!(v, 2 | 6 | 7 | 9)
            });
            assert_eq!(calls, 10);
            assert_eq!(values(&index, b"aa"), [2]);
            assert!(index.get_mut(b"bb").is_none());
            assert_eq!(values(&index, b"cc"), [6]);
            assert_eq!(values(&index, b"dd"), [9, 7]);
            assert_eq!(index.keys(), 3);
            assert_eq!(index.items(), 4);
            assert_eq!(index.pruned(), 6);
            assert_eq!(index.overflow.len(), 1);

            index.insert(b"dd", 11);
            assert_eq!(values(&index, b"dd"), [11, 9, 7]);
            index.retain(b"dd", |v| *v != 9);
            assert_eq!(values(&index, b"dd"), [11, 7]);
        });
    }

    #[test_traced]
    fn test_retain_all_shrinks_overflow() {
        deterministic::Runner::default().start(|context| async move {
            // One key with a 1024-value chain, and 1024 other keys with one overflow value each.
            let mut index = Index::new(context, TwoCap);
            for v in 0..1024 {
                index.insert(b"aa", v);
            }
            for k in 0..1024u16 {
                index.insert(&k.to_be_bytes(), 0);
                index.insert(&k.to_be_bytes(), 1);
            }
            let key = TwoCap.transform(b"aa");
            assert!(index.overflow[&key].capacity() >= 1023);
            let capacity = index.overflow.capacity();
            assert!(capacity >= 1025);

            // Dropping all but two values of the long chain releases its peak allocation, which
            // `Vec::retain` alone keeps, and dropping every other key shrinks the overflow map.
            index.retain_all(|v| *v >= 1022);
            assert_eq!(values(&index, b"aa"), [1023, 1022]);
            assert_eq!(index.keys(), 1);
            assert_eq!(index.items(), 2);
            assert!(index.overflow[&key].capacity() <= 2);
            assert!(index.overflow.capacity() < capacity);
        });
    }

    #[test_traced]
    fn test_retain_all_shrinks_sparse_maps() {
        deterministic::Runner::default().start(|context| async move {
            // GOLDEN_RATIO's inverse mod 2^64. EightCap hashes k to k * GOLDEN_RATIO, so key(i)
            // lands in bucket i.
            const INVERSE: u64 = 0xf1de_83e1_9937_733d;
            assert_eq!(GOLDEN_RATIO.wrapping_mul(INVERSE), 1);
            let key = |i: u64| i.wrapping_mul(INVERSE).to_be_bytes();

            // Fill a map to its load limit (7/8 of 16,384 buckets), so removals leave tombstones
            // rather than empty slots.
            const FULL: u64 = 16_384 / 8 * 7;
            let mut index = Index::new(context, EightCap);
            for i in 0..FULL {
                index.insert(&key(i), i);
            }
            assert_eq!(index.map.len(), FULL as usize);

            // Removing all but 1000 consecutive entries leaves tombstones that `capacity()`
            // does not count, so a `len < capacity() / 4` rule would never shrink this map.
            let mut probe = index.map.clone();
            probe.retain(|_, v| *v < 1000);
            assert!(probe.capacity() < 4 * probe.len());

            // Keeping every value leaves capacity alone.
            let capacity = index.map.capacity();
            index.retain_all(|_| true);
            assert_eq!(index.map.capacity(), capacity);

            // Keeping 1000 values shrinks the map. Reserving past `capacity()` rehashes an
            // oversized map in place, which would expose its peak.
            index.retain_all(|v| *v < 1000);
            assert_eq!(index.items(), 1000);
            index
                .map
                .reserve(index.map.capacity() - index.map.len() + 1);
            assert!(index.map.capacity() < capacity);
        });
    }
}
