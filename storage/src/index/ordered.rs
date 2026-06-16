//! Implementation of [Ordered] that uses an ordered map internally to map translated keys to
//! arbitrary values. Beyond the standard [Unordered] implementation, this variant adds the
//! capability to retrieve values associated with both next and previous translated keys of a given
//! key. There is no ordering guarantee provided over the values associated with each key. Ordering
//! applies only to the _translated_ key space.

use crate::{
    index::{
        storage::{push_displaced, Cursor as CursorImpl, IndexEntry, Overflow, Values},
        Cursor as CursorTrait, Ordered, Unordered,
    },
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::{
    collections::{
        btree_map::{
            Entry as BTreeEntry, OccupiedEntry as BTreeOccupiedEntry,
            VacantEntry as BTreeVacantEntry,
        },
        BTreeMap,
    },
    ops::Bound::{Excluded, Unbounded},
};

/// Implementation of [IndexEntry] for [BTreeOccupiedEntry].
impl<K: Ord + Send + Sync, V: Send + Sync> IndexEntry<V> for BTreeOccupiedEntry<'_, K, V> {
    fn get_mut(&mut self) -> &mut V {
        self.get_mut()
    }
    fn remove(self) {
        self.remove_entry();
    }
}

/// A [crate::index::Cursor] over the values associated with a translated key.
pub type Cursor<'a, K, V> = CursorImpl<'a, K, V, BTreeOccupiedEntry<'a, K, V>>;

/// A memory-efficient index that uses an ordered map internally to map translated keys to arbitrary
/// values.
///
/// Each translated key maps directly to its most recently inserted value; conflicting values (from
/// key collisions or repeated insertions) are stored in a separate overflow map so the common
/// (collision-free) case stays as compact as possible.
pub struct Index<T: Translator, V: Send + Sync> {
    translator: T,
    map: BTreeMap<T::Key, V>,
    overflow: Overflow<T::Key, V>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Send + Sync> Index<T, V> {
    /// Create a new entry in the index.
    fn create(keys: &Gauge, items: &Gauge, vacant: BTreeVacantEntry<'_, T::Key, V>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(v);
    }

    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        Self {
            translator,
            map: BTreeMap::new(),
            overflow: Overflow::new(),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    /// Returns an iterator over the values associated with the translated key `k`, given that
    /// key's inline (head) value.
    fn values<'a>(&'a self, k: &T::Key, head: &'a V) -> Values<'a, T::Key, V> {
        Values::new(Some(head), &self.overflow, *k)
    }

    /// Translate a key without probing.
    pub(super) fn translate(&self, key: &[u8]) -> T::Key {
        self.translator.transform(key)
    }

    /// Returns an iterator over all values associated with an already-translated key.
    pub(super) fn get_translated(&self, key: T::Key) -> Values<'_, T::Key, V> {
        Values::new(self.map.get(&key), &self.overflow, key)
    }

    /// Returns an iterator over the values of the translated key that lexicographically follows
    /// `key`, or None if no such key exists (no cycling).
    pub(super) fn next_translated_values_no_cycle(
        &self,
        key: &[u8],
    ) -> Option<Values<'_, T::Key, V>> {
        let k = self.translator.transform(key);
        self.map
            .range((Excluded(k), Unbounded))
            .next()
            .map(|(k, head)| self.values(k, head))
    }

    /// Returns an iterator over the values of the translated key that lexicographically precedes
    /// `key`, or None if no such key exists (no cycling).
    pub(super) fn prev_translated_values_no_cycle(
        &self,
        key: &[u8],
    ) -> Option<Values<'_, T::Key, V>> {
        let k = self.translator.transform(key);
        self.map
            .range(..k)
            .next_back()
            .map(|(k, head)| self.values(k, head))
    }

    /// Returns an iterator over the values of the lexicographically first translated key, or
    /// None if the index is empty.
    pub(super) fn first_translated_values(&self) -> Option<Values<'_, T::Key, V>> {
        self.map
            .first_key_value()
            .map(|(k, head)| self.values(k, head))
    }

    /// Returns an iterator over the values of the lexicographically last translated key, or
    /// None if the index is empty.
    pub(super) fn last_translated_values(&self) -> Option<Values<'_, T::Key, V>> {
        self.map
            .last_key_value()
            .map(|(k, head)| self.values(k, head))
    }
}

impl<T: Translator, V: Send + Sync> Ordered for Index<T, V> {
    fn prev_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        if let Some(values) = self.prev_translated_values_no_cycle(key) {
            return Some((values, false));
        }
        self.last_translated_values().map(|values| (values, true))
    }

    fn next_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        if let Some(values) = self.next_translated_values_no_cycle(key) {
            return Some((values, false));
        }
        self.first_translated_values().map(|values| (values, true))
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.first_translated_values()
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        self.last_translated_values()
    }
}

impl<T: Translator, V: Send + Sync> super::Factory<T> for Index<T, V> {
    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Send + Sync> Unordered for Index<T, V> {
    type Value = V;

    fn get_many<'a, K: AsRef<[u8]>>(&'a self, keys: &[K], mut visit: impl FnMut(usize, &'a V))
    where
        V: 'a,
    {
        // Probe in translated-key order: consecutive tree descents share upper node paths,
        // which stay cache-resident across the batch.
        let mut order: Vec<(T::Key, usize)> = keys
            .iter()
            .enumerate()
            .map(|(key_idx, key)| (self.translator.transform(key.as_ref()), key_idx))
            .collect();
        order.sort_unstable();
        for (translated, key_idx) in order {
            for value in self.get_translated(translated) {
                visit(key_idx, value);
            }
        }
    }
    type Cursor<'a>
        = Cursor<'a, T::Key, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a
    where
        V: 'a,
    {
        self.get_translated(self.translator.transform(key))
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            BTreeEntry::Occupied(entry) => Some(Cursor::<'_, T::Key, V>::new(
                entry,
                k,
                &mut self.overflow,
                &self.keys,
                &self.items,
                &self.pruned,
            )),
            BTreeEntry::Vacant(_) => None,
        }
    }

    fn get_mut_or_insert<'a>(&'a mut self, key: &[u8], value: V) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            BTreeEntry::Occupied(entry) => Some(Cursor::<'_, T::Key, V>::new(
                entry,
                k,
                &mut self.overflow,
                &self.keys,
                &self.items,
                &self.pruned,
            )),
            BTreeEntry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, value);
                None
            }
        }
    }

    fn insert(&mut self, key: &[u8], value: V) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            BTreeEntry::Occupied(mut entry) => {
                // The newest value is stored inline; the displaced value joins the end of the
                // overflow chain.
                let old = std::mem::replace(entry.get_mut(), value);
                push_displaced(&mut self.overflow, k, old);
                self.items.inc();
            }
            BTreeEntry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, value);
            }
        }
    }

    fn insert_and_retain(&mut self, key: &[u8], value: V, should_retain: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            BTreeEntry::Occupied(mut entry) => {
                // Optimized fast path for the common case of no overflow chain. The cases below
                // match the cursor's value ordering and metric accounting exactly.
                #[allow(clippy::map_entry)] // suppress lint false positive
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
                let mut cursor = Cursor::<'_, T::Key, V>::new(
                    entry,
                    k,
                    &mut self.overflow,
                    &self.keys,
                    &self.items,
                    &self.pruned,
                );

                // Drop anything that should not be retained.
                cursor.retain(&should_retain);

                // Add the new value only if it should be retained.
                if should_retain(&value) {
                    cursor.insert(value);
                }
            }
            BTreeEntry::Vacant(entry) => {
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
            if !self.overflow.is_empty() {
                if let Some(chain) = self.overflow.remove(&k) {
                    self.items.dec_by(chain.len() as i64);
                    self.pruned.inc_by(chain.len() as u64);
                }
            }
        }
    }

    #[cfg(test)]
    fn keys(&self) -> usize {
        self.map.len()
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
    use crate::translator::OneCap;
    use commonware_formatting::hex;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    #[test_traced]
    fn test_ordered_empty_index() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let index = Index::<_, u64>::new(context, OneCap);

            assert!(index.first_translated_key().is_none());
            assert!(index.last_translated_key().is_none());
            assert!(index.prev_translated_key(b"key").is_none());
            assert!(index.next_translated_key(b"key").is_none());
        });
    }

    #[test_traced]
    fn test_ordered_index_ordering() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = Index::<_, u64>::new(context, OneCap);
            assert_eq!(index.keys(), 0);

            let k1 = &hex!("0x0b02AA"); // translated key 0b
            let k2 = &hex!("0x1c04CC"); // translated key 1c
            let k2_collides = &hex!("0x1c0311");
            let k3 = &hex!("0x2d06EE"); // translated key 2d
            index.insert(k1, 1);
            index.insert(k2, 21);
            index.insert(k2_collides, 22);
            index.insert(k3, 3);
            assert_eq!(index.keys(), 3);

            // First translated key is 0b.
            let mut next = index.first_translated_key().unwrap();
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Next translated key to 0x00 is 0b.
            let (mut next, wrapped) = index.next_translated_key(&[0x00]).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Next translated key to 0x0b is 1c.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x0b0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &22);
            assert_eq!(next.next().unwrap(), &21);
            assert_eq!(next.next(), None);

            // Next translated key to 0x1b is 1c.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x1b010203")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &22);
            assert_eq!(next.next().unwrap(), &21);
            assert_eq!(next.next(), None);

            // Next translated key to 0x2a is 2d.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x2a01020304")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &3);
            assert_eq!(next.next(), None);

            // Next translated key to 0x2d cycles around to 0x0b.
            let (mut next, wrapped) = index.next_translated_key(k3).unwrap();
            assert!(wrapped);
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Another cycle-around case.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x2eFF")).unwrap();
            assert!(wrapped);
            assert_eq!(next.next().unwrap(), &1);
            assert_eq!(next.next(), None);

            // Previous translated key of first key is the last key.
            let (mut prev, wrapped) = index.prev_translated_key(k1).unwrap();
            assert!(wrapped);
            assert_eq!(prev.next().unwrap(), &3);
            assert_eq!(prev.next(), None);

            // Previous translated key is 0b.
            let (mut prev, wrapped) = index.prev_translated_key(&hex!("0x0c0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next().unwrap(), &1);
            assert_eq!(prev.next(), None);

            // Previous translated key is 1c.
            let (mut prev, wrapped) = index.prev_translated_key(&hex!("0x1d0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next().unwrap(), &22);
            assert_eq!(prev.next().unwrap(), &21);
            assert_eq!(prev.next(), None);

            // Previous translated key is 2d.
            let (mut prev, wrapped) = index.prev_translated_key(&hex!("0xCC0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next().unwrap(), &3);
            assert_eq!(prev.next(), None);

            // Last translated key is 2d.
            let mut last = index.last_translated_key().unwrap();
            assert_eq!(last.next().unwrap(), &3);
            assert_eq!(last.next(), None);
        });
    }
}
