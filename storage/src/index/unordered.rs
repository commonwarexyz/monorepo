//! A memory-efficient index that uses an unordered map internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

use crate::{
    index::{
        storage::{push_displaced, Cursor as CursorImpl, IndexEntry, Overflow, Values},
        Cursor as CursorTrait, Unordered,
    },
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::collections::{
    hash_map::{Entry, OccupiedEntry, VacantEntry},
    HashMap,
};

/// The initial capacity of the internal hashmap. This is a guess at the number of unique keys we
/// will encounter. The hashmap will grow as needed, but this is a good starting point (covering the
/// entire [crate::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

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

    /// Create a new index with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        Self {
            translator: translator.clone(),
            overflow: HashMap::with_hasher(translator.clone()),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, translator),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }
}

impl<T: Translator, V: Send + Sync> super::Factory<T> for Index<T, V> {
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

    fn insert_and_retain(&mut self, key: &[u8], value: V, should_retain: impl Fn(&V) -> bool) {
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
                cursor.retain(&should_retain);

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
