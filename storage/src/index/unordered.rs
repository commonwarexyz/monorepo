//! A memory-efficient index that uses an unordered map internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

use crate::{
    index::{
        storage::{Cursor as CursorImpl, ImmutableCursor, IndexEntry, Record},
        Cursor as CursorTrait, Index as IndexTrait,
    },
    translator::Translator,
};
use commonware_runtime::Metrics;
use core::hash::Hash;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{
    hash_map::{Entry, OccupiedEntry, VacantEntry},
    HashMap,
};

/// The initial capacity of the internal hashmap. This is a guess at the number of unique keys we
/// will encounter. The hashmap will grow as needed, but this is a good starting point (covering the
/// entire [crate::translator::OneCap] range).
const INITIAL_CAPACITY: usize = 256;

/// Implementation of [IndexEntry] for [OccupiedEntry].
impl<K: Ord + Hash + Copy, V: Eq> IndexEntry<K, V> for OccupiedEntry<'_, K, Record<V>> {
    fn get(&self) -> &V {
        &self.get().value
    }
    fn get_mut(&mut self) -> &mut Record<V> {
        self.get_mut()
    }
    fn remove(self) {
        OccupiedEntry::remove(self);
    }
}

/// A cursor for the unordered [Index] that wraps the shared implementation.
pub struct Cursor<'a, T: Translator, V: Eq> {
    inner: CursorImpl<'a, T::Key, V, OccupiedEntry<'a, T::Key, Record<V>>>,
}

impl<'a, T: Translator, V: Eq> Cursor<'a, T, V> {
    fn new(
        entry: OccupiedEntry<'a, T::Key, Record<V>>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            inner: CursorImpl::<'a, T::Key, V, OccupiedEntry<'a, T::Key, Record<V>>>::new(
                entry, keys, items, pruned,
            ),
        }
    }
}

impl<T: Translator, V: Eq> CursorTrait for Cursor<'_, T, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        self.inner.next()
    }

    fn insert(&mut self, value: V) {
        self.inner.insert(value)
    }

    fn delete(&mut self) {
        self.inner.delete()
    }

    fn update(&mut self, value: V) {
        self.inner.update(value)
    }

    fn prune(&mut self, predicate: &impl Fn(&V) -> bool) {
        self.inner.prune(predicate)
    }
}

/// A memory-efficient index that uses an unordered map internally to map translated keys to
/// arbitrary values.
pub struct Index<T: Translator, V: Eq> {
    translator: T,
    map: HashMap<T::Key, Record<V>, T>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Eq> Index<T, V> {
    /// Create a new [Index] with the given translator.
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: HashMap::with_capacity_and_hasher(INITIAL_CAPACITY, tr),

            keys: Gauge::default(),
            items: Gauge::default(),
            pruned: Counter::default(),
        };
        ctx.register(
            "keys",
            "Number of translated keys in the index",
            s.keys.clone(),
        );
        ctx.register("items", "Number of items in the index", s.items.clone());
        ctx.register("pruned", "Number of items pruned", s.pruned.clone());
        s
    }

    /// Create a new entry in the index.
    fn create(keys: &Gauge, items: &Gauge, vacant: VacantEntry<T::Key, Record<V>>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(Record {
            value: v,
            next: None,
        });
    }
}

impl<T: Translator, V: Eq> IndexTrait for Index<T, V> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T, V>
    where
        Self: 'a;

    fn keys(&self) -> usize {
        self.map.len()
    }

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a {
        let k = self.translator.transform(key);
        self.map
            .get(&k)
            .map(|record| ImmutableCursor::new(record))
            .into_iter()
            .flatten()
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => Some(Cursor::<'_, T, V>::new(
                entry,
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
            Entry::Occupied(entry) => Some(Cursor::<'_, T, V>::new(
                entry,
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
            Entry::Occupied(entry) => {
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);
                cursor.next();
                cursor.insert(v);
            }
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, v);
            }
        }
    }

    fn insert_and_prune(&mut self, key: &[u8], value: V, predicate: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                // Get entry
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);

                cursor.prune(&predicate);

                // Add our new value (if not prunable).
                if !predicate(&value) {
                    cursor.insert(value);
                }
            }
            Entry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, value);
            }
        }
    }

    fn prune(&mut self, key: &[u8], predicate: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            Entry::Occupied(entry) => {
                // Get cursor
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);

                cursor.prune(&predicate);
            }
            Entry::Vacant(_) => {}
        }
    }

    fn remove(&mut self, key: &[u8]) {
        // To ensure metrics are accurate, we iterate over all conflicting values and remove them
        // one-by-one (rather than just removing the entire entry).
        self.prune(key, |_| true);
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

impl<T: Translator, V: Eq> Drop for Index<T, V> {
    /// To avoid stack overflow on keys with many collisions, we implement an iterative drop (in
    /// lieu of Rust's default recursive drop).
    fn drop(&mut self) {
        for (_, mut record) in self.map.drain() {
            let mut next = record.next.take();
            while let Some(mut record) = next {
                next = record.next.take();
            }
        }
    }
}
