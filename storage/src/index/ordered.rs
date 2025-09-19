//! Implementation of [Index] that uses an ordered map internally to map translated keys to
//! arbitrary values. Beyond the standard [IndexTrait] implementation, this variant adds the
//! capability to retrieve values associated with both next and previous translated keys of a given
//! key. There is no ordering guarantees provided over the values associated with each key. Ordering
//! applies only to the _translated_ key space.

use crate::{
    index::{
        storage::{prune_with_cursor, Cursor as CursorImpl, ImmutableCursor, IndexEntry, Record},
        Cursor as CursorTrait, Index as IndexTrait,
    },
    translator::Translator,
};
use commonware_runtime::Metrics;
use core::hash::Hash;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
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
impl<K: Ord + Hash + Copy, V: Eq> IndexEntry<K, V> for BTreeOccupiedEntry<'_, K, Record<V>> {
    fn get(&self) -> &V {
        &self.get().value
    }
    fn get_mut(&mut self) -> &mut Record<V> {
        self.get_mut()
    }
    fn remove(self) {
        self.remove_entry();
    }
}

/// A cursor for the ordered [Index] that wraps the shared implementation.
pub struct Cursor<'a, T: Translator, V: Eq> {
    inner: CursorImpl<'a, T::Key, V, BTreeOccupiedEntry<'a, T::Key, Record<V>>>,
}

impl<'a, T: Translator, V: Eq> Cursor<'a, T, V> {
    fn new(
        entry: BTreeOccupiedEntry<'a, T::Key, Record<V>>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            inner: CursorImpl::<'a, T::Key, V, BTreeOccupiedEntry<'a, T::Key, Record<V>>>::new(
                entry, keys, items, pruned,
            ),
        }
    }
}

impl<T: Translator, V: Eq> CursorTrait for Cursor<'_, T, V> {
    type Value = V;
    fn update(&mut self, v: V) {
        self.inner.update(v)
    }
    fn next(&mut self) -> Option<&V> {
        self.inner.next()
    }
    fn insert(&mut self, v: V) {
        self.inner.insert(v)
    }
    fn delete(&mut self) {
        self.inner.delete()
    }
}

/// A memory-efficient index that uses an ordered map internally to map translated keys to arbitrary
/// values.
pub struct Index<T: Translator, V: Eq> {
    translator: T,
    map: BTreeMap<T::Key, Record<V>>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Eq> Index<T, V> {
    /// Create a new [Index] with the given translator.
    pub fn init(ctx: impl Metrics, tr: T) -> Self {
        let s = Self {
            translator: tr.clone(),
            map: BTreeMap::new(),

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
    fn create(keys: &Gauge, items: &Gauge, vacant: BTreeVacantEntry<T::Key, Record<V>>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(Record {
            value: v,
            next: None,
        });
    }

    /// Get the values associated with the translated key that lexicographically follows the result
    /// of translating `key`.
    ///
    /// For example, if the translator is looking only at the first byte of a key, and the index
    /// contains values for translated keys 0b, 1c, and 2d, then `get_next([0b, 01, 02, ...])` would
    /// return the values associated with 1c, `get_next([2a, 01, 02, ...])` would return the values
    /// associated with 2d, and `get_next([2d])` would return `None`.
    pub fn get_next<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a {
        let k = self.translator.transform(key);
        self.map
            .range((Excluded(k), Unbounded))
            .next()
            .map(|(_, record)| ImmutableCursor::new(record))
            .into_iter()
            .flatten()
    }

    /// Get the values associated with the translated key that lexicographically precedes the result
    /// of translating `key`.
    pub fn prev_key<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a {
        let k = self.translator.transform(key);
        self.map
            .range(..k)
            .next_back()
            .map(|(_, record)| ImmutableCursor::new(record))
            .into_iter()
            .flatten()
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
            BTreeEntry::Occupied(entry) => Some(Cursor::<'_, T, V>::new(
                entry,
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
            BTreeEntry::Occupied(entry) => Some(Cursor::<'_, T, V>::new(
                entry,
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
            BTreeEntry::Occupied(entry) => {
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);
                cursor.next();
                cursor.insert(value);
            }
            BTreeEntry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, value);
            }
        }
    }

    fn insert_and_prune(&mut self, key: &[u8], value: V, predicate: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            BTreeEntry::Occupied(entry) => {
                // Get entry
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);

                // Remove anything that is prunable.
                prune_with_cursor(&mut cursor, &predicate);

                // Add our new value (if not prunable).
                if !predicate(&value) {
                    cursor.insert(value);
                }
            }
            BTreeEntry::Vacant(entry) => {
                Self::create(&self.keys, &self.items, entry, value);
            }
        }
    }

    fn prune(&mut self, key: &[u8], predicate: impl Fn(&V) -> bool) {
        let k = self.translator.transform(key);
        match self.map.entry(k) {
            BTreeEntry::Occupied(entry) => {
                // Get cursor
                let mut cursor =
                    Cursor::<'_, T, V>::new(entry, &self.keys, &self.items, &self.pruned);

                // Remove anything that is prunable.
                prune_with_cursor(&mut cursor, predicate);
            }
            BTreeEntry::Vacant(_) => {}
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
        for (_, record) in self.map.iter_mut() {
            let mut next = record.next.take();
            while let Some(mut record) = next {
                next = record.next.take();
            }
        }
    }
}
