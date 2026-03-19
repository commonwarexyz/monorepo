//! Implementation of [Ordered] that uses an ordered map internally to map translated keys to
//! arbitrary values. Beyond the standard [Unordered] implementation, this variant adds the
//! capability to retrieve values associated with both next and previous translated keys of a given
//! key. There is no ordering guarantee provided over the values associated with each key. Ordering
//! applies only to the _translated_ key space.

use crate::{
    index::{
        storage::{Cursor as CursorImpl, ImmutableCursor, IndexEntry, Record},
        Cursor as CursorTrait, Ordered, Unordered,
    },
    translator::Translator,
};
use commonware_runtime::Metrics;
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
impl<K: Ord + Send + Sync, V: Eq + Send + Sync> IndexEntry<V>
    for BTreeOccupiedEntry<'_, K, Record<V>>
{
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
pub struct Cursor<'a, K: Ord + Send + Sync, V: Eq + Send + Sync> {
    inner: CursorImpl<'a, V, BTreeOccupiedEntry<'a, K, Record<V>>>,
}

impl<'a, K: Ord + Send + Sync, V: Eq + Send + Sync> Cursor<'a, K, V> {
    const fn new(
        entry: BTreeOccupiedEntry<'a, K, Record<V>>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            inner: CursorImpl::<'a, V, BTreeOccupiedEntry<'a, K, Record<V>>>::new(
                entry, keys, items, pruned,
            ),
        }
    }
}

impl<K: Ord + Send + Sync, V: Eq + Send + Sync> CursorTrait for Cursor<'_, K, V> {
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

    fn prune(&mut self, predicate: &impl Fn(&V) -> bool) {
        self.inner.prune(predicate)
    }
}

/// A memory-efficient index that uses an ordered map internally to map translated keys to arbitrary
/// values.
pub struct Index<T: Translator, V: Eq + Send + Sync> {
    translator: T,
    map: BTreeMap<T::Key, Record<V>>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Eq + Send + Sync> Index<T, V> {
    /// Create a new entry in the index.
    fn create(keys: &Gauge, items: &Gauge, vacant: BTreeVacantEntry<'_, T::Key, Record<V>>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(Record {
            value: v,
            next: None,
        });
    }

    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        let s = Self {
            translator,
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

    /// Like [Ordered::next_translated_key] but without cycling around to the first key if there is
    /// no next key.
    pub(super) fn next_translated_key_no_cycle<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<ImmutableCursor<'a, V>> {
        let k = self.translator.transform(key);
        self.map
            .range((Excluded(k), Unbounded))
            .next()
            .map(|(_, record)| ImmutableCursor::new(record))
    }

    /// Like [Ordered::prev_translated_key] but without cycling around to the last key if there is
    /// no previous key.
    pub(super) fn prev_translated_key_no_cycle<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<ImmutableCursor<'a, V>> {
        let k = self.translator.transform(key);
        self.map
            .range(..k)
            .next_back()
            .map(|(_, record)| ImmutableCursor::new(record))
    }
}

impl<T: Translator, V: Eq + Send + Sync> Ordered for Index<T, V> {
    type Iterator<'a>
        = ImmutableCursor<'a, V>
    where
        Self: 'a;

    fn prev_translated_key<'a>(&'a self, key: &[u8]) -> Option<(Self::Iterator<'a>, bool)>
    where
        Self::Value: 'a,
    {
        let res = self.prev_translated_key_no_cycle(key);
        if let Some(res) = res {
            return Some((res, false));
        }

        self.last_translated_key().map(|res| (res, true))
    }

    fn next_translated_key<'a>(&'a self, key: &[u8]) -> Option<(Self::Iterator<'a>, bool)>
    where
        Self::Value: 'a,
    {
        let res = self.next_translated_key_no_cycle(key);
        if let Some(res) = res {
            return Some((res, false));
        }

        self.first_translated_key().map(|res| (res, true))
    }

    fn first_translated_key<'a>(&'a self) -> Option<Self::Iterator<'a>>
    where
        Self::Value: 'a,
    {
        self.map
            .first_key_value()
            .map(|(_, record)| ImmutableCursor::new(record))
    }

    fn last_translated_key<'a>(&'a self) -> Option<Self::Iterator<'a>>
    where
        Self::Value: 'a,
    {
        self.map
            .last_key_value()
            .map(|(_, record)| ImmutableCursor::new(record))
    }
}

impl<T: Translator, V: Eq + Send + Sync> Unordered for Index<T, V> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a
    where
        V: 'a,
    {
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
            BTreeEntry::Occupied(entry) => Some(Cursor::<'_, T::Key, V>::new(
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
            BTreeEntry::Occupied(entry) => Some(Cursor::<'_, T::Key, V>::new(
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
                    Cursor::<'_, T::Key, V>::new(entry, &self.keys, &self.items, &self.pruned);
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
                    Cursor::<'_, T::Key, V>::new(entry, &self.keys, &self.items, &self.pruned);

                // Remove anything that is prunable.
                cursor.prune(&predicate);

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
                    Cursor::<'_, T::Key, V>::new(entry, &self.keys, &self.items, &self.pruned);

                // Remove anything that is prunable.
                cursor.prune(&predicate);
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

impl<T: Translator, V: Eq + Send + Sync> Drop for Index<T, V> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::OneCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::hex;

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
            assert_eq!(next.next().unwrap(), &21);
            assert_eq!(next.next().unwrap(), &22);
            assert_eq!(next.next(), None);

            // Next translated key to 0x1b is 1c.
            let (mut next, wrapped) = index.next_translated_key(&hex!("0x1b010203")).unwrap();
            assert!(!wrapped);
            assert_eq!(next.next().unwrap(), &21);
            assert_eq!(next.next().unwrap(), &22);
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
            assert_eq!(prev.next().unwrap(), &21);
            assert_eq!(prev.next().unwrap(), &22);
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
