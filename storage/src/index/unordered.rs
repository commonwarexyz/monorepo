//! A memory-efficient index that uses an unordered map internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

#[commonware_macros::stability(ALPHA)]
use crate::index::partitioned::{PartitionRange, Partitioned};
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

    /// Create an empty index that shares this index's translator and metrics. It updates the
    /// metrics through detached handles and holds no registrations, so the metrics leave the
    /// registry when this index is dropped. Snapshot-build tasks fill such an index before it
    /// is absorbed.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn empty(&self) -> Self {
        Self {
            translator: self.translator.clone(),
            overflow: HashMap::with_hasher(self.translator.clone()),
            map: HashMap::with_hasher(self.translator.clone()),
            keys: Gauge::detached(self.keys.metric().clone()),
            items: Gauge::detached(self.items.metric().clone()),
            pruned: Counter::detached(self.pruned.metric().clone()),
        }
    }

    /// Move `other`'s contents into self, which must be empty. Moving the maps wholesale lets
    /// an index made by [`Self::empty`] install without re-inserting each entry. Metrics need no
    /// adjustment because `other` updated self's metrics directly.
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

    /// Insert every entry of `entries` as [Unordered::insert] would, growing the map once for
    /// all of them and updating the metrics once.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn load<'a>(&mut self, entries: impl ExactSizeIterator<Item = (&'a [u8], V)>) {
        self.map.reserve(entries.len());
        let mut keys = 0;
        let mut items = 0;
        for (key, v) in entries {
            let k = self.translator.transform(key);
            match self.map.entry(k) {
                Entry::Occupied(mut entry) => {
                    let old = std::mem::replace(entry.get_mut(), v);
                    push_displaced(&mut self.overflow, k, old);
                }
                Entry::Vacant(entry) => {
                    entry.insert(v);
                    keys += 1;
                }
            }
            items += 1;
        }
        self.keys.inc_by(keys);
        self.items.inc_by(items);
    }
}

#[commonware_macros::stability(ALPHA)]
impl<T: Translator, V: Send + Sync + 'static> Partitioned for Index<T, V> {
    type Range = Self;

    fn partition_count(&self) -> usize {
        1
    }

    fn partition_of(_key: &[u8]) -> usize {
        0
    }

    fn new_range(&self, _offset: usize, _count: usize) -> Self {
        self.empty()
    }

    fn install_range(&mut self, range: Self) {
        self.absorb(range);
    }
}

#[commonware_macros::stability(ALPHA)]
impl<T: Translator, V: Send + Sync> PartitionRange for Index<T, V> {
    type Value = V;

    fn load<'a>(&mut self, entries: impl ExactSizeIterator<Item = (&'a [u8], V)>) {
        Self::load(self, entries);
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

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a {
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
    use crate::translator::OneCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    /// Loading must leave the index as inserting the same entries one at a time would, whether
    /// the index is empty or not, whether or not keys share a translated key, and whatever
    /// order the entries are in.
    #[test_traced]
    fn test_load_matches_inserts() {
        deterministic::Runner::default().start(|context| async move {
            let mut loaded = Index::new(context.child("loaded"), OneCap);
            let mut inserted = Index::new(context.child("inserted"), OneCap);
            let loads: [&[(&[u8], u64)]; 4] = [
                &[(&[0x01], 1), (&[0x01, 0xAA], 2), (&[0x02], 3), (&[0x04], 4)],
                &[],
                &[(&[0x03], 5), (&[0x01, 0xBB], 6), (&[0x00], 7)],
                &[(&[0x05], 8)],
            ];
            for entries in loads {
                loaded.load(entries.iter().copied());
                for &(key, value) in entries {
                    inserted.insert(key, value);
                }
            }
            assert_eq!(loaded.keys(), inserted.keys());
            assert_eq!(loaded.items(), inserted.items());
            for &(key, _) in loads.iter().copied().flatten() {
                assert_eq!(
                    loaded.get(key).collect::<Vec<_>>(),
                    inserted.get(key).collect::<Vec<_>>()
                );
            }

            // An empty index loaded out of order takes the same path as one that holds entries.
            let mut loaded = Index::new(context.child("loaded_unordered"), OneCap);
            let mut inserted = Index::new(context.child("inserted_unordered"), OneCap);
            let entries: [(&[u8], u64); 5] = [
                (&[0x03], 1),
                (&[0x01], 2),
                (&[0x03, 0xAA], 3),
                (&[0x02], 4),
                (&[0x01, 0xBB], 5),
            ];
            loaded.load(entries.into_iter());
            for (key, value) in entries {
                inserted.insert(key, value);
            }
            assert_eq!(loaded.keys(), inserted.keys());
            assert_eq!(loaded.items(), inserted.items());
            for (key, _) in entries {
                assert_eq!(
                    loaded.get(key).collect::<Vec<_>>(),
                    inserted.get(key).collect::<Vec<_>>()
                );
            }
        });
    }
}
