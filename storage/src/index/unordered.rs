//! A memory-efficient index that uses an unordered map internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

use crate::{
    index::{
        Cursor as CursorTrait, Packable, Unordered,
        storage::{Cursor as CursorImpl, IndexEntry, Overflow, Unaligned, Values, push_displaced},
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

/// Implementation of [IndexEntry] for an [OccupiedEntry] holding a packed value.
impl<K: Copy + Send + Sync, V: Packable> IndexEntry<V>
    for OccupiedEntry<'_, Unaligned<K>, V::Packed>
{
    type Key = K;

    fn key(&self) -> K {
        OccupiedEntry::key(self).0
    }

    fn get(&self) -> V {
        V::unpack(*OccupiedEntry::get(self))
    }

    fn set(&mut self, value: V) {
        *self.get_mut() = value.pack();
    }

    fn remove(self) {
        OccupiedEntry::remove(self);
    }
}

/// A [crate::index::Cursor] over the values associated with a translated key.
pub type Cursor<'a, K, V, S> =
    CursorImpl<'a, K, V, OccupiedEntry<'a, Unaligned<K>, <V as Packable>::Packed>, S>;

/// A memory-efficient index that uses an unordered map internally to map translated keys to
/// arbitrary values.
///
/// Each translated key maps directly to its most recently inserted value. Conflicting values (from
/// key collisions or repeated insertions) live in a separate overflow map, keeping the common
/// (collision-free) case compact. Map entries hold the key unaligned and the value in its
/// [Packable] form, so a packed form narrower than its value (e.g. for [crate::merkle::Location])
/// saves memory at some cost in lookup latency.
///
/// # Panics
///
/// Storing a value that has no packed form (e.g. a [crate::merkle::Location] of 2^48 or more)
/// panics, either when it is stored or when it later becomes a key's inline value.
pub struct Index<T: Translator, V: Packable> {
    translator: T,
    map: HashMap<Unaligned<T::Key>, V::Packed, T>,
    overflow: Overflow<T::Key, V, T>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Packable> Index<T, V> {
    /// Create a new entry in the index.
    fn create(
        keys: &Gauge,
        items: &Gauge,
        vacant: VacantEntry<'_, Unaligned<T::Key>, V::Packed>,
        v: V,
    ) {
        vacant.insert(v.pack());
        keys.inc();
        items.inc();
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
    pub(crate) fn for_each_value(&self, mut f: impl FnMut(V)) {
        for &packed in self.map.values() {
            f(V::unpack(packed));
        }
        for chain in self.overflow.values() {
            for &v in chain {
                f(v);
            }
        }
    }
}

impl<T: Translator, V: Packable> super::Factory for Index<T, V> {
    type Translator = T;

    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Packable> Unordered for Index<T, V> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V, T>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = V> + 'a {
        let k = self.translator.transform(key);
        let head = self.map.get(&Unaligned(k)).map(|&packed| V::unpack(packed));
        Values::new(head, &self.overflow, k)
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        match self.map.entry(Unaligned(k)) {
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
        match self.map.entry(Unaligned(k)) {
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
        match self.map.entry(Unaligned(k)) {
            Entry::Occupied(mut entry) => {
                // The newest value is stored inline; the displaced value joins the end of the
                // overflow chain.
                let old = V::unpack(std::mem::replace(entry.get_mut(), v.pack()));
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
        match self.map.entry(Unaligned(k)) {
            Entry::Occupied(mut entry) => {
                // Optimized fast path for the common case of no overflow chain.
                #[allow(clippy::map_entry)]
                if !self.overflow.contains_key(&k) {
                    match (
                        should_retain(&V::unpack(*entry.get())),
                        should_retain(&value),
                    ) {
                        // Keep both, with the new value placed at the end of the overflow chain.
                        (true, true) => {
                            self.overflow.insert(k, vec![value]);
                            self.items.inc();
                        }
                        // Drop the existing value, keep the new one: replace in place.
                        (false, true) => {
                            *entry.get_mut() = value.pack();
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
        if self.map.remove(&Unaligned(k)).is_some() {
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
