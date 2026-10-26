//! A memory-efficient index that uses unordered maps internally to map translated keys to
//! arbitrary values. If you require ordering over the map's keys, consider
//! [crate::index::ordered::Index] instead.

use crate::{
    index::{
        Cursor as CursorTrait, KeyUpdate, Unordered,
        storage::{Cursor as CursorImpl, IndexEntry, Overflow, Values, push_displaced},
    },
    translator::Translator,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};
use std::{
    collections::{
        HashMap,
        hash_map::{Entry, OccupiedEntry, VacantEntry},
    },
    iter, mem,
    num::NonZeroUsize,
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

/// One hash table, plus its overflow map, from translated keys to values. Methods taking a
/// `T::Key` expect an already-translated key.
pub(crate) struct Table<T: Translator, V: Send + Sync> {
    translator: T,
    map: HashMap<T::Key, V, T>,
    overflow: Overflow<T::Key, V, T>,

    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator, V: Send + Sync> Table<T, V> {
    /// Create a new entry in the table.
    fn create(keys: &Gauge, items: &Gauge, vacant: VacantEntry<'_, T::Key, V>, v: V) {
        keys.inc();
        items.inc();
        vacant.insert(v);
    }

    /// Create a new table with the given translator and metrics registry. The maps start without
    /// capacity and grow as needed, so unused tables (e.g. empty partitions) cost no memory.
    pub(crate) fn new(ctx: impl Metrics, translator: T) -> Self {
        Self {
            translator: translator.clone(),
            overflow: HashMap::with_hasher(translator.clone()),
            map: HashMap::with_hasher(translator),
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    /// Create an empty table that shares this table's translator and metrics. It updates the
    /// metrics through detached handles and holds no registrations, so the metrics leave the
    /// registry when this table is dropped.
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
    /// [`Self::empty`] build-worker slots install without re-inserting each entry. Metrics need no
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

    /// Visit every value held by the table (inline and overflow), in unspecified order.
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

    fn get_translated(&self, k: T::Key) -> Values<'_, T::Key, V, T> {
        Values::new(self.map.get(&k), &self.overflow, k)
    }

    fn get_mut_translated(&mut self, k: T::Key) -> Option<Cursor<'_, T::Key, V, T>> {
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

    fn get_mut_or_insert_translated(
        &mut self,
        k: T::Key,
        value: V,
    ) -> Option<Cursor<'_, T::Key, V, T>> {
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

    fn insert_translated(&mut self, k: T::Key, v: V) {
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

    fn insert_and_retain_translated(
        &mut self,
        k: T::Key,
        value: V,
        mut should_retain: impl FnMut(&V) -> bool,
    ) {
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

    fn remove_translated(&mut self, k: T::Key) {
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
}

impl<T: Translator, V: Send + Sync> Unordered for Table<T, V> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V, T>
    where
        Self: 'a;

    #[inline]
    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a {
        self.get_translated(self.translator.transform(key))
    }

    #[inline]
    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        self.get_mut_translated(self.translator.transform(key))
    }

    #[inline]
    fn get_mut_or_insert<'a>(&'a mut self, key: &[u8], value: V) -> Option<Self::Cursor<'a>> {
        self.get_mut_or_insert_translated(self.translator.transform(key), value)
    }

    #[inline]
    fn insert(&mut self, key: &[u8], v: V) {
        self.insert_translated(self.translator.transform(key), v);
    }

    #[inline]
    fn insert_and_retain(&mut self, key: &[u8], value: V, should_retain: impl FnMut(&V) -> bool) {
        self.insert_and_retain_translated(self.translator.transform(key), value, should_retain);
    }

    #[inline]
    fn remove(&mut self, key: &[u8]) {
        self.remove_translated(self.translator.transform(key));
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

/// The number of hash bits that pick an [Index]'s table.
const TABLE_BITS: u32 = 8;

/// The number of tables an [Index] spreads translated keys across. At 1B keys, a resize copies
/// about 4M entries.
const TABLES: usize = 1 << TABLE_BITS;

/// The number of top hash bits the tables use as tags.
const TAG_BITS: u32 = 7;

/// The table bits sit just below the tags and above the low bits the tables use for position,
/// so they overlap neither. (On 32-bit targets the tables use only the low 32 bits.)
const TABLE_SHIFT: u32 = u64::BITS - TAG_BITS - TABLE_BITS;

/// A memory-efficient index that uses unordered maps internally to map translated keys to
/// arbitrary values.
///
/// Each translated key maps directly to its most recently inserted value. Conflicting values (from
/// key collisions or repeated insertions) live in per-table overflow maps, keeping the common
/// (collision-free) case compact. Keys are spread across 256 hash tables that grow independently,
/// so a resize copies about 1/256 of the entries instead of the whole index.
pub struct Index<T: Translator, V: Send + Sync> {
    translator: T,
    tables: Box<[Table<T, V>; TABLES]>,
}

impl<T: Translator, V: Send + Sync> Index<T, V> {
    /// Create a new index with the given translator and metrics registry. The tables start without
    /// capacity and grow as needed, so an empty index costs only its 256 table headers.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        // The first table holds the metric registrations, so they live as long as the index.
        let first = Table::new(ctx, translator.clone());
        let rest: Vec<_> = (1..TABLES).map(|_| first.empty()).collect();
        let tables: Box<[Table<T, V>]> = iter::once(first).chain(rest).collect();
        let Ok(tables) = tables.try_into() else {
            unreachable!("collected exactly {TABLES} tables");
        };
        Self { translator, tables }
    }

    /// Returns the position of the table holding translated key `k`.
    #[inline]
    fn table_of(&self, k: &T::Key) -> usize {
        (self.translator.hash_one(k) >> TABLE_SHIFT) as usize & (TABLES - 1)
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

    #[inline]
    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + 'a {
        let k = self.translator.transform(key);
        self.tables[self.table_of(&k)].get_translated(k)
    }

    #[inline]
    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        let i = self.table_of(&k);
        self.tables[i].get_mut_translated(k)
    }

    #[inline]
    fn get_mut_or_insert<'a>(&'a mut self, key: &[u8], value: V) -> Option<Self::Cursor<'a>> {
        let k = self.translator.transform(key);
        let i = self.table_of(&k);
        self.tables[i].get_mut_or_insert_translated(k, value)
    }

    #[inline]
    fn insert(&mut self, key: &[u8], value: V) {
        let k = self.translator.transform(key);
        let i = self.table_of(&k);
        self.tables[i].insert_translated(k, value);
    }

    #[inline]
    fn insert_and_retain(&mut self, key: &[u8], value: V, should_retain: impl FnMut(&V) -> bool) {
        let k = self.translator.transform(key);
        let i = self.table_of(&k);
        self.tables[i].insert_and_retain_translated(k, value, should_retain);
    }

    #[inline]
    fn remove(&mut self, key: &[u8]) {
        let k = self.translator.transform(key);
        let i = self.table_of(&k);
        self.tables[i].remove_translated(k);
    }

    fn update_many<S: Strategy, U: KeyUpdate<V>>(
        &mut self,
        strategy: &S,
        keys: &[&[u8]],
        update: &U,
    ) {
        // A translated key always lives in one table, so runs of tables update independently.
        let per_table = keys.len().div_ceil(TABLES);
        strategy.run_batches(TABLES, NonZeroUsize::MIN, per_table, |batches| {
            if batches.is_whole() {
                for i in 0..keys.len() {
                    update.apply(self, i);
                }
                return;
            }

            // Group the positions by table in one array. Table `t`'s positions are
            // `positions[starts[t]..starts[t + 1]]`, in position order.
            let tables: Vec<usize> = keys
                .iter()
                .map(|key| self.table_of(&self.translator.transform(key)))
                .collect();
            let mut starts = [0usize; TABLES + 1];
            for &table in &tables {
                starts[table + 1] += 1;
            }
            for table in 0..TABLES {
                starts[table + 1] += starts[table];
            }
            let mut next = starts;
            let mut positions = vec![0; keys.len()];
            for (i, &table) in tables.iter().enumerate() {
                positions[next[table]] = i;
                next[table] += 1;
            }

            let (positions, starts) = (&positions, &starts);
            batches.map_collect_vec(
                |ranges| {
                    let mut rest = &mut self.tables[..];
                    ranges
                        .into_iter()
                        .map(|range| {
                            let (run, tail) = mem::take(&mut rest).split_at_mut(range.len());
                            rest = tail;
                            (range.start, run)
                        })
                        .collect::<Vec<_>>()
                },
                |(first, run)| {
                    for (table, index) in (first..).zip(run) {
                        for &i in &positions[starts[table]..starts[table + 1]] {
                            update.apply(index, i);
                        }
                    }
                },
            );
        });
    }

    // The tables share their metric handles, so any table reports the whole index.
    #[cfg(test)]
    fn keys(&self) -> usize {
        self.tables[0].keys()
    }

    #[cfg(test)]
    fn items(&self) -> usize {
        self.tables[0].items()
    }

    #[cfg(test)]
    fn pruned(&self) -> usize {
        self.tables[0].pruned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::{EightCap, TwoCap};
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Rayon;
    use commonware_runtime::{
        Runner, Supervisor as _, deterministic, telemetry::metrics::metric_samples,
    };
    use commonware_utils::NZUsize;
    use std::hash::BuildHasher;

    /// Inserts value `i` under the key at position `i`.
    struct InsertPosition<'a>(&'a [&'a [u8]]);

    impl KeyUpdate<u64> for InsertPosition<'_> {
        fn apply<I: Unordered<Value = u64>>(&self, index: &mut I, i: usize) {
            index.insert(self.0[i], i as u64);
        }
    }

    #[test_traced]
    fn test_index_update_many_matches_serial_updates() {
        deterministic::Runner::default().start(|context| async move {
            // Repeated keys, and a two-byte translation so distinct keys often collide.
            let digests: Vec<_> = (0..20_000u64)
                .map(|i| Sha256::hash(&[&(i % 5_000).to_be_bytes()]))
                .collect();
            let keys: Vec<&[u8]> = digests.iter().map(|digest| digest.as_ref()).collect();

            let mut parallel = Index::<TwoCap, u64>::new(context.child("parallel"), TwoCap);
            let strategy = Rayon::new(NZUsize!(4)).unwrap();
            parallel.update_many(&strategy, &keys, &InsertPosition(&keys));

            let mut serial = Index::<TwoCap, u64>::new(context.child("serial"), TwoCap);
            for (i, key) in keys.iter().enumerate() {
                serial.insert(key, i as u64);
            }
            for key in &keys {
                assert!(parallel.get(key).eq(serial.get(key)));
            }
        });
    }

    #[test_traced]
    fn test_index_table_choice_leaves_hashbrown_bits_free() {
        deterministic::Runner::default().start(|context| async move {
            let index = Index::<EightCap, u64>::new(context, EightCap);
            let (mut any, mut all) = (0u64, u64::MAX);
            let mut sizes = [0usize; TABLES];
            for i in 0..100_000u64 {
                let k = EightCap.transform(&Sha256::hash(&[&i.to_be_bytes()]));
                let table = index.table_of(&k);
                sizes[table] += 1;
                if table == 0 {
                    let hash = EightCap.hash_one(k);
                    any |= hash;
                    all &= hash;
                }
            }
            // Within one table, the 7 tag bits and at least the low 40 position bits must vary.
            let varied = any & !all;
            assert_eq!(varied >> 57, 0x7f);
            assert_eq!(varied & ((1 << 40) - 1), (1 << 40) - 1);
            assert!(sizes.iter().all(|&size| (250..550).contains(&size)));
        });
    }

    #[test_traced]
    fn test_index_shares_metrics_across_tables() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = Index::<EightCap, u64>::new(context.child("index"), EightCap);
            for i in 0..1_000u64 {
                index.insert(&Sha256::hash(&[&i.to_be_bytes()]), i);
            }
            let key = (0..1_000u64)
                .map(|i| Sha256::hash(&[&i.to_be_bytes()]))
                .find(|key| index.table_of(&EightCap.transform(key)) != 0)
                .unwrap();
            {
                let mut cursor = index.get_mut(&key).unwrap();
                assert!(cursor.next().is_some());
                cursor.delete();
            }
            assert_eq!(index.keys(), 999);
            assert_eq!(index.items(), 999);
            assert_eq!(index.pruned(), 1);

            // The index holds its metrics' registrations for as long as it lives.
            let encoded = context.encode();
            for name in ["keys", "items", "pruned_total"] {
                assert!(
                    metric_samples(&encoded, name).next().is_some(),
                    "{name} is registered"
                );
            }
        });
    }
}
