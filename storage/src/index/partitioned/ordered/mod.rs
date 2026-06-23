//! A partitioned index that stores each partition as sorted struct-of-arrays (see the
//! `self::partition` module).
//!
//! The first `P` bytes of the (untranslated) key select a partition; the translator maps the
//! remaining bytes to the partition-local key. Because the partitions are ordered by prefix and each
//! partition's entries are sorted by translated key, this index is inherently ordered. It trades
//! lookup/insert speed for memory density at scale; the unordered variant ([`super::unordered`])
//! uses hash sub-indices instead and is faster when ordering is not required.
//!
//! # Adversarial grinding
//!
//! An order-preserving translator cannot randomize keys (that would break the ordering), so an
//! attacker can grind the key suffix to flood one partition with distinct translated keys, making
//! each sorted-array insert an O(occupancy) memmove. When a partition's array reaches
//! `SPILL_THRESHOLD` entries it spills to a `BTreeMap` (the `spilled` field), bounding *distinct-key*
//! grinding to O(log occupancy) per operation.
//!
//! The guard bounds distinct-key density only, not the length of a single key's value run. A
//! translated key's values (hash collisions, or repeated inserts of one key) form a contiguous
//! newest-first run in both representations -- the SoA `vals` array and a spilled key's value
//! vector -- so inserting into a length-`L` run is O(L) either way: spilling reorganizes *across*
//! keys (array to tree), never *within* one key's run. A long run is therefore not a target of this
//! guard; its length is a function of the translator's collision-resistance (well-distributed keys
//! average ~1) and is the price of this layout's density. Callers that need O(1) collision appends
//! can use the flat `crate::index::ordered::Index`, which keeps a per-key overflow vector instead.

mod partition;

use self::partition::Partition;
use crate::{
    index::{
        partitioned::partition_index_and_sub_key, Cursor as CursorTrait, Factory, Ordered,
        Unordered,
    },
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    ops::{Bound, Range},
};

const MUST_CALL_NEXT: &str = "must call Cursor::next()";
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Position of a [Cursor] within its key's value run (offset 0 is the run's first value).
enum State {
    /// Before the first `next()` or after an `insert()`/`delete()`: the next `next()` returns the
    /// value at run offset `from`.
    NeedNext { from: usize },
    /// `next()` returned the value at run offset `offset`; `update`/`delete`/`insert` are valid.
    Active { offset: usize },
    /// `next()` returned `None`; only `insert()` (which appends) is valid.
    Done,
}

/// A [Cursor] over a single translated key's values, held inline in a partition's sorted arrays
/// where they occupy a contiguous index range (`run`).
///
/// The cursor resolves `run` once, when created, and caches it so each operation indexes straight
/// into the arrays instead of searching for the key again. The cache stays correct because the
/// cursor borrows the partition exclusively: it is the sole writer and only ever adds or removes
/// this key's own values. Nothing shifts the entries before the run, so `run.start` is fixed, and
/// each `insert`/`delete` adjusts `run.end` by one to stay aligned with the array.
struct SoaCursor<'a, K: Ord + Copy, V> {
    partition: &'a mut Partition<K, V>,
    key: K,
    run: Range<usize>,
    state: State,
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, K: Ord + Copy, V> SoaCursor<'a, K, V> {
    const fn new(
        partition: &'a mut Partition<K, V>,
        key: K,
        run: Range<usize>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            partition,
            key,
            run,
            state: State::NeedNext { from: 0 },
            keys,
            items,
            pruned,
        }
    }
}

impl<K: Ord + Copy + Send + Sync, V: Send + Sync> CursorTrait for SoaCursor<'_, K, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        let off = match self.state {
            State::Done => return None,
            State::NeedNext { from } => from,
            State::Active { offset } => offset + 1,
        };
        if off >= self.run.len() {
            self.state = State::Done;
            return None;
        }
        self.state = State::Active { offset: off };
        Some(self.partition.value_at(self.run.start + off))
    }

    fn update(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => self.partition.set(self.run.start + offset, value),
        }
    }

    fn insert(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Active { offset } => {
                // Place immediately after the current value; `next()` then returns the value after
                // the inserted one (skipping both the current and the inserted).
                self.partition
                    .insert_at(self.run.start + offset + 1, self.key, value);
                self.run.end += 1;
                self.items.inc();
                self.state = State::NeedNext { from: offset + 2 };
            }
            State::Done => {
                // Append at the oldest position (run end), re-creating the key if it was emptied.
                if self.run.is_empty() {
                    self.keys.inc();
                }
                self.partition.insert_at(self.run.end, self.key, value);
                self.run.end += 1;
                self.items.inc();
            }
        }
    }

    fn delete(&mut self) {
        let offset = match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => offset,
        };
        self.partition.remove(self.run.start + offset);
        self.run.end -= 1;
        self.items.dec();
        self.pruned.inc();
        if self.run.is_empty() {
            // Removed the key's last value; the key is gone.
            self.keys.dec();
        }

        // The value after the deleted one shifted into `offset`.
        self.state = State::NeedNext { from: offset };
    }
}

/// A [Cursor] over a translated key's values held in a spilled partition's `BTreeMap`.
///
/// A spilled partition lives in the index's `spilled` side-table, each key mapping to its values
/// newest-first. The cursor re-resolves the key's value vector through the side-table on each
/// operation: spilling is the rare, non-uniform key distribution case, so the extra `BTreeMap`
/// descent is off the hot path. Deleting a key's last value drops its entry, and emptying the
/// partition's last key removes it from the side-table (reverting it to an empty sorted-array
/// partition).
struct SpilledCursor<'a, K: Ord + Copy, V> {
    spilled: &'a mut HashMap<usize, BTreeMap<K, Vec<V>>>,
    partition: usize,
    key: K,
    state: State,
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, K: Ord + Copy, V> SpilledCursor<'a, K, V> {
    const fn new(
        spilled: &'a mut HashMap<usize, BTreeMap<K, Vec<V>>>,
        partition: usize,
        key: K,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            spilled,
            partition,
            key,
            state: State::NeedNext { from: 0 },
            keys,
            items,
            pruned,
        }
    }

    /// The values stored for the cursor's key, or `None` if the key has no values -- either its
    /// entry was removed or the whole partition de-spilled.
    fn vals(&self) -> Option<&Vec<V>> {
        self.spilled
            .get(&self.partition)
            .and_then(|inner| inner.get(&self.key))
    }

    fn vals_mut(&mut self) -> Option<&mut Vec<V>> {
        self.spilled
            .get_mut(&self.partition)
            .and_then(|inner| inner.get_mut(&self.key))
    }
}

impl<K: Ord + Copy + Send + Sync, V: Send + Sync> CursorTrait for SpilledCursor<'_, K, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        let off = match self.state {
            State::Done => return None,
            State::NeedNext { from } => from,
            State::Active { offset } => offset + 1,
        };

        // Two resolutions (length, then value): collapsing them needs the resolved borrow held
        // across the `self.state` write, which NLL rejects (the returned value re-borrows `self`).
        if off >= self.vals().map_or(0, Vec::len) {
            self.state = State::Done;
            return None;
        }
        self.state = State::Active { offset: off };
        Some(&self.vals().unwrap()[off])
    }

    fn update(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => self.vals_mut().unwrap()[offset] = value,
        }
    }

    fn insert(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Active { offset } => {
                // Place immediately after the current value (newest-first); `next()` then returns
                // the value after the inserted one.
                self.vals_mut().unwrap().insert(offset + 1, value);
                self.items.inc();
                self.state = State::NeedNext { from: offset + 2 };
            }
            State::Done => {
                // Append at the oldest position (vector end), re-creating the key (and partition
                // entry) if it was emptied; a vacant key entry is a new key.
                let inner = self.spilled.entry(self.partition).or_default();
                match inner.entry(self.key) {
                    btree_map::Entry::Occupied(mut run) => run.get_mut().push(value),
                    btree_map::Entry::Vacant(run) => {
                        run.insert(vec![value]);
                        self.keys.inc();
                    }
                }
                self.items.inc();
            }
        }
    }

    fn delete(&mut self) {
        let offset = match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => offset,
        };

        // The cursor's partition and key must both be present when active.
        let hash_map::Entry::Occupied(mut partition) = self.spilled.entry(self.partition) else {
            unreachable!()
        };
        let btree_map::Entry::Occupied(mut run) = partition.get_mut().entry(self.key) else {
            unreachable!()
        };
        let vals = run.get_mut();
        vals.remove(offset);
        let key_emptied = vals.is_empty();
        self.items.dec();
        self.pruned.inc();

        if key_emptied {
            // Removed the key's last value; drop the key, and de-spill the partition (back to an
            // empty sorted array) if that was its last key.
            self.keys.dec();
            run.remove();
            if partition.get().is_empty() {
                partition.remove();
            }
        }

        // The value after the deleted one shifted into `offset`.
        self.state = State::NeedNext { from: offset };
    }
}

/// A [crate::index::Cursor] over a translated key's values.
pub struct Cursor<'a, K: Ord + Copy, V>(CursorInner<'a, K, V>);

enum CursorInner<'a, K: Ord + Copy, V> {
    Soa(SoaCursor<'a, K, V>),
    Spilled(SpilledCursor<'a, K, V>),
}

impl<'a, K: Ord + Copy, V> Cursor<'a, K, V> {
    const fn soa(cursor: SoaCursor<'a, K, V>) -> Self {
        Self(CursorInner::Soa(cursor))
    }

    const fn spilled(cursor: SpilledCursor<'a, K, V>) -> Self {
        Self(CursorInner::Spilled(cursor))
    }
}

impl<K: Ord + Copy + Send + Sync, V: Send + Sync> CursorTrait for Cursor<'_, K, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        match &mut self.0 {
            CursorInner::Soa(c) => c.next(),
            CursorInner::Spilled(c) => c.next(),
        }
    }

    fn update(&mut self, value: V) {
        match &mut self.0 {
            CursorInner::Soa(c) => c.update(value),
            CursorInner::Spilled(c) => c.update(value),
        }
    }

    fn insert(&mut self, value: V) {
        match &mut self.0 {
            CursorInner::Soa(c) => c.insert(value),
            CursorInner::Spilled(c) => c.insert(value),
        }
    }

    fn delete(&mut self) {
        match &mut self.0 {
            CursorInner::Soa(c) => c.delete(),
            CursorInner::Spilled(c) => c.delete(),
        }
    }
}

/// Sorted-array length at which a partition spills to a `BTreeMap`. Set well above any honest
/// occupancy (even ~1B keys at P=3 averages ~60 entries per partition) so uniformly distributed
/// keys should never spill; it exists only to bound adversarial grinding that floods a partition
/// with distinct translated keys (see the module docs for what the guard does and does not bound).
const SPILL_THRESHOLD: usize = 512;

/// A partitioned index storing each partition as sorted struct-of-arrays, spilling an over-full
/// partition to a `BTreeMap` to bound adversarial distinct-key grinding (see `spilled` and the
/// module docs).
pub struct Index<T: Translator, V: Send + Sync, const P: usize> {
    /// Translates the prefix-stripped key bytes into a partition-local key.
    translator: T,

    /// The `2^(8*P)` partitions, indexed by the `P`-byte key prefix. Each stores its translated
    /// keys and values as sorted arrays (the inline representation); an emptied partition may
    /// instead have spilled (see `spilled`).
    partitions: Box<[Partition<T::Key, V>]>,

    /// Partitions that have spilled out of their sorted arrays (over-full from grinding), keyed by
    /// partition index; each maps translated keys to their values newest-first. Typically empty
    /// unless key distribution is non-uniform, e.g. due to grinding.
    spilled: HashMap<usize, BTreeMap<T::Key, Vec<V>>>,

    /// Sorted-array length at which a partition spills to `spilled`; [SPILL_THRESHOLD] in
    /// production, lowered by tests to exercise spilling cheaply.
    threshold: usize,

    /// Metric: distinct translated keys currently held across all partitions.
    keys: Gauge,

    /// Metric: stored values currently held across all partitions.
    items: Gauge,

    /// Metric: cumulative values removed (via `remove`, cursor `delete`, or `retain`).
    pruned: Counter,
}

impl<T: Translator, V: Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given metrics context and translator.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        const {
            assert!(P > 0 && P <= 3, "P must be in 1..=3");
        }
        let count = 1usize << (P * 8);
        let partitions = (0..count)
            .map(|_| Partition::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            translator,
            partitions,
            spilled: HashMap::new(),
            threshold: SPILL_THRESHOLD,
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    /// Create a new [Index] with an explicit spill threshold so tests can exercise spilling without
    /// inserting [SPILL_THRESHOLD] keys.
    #[cfg(test)]
    pub(crate) fn with_threshold(ctx: impl Metrics, translator: T, threshold: usize) -> Self {
        let mut index = Self::new(ctx, translator);
        index.threshold = threshold;
        index
    }

    /// Spill partition `i` to the side-table if its sorted array has reached the threshold.
    fn maybe_spill(&mut self, i: usize) {
        if self.partitions[i].len() < self.threshold {
            return;
        }
        let inner: BTreeMap<T::Key, Vec<V>> = self.partitions[i].drain_runs().into_iter().collect();
        self.spilled.insert(i, inner);
    }

    /// The values for translated key `k` in partition `i` (empty if absent), from whichever
    /// representation the partition currently uses.
    fn partition_values(&self, i: usize, k: &T::Key) -> &[V] {
        if self.partitions[i].is_empty() && !self.spilled.is_empty() {
            if let Some(inner) = self.spilled.get(&i) {
                return inner.get(k).map_or(&[], Vec::as_slice);
            }
        }
        self.partitions[i].values(k)
    }

    /// Values of the smallest key in partition `i` (None if the partition is empty).
    fn partition_first(&self, i: usize) -> Option<&[V]> {
        if let Some(vals) = self.partitions[i].first_values() {
            return Some(vals);
        }
        if !self.spilled.is_empty() {
            if let Some(inner) = self.spilled.get(&i) {
                return inner.first_key_value().map(|(_, v)| v.as_slice());
            }
        }
        None
    }

    /// Values of the largest key in partition `i` (None if the partition is empty).
    fn partition_last(&self, i: usize) -> Option<&[V]> {
        if let Some(vals) = self.partitions[i].last_values() {
            return Some(vals);
        }
        if !self.spilled.is_empty() {
            if let Some(inner) = self.spilled.get(&i) {
                return inner.last_key_value().map(|(_, v)| v.as_slice());
            }
        }
        None
    }

    /// Values of the smallest key strictly greater than `k` in partition `i`.
    fn partition_next_after(&self, i: usize, k: &T::Key) -> Option<&[V]> {
        if let Some(vals) = self.partitions[i].next_values_after(k) {
            return Some(vals);
        }
        if !self.spilled.is_empty() {
            if let Some(inner) = self.spilled.get(&i) {
                return inner
                    .range((Bound::Excluded(*k), Bound::Unbounded))
                    .next()
                    .map(|(_, v)| v.as_slice());
            }
        }
        None
    }

    /// Values of the largest key strictly less than `k` in partition `i`.
    fn partition_prev_before(&self, i: usize, k: &T::Key) -> Option<&[V]> {
        if let Some(vals) = self.partitions[i].prev_values_before(k) {
            return Some(vals);
        }
        if !self.spilled.is_empty() {
            if let Some(inner) = self.spilled.get(&i) {
                return inner
                    .range((Bound::Unbounded, Bound::Excluded(*k)))
                    .next_back()
                    .map(|(_, v)| v.as_slice());
            }
        }
        None
    }

    /// Number of partitions currently spilled to the side-table.
    #[cfg(test)]
    pub(crate) fn spilled_count(&self) -> usize {
        self.spilled.len()
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Factory<T> for Index<T, V, P> {
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Unordered for Index<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + Send + 'a
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        self.partition_values(i, &k).iter()
    }

    fn get_many<'a, K: AsRef<[u8]>>(&'a self, keys: &[K], mut visit: impl FnMut(usize, &'a V))
    where
        V: 'a,
    {
        // Probe in (partition, translated-key) order so consecutive probes hit the same partition
        // (one region of the 2^(8*P)-entry partition array) and the same value run within it,
        // instead of scattering across partitions in input order.
        let mut order: Vec<(usize, T::Key, usize)> = keys
            .iter()
            .enumerate()
            .map(|(key_idx, key)| {
                let (partition, sub) = partition_index_and_sub_key::<P>(key.as_ref());
                (partition, self.translator.transform(sub), key_idx)
            })
            .collect();
        order.sort_unstable();
        for (partition, translated, key_idx) in order {
            for value in self.partition_values(partition, &translated) {
                visit(key_idx, value);
            }
        }
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        if !self.partitions[i].is_empty() {
            let run = self.partitions[i].run_range(&k);
            if run.is_empty() {
                return None;
            }
            return Some(Cursor::soa(SoaCursor::new(
                &mut self.partitions[i],
                k,
                run,
                &self.keys,
                &self.items,
                &self.pruned,
            )));
        }

        // Hand out a spilled cursor if the partition has spilled and holds `k`.
        if !self.spilled.is_empty()
            && self
                .spilled
                .get(&i)
                .is_some_and(|inner| inner.contains_key(&k))
        {
            return Some(Cursor::spilled(SpilledCursor::new(
                &mut self.spilled,
                i,
                k,
                &self.keys,
                &self.items,
                &self.pruned,
            )));
        }

        // Partition is genuinely empty.
        None
    }

    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        if !self.partitions[i].is_empty() {
            let run = self.partitions[i].run_range(&k);
            if !run.is_empty() {
                return Some(Cursor::soa(SoaCursor::new(
                    &mut self.partitions[i],
                    k,
                    run,
                    &self.keys,
                    &self.items,
                    &self.pruned,
                )));
            }
            self.partitions[i].insert_at(run.start, k, value);
            self.keys.inc();
            self.items.inc();
            self.maybe_spill(i);
            return None;
        }

        // Partition i is empty. If it's because it has spilled, serve or create the key in its
        // `BTreeMap`.
        if !self.spilled.is_empty() {
            if let Some(inner) = self.spilled.get(&i) {
                if inner.contains_key(&k) {
                    return Some(Cursor::spilled(SpilledCursor::new(
                        &mut self.spilled,
                        i,
                        k,
                        &self.keys,
                        &self.items,
                        &self.pruned,
                    )));
                }
                self.spilled.get_mut(&i).unwrap().insert(k, vec![value]);
                self.keys.inc();
                self.items.inc();
                return None;
            }
        }

        // Partition i is genuinely empty: start a fresh sorted array.
        self.partitions[i].insert_at(0, k, value);
        self.keys.inc();
        self.items.inc();
        self.maybe_spill(i);

        None
    }

    fn insert(&mut self, key: &[u8], value: Self::Value) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        if !self.partitions[i].is_empty() {
            let run = self.partitions[i].run_range(&k);
            let new_key = run.is_empty();
            self.partitions[i].insert_at(run.start, k, value);
            self.items.inc();
            if new_key {
                self.keys.inc();
            }
            self.maybe_spill(i);
            return;
        }

        // Route into the spilled partition's `BTreeMap`.
        if !self.spilled.is_empty() {
            if let hash_map::Entry::Occupied(mut partition) = self.spilled.entry(i) {
                match partition.get_mut().entry(k) {
                    btree_map::Entry::Occupied(mut run) => run.get_mut().insert(0, value),
                    btree_map::Entry::Vacant(run) => {
                        run.insert(vec![value]);
                        self.keys.inc();
                    }
                }
                self.items.inc();
                return;
            }
        }

        // Genuinely empty partition: start a fresh sorted array.
        self.partitions[i].insert_at(0, k, value);
        self.items.inc();
        self.keys.inc();
        self.maybe_spill(i);
    }

    fn insert_and_retain(
        &mut self,
        key: &[u8],
        value: Self::Value,
        should_retain: impl Fn(&Self::Value) -> bool,
    ) {
        if let Some(mut cursor) = self.get_mut(key) {
            cursor.retain(&should_retain);
            if should_retain(&value) {
                cursor.insert(value);
            }
        } else if should_retain(&value) {
            self.insert(key, value);
        }
    }

    fn remove(&mut self, key: &[u8]) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        if !self.partitions[i].is_empty() {
            let run = self.partitions[i].run_range(&k);
            if run.is_empty() {
                return;
            }
            let n = run.len();
            self.partitions[i].remove_run(run);
            self.keys.dec();
            self.items.dec_by(n as i64);
            self.pruned.inc_by(n as u64);
            return;
        }
        // Partition i is empty here; if spilled, remove from its `BTreeMap` (and drop the
        // partition entry, reverting to an empty sorted array, once its last key is gone).
        if !self.spilled.is_empty() {
            if let hash_map::Entry::Occupied(mut partition) = self.spilled.entry(i) {
                if let Some(vals) = partition.get_mut().remove(&k) {
                    let n = vals.len();
                    self.keys.dec();
                    self.items.dec_by(n as i64);
                    self.pruned.inc_by(n as u64);
                    if partition.get().is_empty() {
                        partition.remove();
                    }
                }
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

impl<T: Translator, V: Send + Sync, const P: usize> Ordered for Index<T, V, P> {
    fn prev_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        // The largest translated key strictly less than `k`: within the partition first, then the
        // last key of the nearest lower partition, else cycle to the global last key.
        if let Some(vals) = self.partition_prev_before(i, &k) {
            return Some((vals.iter(), false));
        }
        for p in (0..i).rev() {
            if let Some(vals) = self.partition_last(p) {
                return Some((vals.iter(), false));
            }
        }
        for p in (0..self.partitions.len()).rev() {
            if let Some(vals) = self.partition_last(p) {
                return Some((vals.iter(), true));
            }
        }
        None
    }

    fn next_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        // The smallest translated key strictly greater than `k`: within the partition first, then
        // the first key of the nearest higher partition, else cycle to the global first key.
        if let Some(vals) = self.partition_next_after(i, &k) {
            return Some((vals.iter(), false));
        }
        for p in i + 1..self.partitions.len() {
            if let Some(vals) = self.partition_first(p) {
                return Some((vals.iter(), false));
            }
        }
        for p in 0..self.partitions.len() {
            if let Some(vals) = self.partition_first(p) {
                return Some((vals.iter(), true));
            }
        }
        None
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        for p in 0..self.partitions.len() {
            if let Some(vals) = self.partition_first(p) {
                return Some(vals.iter());
            }
        }
        None
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        for p in (0..self.partitions.len()).rev() {
            if let Some(vals) = self.partition_last(p) {
                return Some(vals.iter());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::OneCap;
    use commonware_formatting::hex;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    fn new_index(context: deterministic::Context) -> Index<OneCap, u64, 1> {
        Index::new(context, OneCap)
    }

    /// Index with a tiny spill threshold: a partition spills once it holds two entries. With
    /// `OneCap` + P=1 the key byte selects the partition and the next byte is the translated key,
    /// so keys sharing a first byte land in one partition.
    fn new_index_spilling(context: deterministic::Context) -> Index<OneCap, u64, 1> {
        Index::with_threshold(context, OneCap, 2)
    }

    #[test_traced]
    fn test_spill_transition() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            // Distinct translated keys in one partition (prefix 0x10).
            index.insert(&[0x10, 0x01], 1);
            assert_eq!(index.spilled_count(), 0);
            index.insert(&[0x10, 0x02], 2); // second entry crosses the threshold -> spills
            assert_eq!(index.spilled_count(), 1);
            index.insert(&[0x10, 0x03], 3); // routed straight into the spilled map
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.keys(), 3);
            assert_eq!(index.items(), 3);

            // Values are served correctly from the spilled representation, newest-first.
            assert_eq!(
                index.get(&[0x10, 0x01]).copied().collect::<Vec<_>>(),
                vec![1]
            );
            index.insert(&[0x10, 0x02], 22);
            assert_eq!(
                index.get(&[0x10, 0x02]).copied().collect::<Vec<_>>(),
                vec![22, 2]
            );
            assert_eq!(index.items(), 4);

            // A different prefix lands in its own (still inline) partition.
            index.insert(&[0x20, 0x05], 5);
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(
                index.get(&[0x20, 0x05]).copied().collect::<Vec<_>>(),
                vec![5]
            );
        });
    }

    #[test_traced]
    fn test_spill_nav() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            // Partition 0x10: keys 0x01, 0x02 -> spills. Partition 0x20: key 0x05 -> inline.
            // Partition 0x30: keys 0x07, 0x08 -> spills. Nav must cross spilled<->inline boundaries.
            index.insert(&[0x10, 0x01], 1);
            index.insert(&[0x10, 0x02], 2);
            index.insert(&[0x20, 0x05], 5);
            index.insert(&[0x30, 0x07], 7);
            index.insert(&[0x30, 0x08], 8);
            assert_eq!(index.spilled_count(), 2); // 0x10 and 0x30; 0x20 stays inline

            assert_eq!(index.first_translated_key().unwrap().next(), Some(&1));
            assert_eq!(index.last_translated_key().unwrap().next(), Some(&8));

            // Within a spilled partition.
            let (mut it, wrapped) = index.next_translated_key(&[0x10, 0x01]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&2));
            // Spilled -> inline boundary.
            let (mut it, wrapped) = index.next_translated_key(&[0x10, 0x02]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&5));
            // Inline -> spilled boundary.
            let (mut it, wrapped) = index.next_translated_key(&[0x20, 0x05]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&7));
            // Spilled -> inline boundary, backwards.
            let (mut it, wrapped) = index.prev_translated_key(&[0x30, 0x07]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&5));
            // Inline -> spilled boundary, backwards.
            let (mut it, wrapped) = index.prev_translated_key(&[0x20, 0x05]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&2));
            // Wrap-around from the global last key.
            let (mut it, wrapped) = index.next_translated_key(&[0x30, 0x08]).unwrap();
            assert!(wrapped);
            assert_eq!(it.next(), Some(&1));
        });
    }

    #[test_traced]
    fn test_spill_despill_on_full_drain() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            index.insert(&[0x10, 0x01], 1);
            index.insert(&[0x10, 0x02], 2); // spills
            assert_eq!(index.spilled_count(), 1);

            index.remove(&[0x10, 0x01]);
            assert_eq!(index.spilled_count(), 1); // 0x02 still present
            index.remove(&[0x10, 0x02]);
            assert_eq!(index.spilled_count(), 0); // last key removed -> de-spilled
            assert_eq!(index.keys(), 0);

            // The partition reverts to an inline sorted array.
            index.insert(&[0x10, 0x09], 9);
            assert_eq!(index.spilled_count(), 0);
            assert_eq!(
                index.get(&[0x10, 0x09]).copied().collect::<Vec<_>>(),
                vec![9]
            );
        });
    }

    #[test_traced]
    fn test_spill_full_lifecycle() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);

            // Empty.
            assert_eq!(index.spilled_count(), 0);
            assert_eq!(index.keys(), 0);
            assert_eq!(index.items(), 0);

            // Empty -> inline: one entry stays below the threshold (2).
            index.insert(&[0x10, 0x01], 1);
            assert_eq!(index.spilled_count(), 0);

            // Inline -> spilled: a second distinct key crosses the threshold.
            index.insert(&[0x10, 0x02], 2);
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.keys(), 2);
            assert_eq!(index.items(), 2);

            // Spilled -> empty, draining both keys through a SpilledCursor (the cursor de-spill
            // path); the partition reverts only once its last key is gone.
            {
                let mut cursor = index.get_mut(&[0x10, 0x01]).unwrap();
                assert_eq!(cursor.next().copied(), Some(1));
                cursor.delete();
            }
            assert_eq!(index.spilled_count(), 1); // 0x02 still present
            {
                let mut cursor = index.get_mut(&[0x10, 0x02]).unwrap();
                assert_eq!(cursor.next().copied(), Some(2));
                cursor.delete();
            }
            assert_eq!(index.spilled_count(), 0); // de-spilled back to empty
            assert_eq!(index.keys(), 0);
            assert_eq!(index.items(), 0);

            // Empty -> inline -> spilled a second time: a de-spilled partition is fully reusable.
            index.insert(&[0x10, 0x03], 3);
            assert_eq!(index.spilled_count(), 0);
            index.insert(&[0x10, 0x04], 4);
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(
                index.get(&[0x10, 0x03]).copied().collect::<Vec<_>>(),
                vec![3]
            );
            assert_eq!(
                index.get(&[0x10, 0x04]).copied().collect::<Vec<_>>(),
                vec![4]
            );

            // Spilled -> empty again, this time via `remove` (the other de-spill path).
            index.remove(&[0x10, 0x03]);
            assert_eq!(index.spilled_count(), 1); // 0x04 still present
            index.remove(&[0x10, 0x04]);
            assert_eq!(index.spilled_count(), 0);
            assert_eq!(index.keys(), 0);
            assert_eq!(index.items(), 0);

            // Every removed value was counted once: 2 via cursor delete + 2 via remove.
            assert_eq!(index.pruned(), 4);
        });
    }

    #[test_traced]
    fn test_spill_get_mut_or_insert() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            index.insert(&[0x10, 0x01], 1);
            index.insert(&[0x10, 0x02], 2); // second distinct key crosses the threshold -> spills
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.keys(), 2);
            assert_eq!(index.items(), 2);

            // Existing key in a spilled partition: returns a cursor over its values; the passed
            // value is not inserted.
            {
                let mut cursor = index.get_mut_or_insert(&[0x10, 0x01], 99).unwrap();
                assert_eq!(cursor.next().copied(), Some(1));
                assert!(cursor.next().is_none());
            }
            assert_eq!(index.keys(), 2);
            assert_eq!(index.items(), 2);
            assert_eq!(
                index.get(&[0x10, 0x01]).copied().collect::<Vec<_>>(),
                vec![1]
            );

            // Absent key in a spilled partition: inserts it as a new key and returns None (the
            // partition stays spilled).
            assert!(index.get_mut_or_insert(&[0x10, 0x03], 3).is_none());
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.keys(), 3);
            assert_eq!(index.items(), 3);
            assert_eq!(
                index.get(&[0x10, 0x03]).copied().collect::<Vec<_>>(),
                vec![3]
            );
        });
    }

    #[test_traced]
    #[should_panic(expected = "must call Cursor::next()")]
    fn test_spill_cursor_delete_before_next_panics() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            index.insert(&[0x10, 0x01], 1);
            index.insert(&[0x10, 0x02], 2); // spills
            let mut cursor = index.get_mut(&[0x10, 0x01]).unwrap(); // SpilledCursor
            cursor.delete();
        });
    }

    #[test_traced]
    fn test_soa_basic() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            assert_eq!(index.keys(), 0);

            let key = b"duplicate".as_slice();
            index.insert(key, 1);
            index.insert(key, 2);
            index.insert(key, 3);
            assert_eq!(index.keys(), 1);
            assert_eq!(index.items(), 3);
            assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![3, 2, 1]);

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert_eq!(*cursor.next().unwrap(), 3);
                assert_eq!(*cursor.next().unwrap(), 2);
                assert_eq!(*cursor.next().unwrap(), 1);
                assert!(cursor.next().is_none());
            }

            index.insert(key, 3);
            index.insert(key, 4);
            index.retain(key, |i| *i != 3);
            assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![4, 2, 1]);

            index.retain(key, |_| false);
            assert_eq!(
                index.get(key).copied().collect::<Vec<_>>(),
                Vec::<u64>::new()
            );
            assert_eq!(index.keys(), 0);
            assert!(index.get_mut(key).is_none());

            // No-op on a missing key.
            index.retain(key, |_| false);
        });
    }

    #[test_traced]
    fn test_soa_cursor_find() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            let key = b"test_key";
            for v in [10u64, 20, 30, 40] {
                index.insert(key, v);
            }

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert!(cursor.find(|&v| v == 30));
                cursor.update(35);
            }
            let values: Vec<u64> = index.get(key).copied().collect();
            assert!(values.contains(&35) && !values.contains(&30));

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert!(!cursor.find(|&v| v == 100));
                assert!(cursor.next().is_none());
            }

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert!(cursor.find(|&v| v == 20));
                cursor.delete();
            }
            let values: Vec<u64> = index.get(key).copied().collect();
            assert!(!values.contains(&20));
            assert_eq!(values.len(), 3);
        });
    }

    #[test_traced]
    fn test_soa_get_many_and_partitions() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            // "ab"/"abX" share a partition+translated key; "zz" is a different partition.
            index.insert(b"ab", 1);
            index.insert(b"ab", 2);
            index.insert(b"abX", 3);
            index.insert(b"zz", 4);

            let keys: Vec<&[u8]> = vec![b"zz", b"missing", b"ab", b"zz"];
            let mut visits: Vec<Vec<u64>> = vec![Vec::new(); keys.len()];
            index.get_many(&keys, |key_idx, value| visits[key_idx].push(*value));
            assert_eq!(visits[0], vec![4]);
            assert!(visits[1].is_empty());
            assert_eq!(visits[2], vec![3, 2, 1]);
            assert_eq!(visits[3], vec![4]);
        });
    }

    #[test_traced]
    fn test_soa_insert_and_retain() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            // Keep both: new value joins as oldest.
            index.insert(b"k", 1u64);
            index.insert_and_retain(b"k", 2, |_| true);
            assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![1, 2]);

            // Drop the new value: no-op.
            index.insert_and_retain(b"k", 9, |v| *v != 9);
            assert_eq!(index.get(b"k").copied().collect::<Vec<_>>(), vec![1, 2]);

            // Drop everything.
            index.insert_and_retain(b"k", 9, |_| false);
            assert!(index.get_mut(b"k").is_none());
            assert_eq!(index.keys(), 0);

            // Vacant key: insert only if retained.
            index.insert_and_retain(b"new", 7, |_| true);
            assert_eq!(index.get(b"new").copied().collect::<Vec<_>>(), vec![7]);
            assert_eq!(index.keys(), 1);
        });
    }

    #[test_traced]
    fn test_soa_remove() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            index.insert(b"k", 1u64);
            index.insert(b"k", 2);
            index.insert(b"other", 3);
            assert_eq!(index.items(), 3);
            assert_eq!(index.keys(), 2);

            index.remove(b"k");
            assert!(index.get_mut(b"k").is_none());
            assert_eq!(index.keys(), 1);
            assert_eq!(index.items(), 1);
            assert_eq!(index.pruned(), 2);
            assert_eq!(index.get(b"other").copied().collect::<Vec<_>>(), vec![3]);

            index.remove(b"missing"); // no-op
            assert_eq!(index.keys(), 1);
        });
    }

    #[test_traced]
    fn test_soa_ordered() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            assert!(index.first_translated_key().is_none());
            assert!(index.last_translated_key().is_none());
            assert!(index.next_translated_key(b"key").is_none());
            assert!(index.prev_translated_key(b"key").is_none());

            // With OneCap + P=1, the full key orders as (prefix byte, first sub-key byte).
            let k1 = &hex!("0x0b02AA"); // -> partition 0b, sub-key 02
            let k2 = &hex!("0x1c04CC"); // -> partition 1c, sub-key 04
            let k2_collides = &hex!("0x1c0411"); // same (1c, 04) as k2
            let k3 = &hex!("0x2d06EE"); // -> partition 2d, sub-key 06
            index.insert(k1, 1);
            index.insert(k2, 21);
            index.insert(k2_collides, 22);
            index.insert(k3, 3);
            assert_eq!(index.keys(), 3);

            assert_eq!(index.first_translated_key().unwrap().next(), Some(&1));
            assert_eq!(index.last_translated_key().unwrap().next(), Some(&3));

            // From before the first key: the first key, not wrapped.
            let (mut it, wrapped) = index.next_translated_key(&[0x00]).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&1));
            assert_eq!(it.next(), None);

            // From k1's bucket: jumps partitions to k2's collision run (newest first).
            let (mut it, wrapped) = index.next_translated_key(&hex!("0x0b02F2")).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&22));
            assert_eq!(it.next(), Some(&21));
            assert_eq!(it.next(), None);

            // From the last key: cycles to the first.
            let (mut it, wrapped) = index.next_translated_key(k3).unwrap();
            assert!(wrapped);
            assert_eq!(it.next(), Some(&1));

            // From the first key going backwards: cycles to the last.
            let (mut it, wrapped) = index.prev_translated_key(k1).unwrap();
            assert!(wrapped);
            assert_eq!(it.next(), Some(&3));

            // Previous bucket below 1d is 1c's collision run.
            let (mut it, wrapped) = index.prev_translated_key(&hex!("0x1d0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&22));
            assert_eq!(it.next(), Some(&21));
            assert_eq!(it.next(), None);
        });
    }

    #[test_traced]
    fn test_soa_ordered_exhaustive_traversal() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);

            // A grid of (prefix, sub-key) keys spanning several partitions, including the edge
            // bytes 0x00/0xFF, each a distinct translated key (OneCap + P=1 orders by
            // (prefix, first sub-key byte)). `keys` is built in ascending order.
            let prefixes = [0x00u8, 0x05, 0xAA, 0xFF];
            let subkeys = [0x00u8, 0x80, 0xFF];
            let mut keys: Vec<[u8; 2]> = Vec::new();
            for &p in &prefixes {
                for &s in &subkeys {
                    keys.push([p, s]);
                }
            }
            let value_of = |k: &[u8; 2]| ((k[0] as u64) << 8) | k[1] as u64;
            let n = keys.len();

            // Insert scrambled to exercise sorted-array maintenance regardless of insertion order.
            let mut scrambled = keys.clone();
            scrambled.reverse();
            scrambled.rotate_left(5);
            for k in &scrambled {
                index.insert(k, value_of(k));
            }
            assert_eq!(index.keys(), n);

            assert_eq!(
                index.first_translated_key().unwrap().next(),
                Some(&value_of(&keys[0]))
            );
            assert_eq!(
                index.last_translated_key().unwrap().next(),
                Some(&value_of(&keys[n - 1]))
            );

            // For every key, `next` is its successor and `prev` its predecessor, wrapping at the
            // ends. This walks run_starting_at / run_ending_at across every partition boundary.
            for i in 0..n {
                let next = value_of(&keys[(i + 1) % n]);
                let (mut it, wrapped) = index.next_translated_key(&keys[i]).unwrap();
                assert_eq!(wrapped, i + 1 == n, "next wrap at index {i}");
                assert_eq!(it.next(), Some(&next), "next at {i}");
                assert_eq!(it.next(), None);

                let prev = value_of(&keys[(i + n - 1) % n]);
                let (mut it, wrapped) = index.prev_translated_key(&keys[i]).unwrap();
                assert_eq!(wrapped, i == 0, "prev wrap at index {i}");
                assert_eq!(it.next(), Some(&prev), "prev at {i}");
                assert_eq!(it.next(), None);
            }
        });
    }
}
