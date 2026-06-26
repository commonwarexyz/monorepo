//! A partitioned index that stores each partition as sorted struct-of-arrays (see the
//! `self::partition` module).
//!
//! The first `P` bytes of the (untranslated) key select a partition; the translator maps the
//! remaining bytes to the partition-local key. Because the partitions are ordered by prefix and each
//! partition's entries are sorted by translated key, this index is inherently ordered. It trades
//! lookup/insert speed for memory density at scale; the unordered variant ([`super::unordered`])
//! uses hash sub-indices instead and is faster when ordering is not required.
//!
//! # Spilling over-full partitions
//!
//! Each sorted-array insert is an O(occupancy) memmove, so a partition that grows large makes
//! inserts expensive. When a partition's array reaches `SPILL_THRESHOLD` entries it converts to a
//! `BTreeMap` (the `spilled` field) -- a supported alternate representation whose insert, lookup,
//! and traversal are O(log occupancy). A partition reaches that size two ways:
//!
//! - *Adversarial grinding.* An order-preserving translator cannot randomize keys (that would break
//!   the ordering), so an attacker can grind the key suffix to flood one partition with distinct
//!   translated keys. Spilling bounds flooding M keys from O(M^2) to O(M log M).
//! - *Honest high-occupancy growth at low `P`.* With few partitions a uniform workload fills them: a
//!   `P=1` index (256 partitions) is guaranteed to spill once it holds more than 256*511 = 130,816
//!   entries, `P=2` past ~33M, while `P=3`'s 16.8M partitions push this past ~8.5B (so P=3 is
//!   effectively unreachable under honest load).
//!
//! A partition also fills when a single key collects many values -- keys that collide on the full
//! prefix, or repeated inserts of one key. The spill covers this too: it triggers on the total
//! value count, so these inserts stay as cheap as any other. What it cannot bound is how many
//! values one key holds, and a lookup must scan all of them -- a key with `M` values costs O(M) per
//! lookup. Every index that resolves collisions pays this (the flat `crate::index::ordered::Index`
//! included); `M` stays near 1 only when the indexed `P + N`-byte prefix is well-distributed, so
//! use enough prefix bytes and high-entropy keys.

mod cursor;
mod partition;

pub use self::cursor::Cursor;
use self::partition::PartitionState;
use crate::{
    index::{
        partitioned::partition_index_and_sub_key, Cursor as CursorTrait, Factory, Ordered,
        OrderedReadable, Readable, Snapshottable, Unordered,
    },
    translator::Translator,
};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
    Metrics,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// Sorted-array length at which a partition converts to a `BTreeMap`, bounding the O(occupancy)
/// insert memmove to O(log occupancy). A partition reaches this from adversarial distinct-key
/// grinding or from honest growth once partitions fill: a spill is guaranteed past 256*511 = 130,816
/// entries at `P=1`, past ~33M at `P=2`, and only past ~8.5B at `P=3` (so P=3 effectively never
/// spills under honest load). See the module docs.
const SPILL_THRESHOLD: usize = 512;
const MAX_SPARSE_DEPTH: u16 = 8;

/// A partitioned index storing each partition as sorted struct-of-arrays, spilling an over-full
/// partition to a `BTreeMap` to bound its O(occupancy) insert cost (see `spilled` and the module
/// docs).
pub struct Index<T: Translator, V: Send + Sync, const P: usize> {
    /// Translates the prefix-stripped key bytes into a partition-local key.
    translator: T,

    /// Compacted base visible to snapshots.
    base: Arc<Base<T::Key, V>>,

    /// Immutable overlay chain visible to snapshots.
    sealed: Arc<Epoch<T::Key, V>>,

    /// Writer-owned changed runs since `sealed`.
    head: Overlay<T::Key, V>,

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

/// Read-only snapshot of a partitioned ordered index.
#[derive(Clone)]
pub struct Snapshot<T: Translator, V: Send + Sync, const P: usize> {
    translator: T,
    base: Arc<Base<T::Key, V>>,
    sealed: Arc<Epoch<T::Key, V>>,
    count: usize,
}

struct Base<K, V> {
    partitions: Box<[PartitionState<K, V>]>,
}

struct Overlay<K, V> {
    partitions: HashMap<usize, BTreeMap<K, Vec<V>>>,
}

impl<K, V> Default for Overlay<K, V> {
    fn default() -> Self {
        Self {
            partitions: HashMap::new(),
        }
    }
}

struct Epoch<K, V> {
    parent: Option<Arc<Self>>,
    overlay: Overlay<K, V>,
    depth: u16,
    changed_runs: usize,
}

impl<K, V> Default for Epoch<K, V> {
    fn default() -> Self {
        Self {
            parent: None,
            overlay: Overlay::default(),
            depth: 0,
            changed_runs: 0,
        }
    }
}

impl<K: Ord + Copy, V> Overlay<K, V> {
    fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }

    fn changed_runs(&self) -> usize {
        self.partitions.values().map(BTreeMap::len).sum()
    }

    fn run(&self, i: usize, key: &K) -> Option<&[V]> {
        self.partitions
            .get(&i)
            .and_then(|partition| partition.get(key))
            .map(Vec::as_slice)
    }

    fn next_key(&self, i: usize, after: Option<K>) -> Option<K> {
        let partition = self.partitions.get(&i)?;
        after.map_or_else(
            || partition.first_key_value().map(|(key, _)| *key),
            |key| {
                partition
                    .range((std::ops::Bound::Excluded(key), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(key, _)| *key)
            },
        )
    }

    fn prev_key(&self, i: usize, before: Option<K>) -> Option<K> {
        let partition = self.partitions.get(&i)?;
        before.map_or_else(
            || partition.last_key_value().map(|(key, _)| *key),
            |key| {
                partition
                    .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(key)))
                    .next_back()
                    .map(|(key, _)| *key)
            },
        )
    }

    fn apply_to_partition(&self, i: usize, runs: &mut BTreeMap<K, Vec<V>>)
    where
        V: Clone,
    {
        let Some(partition) = self.partitions.get(&i) else {
            return;
        };
        for (key, values) in partition {
            // Empty runs are tombstones that mask older/base values.
            if values.is_empty() {
                runs.remove(key);
            } else {
                runs.insert(*key, values.clone());
            }
        }
    }
}

impl<K: Ord + Copy, V> Epoch<K, V> {
    fn run(&self, i: usize, key: &K) -> Option<&[V]> {
        self.overlay
            .run(i, key)
            .or_else(|| self.parent.as_deref().and_then(|parent| parent.run(i, key)))
    }

    fn parent_changed_runs(parent: &Option<Arc<Self>>) -> usize {
        parent.as_ref().map_or(0, |parent| parent.changed_runs)
    }

    fn next_key(&self, i: usize, after: Option<K>) -> Option<K> {
        let parent = self
            .parent
            .as_deref()
            .and_then(|parent| parent.next_key(i, after));
        next_candidate(after, [self.overlay.next_key(i, after), parent])
    }

    fn prev_key(&self, i: usize, before: Option<K>) -> Option<K> {
        let parent = self
            .parent
            .as_deref()
            .and_then(|parent| parent.prev_key(i, before));
        prev_candidate(before, [self.overlay.prev_key(i, before), parent])
    }

    fn apply_to_partition(&self, i: usize, runs: &mut BTreeMap<K, Vec<V>>)
    where
        V: Clone,
    {
        // Apply oldest to newest so later overlays win.
        if let Some(parent) = &self.parent {
            parent.apply_to_partition(i, runs);
        }
        self.overlay.apply_to_partition(i, runs);
    }
}

fn base_next_key<K: Ord + Copy, V>(
    partition: &PartitionState<K, V>,
    after: Option<K>,
) -> Option<K> {
    after.map_or_else(
        || partition.first_key(),
        |key| partition.next_key_after(&key),
    )
}

fn base_prev_key<K: Ord + Copy, V>(
    partition: &PartitionState<K, V>,
    before: Option<K>,
) -> Option<K> {
    before.map_or_else(
        || partition.last_key(),
        |key| partition.prev_key_before(&key),
    )
}

fn next_candidate<K: Ord + Copy>(
    after: Option<K>,
    candidates: impl IntoIterator<Item = Option<K>>,
) -> Option<K> {
    candidates
        .into_iter()
        .flatten()
        .filter(|candidate| after.is_none_or(|after| *candidate > after))
        .min()
}

fn prev_candidate<K: Ord + Copy>(
    before: Option<K>,
    candidates: impl IntoIterator<Item = Option<K>>,
) -> Option<K> {
    candidates
        .into_iter()
        .flatten()
        .filter(|candidate| before.is_none_or(|before| *candidate < before))
        .max()
}

impl<T: Translator, V: Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given metrics context and translator.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        const {
            assert!(P > 0 && P <= 3, "P must be in 1..=3");
        }
        let count = 1usize << (P * 8);
        let partitions = (0..count)
            .map(|_| PartitionState::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            translator,
            base: Arc::new(Base { partitions }),
            sealed: Arc::new(Epoch::default()),
            head: Overlay::default(),
            threshold: SPILL_THRESHOLD,
            keys: ctx.gauge("keys", "Number of translated keys in the index"),
            items: ctx.gauge("items", "Number of items in the index"),
            pruned: ctx.counter("pruned", "Number of items pruned"),
        }
    }

    /// Merge base and overlays for one partition.
    fn compact_base_partition(&self, i: usize) -> PartitionState<T::Key, V>
    where
        V: Clone,
    {
        let mut runs = self.base.partitions[i]
            .runs()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        self.sealed.apply_to_partition(i, &mut runs);
        self.head.apply_to_partition(i, &mut runs);
        PartitionState::from_runs(runs, self.threshold)
    }

    const fn count(&self) -> usize {
        1usize << (P * 8)
    }

    fn run(&self, i: usize, k: &T::Key) -> &[V] {
        self.head
            .run(i, k)
            .or_else(|| self.sealed.run(i, k))
            .unwrap_or_else(|| self.base.partitions[i].values(k))
    }

    /// Materialize the visible run into the live head overlay.
    fn ensure_run(&mut self, i: usize, k: T::Key) -> &mut Vec<V>
    where
        V: Clone,
    {
        if self
            .head
            .partitions
            .get(&i)
            .is_some_and(|partition| partition.contains_key(&k))
        {
            return self
                .head
                .partitions
                .get_mut(&i)
                .unwrap()
                .get_mut(&k)
                .unwrap();
        }

        // First mutation after a snapshot clones the visible run.
        let run = self
            .sealed
            .run(i, &k)
            .unwrap_or_else(|| self.base.partitions[i].values(&k))
            .to_vec();
        self.head
            .partitions
            .entry(i)
            .or_default()
            .entry(k)
            .or_insert(run)
    }

    /// Smallest visible key in partition `i` strictly greater than `after`.
    fn next_key_in_partition(&self, i: usize, after: Option<T::Key>) -> Option<T::Key> {
        next_candidate(
            after,
            [
                self.head.next_key(i, after),
                self.sealed.next_key(i, after),
                base_next_key(&self.base.partitions[i], after),
            ],
        )
    }

    /// Largest visible key in partition `i` strictly less than `before`.
    fn prev_key_in_partition(&self, i: usize, before: Option<T::Key>) -> Option<T::Key> {
        prev_candidate(
            before,
            [
                self.head.prev_key(i, before),
                self.sealed.prev_key(i, before),
                base_prev_key(&self.base.partitions[i], before),
            ],
        )
    }

    /// Returns whether sealed overlays should be merged into the base soon.
    pub fn needs_compaction(&self) -> bool {
        self.sealed.depth >= MAX_SPARSE_DEPTH || self.sealed.changed_runs >= self.count()
    }
}

impl<T: Translator, V: Clone + Send + Sync, const P: usize> Index<T, V, P> {
    /// Merge sealed overlays and the live head into a new base.
    pub fn compact(&mut self) {
        let count = self.count();
        self.base = Arc::new(Base {
            partitions: (0..count)
                .map(|i| self.compact_base_partition(i))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        });
        self.sealed = Arc::new(Epoch::default());
        self.head = Overlay::default();
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Snapshot<T, V, P> {
    fn run(&self, i: usize, k: &T::Key) -> &[V] {
        self.sealed
            .run(i, k)
            .unwrap_or_else(|| self.base.partitions[i].values(k))
    }

    fn next_key_in_partition(&self, i: usize, after: Option<T::Key>) -> Option<T::Key> {
        next_candidate(
            after,
            [
                self.sealed.next_key(i, after),
                base_next_key(&self.base.partitions[i], after),
            ],
        )
    }

    fn prev_key_in_partition(&self, i: usize, before: Option<T::Key>) -> Option<T::Key> {
        prev_candidate(
            before,
            [
                self.sealed.prev_key(i, before),
                base_prev_key(&self.base.partitions[i], before),
            ],
        )
    }
}

impl<T: Translator, V: Clone + Send + Sync, const P: usize> Factory<T> for Index<T, V, P> {
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Clone + Send + Sync, const P: usize> Unordered for Index<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, V>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + Send + 'a
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        self.run(i, &k).iter()
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
            for value in self.run(partition, &translated) {
                visit(key_idx, value);
            }
        }
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        if self.run(i, &k).is_empty() {
            return None;
        }
        let keys = self.keys.clone();
        let items = self.items.clone();
        let pruned = self.pruned.clone();
        Some(Cursor::new(self.ensure_run(i, k), keys, items, pruned))
    }

    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        if !self.run(i, &k).is_empty() {
            let keys = self.keys.clone();
            let items = self.items.clone();
            let pruned = self.pruned.clone();
            return Some(Cursor::new(self.ensure_run(i, k), keys, items, pruned));
        }
        self.ensure_run(i, k).insert(0, value);
        self.keys.inc();
        self.items.inc();
        None
    }

    fn insert(&mut self, key: &[u8], value: Self::Value) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        let run = self.ensure_run(i, k);
        let new_key = run.is_empty();
        run.insert(0, value);
        self.items.inc();
        if new_key {
            self.keys.inc();
        }
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
        if self.run(i, &k).is_empty() {
            return;
        }
        let run = self.ensure_run(i, k);
        let n = run.len();
        run.clear();
        self.keys.dec();
        self.items.dec_by(n as i64);
        self.pruned.inc_by(n as u64);
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

impl<T: Translator, V: Send + Sync, const P: usize> Readable for Snapshot<T, V, P> {
    type Value = V;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a V> + Send + 'a
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        self.run(i, &k).iter()
    }

    fn get_many<'a, K: AsRef<[u8]>>(&'a self, keys: &[K], mut visit: impl FnMut(usize, &'a V))
    where
        V: 'a,
    {
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
            for value in self.run(partition, &translated) {
                visit(key_idx, value);
            }
        }
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> OrderedReadable for Snapshot<T, V, P> {
    fn prev_translated_key<'a>(
        &'a self,
        key: &[u8],
    ) -> Option<(impl Iterator<Item = &'a V> + Send + 'a, bool)>
    where
        V: 'a,
    {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        let mut before = Some(k);
        while let Some(candidate) = self.prev_key_in_partition(i, before) {
            let vals = self.run(i, &candidate);
            if !vals.is_empty() {
                return Some((vals.iter(), false));
            }
            before = Some(candidate);
        }
        for p in (0..i).rev() {
            let mut before = None;
            while let Some(candidate) = self.prev_key_in_partition(p, before) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), false));
                }
                before = Some(candidate);
            }
        }
        for p in (0..self.count).rev() {
            let mut before = None;
            while let Some(candidate) = self.prev_key_in_partition(p, before) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), true));
                }
                before = Some(candidate);
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
        let mut after = Some(k);
        while let Some(candidate) = self.next_key_in_partition(i, after) {
            let vals = self.run(i, &candidate);
            if !vals.is_empty() {
                return Some((vals.iter(), false));
            }
            after = Some(candidate);
        }
        for p in i + 1..self.count {
            let mut after = None;
            while let Some(candidate) = self.next_key_in_partition(p, after) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), false));
                }
                after = Some(candidate);
            }
        }
        for p in 0..self.count {
            let mut after = None;
            while let Some(candidate) = self.next_key_in_partition(p, after) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), true));
                }
                after = Some(candidate);
            }
        }
        None
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        for p in 0..self.count {
            let mut after = None;
            while let Some(candidate) = self.next_key_in_partition(p, after) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some(vals.iter());
                }
                after = Some(candidate);
            }
        }
        None
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        for p in (0..self.count).rev() {
            let mut before = None;
            while let Some(candidate) = self.prev_key_in_partition(p, before) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some(vals.iter());
                }
                before = Some(candidate);
            }
        }
        None
    }
}

impl<T: Translator, V: Clone + Send + Sync + 'static, const P: usize> Snapshottable
    for Index<T, V, P>
{
    type Value = V;
    type Snapshot = Snapshot<T, V, P>;

    fn snapshot(&mut self) -> Self::Snapshot {
        let count = self.count();
        if !self.head.is_empty() {
            // Avoid linking the empty root epoch.
            let parent = (self.sealed.depth > 0).then(|| Arc::clone(&self.sealed));
            let overlay = std::mem::take(&mut self.head);
            self.sealed = Arc::new(Epoch {
                depth: self.sealed.depth + 1,
                changed_runs: Epoch::parent_changed_runs(&parent) + overlay.changed_runs(),
                parent,
                overlay,
            });
        }
        Snapshot {
            translator: self.translator.clone(),
            base: Arc::clone(&self.base),
            sealed: Arc::clone(&self.sealed),
            count,
        }
    }
}

impl<T: Translator, V: Clone + Send + Sync, const P: usize> Ordered for Index<T, V, P> {
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
        let mut before = Some(k);
        while let Some(candidate) = self.prev_key_in_partition(i, before) {
            let vals = self.run(i, &candidate);
            if !vals.is_empty() {
                return Some((vals.iter(), false));
            }
            before = Some(candidate);
        }
        for p in (0..i).rev() {
            let mut before = None;
            while let Some(candidate) = self.prev_key_in_partition(p, before) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), false));
                }
                before = Some(candidate);
            }
        }
        for p in (0..self.count()).rev() {
            let mut before = None;
            while let Some(candidate) = self.prev_key_in_partition(p, before) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), true));
                }
                before = Some(candidate);
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
        let mut after = Some(k);
        while let Some(candidate) = self.next_key_in_partition(i, after) {
            let vals = self.run(i, &candidate);
            if !vals.is_empty() {
                return Some((vals.iter(), false));
            }
            after = Some(candidate);
        }
        for p in i + 1..self.count() {
            let mut after = None;
            while let Some(candidate) = self.next_key_in_partition(p, after) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), false));
                }
                after = Some(candidate);
            }
        }
        for p in 0..self.count() {
            let mut after = None;
            while let Some(candidate) = self.next_key_in_partition(p, after) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some((vals.iter(), true));
                }
                after = Some(candidate);
            }
        }
        None
    }

    fn first_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        for p in 0..self.count() {
            let mut after = None;
            while let Some(candidate) = self.next_key_in_partition(p, after) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some(vals.iter());
                }
                after = Some(candidate);
            }
        }
        None
    }

    fn last_translated_key<'a>(&'a self) -> Option<impl Iterator<Item = &'a V> + Send + 'a>
    where
        V: 'a,
    {
        for p in (0..self.count()).rev() {
            let mut before = None;
            while let Some(candidate) = self.prev_key_in_partition(p, before) {
                let vals = self.run(p, &candidate);
                if !vals.is_empty() {
                    return Some(vals.iter());
                }
                before = Some(candidate);
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

    impl<T: Translator, V: Clone + Send + Sync, const P: usize> Index<T, V, P> {
        /// Create a new [Index] with an explicit spill threshold so tests can exercise spilling without
        /// inserting [SPILL_THRESHOLD] keys.
        pub(crate) fn with_threshold(ctx: impl Metrics, translator: T, threshold: usize) -> Self {
            let mut index = Self::new(ctx, translator);
            index.threshold = threshold;
            index
        }

        /// Number of partitions that compact into the spilled representation.
        pub(crate) fn spilled_count(&self) -> usize {
            (0..self.count())
                .filter(|&i| self.compact_base_partition(i).is_spilled())
                .count()
        }

        pub(crate) fn epoch_depth(&self) -> u16 {
            self.sealed.depth
        }

        pub(crate) fn changed_runs(&self) -> usize {
            self.sealed.changed_runs
        }

        pub(crate) fn head_changed_runs(&self) -> usize {
            self.head.changed_runs()
        }
    }

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
            assert_eq!(index.spilled_count(), 0); // 0x02 compacts to inline in the live overlay
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

            // Spilled -> empty, draining both keys through materialized overlay runs.
            {
                let mut cursor = index.get_mut(&[0x10, 0x01]).unwrap();
                assert_eq!(cursor.next().copied(), Some(1));
                cursor.delete();
            }
            assert_eq!(index.spilled_count(), 0); // 0x02 compacts to inline in the live overlay
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

            // Spilled -> empty again, this time via `remove`.
            index.remove(&[0x10, 0x03]);
            assert_eq!(index.spilled_count(), 0); // 0x04 compacts to inline in the live overlay
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

            // Existing key in a spilled base partition: returns a cursor over its materialized run;
            // the passed value is not inserted.
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
            let mut cursor = index.get_mut(&[0x10, 0x01]).unwrap();
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
