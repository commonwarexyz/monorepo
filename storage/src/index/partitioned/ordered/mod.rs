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
//! value count, so a single over-full key still converts the partition and keeps inserts for the
//! partition's other keys cheap. Values append to the end of a key's run. In the single-key case
//! this makes inline inserts append-only, and after spilling they remain append-only in the run's
//! `Vec`. Other inline inserts may shift later key runs, but the spill threshold bounds this cost.
//! What spilling cannot bound is how many values one key holds, and a lookup must scan all of
//! them: a key with `M` values costs O(M) per lookup. Every index that resolves collisions pays
//! this scan (the flat `crate::index::ordered::Index` included); `M` stays near 1 only when the
//! indexed `P + N`-byte prefix is well-distributed, so use enough prefix bytes and high-entropy
//! keys.
//!
//! A caller-held cursor can temporarily grow an inline partition to or past the spill threshold.
//! The next index mutation of that partition spills it before access. `insert_and_retain` performs
//! the check after releasing its internal cursor.

mod cursor;
mod partition;

pub use self::cursor::Cursor;
use self::partition::Partition;
#[commonware_macros::stability(ALPHA)]
use crate::index::partitioned::{PartitionRange, Partitioned};
use crate::{
    index::{
        Cursor as CursorTrait, Factory, Ordered, Unordered,
        partitioned::partition_index_and_sub_key,
    },
    translator::Translator,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};
use std::{
    collections::{BTreeMap, HashMap, btree_map, hash_map},
    ops::Bound,
};

/// Sorted-array length at which a partition converts to a `BTreeMap`, bounding the O(occupancy)
/// insert memmove to O(log occupancy). A partition reaches this from adversarial distinct-key
/// grinding or from honest growth once partitions fill: a spill is guaranteed past 256*511 = 130,816
/// entries at `P=1`, past ~33M at `P=2`, and only past ~8.5B at `P=3` (so P=3 effectively never
/// spills under honest load). See the module docs.
const SPILL_THRESHOLD: usize = 512;

/// A partitioned index storing each partition as sorted struct-of-arrays, spilling an over-full
/// partition to a `BTreeMap` to bound its O(occupancy) insert cost (see `spilled` and the module
/// docs).
pub struct Index<T: Translator, V: Send + Sync, const P: usize> {
    /// Translates the prefix-stripped key bytes into a partition-local key.
    translator: T,

    /// The partitions, indexed by a key's partition index. A full index holds all `2^(8*P)`, while
    /// the index inside a [RangeIndex] build worker holds only the worker's range (addressed by
    /// local slot). Each stores its translated keys and values as sorted arrays (the inline
    /// representation), though an emptied partition may instead have spilled (see `spilled`).
    partitions: Box<[Partition<T::Key, V>]>,

    /// Partitions that have spilled out of their sorted arrays (reached `SPILL_THRESHOLD` entries),
    /// keyed by partition index; each maps translated keys to their value runs. Empty until a
    /// partition fills, whether from honest growth at low `P` or adversarial grinding.
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

    /// Metric: cumulative partitions spilled to the side-table. Emptied partitions that de-spill
    /// (rare) are not subtracted. Build workers hold clones of the handle, so their spills count
    /// here live.
    spills: Counter,
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
            spills: ctx.counter("spills", "Number of partitions spilled to the side-table"),
        }
    }

    /// Create a new [Index] with an explicit spill threshold so tests can exercise spilling without
    /// inserting [SPILL_THRESHOLD] keys. The threshold must be at least 1: `maybe_spill` relies on
    /// an already-spilled partition's empty inline array staying strictly below the threshold.
    #[cfg(test)]
    pub(crate) fn with_threshold(ctx: impl Metrics, translator: T, threshold: usize) -> Self {
        assert!(threshold > 0, "spill threshold must be at least 1");
        let mut index = Self::new(ctx, translator);
        index.threshold = threshold;
        index
    }

    /// Visit every value held across all partitions (inline and spilled), in unspecified order.
    #[commonware_macros::stability(ALPHA)]
    fn for_each_value(&self, mut f: impl FnMut(&V)) {
        for (p, partition) in self.partitions.iter().enumerate() {
            for v in partition.values_iter() {
                f(v);
            }
            if let Some(inner) = self.spilled_partition(p) {
                for vals in inner.values() {
                    for v in vals {
                        f(v);
                    }
                }
            }
        }
    }

    /// Spill partition `i` to the side-table if its sorted array has reached the threshold.
    fn maybe_spill(&mut self, i: usize) {
        self.parts().maybe_spill(i);
    }

    /// A full-range [ShardParts] view over this index's mutable state.
    fn parts(&mut self) -> ShardParts<'_, T, V> {
        ShardParts {
            base: 0,
            partitions: &mut self.partitions,
            spilled: &mut self.spilled,
            translator: &self.translator,
            threshold: self.threshold,
            keys: &self.keys,
            items: &self.items,
            pruned: &self.pruned,
            spills: &self.spills,
        }
    }

    /// The `BTreeMap` of spilled partition `i`, or `None` if `i` has not spilled. The empty-map
    /// check skips hashing `i` in the common case where no partition has ever spilled.
    fn spilled_partition(&self, i: usize) -> Option<&BTreeMap<T::Key, Vec<V>>> {
        if self.spilled.is_empty() {
            return None;
        }
        self.spilled.get(&i)
    }

    /// The values for translated key `k` in partition `i` (empty if absent), from whichever
    /// representation the partition currently uses.
    fn partition_values(&self, i: usize, k: &T::Key) -> &[V] {
        if !self.partitions[i].is_empty() {
            return self.partitions[i].values(k);
        }
        self.spilled_partition(i)
            .and_then(|inner| inner.get(k))
            .map_or(&[], Vec::as_slice)
    }

    /// Values of the smallest key in partition `i` (None if the partition is empty).
    fn partition_first(&self, i: usize) -> Option<&[V]> {
        self.partitions[i].first_values().or_else(|| {
            self.spilled_partition(i)?
                .first_key_value()
                .map(|(_, v)| v.as_slice())
        })
    }

    /// Values of the largest key in partition `i` (None if the partition is empty).
    fn partition_last(&self, i: usize) -> Option<&[V]> {
        self.partitions[i].last_values().or_else(|| {
            self.spilled_partition(i)?
                .last_key_value()
                .map(|(_, v)| v.as_slice())
        })
    }

    /// Whether the index currently holds no keys.
    fn is_empty(&self) -> bool {
        self.keys.get() == 0
    }

    /// Values of the smallest key strictly greater than `k` in partition `i`.
    fn partition_next_after(&self, i: usize, k: &T::Key) -> Option<&[V]> {
        self.partitions[i].next_values_after(k).or_else(|| {
            self.spilled_partition(i)?
                .range((Bound::Excluded(*k), Bound::Unbounded))
                .next()
                .map(|(_, v)| v.as_slice())
        })
    }

    /// Values of the largest key strictly less than `k` in partition `i`.
    fn partition_prev_before(&self, i: usize, k: &T::Key) -> Option<&[V]> {
        self.partitions[i].prev_values_before(k).or_else(|| {
            self.spilled_partition(i)?
                .range((Bound::Unbounded, Bound::Excluded(*k)))
                .next_back()
                .map(|(_, v)| v.as_slice())
        })
    }

    /// Number of partitions currently spilled to the side-table.
    #[cfg(test)]
    pub(crate) fn spilled_count(&self) -> usize {
        self.spilled.len()
    }

    /// Cumulative value of the `spills` metric.
    #[cfg(test)]
    fn spills(&self) -> usize {
        self.spills.get() as usize
    }

    /// Mutable cursor over the values of sub-key `sub` in the partition at local slot `i`, if the
    /// key exists (see [Unordered::get_mut]).
    fn get_mut_slot(&mut self, i: usize, sub: &[u8]) -> Option<Cursor<'_, T::Key, V>> {
        self.parts().get_mut(i, sub)
    }

    /// Mutable cursor over the values of sub-key `sub` in the partition at local slot `i` if the
    /// key exists, otherwise inserts `value` for it and returns `None` (see
    /// [Unordered::get_mut_or_insert]).
    fn get_mut_or_insert_slot(
        &mut self,
        i: usize,
        sub: &[u8],
        value: V,
    ) -> Option<Cursor<'_, T::Key, V>> {
        self.parts().get_mut_or_insert(i, sub, value)
    }
}

/// A mutable view over a contiguous range of an [Index]'s partitions plus that range's
/// spilled entries. This is the canonical home of the index's mutation logic: the full
/// index operates through a `base = 0` view over all partitions, and
/// `apply_sorted_diffs` shard workers operate through disjoint range views in parallel.
/// Partition addressing is by global index; `base` maps it to the local slice.
struct ShardParts<'a, T: Translator, V: Send + Sync> {
    base: usize,
    partitions: &'a mut [Partition<T::Key, V>],
    spilled: &'a mut HashMap<usize, BTreeMap<T::Key, Vec<V>>>,
    translator: &'a T,
    threshold: usize,
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
    spills: &'a Counter,
}

/// Per-shard extraction of the spilled partition maps a batch touches, one map per shard.
type SpilledMinis<K, V> = Vec<HashMap<usize, BTreeMap<K, Vec<V>>>>;

impl<'a, T: Translator, V: Send + Sync> ShardParts<'a, T, V> {
    /// Reborrow a shorter-lived view, letting a caller keep this one after a
    /// consuming call.
    const fn reborrow(&mut self) -> ShardParts<'_, T, V> {
        ShardParts {
            base: self.base,
            partitions: self.partitions,
            spilled: self.spilled,
            translator: self.translator,
            threshold: self.threshold,
            keys: self.keys,
            items: self.items,
            pruned: self.pruned,
            spills: self.spills,
        }
    }

    /// The partition at global index `i`.
    const fn partition(&mut self, i: usize) -> &mut Partition<T::Key, V> {
        &mut self.partitions[i - self.base]
    }

    /// Spill partition `i` to the side-table if its sorted array has reached the threshold.
    fn maybe_spill(&mut self, i: usize) {
        if self.partition(i).len() < self.threshold {
            return;
        }
        let inner: BTreeMap<T::Key, Vec<V>> = self.partition(i).drain_runs().into_iter().collect();
        self.spilled.insert(i, inner);
        self.spills.inc();
    }

    /// The `BTreeMap` of spilled partition `i`, or `None` if `i` has not spilled. The empty-map
    /// check skips hashing `i` in the common case where no partition has ever spilled.
    fn spilled_partition(&self, i: usize) -> Option<&BTreeMap<T::Key, Vec<V>>> {
        if self.spilled.is_empty() {
            return None;
        }
        self.spilled.get(&i)
    }

    /// Mutable cursor over the values of sub-key `sub` in partition `i`, if the key exists.
    /// Consumes the view so the cursor can carry its full lifetime; use
    /// [`Self::reborrow`] to keep working with the view afterwards.
    fn get_mut(mut self, i: usize, sub: &[u8]) -> Option<Cursor<'a, T::Key, V>> {
        let k = self.translator.transform(sub);
        self.maybe_spill(i);
        let local = i - self.base;
        if !self.partitions[local].is_empty() {
            let run = self.partitions[local].run_range(&k);
            if run.is_empty() {
                return None;
            }
            return Some(Cursor::soa(
                &mut self.partitions[local],
                k,
                run,
                self.keys,
                self.items,
                self.pruned,
            ));
        }

        // Hand out a spilled cursor if the partition has spilled and holds `k`.
        if self
            .spilled_partition(i)
            .is_some_and(|inner| inner.contains_key(&k))
        {
            return Some(Cursor::spilled(
                self.spilled,
                i,
                k,
                self.keys,
                self.items,
                self.pruned,
            ));
        }

        // Partition is genuinely empty.
        None
    }

    /// Mutable cursor over the values of sub-key `sub` in partition `i` if the key exists,
    /// otherwise inserts `value` for it and returns `None`.
    fn get_mut_or_insert(
        mut self,
        i: usize,
        sub: &[u8],
        value: V,
    ) -> Option<Cursor<'a, T::Key, V>> {
        let k = self.translator.transform(sub);
        self.maybe_spill(i);
        let local = i - self.base;
        if !self.partitions[local].is_empty() {
            let run = self.partitions[local].run_range(&k);
            if !run.is_empty() {
                return Some(Cursor::soa(
                    &mut self.partitions[local],
                    k,
                    run,
                    self.keys,
                    self.items,
                    self.pruned,
                ));
            }
            self.partitions[local].insert_at(run.end, k, value);
            self.keys.inc();
            self.items.inc();
            self.maybe_spill(i);
            return None;
        }

        // Partition i is empty. If it's because it has spilled, serve or create the key in its
        // `BTreeMap`.
        if let Some(inner) = self.spilled_partition(i) {
            if inner.contains_key(&k) {
                return Some(Cursor::spilled(
                    self.spilled,
                    i,
                    k,
                    self.keys,
                    self.items,
                    self.pruned,
                ));
            }
            self.spilled.get_mut(&i).unwrap().insert(k, vec![value]);
            self.keys.inc();
            self.items.inc();
            return None;
        }

        // Partition i is genuinely empty: start a fresh sorted array.
        self.partitions[local].insert_at(0, k, value);
        self.keys.inc();
        self.items.inc();
        self.maybe_spill(i);

        None
    }

    /// Insert `value` for sub-key `sub` in partition `i` (see [Unordered::insert]).
    fn insert(&mut self, i: usize, sub: &[u8], value: V) {
        let k = self.translator.transform(sub);
        self.maybe_spill(i);
        let local = i - self.base;
        if !self.partitions[local].is_empty() {
            let run = self.partitions[local].run_range(&k);
            let new_key = run.is_empty();
            self.partitions[local].insert_at(run.end, k, value);
            self.items.inc();
            if new_key {
                self.keys.inc();
            }
            self.maybe_spill(i);
            return;
        }

        // Route into the spilled partition's `BTreeMap`.
        if !self.spilled.is_empty()
            && let hash_map::Entry::Occupied(mut partition) = self.spilled.entry(i)
        {
            match partition.get_mut().entry(k) {
                btree_map::Entry::Occupied(mut run) => run.get_mut().push(value),
                btree_map::Entry::Vacant(run) => {
                    run.insert(vec![value]);
                    self.keys.inc();
                }
            }
            self.items.inc();
            return;
        }

        // Genuinely empty partition: start a fresh sorted array.
        self.partitions[local].insert_at(0, k, value);
        self.items.inc();
        self.keys.inc();
        self.maybe_spill(i);
    }
}

#[commonware_macros::stability(ALPHA)]
impl<T: Translator, V: Send + Sync + 'static, const P: usize> Partitioned for Index<T, V, P> {
    type Range = RangeIndex<T, V, P>;

    fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    fn partition_of(key: &[u8]) -> usize {
        partition_index_and_sub_key::<P>(key).0
    }

    /// The range matches this index's translator and spill threshold. It allocates only `count`
    /// partition slots, so per-worker memory is the range rather than the full `2^(8*P)`, which
    /// is what makes a large `P` affordable.
    fn new_range(&self, offset: usize, count: usize) -> RangeIndex<T, V, P> {
        let partitions = (0..count)
            .map(|_| Partition::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        RangeIndex {
            index: Self {
                translator: self.translator.clone(),
                partitions,
                spilled: HashMap::new(),
                threshold: self.threshold,
                keys: self.keys.clone(),
                items: self.items.clone(),
                pruned: self.pruned.clone(),
                spills: self.spills.clone(),
            },
            offset,
        }
    }

    /// Moves the worker's partitions and spilled entries wholesale. Metrics need no adjustment,
    /// since the worker updated this index's handles directly.
    fn install_range(&mut self, mut worker: RangeIndex<T, V, P>) {
        let lo = worker.offset;
        let len = worker.index.partitions.len();

        // Probe the spilled side-table by its (usually empty) key set rather than once per slot.
        assert!(
            self.spilled.keys().all(|&p| p < lo || p >= lo + len),
            "install target range must be empty"
        );
        for (local, partition) in worker.index.partitions.iter_mut().enumerate() {
            let global = lo + local;
            assert!(
                self.partitions[global].is_empty(),
                "install target range must be empty"
            );
            self.partitions[global] = std::mem::take(partition);
        }

        // Drain only the partitions that actually spilled (remapping local -> global), rather than
        // probing every slot in the range.
        for (local, inner) in worker.index.spilled.drain() {
            self.spilled.insert(lo + local, inner);
        }
    }
}

/// A restricted view of an [Index] covering only a contiguous range of partitions, held by one
/// parallel snapshot-build worker (created by [Index::new_range], folded back into a full index by
/// [Index::install_range]). It exposes only the cursor operations, which map a key's global
/// partition index to the worker's local slot. The other [Unordered] operations index partitions
/// globally and are deliberately unavailable, so they cannot be miscalled on a worker.
#[commonware_macros::stability(ALPHA)]
pub(crate) struct RangeIndex<T: Translator, V: Send + Sync, const P: usize> {
    /// The worker's partitions, addressed by local slot (`global partition - offset`).
    index: Index<T, V, P>,

    /// The first global partition index the worker covers.
    offset: usize,
}

#[commonware_macros::stability(ALPHA)]
impl<T: Translator, V: Send + Sync, const P: usize> PartitionRange for RangeIndex<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = Cursor<'a, T::Key, V>
    where
        Self: 'a;

    fn get_mut(&mut self, key: &[u8]) -> Option<Cursor<'_, T::Key, V>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        self.index.get_mut_slot(i - self.offset, sub)
    }

    fn get_mut_or_insert(&mut self, key: &[u8], value: V) -> Option<Cursor<'_, T::Key, V>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        self.index
            .get_mut_or_insert_slot(i - self.offset, sub, value)
    }

    fn for_each_value(&self, f: impl FnMut(&V)) {
        self.index.for_each_value(f);
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> Factory for Index<T, V, P> {
    type Translator = T;

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
        self.get_mut_slot(i, sub)
    }

    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        self.get_mut_or_insert_slot(i, sub, value)
    }

    fn insert(&mut self, key: &[u8], value: Self::Value) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        self.parts().insert(i, sub, value);
    }

    fn apply_sorted_diffs<S: Strategy>(
        &mut self,
        strategy: &S,
        diffs: &[(&[u8], Option<Self::Value>, Option<Self::Value>)],
    ) where
        Self::Value: PartialEq + Copy,
    {
        // Shard the batch across the strategy's workers, snapping shard boundaries to
        // partition boundaries so each worker mutates a disjoint partition range. Small
        // batches apply sequentially: below this size the fan-out costs more than the
        // walk it splits.
        const MIN_DIFFS_PER_SHARD: usize = 64;
        let workers = strategy.manual().parallelism();
        let shards = workers.min(diffs.len() / MIN_DIFFS_PER_SHARD);
        if shards <= 1 {
            for &(key, old, new) in diffs {
                crate::index::apply_one_diff(self, key, old, new);
            }
            return;
        }

        // Split points in `diffs`, advanced past any run of equal partitions so a
        // partition never straddles two shards.
        let mut bounds: Vec<usize> = Vec::with_capacity(shards + 1);
        bounds.push(0);
        for s in 1..shards {
            // Start at the previous bound when it already passed this target:
            // a partition run spanning several targets is then walked once
            // in total instead of once per target.
            let mut at =
                (diffs.len() * s / shards).max(*bounds.last().expect("bounds is non-empty"));
            while at < diffs.len()
                && at > 0
                && partition_index_and_sub_key::<P>(diffs[at].0).0
                    == partition_index_and_sub_key::<P>(diffs[at - 1].0).0
            {
                at += 1;
            }
            if at >= diffs.len() {
                // A run reaching the end of `diffs` can never host a later
                // bound, and it would otherwise be rescanned from every
                // remaining target.
                break;
            }
            if at > *bounds.last().expect("bounds is non-empty") {
                bounds.push(at);
            }
        }
        bounds.push(diffs.len());

        // Boundary snapping can collapse everything into a single shard (e.g.
        // one partition dominating the batch); no parallelism is possible, so
        // skip the fan-out machinery.
        if bounds.len() == 2 {
            for &(key, old, new) in diffs {
                crate::index::apply_one_diff(self, key, old, new);
            }
            return;
        }

        // Partition ranges per shard (for carving the partition array), then
        // the spilled entries each shard owns for the duration of the fan-out.
        let ranges: Vec<(usize, usize)> = bounds
            .windows(2)
            .map(|w| {
                let p_lo = partition_index_and_sub_key::<P>(diffs[w[0]].0).0;
                let p_hi = partition_index_and_sub_key::<P>(diffs[w[1] - 1].0).0 + 1;
                (p_lo, p_hi)
            })
            .collect();
        let mut minis: SpilledMinis<T::Key, V> =
            (0..ranges.len()).map(|_| HashMap::new()).collect();
        if !self.spilled.is_empty() {
            // Extract exactly the spilled maps this batch touches: walk each
            // shard's key-sorted diff slice and pull its distinct partitions.
            // Probing by shard endpoint ranges instead would churn every
            // spilled partition that merely falls between a shard's first and
            // last touched partition.
            for (s, w) in bounds.windows(2).enumerate() {
                let mut prev = usize::MAX;
                for &(key, _, _) in &diffs[w[0]..w[1]] {
                    let (pid, _) = partition_index_and_sub_key::<P>(key);
                    if pid != prev {
                        prev = pid;
                        if let Some(entry) = self.spilled.remove(&pid) {
                            minis[s].insert(pid, entry);
                        }
                    }
                }
            }
        }

        // Carve the partition array into one disjoint mutable slice per shard.
        struct Shard<'s, T: Translator, V: Send + Sync> {
            parts: ShardParts<'s, T, V>,
            diffs: &'s [(&'s [u8], Option<V>, Option<V>)],
        }
        let mut shard_tasks: Vec<Shard<'_, T, V>> = Vec::with_capacity(ranges.len());
        let mut remaining: &mut [Partition<T::Key, V>] = &mut self.partitions;
        let mut carved = 0usize;
        for ((&(p_lo, p_hi), mini), w) in ranges.iter().zip(minis.iter_mut()).zip(bounds.windows(2))
        {
            let (lo, hi) = (w[0], w[1]);
            let (_, tail) = remaining.split_at_mut(p_lo - carved);
            let (mine, rest) = tail.split_at_mut(p_hi - p_lo);
            remaining = rest;
            carved = p_hi;
            shard_tasks.push(Shard {
                parts: ShardParts {
                    base: p_lo,
                    partitions: mine,
                    spilled: mini,
                    translator: &self.translator,
                    threshold: self.threshold,
                    keys: &self.keys,
                    items: &self.items,
                    pruned: &self.pruned,
                    spills: &self.spills,
                },
                diffs: &diffs[lo..hi],
            });
        }

        // Feed the policy the per-shard diff count: the fan-out presents only
        // shard-count items, which alone would read as trivial work and
        // converge the adaptive policy to serial.
        let per_shard = diffs.len() / shard_tasks.len().max(1);
        strategy.map_collect_vec_with_multiplier(shard_tasks, per_shard, |mut shard| {
            for &(key, old, new) in shard.diffs {
                let (i, sub) = partition_index_and_sub_key::<P>(key);
                match (old, new) {
                    (None, Some(new)) => shard.parts.insert(i, sub, new),
                    (Some(old), Some(new)) => {
                        let mut cursor = shard
                            .parts
                            .reborrow()
                            .get_mut(i, sub)
                            .expect("key should be known to exist");
                        assert!(
                            cursor.find(|v| *v == old),
                            "known key with given old value should have been found"
                        );
                        cursor.update(new);
                    }
                    (Some(old), None) => {
                        let mut cursor = shard
                            .parts
                            .reborrow()
                            .get_mut(i, sub)
                            .expect("key should be known to exist");
                        assert!(
                            cursor.find(|v| *v == old),
                            "known key with given old value should have been found"
                        );
                        cursor.delete();
                    }
                    (None, None) => {}
                }
            }
        });

        // Fold any spilled entries (including new spills) back into the side-table.
        for mini in minis {
            self.spilled.extend(mini);
        }
    }

    fn insert_and_retain(
        &mut self,
        key: &[u8],
        value: Self::Value,
        should_retain: impl Fn(&Self::Value) -> bool,
    ) {
        let (i, _) = partition_index_and_sub_key::<P>(key);
        if let Some(mut cursor) = self.get_mut(key) {
            cursor.retain(&should_retain);
            if should_retain(&value) {
                cursor.insert(value);
            }
        } else if should_retain(&value) {
            self.insert(key, value);
        }
        self.maybe_spill(i);
    }

    fn remove(&mut self, key: &[u8]) {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
        self.maybe_spill(i);
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
        if !self.spilled.is_empty()
            && let hash_map::Entry::Occupied(mut partition) = self.spilled.entry(i)
            && let Some(vals) = partition.get_mut().remove(&k)
        {
            let n = vals.len();
            self.keys.dec();
            self.items.dec_by(n as i64);
            self.pruned.inc_by(n as u64);
            if partition.get().is_empty() {
                partition.remove();
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
        // Skip the all-partitions scan when there is nothing to find.
        if self.is_empty() {
            return None;
        }

        // The largest translated key strictly less than `k`: within the partition first, then the
        // last key of the nearest lower partition, else cycle to the global last key.
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
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
        // Skip the all-partitions scan when there is nothing to find.
        if self.is_empty() {
            return None;
        }

        // The smallest translated key strictly greater than `k`: within the partition first, then
        // the first key of the nearest higher partition, else cycle to the global first key.
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        let k = self.translator.transform(sub);
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
        // Skip the all-partitions scan when there is nothing to find.
        if self.is_empty() {
            return None;
        }

        // Scan partitions in ascending order for the global first key.
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
        // Skip the all-partitions scan when there is nothing to find.
        if self.is_empty() {
            return None;
        }

        // Scan partitions in descending order for the global last key.
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
    use commonware_runtime::{Runner, Supervisor as _, deterministic};

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
    fn test_empty_and_sparse_nav() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);

            // Empty index: every ordered navigation returns None (via the empty fast path, without
            // scanning all partitions).
            assert!(index.first_translated_key().is_none());
            assert!(index.last_translated_key().is_none());
            assert!(index.prev_translated_key(&[0x80, 0x00]).is_none());
            assert!(index.next_translated_key(&[0x80, 0x00]).is_none());

            // Two keys in widely separated partitions (0x05 and 0xF0): neighbor scans must still
            // cross the large empty gap between them.
            index.insert(&[0x05, 0x01], 1);
            index.insert(&[0xF0, 0x02], 2);
            assert_eq!(index.keys(), 2);
            assert_eq!(
                index
                    .first_translated_key()
                    .unwrap()
                    .copied()
                    .collect::<Vec<_>>(),
                vec![1]
            );
            assert_eq!(
                index
                    .last_translated_key()
                    .unwrap()
                    .copied()
                    .collect::<Vec<_>>(),
                vec![2]
            );

            // Forward across the gap, then wrap from the global last key.
            let (it, wrapped) = index.next_translated_key(&[0x05, 0x01]).unwrap();
            assert_eq!((it.copied().collect::<Vec<_>>(), wrapped), (vec![2], false));
            let (it, wrapped) = index.next_translated_key(&[0xF0, 0x02]).unwrap();
            assert_eq!((it.copied().collect::<Vec<_>>(), wrapped), (vec![1], true));

            // Backward across the gap, then wrap from the global first key.
            let (it, wrapped) = index.prev_translated_key(&[0xF0, 0x02]).unwrap();
            assert_eq!((it.copied().collect::<Vec<_>>(), wrapped), (vec![1], false));
            let (it, wrapped) = index.prev_translated_key(&[0x05, 0x01]).unwrap();
            assert_eq!((it.copied().collect::<Vec<_>>(), wrapped), (vec![2], true));

            // A query landing in an empty partition between the two finds both neighbors.
            let (it, wrapped) = index.prev_translated_key(&[0x80, 0x00]).unwrap();
            assert_eq!((it.copied().collect::<Vec<_>>(), wrapped), (vec![1], false));
            let (it, wrapped) = index.next_translated_key(&[0x80, 0x00]).unwrap();
            assert_eq!((it.copied().collect::<Vec<_>>(), wrapped), (vec![2], false));

            // Removing all keys returns to the empty fast path.
            index.remove(&[0x05, 0x01]);
            index.remove(&[0xF0, 0x02]);
            assert_eq!(index.keys(), 0);
            assert!(index.prev_translated_key(&[0x80, 0x00]).is_none());
            assert!(index.next_translated_key(&[0x80, 0x00]).is_none());
        });
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

            // Values are served correctly from the spilled representation in append order.
            assert_eq!(
                index.get(&[0x10, 0x01]).copied().collect::<Vec<_>>(),
                vec![1]
            );
            index.insert(&[0x10, 0x02], 22);
            assert_eq!(
                index.get(&[0x10, 0x02]).copied().collect::<Vec<_>>(),
                vec![2, 22]
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
    fn test_spill_after_cursor_growth() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            let key = [0x10, 0x01];

            index.insert(&key, 1);
            {
                let mut cursor = index.get_mut(&key).unwrap();
                assert_eq!(cursor.next().copied(), Some(1));
                assert_eq!(cursor.next(), None);
                cursor.insert(2);
            }
            assert_eq!(index.spilled_count(), 0);

            // The next index mutation spills the over-full inline partition.
            index.insert(&key, 3);
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.get(&key).copied().collect::<Vec<_>>(), vec![1, 2, 3]);

            // Mutations that own their cursor can spill as soon as they release it.
            let other = [0x20, 0x01];
            index.insert(&other, 4);
            index.insert_and_retain(&other, 5, |_| true);
            assert_eq!(index.spilled_count(), 2);
            assert_eq!(index.get(&other).copied().collect::<Vec<_>>(), vec![4, 5]);

            // `get_mut` spills an over-full partition before handing out a cursor, so the cursor
            // serves the spilled representation.
            let third = [0x30, 0x01];
            index.insert(&third, 6);
            {
                let mut cursor = index.get_mut(&third).unwrap();
                assert_eq!(cursor.next().copied(), Some(6));
                assert_eq!(cursor.next(), None);
                cursor.insert(7);
            }
            assert_eq!(index.spilled_count(), 2);
            {
                let mut cursor = index.get_mut(&third).unwrap();
                assert_eq!(cursor.next().copied(), Some(6));
                assert_eq!(cursor.next().copied(), Some(7));
                assert_eq!(cursor.next(), None);
            }
            assert_eq!(index.spilled_count(), 3);
            assert_eq!(index.get(&third).copied().collect::<Vec<_>>(), vec![6, 7]);

            // `remove` spills an over-full partition before access, even for an absent key.
            let fourth = [0x40, 0x01];
            index.insert(&fourth, 8);
            {
                let mut cursor = index.get_mut(&fourth).unwrap();
                assert_eq!(cursor.next().copied(), Some(8));
                assert_eq!(cursor.next(), None);
                cursor.insert(9);
            }
            assert_eq!(index.spilled_count(), 3);
            index.remove(&[0x40, 0x02]);
            assert_eq!(index.spilled_count(), 4);
            assert_eq!(index.get(&fourth).copied().collect::<Vec<_>>(), vec![8, 9]);
        });
    }

    #[test_traced]
    fn test_spill_after_get_mut_or_insert_cursor_growth() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index_spilling(context);
            let key = [0x10, 0x01];

            index.insert(&key, 1);
            {
                let mut cursor = index.get_mut_or_insert(&key, 2).unwrap();
                assert_eq!(cursor.next().copied(), Some(1));
                assert_eq!(cursor.next(), None);
                cursor.insert(2);
            }
            assert_eq!(index.spilled_count(), 0);

            // The next replay-style update spills before returning another collision cursor.
            assert!(index.get_mut_or_insert(&key, 3).is_some());
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.get(&key).copied().collect::<Vec<_>>(), vec![1, 2]);
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
            assert_eq!(index.spills(), 1);
            assert_eq!(index.keys(), 2);
            assert_eq!(index.items(), 2);

            // Spilled -> empty, draining both keys through a cursor over the spilled representation
            // (the cursor de-spill path); the partition reverts only once its last key is gone.
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
            assert_eq!(index.spills(), 1); // cumulative: a de-spill does not decrement it
            assert_eq!(index.keys(), 0);
            assert_eq!(index.items(), 0);

            // Empty -> inline -> spilled a second time: a de-spilled partition is fully reusable.
            index.insert(&[0x10, 0x03], 3);
            assert_eq!(index.spilled_count(), 0);
            index.insert(&[0x10, 0x04], 4);
            assert_eq!(index.spilled_count(), 1);
            assert_eq!(index.spills(), 2); // a fresh spill of the same partition counts again
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
            assert_eq!(index.spills(), 2); // still cumulative after a second spill + de-spill
            assert_eq!(index.keys(), 0);
            assert_eq!(index.items(), 0);

            // Every removed value was counted once: 2 via cursor delete + 2 via remove.
            assert_eq!(index.pruned(), 4);
        });
    }

    #[test_traced]
    fn test_spill_counts_live() {
        deterministic::Runner::default().start(|context| async move {
            // The full index that build workers install into. It spills once a partition holds
            // two entries.
            let mut full = new_index_spilling(context.child("full"));
            assert_eq!(full.spills(), 0);

            // A build worker covering the whole partition range (offset 0, so the inner index's
            // globally-addressed methods are usable directly). It holds clones of the full
            // index's metric handles, so every spill event counts there as it happens, including
            // one whose partition later de-spills (fully drained via remove).
            let mut worker = full.new_range(0, full.partition_count());
            worker.get_mut_or_insert(&[0x10, 0x01], 1);
            worker.get_mut_or_insert(&[0x10, 0x02], 2); // second key in partition 0x10 -> spills
            worker.index.insert(&[0x20, 0x01], 3);
            worker.index.insert(&[0x20, 0x02], 4); // partition 0x20 spills too...
            worker.index.remove(&[0x20, 0x01]);
            worker.index.remove(&[0x20, 0x02]); // ...then fully drains, de-spilling
            assert_eq!(worker.index.spilled_count(), 1);
            assert_eq!(full.spills(), 2); // cumulative: the de-spilled partition still counts

            // Installing moves the structures without touching the already-live counts.
            full.install_range(worker);
            assert_eq!(full.spilled_count(), 1);
            assert_eq!(full.spills(), 2);
        });
    }

    #[test_traced]
    fn test_worker_prunes_count_live() {
        deterministic::Runner::default().start(|context| async move {
            let mut full = new_index(context.child("full"));
            assert_eq!(full.pruned(), 0);

            // A worker covering the whole partition range (offset 0, so the inner index's
            // globally-addressed methods are usable directly). Give a key two values, then delete
            // both through a cursor (the same path the parallel build's deletes take). The worker
            // holds clones of the full index's metric handles, so the prunes count there
            // immediately, matching what the serial build records.
            let mut worker = full.new_range(0, full.partition_count());
            worker.index.insert(&[0x10, 0x01], 1);
            worker.index.insert(&[0x10, 0x01], 2);
            {
                let mut cursor = worker.get_mut(&[0x10, 0x01]).unwrap();
                while cursor.next().is_some() {
                    cursor.delete();
                }
            }
            assert_eq!(full.pruned(), 2);

            // Installing moves the structures without touching the already-live counts.
            full.install_range(worker);
            assert_eq!(full.pruned(), 2);
        });
    }

    /// A worker's value walk must visit every value it holds exactly once, whichever
    /// representation each partition uses (inline sorted arrays or the spilled side-table),
    /// since the snapshot build derives the activity bitmap and active-key counts from it.
    #[test_traced]
    fn test_range_for_each_value_visits_all_values_once() {
        deterministic::Runner::default().start(|context| async move {
            let full = new_index_spilling(context.child("full"));

            // Two distinct keys spill partition 0x80 (threshold 2), then a translated-key
            // collision appends a second value to a spilled run. Partition 0x81 holds one key
            // and stays inline.
            let mut worker = full.new_range(0x80, 2);
            assert!(worker.get_mut_or_insert(&[0x80, 0x01], 1).is_none());
            assert!(worker.get_mut_or_insert(&[0x80, 0x02, 0xAA], 2).is_none());
            assert!(worker.get_mut_or_insert(&[0x80, 0x02, 0xBB], 3).is_some());
            {
                let mut cursor = worker.get_mut(&[0x80, 0x02, 0xBB]).unwrap();
                cursor.next();
                cursor.insert(3);
            }
            assert!(worker.get_mut_or_insert(&[0x81, 0x07], 4).is_none());
            assert_eq!(worker.index.spilled_count(), 1);

            let mut seen = Vec::new();
            worker.for_each_value(|v| seen.push(*v));
            seen.sort_unstable();
            assert_eq!(seen, vec![1, 2, 3, 4]);
        });
    }

    /// A worker with a nonzero offset must land its partitions AND its spilled entries at the
    /// global slots `offset + local` when installed. The multi-worker equivalence tests never
    /// spill inside a worker range (their per-partition load stays below the spill threshold), so
    /// this is the only coverage of the spilled remap off offset zero.
    #[test_traced]
    fn test_install_range_nonzero_offset() {
        deterministic::Runner::default().start(|context| async move {
            // The full index spills once a partition holds two entries, as does the worker
            // (`new_range` copies the threshold).
            let mut full = new_index_spilling(context.child("full"));

            // A worker covering global partitions [0x80, 0x82): two distinct keys spill partition
            // 0x80, and a third key stays inline in partition 0x81.
            let mut worker = full.new_range(0x80, 2);
            worker.get_mut_or_insert(&[0x80, 0x01], 1);
            worker.get_mut_or_insert(&[0x80, 0x02], 2);
            worker.get_mut_or_insert(&[0x81, 0x07], 3);
            assert_eq!(worker.index.spilled_count(), 1);
            assert_eq!(worker.index.keys(), 3);

            // Installing must remap both the inline partition and the spilled entry to the
            // worker's global range.
            full.install_range(worker);
            assert_eq!(full.spilled_count(), 1);
            assert_eq!(full.keys(), 3);
            assert_eq!(full.items(), 3);
            assert_eq!(
                full.get(&[0x80, 0x01]).copied().collect::<Vec<_>>(),
                vec![1]
            );
            assert_eq!(
                full.get(&[0x80, 0x02]).copied().collect::<Vec<_>>(),
                vec![2]
            );
            assert_eq!(
                full.get(&[0x81, 0x07]).copied().collect::<Vec<_>>(),
                vec![3]
            );

            // Nothing may land at the worker's local slots (global partitions 0x00 and 0x01),
            // which is exactly where a remap that dropped the offset would file these entries.
            assert!(full.get(&[0x00, 0x01]).next().is_none());
            assert!(full.get(&[0x01, 0x07]).next().is_none());
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
            let mut cursor = index.get_mut(&[0x10, 0x01]).unwrap(); // cursor over the spilled partition
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
            assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![1, 2, 3]);

            {
                let mut cursor = index.get_mut(key).unwrap();
                assert_eq!(*cursor.next().unwrap(), 1);
                assert_eq!(*cursor.next().unwrap(), 2);
                assert_eq!(*cursor.next().unwrap(), 3);
                assert!(cursor.next().is_none());
            }

            index.insert(key, 3);
            index.insert(key, 4);
            index.retain(key, |i| *i != 3);
            assert_eq!(index.get(key).copied().collect::<Vec<_>>(), vec![1, 2, 4]);

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
            assert_eq!(visits[2], vec![1, 2, 3]);
            assert_eq!(visits[3], vec![4]);
        });
    }

    #[test_traced]
    fn test_soa_insert_and_retain() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = new_index(context);
            // Keep both: new value appends to the run.
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

            // From k1's bucket: jumps partitions to k2's collision run.
            let (mut it, wrapped) = index.next_translated_key(&hex!("0x0b02F2")).unwrap();
            assert!(!wrapped);
            assert_eq!(it.next(), Some(&21));
            assert_eq!(it.next(), Some(&22));
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
            assert_eq!(it.next(), Some(&21));
            assert_eq!(it.next(), Some(&22));
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

    /// The parallel sharded `apply_sorted_diffs` must produce the same index state as
    /// the sequential trait default, including when partitions spill mid-batch and when
    /// shard boundaries need snapping to partition boundaries.
    #[test_traced]
    fn apply_sorted_diffs_parallel_matches_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut parallel =
                Index::<OneCap, u64, 1>::with_threshold(context.child("parallel"), OneCap, 4);
            let mut sequential =
                Index::<OneCap, u64, 1>::with_threshold(context.child("sequential"), OneCap, 4);
            let rayon =
                commonware_parallel::Rayon::new(std::num::NonZeroUsize::new(4).unwrap()).unwrap();

            // Seed both indices identically: several values per key across many partitions,
            // enough per partition to cross the spill threshold for some.
            let mut keys: Vec<[u8; 2]> = Vec::new();
            for hi in 0u8..64 {
                for lo in 0u8..8 {
                    keys.push([hi, lo]);
                }
            }
            for (n, key) in keys.iter().enumerate() {
                parallel.insert(key, n as u64);
                sequential.insert(key, n as u64);
            }

            // A key-sorted diff batch mixing inserts (new suffixes), moves, and deletes.
            let mut diffs: Vec<(&[u8], Option<u64>, Option<u64>)> = Vec::new();
            let mut fresh: Vec<[u8; 2]> = Vec::new();
            for hi in 0u8..64 {
                fresh.push([hi, 100]);
            }
            for (n, key) in keys.iter().enumerate() {
                match n % 3 {
                    0 => diffs.push((key.as_slice(), Some(n as u64), Some(n as u64 + 10_000))),
                    1 => diffs.push((key.as_slice(), Some(n as u64), None)),
                    _ => {}
                }
            }
            for (n, key) in fresh.iter().enumerate() {
                diffs.push((key.as_slice(), None, Some(n as u64 + 20_000)));
            }
            diffs.sort_by(|a, b| a.0.cmp(b.0));

            // Apply the same batch through the sharded path and the sequential default.
            parallel.apply_sorted_diffs(&rayon, &diffs);
            for &(key, old, new) in &diffs {
                crate::index::apply_one_diff(&mut sequential, key, old, new);
            }

            // Every key's value set must match.
            for key in keys
                .iter()
                .map(|k| k.as_slice())
                .chain(fresh.iter().map(|k| k.as_slice()))
            {
                let mut a: Vec<u64> = parallel.get(key).copied().collect();
                let mut b: Vec<u64> = sequential.get(key).copied().collect();
                a.sort_unstable();
                b.sort_unstable();
                assert_eq!(a, b, "mismatch at key {:?}", key);
            }
            assert_eq!(parallel.keys(), sequential.keys());
            assert_eq!(parallel.items(), sequential.items());
            assert_eq!(parallel.spilled_count(), sequential.spilled_count());
        });
    }

    /// The sharded path must also hold at P=2: a sparse slice of a 65,536-entry
    /// partition array, keys of exactly P bytes (empty sub-keys), and spills,
    /// none of which the P=1 tests can produce.
    #[test_traced]
    fn apply_sorted_diffs_parallel_matches_sequential_p2() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut parallel =
                Index::<OneCap, u64, 2>::with_threshold(context.child("parallel"), OneCap, 4);
            let mut sequential =
                Index::<OneCap, u64, 2>::with_threshold(context.child("sequential"), OneCap, 4);
            let rayon =
                commonware_parallel::Rayon::new(std::num::NonZeroUsize::new(4).unwrap()).unwrap();

            // Sparse partitions spread across the 65,536-entry array; per
            // partition, keys of exactly P bytes (empty sub-key) and longer,
            // several values per translated key to cross the spill threshold.
            let mut keys: Vec<Vec<u8>> = Vec::new();
            for i in 0u16..48 {
                let p = i.wrapping_mul(1381).to_be_bytes();
                keys.push(vec![p[0], p[1]]);
                for suffix in 0u8..6 {
                    keys.push(vec![p[0], p[1], suffix]);
                    keys.push(vec![p[0], p[1], suffix, 0xEE]);
                }
            }
            keys.sort();
            keys.dedup();
            for (n, key) in keys.iter().enumerate() {
                parallel.insert(key, n as u64);
                sequential.insert(key, n as u64);
            }

            // Key-sorted diffs mixing moves, deletes, and fresh inserts
            // (including fresh empty-sub-key keys).
            let mut fresh: Vec<Vec<u8>> = Vec::new();
            for i in 0u16..48 {
                let p = i.wrapping_mul(2749).to_be_bytes();
                fresh.push(vec![p[0], p[1]]);
            }
            fresh.sort();
            fresh.dedup();
            let mut diffs: Vec<(&[u8], Option<u64>, Option<u64>)> = Vec::new();
            for (n, key) in keys.iter().enumerate() {
                match n % 3 {
                    0 => diffs.push((key.as_slice(), Some(n as u64), Some(n as u64 + 10_000))),
                    1 => diffs.push((key.as_slice(), Some(n as u64), None)),
                    _ => {}
                }
            }
            for (n, key) in fresh.iter().enumerate() {
                diffs.push((key.as_slice(), None, Some(n as u64 + 20_000)));
            }
            diffs.sort_by(|a, b| a.0.cmp(b.0));

            parallel.apply_sorted_diffs(&rayon, &diffs);
            for &(key, old, new) in &diffs {
                crate::index::apply_one_diff(&mut sequential, key, old, new);
            }

            for key in keys.iter().chain(fresh.iter()) {
                let mut a: Vec<u64> = parallel.get(key).copied().collect();
                let mut b: Vec<u64> = sequential.get(key).copied().collect();
                a.sort_unstable();
                b.sort_unstable();
                assert_eq!(a, b, "mismatch at key {key:?}");
            }
            assert_eq!(parallel.keys(), sequential.keys());
            assert_eq!(parallel.items(), sequential.items());
            assert_eq!(parallel.spilled_count(), sequential.spilled_count());
        });
    }

    /// Sequential-executing strategy that records the work hints passed to the
    /// multiplier-aware map, reporting parallelism 4 so the sharded path engages.
    #[derive(Clone, Debug)]
    struct RecordingStrategy {
        inner: commonware_parallel::Sequential,
        multiplier_calls: std::sync::Arc<std::sync::Mutex<Vec<(usize, usize)>>>,
    }

    impl RecordingStrategy {
        fn new() -> Self {
            Self {
                inner: commonware_parallel::Sequential,
                multiplier_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    impl commonware_parallel::Strategy for RecordingStrategy {
        fn manual(&self) -> commonware_parallel::Manual<Self> {
            commonware_parallel::Manual::new(self.clone(), std::num::NonZeroUsize::new(4).unwrap())
        }

        fn spawn<F, T>(
            &self,
            _len: usize,
            f: F,
        ) -> impl core::future::Future<Output = T> + Send + 'static
        where
            F: FnOnce(Self) -> T + Send + 'static,
            T: Send + 'static,
        {
            core::future::ready(f(self.clone()))
        }

        fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send,
        {
            self.inner.run(len, serial, parallel)
        }

        fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
        where
            R: Send,
            E: Send,
            SEQ: FnOnce() -> Result<R, E> + Send,
            PAR: FnOnce() -> Result<R, E> + Send,
        {
            self.inner.try_run(len, serial, parallel)
        }

        fn fold_init<I, INIT, T, R, ID, F, RD>(
            &self,
            iter: I,
            init: INIT,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> R
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            R: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            self.inner
                .fold_init(iter, init, identity, fold_op, reduce_op)
        }

        fn try_fold<I, R, E, ID, F, RD>(
            &self,
            iter: I,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> Result<R, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            E: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            self.inner.try_fold(iter, identity, fold_op, reduce_op)
        }

        fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send,
        {
            self.inner.join(a, b)
        }

        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> core::cmp::Ordering + Send + Sync,
        {
            self.inner.sort_by(items, compare)
        }

        fn map_init_collect_vec_with_multiplier<I, INIT, T, F, R>(
            &self,
            iter: I,
            multiplier: usize,
            init: INIT,
            map_op: F,
        ) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            F: Fn(&mut T, I::Item) -> R + Send + Sync,
            R: Send,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            self.multiplier_calls
                .lock()
                .expect("lock poisoned")
                .push((items.len(), multiplier));
            self.inner.map_init_collect_vec(items, init, map_op)
        }
    }

    /// The sharded fan-out must pass its true per-shard workload to the
    /// adaptive policy. A regression to the plain map keeps every result
    /// identical (so the equivalence test stays green) while silently
    /// re-exposing the policy to shard-count-as-work serial convergence.
    #[test_traced]
    fn apply_sorted_diffs_reports_work_multiplier() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut index =
                Index::<OneCap, u64, 1>::with_threshold(context.child("index"), OneCap, 64);
            let mut keys: Vec<[u8; 2]> = Vec::new();
            for hi in 0u8..64 {
                for lo in 0u8..8 {
                    keys.push([hi, lo]);
                }
            }
            for (n, key) in keys.iter().enumerate() {
                index.insert(key, n as u64);
            }
            let mut diffs: Vec<(&[u8], Option<u64>, Option<u64>)> = Vec::new();
            for (n, key) in keys.iter().enumerate() {
                diffs.push((key.as_slice(), Some(n as u64), Some(n as u64 + 10_000)));
            }
            diffs.sort_by(|a, b| a.0.cmp(b.0));

            let strategy = RecordingStrategy::new();
            index.apply_sorted_diffs(&strategy, &diffs);

            let calls = strategy.multiplier_calls.lock().expect("lock poisoned");
            assert_eq!(
                calls.len(),
                1,
                "sharded apply must use the multiplier-aware map"
            );
            let (shards, multiplier) = calls[0];
            assert!(shards > 1, "fan-out should have sharded (got {shards})");
            assert_eq!(multiplier, diffs.len() / shards);
        });
    }

    /// A batch concentrated in one partition collapses to a single shard after
    /// boundary snapping: the apply must fall back to the sequential path
    /// (no fan-out call) and still produce correct results.
    #[test_traced]
    fn apply_sorted_diffs_single_partition_batch_falls_back() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut index =
                Index::<OneCap, u64, 1>::with_threshold(context.child("index"), OneCap, 1024);
            let mut keys: Vec<[u8; 2]> = Vec::new();
            for lo in 0u8..=255 {
                keys.push([7, lo]);
            }
            for (n, key) in keys.iter().enumerate() {
                index.insert(key, n as u64);
            }
            let mut diffs: Vec<(&[u8], Option<u64>, Option<u64>)> = Vec::new();
            for (n, key) in keys.iter().enumerate() {
                diffs.push((key.as_slice(), Some(n as u64), Some(n as u64 + 10_000)));
            }
            diffs.sort_by(|a, b| a.0.cmp(b.0));

            let strategy = RecordingStrategy::new();
            index.apply_sorted_diffs(&strategy, &diffs);

            assert!(
                strategy
                    .multiplier_calls
                    .lock()
                    .expect("lock poisoned")
                    .is_empty(),
                "single-partition batch must not fan out"
            );
            for (n, key) in keys.iter().enumerate() {
                let got: Vec<u64> = index.get(key).copied().collect();
                assert_eq!(got, vec![n as u64 + 10_000], "key {key:?}");
            }
        });
    }
}
