//! The unordered variant of a partitioned index.

#[commonware_macros::stability(ALPHA)]
use crate::index::partitioned::{PartitionRange, Partitioned};
use crate::{
    index::{
        Unordered as UnorderedTrait, partitioned::partition_index_and_sub_key,
        unordered::Index as UnorderedIndex,
    },
    translator::Translator,
};
use commonware_runtime::Metrics;

/// A partitioned index that maps translated keys to values. The first `P` bytes of the
/// (untranslated) key are used to determine the partition, and the translator is used by the
/// partition-specific indices on the key after stripping this prefix. The value of `P` should be
/// small, typically 1 or 2. Anything larger than 3 will fail to compile.
pub struct Index<T: Translator, V: Send + Sync, const P: usize> {
    partitions: Vec<UnorderedIndex<T, V>>,
}

impl<T: Translator, V: Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        let partition_count = 1 << (P * 8);
        let mut partitions = Vec::with_capacity(partition_count);
        for i in 0..partition_count {
            partitions.push(UnorderedIndex::new(
                ctx.child("partition").with_attribute("index", i),
                translator.clone(),
            ));
        }

        Self { partitions }
    }

    /// Get the partition for the given key, along with the prefix-stripped key for probing it.
    fn get_partition<'a>(&self, key: &'a [u8]) -> (&UnorderedIndex<T, V>, &'a [u8]) {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);

        (&self.partitions[i], sub_key)
    }

    /// Get the mutable partition for the given key, along with the prefix-stripped key for probing
    /// it.
    fn get_partition_mut<'a>(&mut self, key: &'a [u8]) -> (&mut UnorderedIndex<T, V>, &'a [u8]) {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);

        (&mut self.partitions[i], sub_key)
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

    /// The range allocates only `count` slots, so per-worker memory is the range rather than
    /// the full `2^(8*P)`.
    fn new_range(&self, offset: usize, count: usize) -> RangeIndex<T, V, P> {
        let partitions = (0..count)
            .map(|i| self.partitions[offset + i].empty())
            .collect();
        RangeIndex { partitions, offset }
    }

    /// Absorbs each slot's maps wholesale into the matching partition.
    fn install_range(&mut self, worker: RangeIndex<T, V, P>) {
        let lo = worker.offset;
        for (local, slot) in worker.partitions.into_iter().enumerate() {
            self.partitions[lo + local].absorb(slot);
        }
    }
}

/// A restricted view of an [Index] covering only a contiguous range of partitions, held by one
/// parallel snapshot-build worker (created by [Index::new_range], folded back into a full index by
/// [Index::install_range]). It exposes only the cursor operations, which map a key's global
/// partition index to the worker's local slot. The other [UnorderedTrait] operations index
/// partitions globally and are deliberately unavailable, so they cannot be miscalled on a worker.
#[commonware_macros::stability(ALPHA)]
pub(crate) struct RangeIndex<T: Translator, V: Send + Sync, const P: usize> {
    /// The worker's partition slots, addressed by local slot (`global partition - offset`).
    partitions: Vec<UnorderedIndex<T, V>>,

    /// The first global partition index the worker covers.
    offset: usize,
}

#[commonware_macros::stability(ALPHA)]
impl<T: Translator, V: Send + Sync, const P: usize> PartitionRange for RangeIndex<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = <UnorderedIndex<T, V> as UnorderedTrait>::Cursor<'a>
    where
        Self: 'a;

    fn get_mut(&mut self, key: &[u8]) -> Option<Self::Cursor<'_>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        self.partitions[i - self.offset].get_mut(sub)
    }

    fn get_mut_or_insert(&mut self, key: &[u8], value: V) -> Option<Self::Cursor<'_>> {
        let (i, sub) = partition_index_and_sub_key::<P>(key);
        self.partitions[i - self.offset].get_mut_or_insert(sub, value)
    }

    fn for_each_value(&self, mut f: impl FnMut(&V)) {
        for partition in &self.partitions {
            partition.for_each_value(&mut f);
        }
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> super::super::Factory<T> for Index<T, V, P> {
    fn new(ctx: impl commonware_runtime::Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> UnorderedTrait for Index<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = <UnorderedIndex<T, V> as UnorderedTrait>::Cursor<'a>
    where
        Self: 'a;

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + 'a
    where
        Self::Value: 'a,
    {
        let (partition, sub_key) = self.get_partition(key);

        partition.get(sub_key)
    }

    fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<Self::Cursor<'a>> {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.get_mut(sub_key)
    }

    fn get_mut_or_insert<'a>(
        &'a mut self,
        key: &[u8],
        value: Self::Value,
    ) -> Option<Self::Cursor<'a>> {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.get_mut_or_insert(sub_key, value)
    }

    fn insert(&mut self, key: &[u8], value: Self::Value) {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.insert(sub_key, value);
    }

    fn insert_and_retain(
        &mut self,
        key: &[u8],
        value: Self::Value,
        should_retain: impl Fn(&Self::Value) -> bool,
    ) {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.insert_and_retain(sub_key, value, should_retain);
    }

    fn remove(&mut self, key: &[u8]) {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.remove(sub_key);
    }

    #[cfg(test)]
    fn keys(&self) -> usize {
        // Note: this is really inefficient, but it's only used for testing.
        let mut keys = 0;
        for partition in &self.partitions {
            keys += partition.keys();
        }

        keys
    }

    #[cfg(test)]
    fn items(&self) -> usize {
        // Note: this is really inefficient, but it's only used for testing.
        let mut items = 0;
        for partition in &self.partitions {
            items += partition.items();
        }

        items
    }

    #[cfg(test)]
    fn pruned(&self) -> usize {
        // Note: this is really inefficient, but it's only used for testing.
        let mut pruned = 0;
        for partition in &self.partitions {
            pruned += partition.pruned();
        }

        pruned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{index::Cursor as _, translator::OneCap};
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    /// A `P=1` index over `u64` values with a one-byte translator, so distinct keys sharing a
    /// partition and translated sub-key collide into an overflow chain.
    fn new_index(ctx: impl Metrics) -> Index<OneCap, u64, 1> {
        Index::new(ctx, OneCap)
    }

    /// A worker's value walk must visit every value it holds exactly once (inline values and
    /// overflow chains alike), since the snapshot build derives the activity bitmap and
    /// active-key counts from it.
    #[test_traced]
    fn test_range_for_each_value_visits_all_values_once() {
        deterministic::Runner::default().start(|context| async move {
            let full = new_index(context.child("full"));

            // Two keys in partition 0x80 that collide on the one-byte translated sub-key (an
            // overflow chain), one distinct key beside them, and one key in partition 0x81.
            let mut worker = full.new_range(0x80, 2);
            assert!(worker.get_mut_or_insert(&[0x80, 0x01, 0xAA], 1).is_none());
            assert!(worker.get_mut_or_insert(&[0x80, 0x01, 0xBB], 2).is_some());
            {
                let mut cursor = worker.get_mut(&[0x80, 0x01, 0xBB]).unwrap();
                cursor.next();
                cursor.insert(2);
            }
            assert!(worker.get_mut_or_insert(&[0x80, 0x02], 3).is_none());
            assert!(worker.get_mut_or_insert(&[0x81, 0x07], 4).is_none());

            let mut seen = Vec::new();
            worker.for_each_value(|v| seen.push(*v));
            seen.sort_unstable();
            assert_eq!(seen, vec![1, 2, 3, 4]);
        });
    }

    /// A worker with a nonzero offset must land its slots at the global partitions
    /// `offset + local` when installed, carrying inline values and overflow chains (the
    /// key/item counts are live through the shared handles, so the `get` asserts are what pin
    /// the moved contents).
    #[test_traced]
    fn test_install_range_nonzero_offset() {
        deterministic::Runner::default().start(|context| async move {
            let mut full = new_index(context.child("full"));

            // A worker covering global partitions [0x80, 0x82): two keys in partition 0x80, one
            // in 0x81.
            let mut worker = full.new_range(0x80, 2);
            assert!(worker.get_mut_or_insert(&[0x80, 0x01], 1).is_none());
            assert!(worker.get_mut_or_insert(&[0x80, 0x02], 2).is_none());
            assert!(worker.get_mut_or_insert(&[0x81, 0x07], 3).is_none());

            // A colliding key (same partition and translated sub-key as the first) joins the
            // first key's chain through the cursor, the same path the build worker's collision
            // resolution takes.
            {
                let mut cursor = worker.get_mut_or_insert(&[0x80, 0x01, 0xFF], 4).unwrap();
                while cursor.next().is_some() {}
                cursor.insert(4);
            }

            // Installing must remap the slots to the worker's global range and preserve every
            // value, including the chained one.
            full.install_range(worker);
            assert_eq!(full.keys(), 3);
            assert_eq!(full.items(), 4);
            assert_eq!(
                full.get(&[0x80, 0x01]).copied().collect::<Vec<_>>(),
                vec![1, 4]
            );
            assert_eq!(
                full.get(&[0x80, 0x02]).copied().collect::<Vec<_>>(),
                vec![2]
            );
            assert_eq!(
                full.get(&[0x81, 0x07]).copied().collect::<Vec<_>>(),
                vec![3]
            );
        });
    }

    /// A worker's cursor deletes (the parallel build's delete path) count on the covered
    /// partition's shared `pruned` handle as they happen, matching what the serial build
    /// records.
    #[test_traced]
    fn test_worker_prunes_count_live() {
        deterministic::Runner::default().start(|context| async move {
            let mut full = new_index(context.child("full"));
            assert_eq!(full.pruned(), 0);

            // Give one translated key two values, then delete both through a cursor. The worker
            // slots hold clones of their partitions' metric handles, so the prunes count on the
            // full index immediately.
            let mut worker = full.new_range(0, full.partition_count());
            assert!(worker.get_mut_or_insert(&[0x10, 0x01], 1).is_none());
            {
                let mut cursor = worker.get_mut_or_insert(&[0x10, 0x01, 0xFF], 2).unwrap();
                while cursor.next().is_some() {}
                cursor.insert(2);
            }
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
            assert_eq!(full.keys(), 0);
            assert_eq!(full.items(), 0);
        });
    }
}
