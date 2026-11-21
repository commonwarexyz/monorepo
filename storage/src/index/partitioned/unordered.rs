//! The unordered variant of a partitioned index.

use crate::{
    index::{
        Unordered as UnorderedTrait,
        partitioned::{PartitionRange, Partitioned, partition_index_and_sub_key},
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

impl<T: Translator, V: Send + Sync + 'static, const P: usize> Partitioned for Index<T, V, P> {
    type Range = RangeIndex<T, V, P>;

    fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    fn partition_of(key: &[u8]) -> usize {
        partition_index_and_sub_key::<P>(key).0
    }

    /// The range allocates only `count` slots, so its memory is the range rather than the
    /// full `2^(8*P)`.
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
/// snapshot-build task (created by [Index::new_range], folded back into a full index by
/// [Index::install_range]). It accepts only bulk loads, which map a key's global partition index
/// to the range's local slot. The [UnorderedTrait] operations index partitions globally and are
/// deliberately unavailable, so they cannot be miscalled on a range.
pub(crate) struct RangeIndex<T: Translator, V: Send + Sync, const P: usize> {
    /// The range's partition slots, addressed by local slot (`global partition - offset`).
    partitions: Vec<UnorderedIndex<T, V>>,

    /// The first global partition index the range covers.
    offset: usize,
}

impl<T: Translator, V: Send + Sync, const P: usize> PartitionRange for RangeIndex<T, V, P> {
    type Value = V;

    fn load<'a>(&mut self, entries: impl ExactSizeIterator<Item = (&'a [u8], V)>) {
        let mut entries = entries.peekable();
        let Some((first, _)) = entries.peek() else {
            return;
        };
        let (i, _) = partition_index_and_sub_key::<P>(first);
        self.partitions[i - self.offset]
            .load(entries.map(|(key, value)| (partition_index_and_sub_key::<P>(key).1, value)));
    }
}

impl<T: Translator, V: Send + Sync, const P: usize> super::super::Factory for Index<T, V, P> {
    type Translator = T;

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

    fn get<'a>(&'a self, key: &[u8]) -> impl Iterator<Item = &'a Self::Value> + 'a {
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
        should_retain: impl FnMut(&Self::Value) -> bool,
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
    use crate::translator::OneCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic, telemetry::metrics::metric_samples,
    };

    /// A `P=1` index over `u64` values with a one-byte translator, so distinct keys sharing a
    /// partition and translated sub-key collide into an overflow chain.
    fn new_index(ctx: impl Metrics) -> Index<OneCap, u64, 1> {
        Index::new(ctx, OneCap)
    }

    /// Loading a range must leave the index as inserting the same entries one at a time would,
    /// whether a partition is loaded once or again, and whether or not its keys collide.
    #[test_traced]
    fn test_range_load_matches_inserts() {
        deterministic::Runner::default().start(|context| async move {
            let mut loaded = new_index(context.child("loaded"));
            let mut inserted = new_index(context.child("inserted"));

            // Each load holds one partition's entries in ascending key order. Partition 0x80
            // has keys that share a translated sub-key and is loaded twice.
            let loads: [&[(&[u8], u64)]; 4] = [
                &[
                    (&[0x80, 0x01], 1),
                    (&[0x80, 0x01, 0xAA], 2),
                    (&[0x80, 0x01, 0xBB], 3),
                    (&[0x80, 0x02], 4),
                ],
                &[(&[0x81, 0x07], 5)],
                &[],
                &[(&[0x80, 0x01, 0xCC], 6), (&[0x80, 0x03], 7)],
            ];
            let mut range = loaded.new_range(0x80, 2);
            for entries in loads {
                range.load(entries.iter().copied());
                for &(key, value) in entries {
                    inserted.insert(key, value);
                }
            }
            loaded.install_range(range);
            assert_eq!(loaded.keys(), inserted.keys());
            assert_eq!(loaded.items(), inserted.items());
            for &(key, _) in loads.iter().copied().flatten() {
                assert_eq!(
                    loaded.get(key).collect::<Vec<_>>(),
                    inserted.get(key).collect::<Vec<_>>()
                );
            }
        });
    }

    /// Installing a range with a nonzero offset must land its slots, with their inline values and
    /// overflow chains, at the global partitions `offset + local`. The key and item counts are
    /// live through the shared metrics, so the `get` asserts are what pin the moved contents.
    #[test_traced]
    fn test_install_range_nonzero_offset() {
        deterministic::Runner::default().start(|context| async move {
            let mut full = new_index(context.child("full"));

            // A range covering global partitions [0x80, 0x82): three keys in partition 0x80,
            // two of which share a translated sub-key, and one key in 0x81.
            let mut range = full.new_range(0x80, 2);
            let entries: [(&[u8], u64); 3] = [
                (&[0x80, 0x01], 1),
                (&[0x80, 0x01, 0xFF], 4),
                (&[0x80, 0x02], 2),
            ];
            range.load(entries.into_iter());
            let entries: [(&[u8], u64); 1] = [(&[0x81, 0x07], 3)];
            range.load(entries.into_iter());

            // Installing must remap the slots to the range's global partitions and preserve
            // every value, including the chained one.
            full.install_range(range);
            assert_eq!(full.keys(), 3);
            assert_eq!(full.items(), 4);
            assert_eq!(
                full.get(&[0x80, 0x01]).copied().collect::<Vec<_>>(),
                vec![4, 1]
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

    /// A range's slots update their partitions' metrics without holding their registrations,
    /// so dropping the full index unregisters those metrics while the range lives on.
    #[test_traced]
    fn test_range_does_not_hold_registrations() {
        deterministic::Runner::default().start(|context| async move {
            // The range's load counts on the full index's metrics as it happens.
            let full = new_index(context.child("full"));
            let mut range = full.new_range(0, full.partition_count());
            let entries: [(&[u8], u64); 1] = [(&[0x10, 0x01], 1)];
            range.load(entries.into_iter());
            assert_eq!(full.keys(), 1);

            // Dropping the full index unregisters its metrics while the range still holds its
            // slots. An index created again under the same names starts from zero and misses the
            // range's later loads.
            drop(full);
            let encoded = context.encode();
            for name in ["keys", "items", "pruned_total"] {
                assert!(
                    metric_samples(&encoded, name).next().is_none(),
                    "{name} must leave the registry"
                );
            }
            let fresh = new_index(context.child("full"));
            let entries: [(&[u8], u64); 1] = [(&[0x20, 0x01], 2)];
            range.load(entries.into_iter());
            assert_eq!(fresh.keys(), 0);
        });
    }
}
