//! The unordered variant of a partitioned index.

use crate::{
    index::{
        partitioned::partition_index_and_sub_key, unordered::Index as UnorderedIndex,
        Unordered as UnorderedTrait,
    },
    translator::Translator,
};
use commonware_runtime::Metrics;

/// A partitioned index that maps translated keys to values. The first `P` bytes of the
/// (untranslated) key are used to determine the partition, and the translator is used by the
/// partition-specific indices on the key after stripping this prefix. The value of `P` should be
/// small, typically 1 or 2. Anything larger than 3 will fail to compile.
pub struct Index<T: Translator, V: Eq + Send + Sync, const P: usize> {
    partitions: Vec<UnorderedIndex<T, V>>,
}

impl<T: Translator, V: Eq + Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        let partition_count = 1 << (P * 8);
        let mut partitions = Vec::with_capacity(partition_count);
        for i in 0..partition_count {
            partitions.push(UnorderedIndex::new(
                ctx.with_label("partition").with_attribute("idx", i),
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

impl<T: Translator, V: Eq + Send + Sync, const P: usize> UnorderedTrait for Index<T, V, P> {
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

    fn insert_and_prune(
        &mut self,
        key: &[u8],
        value: Self::Value,
        predicate: impl Fn(&Self::Value) -> bool,
    ) {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.insert_and_prune(sub_key, value, predicate);
    }

    fn prune(&mut self, key: &[u8], predicate: impl Fn(&Self::Value) -> bool) {
        let (partition, sub_key) = self.get_partition_mut(key);

        partition.prune(sub_key, predicate);
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
