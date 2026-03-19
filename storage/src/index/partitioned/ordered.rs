//! The ordered variant of a partitioned index.

use crate::{
    index::{
        ordered::Index as OrderedIndex, partitioned::partition_index_and_sub_key,
        Ordered as OrderedTrait, Unordered as UnorderedTrait,
    },
    translator::Translator,
};
use commonware_runtime::Metrics;

/// A partitioned index that maps translated keys to values. The first `P` bytes of the
/// (untranslated) key are used to determine the partition, and the translator is used by the
/// partition-specific indices on the key after stripping this prefix. The value of `P` should be
/// small, typically 1 or 2. Anything larger than 3 will fail to compile.
pub struct Index<T: Translator, V: Eq + Send + Sync, const P: usize> {
    partitions: Vec<OrderedIndex<T, V>>,
}

impl<T: Translator, V: Eq + Send + Sync, const P: usize> Index<T, V, P> {
    /// Create a new [Index] with the given translator and metrics registry.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        let partition_count = 1 << (P * 8);
        let mut partitions = Vec::with_capacity(partition_count);
        for i in 0..partition_count {
            partitions.push(OrderedIndex::new(
                ctx.with_label("partition").with_attribute("idx", i),
                translator.clone(),
            ));
        }

        Self { partitions }
    }

    /// Get the partition for the given key, along with the prefix-stripped key for probing it.
    fn get_partition<'a>(&self, key: &'a [u8]) -> (&OrderedIndex<T, V>, &'a [u8]) {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);

        (&self.partitions[i], sub_key)
    }

    /// Get the mutable partition for the given key, along with the prefix-stripped key for probing
    /// it.
    fn get_partition_mut<'a>(&mut self, key: &'a [u8]) -> (&mut OrderedIndex<T, V>, &'a [u8]) {
        let (i, sub_key) = partition_index_and_sub_key::<P>(key);

        (&mut self.partitions[i], sub_key)
    }
}

impl<T: Translator, V: Eq + Send + Sync, const P: usize> UnorderedTrait for Index<T, V, P> {
    type Value = V;
    type Cursor<'a>
        = <OrderedIndex<T, V> as UnorderedTrait>::Cursor<'a>
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

impl<T: Translator, V: Eq + Send + Sync, const P: usize> OrderedTrait for Index<T, V, P> {
    type Iterator<'a>
        = <OrderedIndex<T, V> as OrderedTrait>::Iterator<'a>
    where
        Self: 'a;

    fn prev_translated_key<'a>(&'a self, key: &[u8]) -> Option<(Self::Iterator<'a>, bool)>
    where
        Self::Value: 'a,
    {
        let (partition_index, sub_key) = partition_index_and_sub_key::<P>(key);
        {
            let partition = &self.partitions[partition_index];
            let iter = partition.prev_translated_key_no_cycle(sub_key);
            if let Some(iter) = iter {
                return Some((iter, false));
            }
        }

        for partition in self.partitions[..partition_index].iter().rev() {
            let iter = partition.last_translated_key();
            if let Some(iter) = iter {
                return Some((iter, false));
            }
        }

        self.last_translated_key().map(|iter| (iter, true))
    }

    fn next_translated_key<'a>(&'a self, key: &[u8]) -> Option<(Self::Iterator<'a>, bool)>
    where
        Self::Value: 'a,
    {
        let (partition_index, sub_key) = partition_index_and_sub_key::<P>(key);
        {
            let partition = &self.partitions[partition_index];
            let iter = partition.next_translated_key_no_cycle(sub_key);
            if let Some(iter) = iter {
                return Some((iter, false));
            }
        }

        for partition in self.partitions[partition_index + 1..].iter() {
            let iter = partition.first_translated_key();
            if let Some(iter) = iter {
                return Some((iter, false));
            }
        }

        self.first_translated_key().map(|iter| (iter, true))
    }

    fn first_translated_key<'a>(&'a self) -> Option<Self::Iterator<'a>>
    where
        Self::Value: 'a,
    {
        for partition in &self.partitions {
            let iter = partition.first_translated_key();
            if iter.is_none() {
                continue;
            }
            return iter;
        }

        None
    }

    fn last_translated_key<'a>(&'a self) -> Option<Self::Iterator<'a>>
    where
        Self::Value: 'a,
    {
        for partition in self.partitions.iter().rev() {
            let iter = partition.last_translated_key();
            if iter.is_none() {
                continue;
            }
            return iter;
        }

        None
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
    fn test_ordered_trait_empty_index() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let index = Index::<_, u64, 1>::new(context, OneCap);

            assert!(index.first_translated_key().is_none());
            assert!(index.last_translated_key().is_none());
            assert!(index.prev_translated_key(b"key").is_none());
            assert!(index.next_translated_key(b"key").is_none());
        });
    }

    #[test_traced]
    fn test_ordered_trait_single_key() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = Index::<_, u64, 1>::new(context, OneCap);
            let key = b"\x0a\xff";

            index.insert(key, 42u64);

            let mut first = index.first_translated_key().unwrap();
            assert_eq!(first.next(), Some(&42));
            assert!(first.next().is_none());

            let mut last = index.last_translated_key().unwrap();
            assert_eq!(last.next(), Some(&42));
            assert!(last.next().is_none());

            let (mut iter, wrapped) = index.prev_translated_key(key).unwrap();
            assert!(wrapped);
            assert_eq!(iter.next(), Some(&42));
            assert!(iter.next().is_none());
            let (mut iter, wrapped) = index.next_translated_key(key).unwrap();
            assert!(wrapped);
            assert_eq!(iter.next(), Some(&42));
            assert!(iter.next().is_none());

            let (mut next, wrapped) = index.next_translated_key(b"\x00").unwrap();
            assert!(!wrapped);
            assert_eq!(next.next(), Some(&42));
            assert!(next.next().is_none());

            let (mut prev, wrapped) = index.prev_translated_key(b"\xff\x00").unwrap();
            assert!(!wrapped);
            assert_eq!(prev.next(), Some(&42));
            assert!(prev.next().is_none());
        });
    }

    #[test_traced]
    fn test_ordered_trait_all_keys() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = Index::<_, u64, 1>::new(context, OneCap);
            // Insert a key for every possible prefix + 1-cap
            for b1 in 0..=255u8 {
                for b2 in 0..=255u8 {
                    let key = [b1, b2];
                    index.insert(&key, (b1 as u64) << 8 | b2 as u64);
                }
            }

            // Insert some longer keys to test conflicts.
            for b1 in (0..=255u8).rev() {
                for b2 in 0..=255u8 {
                    let key = [b1, b2, 0xff];
                    index.insert(&key, u64::MAX);
                }
            }

            let first_translated_key = index.first_translated_key().unwrap().next().unwrap();
            assert_eq!(*first_translated_key, 0);

            let last_translated_key = index.last_translated_key().unwrap().next().unwrap();
            assert_eq!(*last_translated_key, (255u64 << 8) | 255);

            let last = [255u8, 255u8];
            let (mut iter, wrapped) = index.next_translated_key(&last).unwrap();
            assert!(wrapped);
            assert_eq!(iter.next(), Some(first_translated_key));

            for b1 in 0..=255u8 {
                for b2 in 0..=255u8 {
                    let key = [b1, b2];
                    if !(b1 == 255 && b2 == 255) {
                        let (mut iter, _) = index.next_translated_key(&key).unwrap();
                        let next = *iter.next().unwrap();
                        assert_eq!(next, ((b1 as u64) << 8 | b2 as u64) + 1);
                        let next = *iter.next().unwrap();
                        assert_eq!(next, u64::MAX);
                        assert!(iter.next().is_none());
                    }
                    if !(b1 == 0 && b2 == 0) {
                        let (mut iter, _) = index.prev_translated_key(&key).unwrap();
                        let prev = *iter.next().unwrap();
                        assert_eq!(prev, ((b1 as u64) << 8 | b2 as u64) - 1);
                        let prev = *iter.next().unwrap();
                        assert_eq!(prev, u64::MAX);
                        assert!(iter.next().is_none());
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_ordered_trait_multiple_keys() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut index = Index::<_, u64, 1>::new(context, OneCap);
            assert_eq!(index.keys(), 0);

            let k1 = &hex!("0x0b02AA"); // translated key 0b02
            let k2 = &hex!("0x1c04CC"); // translated key 1c04
            let k2_collides = &hex!("0x1c0411");
            let k3 = &hex!("0x2d06EE"); // translated key 2d06
            index.insert(k1, 1);
            index.insert(k2, 21);
            index.insert(k2_collides, 22);
            index.insert(k3, 3);
            assert_eq!(index.keys(), 3);

            // First translated key is 0b.
            let mut iter = index.first_translated_key().unwrap();
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);

            // Next translated key to 0x00 is 0b02.
            let (mut iter, wrapped) = index.next_translated_key(&[0x00]).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);

            // Next translated key to 0x0b02 is 1c.
            let (mut iter, wrapped) = index.next_translated_key(&hex!("0x0b02F2")).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&21));
            assert_eq!(iter.next(), Some(&22));
            assert_eq!(iter.next(), None);

            // Next translated key to 0x1b is 1c.
            let (mut iter, wrapped) = index.next_translated_key(&hex!("0x1b010203")).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&21));
            assert_eq!(iter.next(), Some(&22));
            assert_eq!(iter.next(), None);

            // Next translated key to 0x2a is 2d.
            let (mut iter, wrapped) = index.next_translated_key(&hex!("0x2a01020304")).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&3));
            assert_eq!(iter.next(), None);

            // Next translated key to 0x2d is 0b.
            let (mut iter, wrapped) = index.next_translated_key(k3).unwrap();
            assert!(wrapped);
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);

            // Another cycle around case.
            let (mut iter, wrapped) = index.next_translated_key(&hex!("0x2eFF")).unwrap();
            assert!(wrapped);
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);

            // Previous translated key is the last key due to cycling.
            let (mut iter, wrapped) = index.prev_translated_key(k1).unwrap();
            assert!(wrapped);
            assert_eq!(iter.next(), Some(&3));
            assert_eq!(iter.next(), None);

            // Previous translated key is 0b.
            let (mut iter, wrapped) = index.prev_translated_key(&hex!("0x0c0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);

            // Previous translated key is 1c.
            let (mut iter, wrapped) = index.prev_translated_key(&hex!("0x1d0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&21));
            assert_eq!(iter.next(), Some(&22));
            assert_eq!(iter.next(), None);

            // Previous translated key is 2d.
            let (mut iter, wrapped) = index.prev_translated_key(&hex!("0xCC0102")).unwrap();
            assert!(!wrapped);
            assert_eq!(iter.next(), Some(&3));
            assert_eq!(iter.next(), None);

            // Last translated key is 2d.
            let mut iter = index.last_translated_key().unwrap();
            assert_eq!(iter.next(), Some(&3));
            assert_eq!(iter.next(), None);
        });
    }
}
