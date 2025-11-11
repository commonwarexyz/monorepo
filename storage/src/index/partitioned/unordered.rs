//! The unordered variant of a partitioned index.

use crate::{index::Unordered, translator::Translator};
use commonware_runtime::Metrics;
use std::marker::PhantomData;

/// A partitioned index that maps translated keys to values. The first `P` bytes of the
/// (untranslated) key are used to determine the partition, and the translator is used by the
/// partition-specific indices on the key after stripping this prefix. The value of `P` should be
/// small, typically 1 or 2. Anything larger than 3 will fail to compile.
pub struct Index<T: Translator, I: Unordered<T>, const P: usize> {
    partitions: Vec<I>,
    _phantom: PhantomData<T>,
}

// Because the prefix length has a max of 3, we can safely use a 4-byte int for the index type
// used by prefix conversion.
const INDEX_INT_SIZE: usize = 4;

impl<T: Translator, I: Unordered<T>, const P: usize> Index<T, I, P> {
    /// Create a new [Index] with the given translator.
    pub fn new(ctx: impl Metrics, translator: T) -> Self {
        let partition_count = 1 << (P * 8);
        let mut partitions = Vec::with_capacity(partition_count);
        for i in 0..partition_count {
            partitions.push(I::init(
                ctx.with_label(&format!("partition_{i}")),
                translator.clone(),
            ));
        }

        Self {
            partitions,
            _phantom: PhantomData,
        }
    }

    /// Get the partition index for the given key, along with the prefix-stripped key for probing
    /// the referenced partition. The returned index value is in the range `[0, 2^(P*8) - 1]`.
    fn partition_index_and_sub_key(key: &[u8]) -> (usize, &[u8]) {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            assert!(P > 0, "P must be greater than 0");
            assert!(P <= 3, "P must be 3 or less");
        }
        let copy_len = P.min(key.len());

        let mut bytes = [0u8; INDEX_INT_SIZE];
        bytes[INDEX_INT_SIZE - copy_len..].copy_from_slice(&key[..copy_len]);

        (u32::from_be_bytes(bytes) as usize, &key[copy_len..])
    }

    /// Get the partition for the given key, along with the prefix-stripped key for probing it.
    fn get_partition<'a>(&self, key: &'a [u8]) -> (&I, &'a [u8]) {
        let (i, sub_key) = Self::partition_index_and_sub_key(key);

        (&self.partitions[i], sub_key)
    }

    /// Get the mutable partition for the given key, along with the prefix-stripped key for probing
    /// it.
    fn get_partition_mut<'a>(&mut self, key: &'a [u8]) -> (&mut I, &'a [u8]) {
        let (i, sub_key) = Self::partition_index_and_sub_key(key);

        (&mut self.partitions[i], sub_key)
    }
}

impl<T: Translator, I: Unordered<T>, const P: usize> Unordered<T> for Index<T, I, P> {
    type Value = I::Value;
    type Cursor<'a>
        = I::Cursor<'a>
    where
        Self: 'a;

    fn init(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{index::unordered, translator::OneCap};

    #[test]
    fn test_partitioned_prefix_length_1() {
        const PREFIX_LENGTH: usize = 1;

        let key = [];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, &[0x01]);

        let key = [0x00, 0x00, 0x01];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, &[0x00, 0x01]);
    }

    #[test]
    fn test_partitioned_prefix_length_2() {
        const PREFIX_LENGTH: usize = 2;

        let key = [];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01]; // Key shorter than the prefix should act as 0 padded.
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0xFF, 0x01];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 0xFF);
        assert_eq!(sub_key, &[0x01]);

        let key = [0x01, 0xFF, 0x02]; // Bytes after the prefix should be ignored.
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, (0x01 << 8) | (0xFF));
        assert_eq!(sub_key, &[0x02]);
    }

    #[test]
    fn test_partitioned_prefix_length_3() {
        const PREFIX_LENGTH: usize = 3;

        let key = [];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01]; // Key shorter than the prefix should act as 0 padded.
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01, 0x02];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, (0x01 << 8) | 0x02);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01, 0x02, 0x03];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, (0x01 << 8) | 0x02);
        assert_eq!(sub_key, &[0x03]);

        let key = [0x01, 0xFF, 0xAB, 0xCD, 0xEF];
        let (index, sub_key) =
            Index::<OneCap, unordered::Index<OneCap, u64>, PREFIX_LENGTH>::partition_index_and_sub_key(&key);
        assert_eq!(index, (0x01 << 16) | (0xFF << 8) | 0xAB);
        assert_eq!(sub_key, &[0xCD, 0xEF]);
    }
}
