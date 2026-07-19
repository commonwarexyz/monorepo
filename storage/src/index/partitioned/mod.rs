//! Index implementations that partition the key space across `2^(8*P)` independent partitions
//! selected by a fixed-size `P`-byte prefix of the key.
//!
//! Two variants share this partitioning:
//! - [`ordered`] keeps each partition as sorted struct-of-arrays. Eliding the shared prefix from
//!   the stored keys makes it dense per key, so partitioning lowers the average bytes/key (by the
//!   prefix length) once the fixed per-partition overhead is amortized over enough keys.
//! - [`unordered`] keeps each partition as a hash sub-index. Due to struct element alignment this
//!   doesn't necessarily reduce memory per key even ignoring the fixed per-partition overhead.
//!
//! # Example
//!
//! A 2-byte prefix results in 2^16 = 64K partitions, each independently indexed using the remaining
//! bytes of the key.
//!
//! Partitioning introduces an up-front fixed RAM cost to pre-allocate the per-partition state. This
//! makes a 2-byte prefix efficient only when indexing a large number (>> 2^16) of values, whereas a
//! 1-byte prefix (256 partitions) can suit smaller datasets. Prefixes larger than 3 bytes are
//! impractical and fail to compile.
//!
//! For the [`ordered`] variant a smaller prefix also lowers the point at which partitions spill to a
//! `BTreeMap` (see its docs): a `P=1` index is guaranteed to spill once it holds more than 130,816
//! entries, so prefer `P=2` or higher when keeping ordered access mostly inline matters at that
//! scale.

pub mod ordered;
pub mod unordered;

#[commonware_macros::stability(ALPHA)]
use crate::index::{Cursor, Unordered};

// Because the prefix length has a max of 3, we can safely use a 4-byte int for the index type
// used by prefix conversion.
const INDEX_INT_SIZE: usize = 4;

/// An index whose snapshot build can be split across parallel workers, each owning a contiguous
/// range of its partitions. A worker's [Self::Range] is created empty by [Self::new_range],
/// populated through its cursor operations, and folded back into the full index by
/// [Self::install_range].
#[commonware_macros::stability(ALPHA)]
pub(crate) trait Partitioned: Unordered {
    /// A worker's restricted view over the contiguous partition range it owns.
    type Range: PartitionRange<Value = Self::Value> + Send + 'static;

    /// The number of partitions in the index.
    fn partition_count(&self) -> usize;

    /// The partition index that holds `key`.
    fn partition_of(key: &[u8]) -> usize;

    /// Create a [Self::Range] covering partitions `[offset, offset + count)`.
    fn new_range(&self, offset: usize, count: usize) -> Self::Range;

    /// Move a populated `range`'s contents into self at the global slot range it was created
    /// with, which must be empty.
    fn install_range(&mut self, range: Self::Range);

    /// Visit every value held across all partitions, in unspecified order.
    fn for_each_value(&self, f: impl FnMut(&Self::Value));
}

/// One [Partitioned] worker's restricted view of its partition range: only the cursor
/// operations (addressed by full key), so the globally-addressed [Unordered] methods cannot be
/// miscalled on a worker.
#[commonware_macros::stability(ALPHA)]
pub(crate) trait PartitionRange: Sized {
    /// The value type held by the range.
    type Value: Send + Sync;

    /// The cursor over one key's values (see [Unordered::Cursor]).
    type Cursor<'a>: Cursor<Value = Self::Value>
    where
        Self: 'a;

    /// Mutable access to `key`'s values, if the key exists (see [Unordered::get_mut]). The key's
    /// partition must fall within this range.
    fn get_mut(&mut self, key: &[u8]) -> Option<Self::Cursor<'_>>;

    /// Mutable access to `key`'s values if the key exists, otherwise insert `value` for it and
    /// return `None` (see [Unordered::get_mut_or_insert]). The key's partition must fall within
    /// this range.
    fn get_mut_or_insert(&mut self, key: &[u8], value: Self::Value) -> Option<Self::Cursor<'_>>;
}

/// Get the partition index for the given key, along with the prefix-stripped key for probing
/// the referenced partition. The returned index value is in the range `[0, 2^(P*8) - 1]`.
///
/// Partition order tracks lexicographic key order, which the [`ordered`] variant relies on to
/// traverse keys in order.
pub(crate) fn partition_index_and_sub_key<const P: usize>(key: &[u8]) -> (usize, &[u8]) {
    // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
    const {
        assert!(P > 0, "P must be greater than 0");
        assert!(P <= 3, "P must be 3 or less");
    }
    // The common path strips exactly `P` (a const) bytes, so the copy is fixed-size and its bounds
    // checks fold away; the `else` only handles keys shorter than the prefix.
    if key.len() >= P {
        let mut bytes = [0u8; INDEX_INT_SIZE];
        bytes[INDEX_INT_SIZE - P..].copy_from_slice(&key[..P]);
        (u32::from_be_bytes(bytes) as usize, &key[P..])
    } else {
        // Right-pad the short key into the high bytes of the P-byte window so partition order stays
        // lexicographic (the low bytes stay zero).
        let copy_len = key.len();
        let mut bytes = [0u8; INDEX_INT_SIZE];
        bytes[INDEX_INT_SIZE - P..INDEX_INT_SIZE - P + copy_len].copy_from_slice(&key[..copy_len]);
        (u32::from_be_bytes(bytes) as usize, &key[copy_len..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partitioned_prefix_length_1() {
        const PREFIX_LENGTH: usize = 1;

        let key = [];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, &[0x01]);

        let key = [0x00, 0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, &[0x00, 0x01]);
    }

    #[test]
    fn test_partitioned_prefix_length_2() {
        const PREFIX_LENGTH: usize = 2;

        let key = [];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01]; // Short keys are right-padded, so this routes to 0x0100, not 0x0001.
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0x0100);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0xFF, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0xFF);
        assert_eq!(sub_key, &[0x01]);

        let key = [0x01, 0xFF, 0x02]; // Bytes after the prefix should be ignored.
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 8) | (0xFF));
        assert_eq!(sub_key, &[0x02]);
    }

    #[test]
    fn test_partitioned_prefix_length_3() {
        const PREFIX_LENGTH: usize = 3;

        let key = [];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01]; // Short keys are right-padded into the high bytes.
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0x010000);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0x000100);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01, 0x02];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 8) | 0x02);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01, 0x02, 0x03];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 8) | 0x02);
        assert_eq!(sub_key, &[0x03]);

        let key = [0x01, 0xFF, 0xAB, 0xCD, 0xEF];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 16) | (0xFF << 8) | 0xAB);
        assert_eq!(sub_key, &[0xCD, 0xEF]);
    }

    #[test]
    fn test_partition_index_preserves_key_order() {
        // Walking keys in lexicographic order must yield non-decreasing partition indices, including
        // across short keys and prefix overlaps (e.g. `[0x01]` must sort between `[0x00, 0xFF]` and
        // `[0x01, 0x00]`, not below them). This is the invariant the ordered variant's traversal
        // relies on; the bytes b/c below are the forged-exclusion-proof reproducer's keys.
        let ordered_keys: &[&[u8]] = &[
            &[],
            &[0x00],
            &[0x00, 0x00],
            &[0x00, 0x80], // a
            &[0x00, 0xFF],
            &[0x00, 0xFF, 0x01],
            &[0x01],       // b
            &[0x01, 0x00], // c
            &[0x01, 0x00, 0x05],
            &[0x01, 0xFF],
            &[0x02],
            &[0xFF],
            &[0xFF, 0xFF],
        ];
        assert!(
            ordered_keys.is_sorted_by(|a, b| a < b),
            "test keys must be in lexicographic order"
        );

        let mut prev = 0;
        for key in ordered_keys {
            let (index, _) = partition_index_and_sub_key::<2>(key);
            assert!(
                index >= prev,
                "partition index for {key:?} ({index}) regressed below {prev}"
            );
            prev = index;
        }
    }
}
