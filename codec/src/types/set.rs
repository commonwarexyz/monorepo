//! Codec implementations for various set types.
//!
//! For portability and consistency between architectures,
//! the size of the set must fit within a [`u32`].

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    varint, Config, RangeConfig,
};
use bytes::{Buf, BufMut};
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    hash::Hash,
};

// ---------- BTreeSet ----------

impl<K: Ord + Hash + Eq + Write> Write for BTreeSet<K> {
    fn write(&self, buf: &mut impl BufMut) {
        let len = u32::try_from(self.len()).expect("BTreeSet length exceeds u32::MAX");
        varint::write(len, buf);

        // Items are already sorted in BTreeSet, so we can iterate directly
        for item in self {
            item.write(buf);
        }
    }
}

impl<K: Ord + Hash + Eq + EncodeSize> EncodeSize for BTreeSet<K> {
    fn encode_size(&self) -> usize {
        let len = u32::try_from(self.len()).expect("BTreeSet length exceeds u32::MAX");
        let mut size = varint::size(len);
        for item in self {
            size += item.encode_size();
        }
        size
    }
}

impl<R: RangeConfig, Cfg: Config, K: Read<Cfg> + Clone + Ord + Hash + Eq> Read<(R, Cfg)>
    for BTreeSet<K>
{
    fn read_cfg(buf: &mut impl Buf, (range, cfg): &(R, Cfg)) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len32 = varint::read::<u32>(buf)?;
        let len = usize::try_from(len32).map_err(|_| Error::InvalidVarint)?;
        if !range.contains(&len) {
            return Err(Error::InvalidLength(len));
        }
        let mut set = BTreeSet::new(); // BTreeSet does not have a capacity method

        // Keep track of the last item read
        let mut last: Option<K> = None;

        // Read each item
        for _ in 0..len {
            let item = K::read_cfg(buf, cfg)?;

            // Check if items are in ascending order
            if let Some(ref last) = last {
                match item.cmp(last) {
                    Ordering::Equal => return Err(Error::Invalid("HashSet", "Duplicate item")),
                    Ordering::Less => return Err(Error::Invalid("HashSet", "Items must ascend")),
                    _ => {}
                }
            }
            last = Some(item.clone());
            set.insert(item);
        }

        Ok(set)
    }
}

// ---------- HashSet ----------

impl<K: Ord + Hash + Eq + Write> Write for HashSet<K> {
    fn write(&self, buf: &mut impl BufMut) {
        let len = u32::try_from(self.len()).expect("HashSet length exceeds u32::MAX");
        varint::write(len, buf);

        // Sort the items to ensure deterministic encoding
        let mut items: Vec<_> = self.iter().collect();
        items.sort();
        for item in items {
            item.write(buf);
        }
    }
}

impl<K: Ord + Hash + Eq + EncodeSize> EncodeSize for HashSet<K> {
    fn encode_size(&self) -> usize {
        let len = u32::try_from(self.len()).expect("HashSet length exceeds u32::MAX");
        let mut size = varint::size(len);
        // Note: Iteration order doesn't matter for size calculation.
        for item in self {
            size += item.encode_size();
        }
        size
    }
}

impl<R: RangeConfig, Cfg: Config, K: Read<Cfg> + Clone + Ord + Hash + Eq> Read<(R, Cfg)>
    for HashSet<K>
{
    fn read_cfg(buf: &mut impl Buf, (range, cfg): &(R, Cfg)) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len32 = varint::read::<u32>(buf)?;
        let len = usize::try_from(len32).map_err(|_| Error::InvalidVarint)?;
        if !range.contains(&len) {
            return Err(Error::InvalidLength(len));
        }
        let mut set = HashSet::with_capacity(len);

        // Keep track of the last item read
        let mut last: Option<K> = None;

        // Read each item
        for _ in 0..len {
            let item = K::read_cfg(buf, cfg)?;

            // Check if items are in ascending order
            if let Some(ref last) = last {
                match item.cmp(last) {
                    Ordering::Equal => return Err(Error::Invalid("HashSet", "Duplicate item")),
                    Ordering::Less => return Err(Error::Invalid("HashSet", "Items must ascend")),
                    _ => {}
                }
            }
            last = Some(item.clone());
            set.insert(item);
        }

        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{Decode, Encode},
        Config, FixedSize,
    };
    use bytes::{Bytes, BytesMut};
    use std::collections::{BTreeSet, HashSet};
    use std::fmt::Debug;
    use std::ops::RangeInclusive;

    // Helper to create a range allowing any length
    fn allow_any_len() -> RangeInclusive<usize> {
        0..=usize::MAX
    }

    // Generic round trip test function for BTreeSet
    fn round_trip_btree<K, R, Cfg>(set: &BTreeSet<K>, range_cfg: R, item_cfg: Cfg)
    where
        K: Write + EncodeSize + Read<Cfg> + Clone + Ord + Hash + Eq + Debug + PartialEq,
        R: RangeConfig + Clone,
        Cfg: Config + Clone,
        BTreeSet<K>: Read<(R, Cfg)> + Decode<(R, Cfg)> + Debug + PartialEq + Write + EncodeSize,
    {
        let encoded = set.encode();
        let config_tuple = (range_cfg, item_cfg);
        let decoded = BTreeSet::<K>::decode_cfg(encoded, &config_tuple).expect("decode_cfg failed");
        assert_eq!(set, &decoded);
    }

    // Generic round trip test function for HashSet
    fn round_trip_hash<K, R, Cfg>(set: &HashSet<K>, range_cfg: R, item_cfg: Cfg)
    where
        K: Write + EncodeSize + Read<Cfg> + Clone + Ord + Hash + Eq + Debug + PartialEq,
        R: RangeConfig + Clone,
        Cfg: Config + Clone,
        HashSet<K>: Read<(R, Cfg)> + Decode<(R, Cfg)> + Debug + PartialEq + Write + EncodeSize,
    {
        let encoded = set.encode();
        let config_tuple = (range_cfg, item_cfg);
        let decoded = HashSet::<K>::decode_cfg(encoded, &config_tuple).expect("decode_cfg failed");
        assert_eq!(set, &decoded);
    }

    // --- BTreeSet Tests ---

    #[test]
    fn test_empty_btree_set() {
        let set = BTreeSet::<u32>::new();
        round_trip_btree(&set, allow_any_len(), ());
        assert_eq!(set.encode_size(), 1); // varint 0
        let encoded = set.encode();
        assert_eq!(encoded, Bytes::from_static(&[0]));
    }

    #[test]
    fn test_simple_btree_set_u32() {
        let mut set = BTreeSet::new();
        set.insert(1u32);
        set.insert(5u32);
        set.insert(2u32);
        round_trip_btree(&set, allow_any_len(), ());
        assert_eq!(set.encode_size(), 1 + 3 * u32::SIZE);
    }

    #[test]
    fn test_large_btree_set() {
        let set: BTreeSet<_> = (0..1000u16).collect();
        round_trip_btree(&set, 0..=1000, ());
    }

    #[test]
    fn test_btree_set_with_variable_items() {
        let mut set = BTreeSet::new();
        set.insert(Bytes::from_static(b"apple"));
        set.insert(Bytes::from_static(b"banana"));
        set.insert(Bytes::from_static(b"cherry"));

        let set_range = 0..=10;
        let item_range = ..=10; // Range for Bytes length

        round_trip_btree(&set, set_range, item_range);
    }

    #[test]
    fn test_btree_decode_length_limit_exceeded() {
        let mut set = BTreeSet::new();
        set.insert(1u32);
        set.insert(5u32);

        let encoded = set.encode();
        let restrictive_range = 0..=1;
        let config_tuple = (restrictive_range, ());

        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_btree_decode_item_length_limit_exceeded() {
        let mut set = BTreeSet::new();
        set.insert(Bytes::from_static(b"longitem")); // 8 bytes

        let set_range = 0..=10;
        let restrictive_item_range = ..=5; // Limit item length

        let encoded = set.encode();
        let config_tuple = (set_range, restrictive_item_range);
        let result = BTreeSet::<Bytes>::decode_cfg(encoded, &config_tuple);

        assert!(matches!(result, Err(Error::InvalidLength(8))));
    }

    #[test]
    fn test_btree_decode_invalid_item_order() {
        let mut encoded = BytesMut::new();
        varint::write(2u32, &mut encoded); // Set length = 2
        5u32.write(&mut encoded); // Item 5
        2u32.write(&mut encoded); // Item 2 (out of order)

        let range = allow_any_len();
        let config_tuple = (range, ());

        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashSet", "Items must ascend")) // Note: Error message uses HashSet currently
        ));
    }

    #[test]
    fn test_btree_decode_duplicate_item() {
        let mut encoded = BytesMut::new();
        varint::write(2u32, &mut encoded); // Set length = 2
        1u32.write(&mut encoded); // Item 1
        1u32.write(&mut encoded); // Duplicate Item 1

        let range = allow_any_len();
        let config_tuple = (range, ());

        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashSet", "Duplicate item")) // Note: Error message uses HashSet currently
        ));
    }

    #[test]
    fn test_btree_decode_end_of_buffer() {
        let mut set = BTreeSet::new();
        set.insert(1u32);
        set.insert(5u32);

        let mut encoded = set.encode();
        encoded.truncate(set.encode_size() - 2); // Truncate during last item

        let range = allow_any_len();
        let config_tuple = (range, ());
        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_btree_decode_extra_data() {
        let mut set = BTreeSet::new();
        set.insert(1u32);

        let mut encoded = set.encode();
        encoded.put_u8(0xFF); // Add extra byte

        let range = allow_any_len();
        let config_tuple = (range.clone(), ()); // Clone range for read_cfg later

        // Use decode_cfg which enforces buffer is fully consumed
        let result = BTreeSet::<u32>::decode_cfg(encoded.clone(), &config_tuple);
        assert!(matches!(result, Err(Error::ExtraData(1))));

        // Verify that read_cfg would succeed (doesn't check for extra data)
        let read_result = BTreeSet::<u32>::read_cfg(&mut encoded.clone(), &config_tuple);
        assert!(read_result.is_ok());
        let decoded_set = read_result.unwrap();
        assert_eq!(decoded_set.len(), 1);
        assert!(decoded_set.contains(&1u32));
    }

    // --- HashSet Tests ---

    #[test]
    fn test_empty_hash_set() {
        let set = HashSet::<u32>::new();
        round_trip_hash(&set, allow_any_len(), ());
        assert_eq!(set.encode_size(), 1); // varint 0
        let encoded = set.encode();
        assert_eq!(encoded, Bytes::from_static(&[0]));
    }

    #[test]
    fn test_simple_hash_set_u32() {
        let mut set = HashSet::new();
        set.insert(1u32);
        set.insert(5u32);
        set.insert(2u32);
        round_trip_hash(&set, allow_any_len(), ());
        // Size calculation: varint len + size of each item (order doesn't matter for size)
        assert_eq!(set.encode_size(), 1 + 3 * u32::SIZE);
        // Encoding check: items must be sorted (1, 2, 5)
        let mut expected = BytesMut::new();
        varint::write(3u32, &mut expected);
        1u32.write(&mut expected);
        2u32.write(&mut expected);
        5u32.write(&mut expected);
        assert_eq!(set.encode(), expected.freeze());
    }

    #[test]
    fn test_large_hash_set() {
        let set: HashSet<_> = (0..1000u16).collect();
        round_trip_hash(&set, 0..=1000, ());
    }

    #[test]
    fn test_hash_set_with_variable_items() {
        let mut set = HashSet::new();
        set.insert(Bytes::from_static(b"apple"));
        set.insert(Bytes::from_static(b"banana"));
        set.insert(Bytes::from_static(b"cherry"));

        let set_range = 0..=10;
        let item_range = ..=10; // Range for Bytes length

        round_trip_hash(&set, set_range, item_range);
    }

    #[test]
    fn test_hash_decode_length_limit_exceeded() {
        let mut set = HashSet::new();
        set.insert(1u32);
        set.insert(5u32);

        let encoded = set.encode();
        let restrictive_range = 0..=1;
        let config_tuple = (restrictive_range, ());

        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_hash_decode_item_length_limit_exceeded() {
        let mut set = HashSet::new();
        set.insert(Bytes::from_static(b"longitem")); // 8 bytes

        let set_range = 0..=10;
        let restrictive_item_range = ..=5; // Limit item length

        let encoded = set.encode();
        let config_tuple = (set_range, restrictive_item_range);
        let result = HashSet::<Bytes>::decode_cfg(encoded, &config_tuple);

        assert!(matches!(result, Err(Error::InvalidLength(8))));
    }

    #[test]
    fn test_hash_decode_invalid_item_order() {
        let mut encoded = BytesMut::new();
        varint::write(2u32, &mut encoded); // Set length = 2
        5u32.write(&mut encoded); // Item 5
        2u32.write(&mut encoded); // Item 2 (out of order)

        let range = allow_any_len();
        let config_tuple = (range, ());

        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashSet", "Items must ascend"))
        ));
    }

    #[test]
    fn test_hash_decode_duplicate_item() {
        let mut encoded = BytesMut::new();
        varint::write(2u32, &mut encoded); // Set length = 2
        1u32.write(&mut encoded); // Item 1
        1u32.write(&mut encoded); // Duplicate Item 1

        let range = allow_any_len();
        let config_tuple = (range, ());

        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashSet", "Duplicate item"))
        ));
    }

    #[test]
    fn test_hash_decode_end_of_buffer() {
        let mut set = HashSet::new();
        set.insert(1u32);
        set.insert(5u32);

        let mut encoded = set.encode(); // Will be sorted: [1, 5]
        encoded.truncate(set.encode_size() - 2); // Truncate during last item (5)

        let range = allow_any_len();
        let config_tuple = (range, ());
        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_hash_decode_extra_data() {
        let mut set = HashSet::new();
        set.insert(1u32);

        let mut encoded = set.encode();
        encoded.put_u8(0xFF); // Add extra byte

        let range = allow_any_len();
        let config_tuple = (range.clone(), ()); // Clone range for read_cfg later

        // Use decode_cfg which enforces buffer is fully consumed
        let result = HashSet::<u32>::decode_cfg(encoded.clone(), &config_tuple);
        assert!(matches!(result, Err(Error::ExtraData(1))));

        // Verify that read_cfg would succeed (doesn't check for extra data)
        let read_result = HashSet::<u32>::read_cfg(&mut encoded.clone(), &config_tuple);
        assert!(read_result.is_ok());
        let decoded_set = read_result.unwrap();
        assert_eq!(decoded_set.len(), 1);
        assert!(decoded_set.contains(&1u32));
    }
}
