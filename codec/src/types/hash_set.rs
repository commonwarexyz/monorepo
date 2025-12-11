//! Codec implementations for HashSet (requires std).
//!
//! For portability and consistency between architectures,
//! the size of the set must fit within a [u32].

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    RangeCfg,
};
use bytes::{Buf, BufMut};
use std::{cmp::Ordering, collections::HashSet, hash::Hash};

const HASHSET_TYPE: &str = "HashSet";

/// Read items from [Buf] in ascending order.
fn read_ordered_set<K, F>(
    buf: &mut impl Buf,
    len: usize,
    cfg: &K::Cfg,
    mut insert: F,
    set_type: &'static str,
) -> Result<(), Error>
where
    K: Read + Ord,
    F: FnMut(K) -> bool,
{
    let mut last: Option<K> = None;
    for _ in 0..len {
        // Read item
        let item = K::read_cfg(buf, cfg)?;

        // Check if items are in ascending order
        if let Some(ref last) = last {
            match item.cmp(last) {
                Ordering::Equal => return Err(Error::Invalid(set_type, "Duplicate item")),
                Ordering::Less => return Err(Error::Invalid(set_type, "Items must ascend")),
                _ => {}
            }
        }

        // Add previous item, if exists
        if let Some(last) = last.take() {
            insert(last);
        }
        last = Some(item);
    }

    // Add last item, if exists
    if let Some(last) = last {
        insert(last);
    }

    Ok(())
}

impl<K: Ord + Hash + Eq + Write> Write for HashSet<K> {
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);

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
        let mut size = self.len().encode_size();

        // Note: Iteration order doesn't matter for size calculation.
        for item in self {
            size += item.encode_size();
        }
        size
    }
}

impl<K: Read + Clone + Ord + Hash + Eq> Read for HashSet<K> {
    type Cfg = (RangeCfg<usize>, K::Cfg);

    fn read_cfg(buf: &mut impl Buf, (range, cfg): &Self::Cfg) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len = usize::read_cfg(buf, range)?;
        let mut set = Self::with_capacity(len);

        // Read items in ascending order
        read_ordered_set(buf, len, cfg, |item| set.insert(item), HASHSET_TYPE)?;

        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{Decode, Encode},
        FixedSize,
    };
    use bytes::{Bytes, BytesMut};
    use std::fmt::Debug;

    // Generic round trip test function for HashSet
    fn round_trip_hash<K>(set: &HashSet<K>, range_cfg: RangeCfg<usize>, item_cfg: K::Cfg)
    where
        K: Write + EncodeSize + Read + Clone + Ord + Hash + Eq + Debug + PartialEq,
        HashSet<K>: Read<Cfg = (RangeCfg<usize>, K::Cfg)>
            + Decode<Cfg = (RangeCfg<usize>, K::Cfg)>
            + Debug
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = set.encode();
        assert_eq!(set.encode_size(), encoded.len());
        let config_tuple = (range_cfg, item_cfg);
        let decoded = HashSet::<K>::decode_cfg(encoded, &config_tuple).expect("decode_cfg failed");
        assert_eq!(set, &decoded);
    }

    // --- HashSet Tests ---

    #[test]
    fn test_empty_hashset() {
        let set = HashSet::<u32>::new();
        round_trip_hash(&set, (..).into(), ());
        assert_eq!(set.encode_size(), 1); // varint 0
        let encoded = set.encode();
        assert_eq!(encoded, Bytes::from_static(&[0]));
    }

    #[test]
    fn test_simple_hashset_u32() {
        let mut set = HashSet::new();
        set.insert(1u32);
        set.insert(5u32);
        set.insert(2u32);
        round_trip_hash(&set, (..).into(), ());
        // Size calculation: varint len + size of each item (order doesn't matter for size)
        assert_eq!(set.encode_size(), 1 + 3 * u32::SIZE);
        // Encoding check: items must be sorted (1, 2, 5)
        let mut expected = BytesMut::new();
        3usize.write(&mut expected); // Set length = 3
        1u32.write(&mut expected);
        2u32.write(&mut expected);
        5u32.write(&mut expected);
        assert_eq!(set.encode(), expected.freeze());
    }

    #[test]
    fn test_large_hashset() {
        // Fixed-size items
        let set: HashSet<_> = (0..1000u16).collect();
        round_trip_hash(&set, (1000..=1000).into(), ());

        // Variable-size items
        let set: HashSet<_> = (0..1000usize).collect();
        round_trip_hash(&set, (1000..=1000).into(), (..=1000).into());
    }

    #[test]
    fn test_hashset_with_variable_items() {
        let mut set = HashSet::new();
        set.insert(Bytes::from_static(b"apple"));
        set.insert(Bytes::from_static(b"banana"));
        set.insert(Bytes::from_static(b"cherry"));

        let set_range = 0..=10;
        let item_range = ..=10; // Range for Bytes length

        round_trip_hash(&set, set_range.into(), item_range.into());
    }

    #[test]
    fn test_hashset_decode_length_limit_exceeded() {
        let mut set = HashSet::new();
        set.insert(1u32);
        set.insert(5u32);

        let encoded = set.encode();
        let config_tuple = ((0..=1).into(), ());

        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_hashset_decode_item_length_limit_exceeded() {
        let mut set = HashSet::new();
        set.insert(Bytes::from_static(b"longitem")); // 8 bytes

        let set_range = 0..=10;
        let restrictive_item_range = ..=5; // Limit item length

        let encoded = set.encode();
        let config_tuple = (set_range.into(), restrictive_item_range.into());
        let result = HashSet::<Bytes>::decode_cfg(encoded, &config_tuple);

        assert!(matches!(result, Err(Error::InvalidLength(8))));
    }

    #[test]
    fn test_hashset_decode_invalid_item_order() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Set length = 2
        5u32.write(&mut encoded); // Item 5
        2u32.write(&mut encoded); // Item 2 (out of order)

        let config_tuple = ((..).into(), ());

        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashSet", "Items must ascend"))
        ));
    }

    #[test]
    fn test_hashset_decode_duplicate_item() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Set length = 2
        1u32.write(&mut encoded); // Item 1
        1u32.write(&mut encoded); // Duplicate Item 1

        let config_tuple = ((..).into(), ());
        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashSet", "Duplicate item"))
        ));
    }

    #[test]
    fn test_hashset_decode_end_of_buffer() {
        let mut set = HashSet::new();
        set.insert(1u32);
        set.insert(5u32);

        let mut encoded = set.encode(); // Will be sorted: [1, 5]
        encoded.truncate(set.encode_size() - 2); // Truncate during last item (5)

        let config_tuple = ((..).into(), ());
        let result = HashSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_hashset_decode_extra_data() {
        let mut set = HashSet::new();
        set.insert(1u32);

        let mut encoded = set.encode();
        encoded.put_u8(0xFF); // Add extra byte

        // Use decode_cfg which enforces buffer is fully consumed
        let config_tuple = ((..).into(), ()); // Clone range for read_cfg later
        let result = HashSet::<u32>::decode_cfg(encoded.clone(), &config_tuple);
        assert!(matches!(result, Err(Error::ExtraData(1))));

        // Verify that read_cfg would succeed (doesn't check for extra data)
        let read_result = HashSet::<u32>::read_cfg(&mut encoded.clone(), &config_tuple);
        assert!(read_result.is_ok());
        let decoded_set = read_result.unwrap();
        assert_eq!(decoded_set.len(), 1);
        assert!(decoded_set.contains(&1u32));
    }

    #[test]
    fn test_hashset_deterministic_encoding() {
        let mut set1 = HashSet::new();
        (0..1000u32).for_each(|i| {
            set1.insert(i);
        });

        let mut set2 = HashSet::new();
        (0..1000u32).rev().for_each(|i| {
            set2.insert(i);
        });

        assert_eq!(set1.encode(), set2.encode());
    }

    #[test]
    fn test_hashset_conformity() {
        // Case 1: Empty HashSet<u8>
        let set1 = HashSet::<u8>::new();
        let mut expected1 = BytesMut::new();
        0usize.write(&mut expected1); // Length 0
        assert_eq!(set1.encode(), expected1.freeze());
        assert_eq!(set1.encode_size(), 1);

        // Case 2: Simple HashSet<u8>
        // HashSet will sort items for encoding: 1, 2, 5
        let mut set2 = HashSet::<u8>::new();
        set2.insert(5u8);
        set2.insert(1u8);
        set2.insert(2u8);

        let mut expected2 = BytesMut::new();
        3usize.write(&mut expected2); // Length 3
        1u8.write(&mut expected2); // Item 1
        2u8.write(&mut expected2); // Item 2
        5u8.write(&mut expected2); // Item 5
        assert_eq!(set2.encode(), expected2.freeze());
        assert_eq!(set2.encode_size(), 1 + 3 * u8::SIZE);

        // Case 3: HashSet<Bytes>
        // HashSet sorts items for encoding: "apple", "banana", "cherry"
        let mut set3 = HashSet::<Bytes>::new();
        set3.insert(Bytes::from_static(b"cherry"));
        set3.insert(Bytes::from_static(b"apple"));
        set3.insert(Bytes::from_static(b"banana"));

        let mut expected3 = BytesMut::new();
        3usize.write(&mut expected3); // Length 3
        Bytes::from_static(b"apple").write(&mut expected3);
        Bytes::from_static(b"banana").write(&mut expected3);
        Bytes::from_static(b"cherry").write(&mut expected3);
        assert_eq!(set3.encode(), expected3.freeze());
        let expected_size = 1usize.encode_size()
            + Bytes::from_static(b"apple").encode_size()
            + Bytes::from_static(b"banana").encode_size()
            + Bytes::from_static(b"cherry").encode_size();
        assert_eq!(set3.encode_size(), expected_size);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;

        crate::conformance_tests! {
            HashSet<u32>
        }
    }
}
