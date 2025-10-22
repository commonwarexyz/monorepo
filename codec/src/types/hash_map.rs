//! Codec implementations for HashMap (requires std).
//!
//! For portability and consistency between architectures,
//! the size of the map must fit within a [u32].

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    RangeCfg,
};
use bytes::{Buf, BufMut};
use std::{cmp::Ordering, collections::HashMap, hash::Hash};

const HASHMAP_TYPE: &str = "HashMap";

/// Read keyed items from [Buf] in ascending order.
fn read_ordered_map<K, V, F>(
    buf: &mut impl Buf,
    len: usize,
    k_cfg: &K::Cfg,
    v_cfg: &V::Cfg,
    mut insert: F,
    map_type: &'static str,
) -> Result<(), Error>
where
    K: Read + Ord,
    V: Read,
    F: FnMut(K, V) -> Option<V>,
{
    let mut last: Option<(K, V)> = None;
    for _ in 0..len {
        // Read key
        let key = K::read_cfg(buf, k_cfg)?;

        // Check if keys are in ascending order relative to the previous key
        if let Some((ref last_key, _)) = last {
            match key.cmp(last_key) {
                Ordering::Equal => return Err(Error::Invalid(map_type, "Duplicate key")),
                Ordering::Less => return Err(Error::Invalid(map_type, "Keys must ascend")),
                _ => {}
            }
        }

        // Read value
        let value = V::read_cfg(buf, v_cfg)?;

        // Add previous item, if exists
        if let Some((last_key, last_value)) = last.take() {
            insert(last_key, last_value);
        }
        last = Some((key, value));
    }

    // Add last item, if exists
    if let Some((last_key, last_value)) = last {
        insert(last_key, last_value);
    }

    Ok(())
}

// ---------- HashMap ----------

impl<K: Ord + Hash + Eq + Write, V: Write> Write for HashMap<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);

        // Sort the keys to ensure deterministic encoding
        let mut entries: Vec<_> = self.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in entries {
            k.write(buf);
            v.write(buf);
        }
    }
}

impl<K: Ord + Hash + Eq + EncodeSize, V: EncodeSize> EncodeSize for HashMap<K, V> {
    fn encode_size(&self) -> usize {
        // Start with the size of the length prefix
        let mut size = self.len().encode_size();

        // Add the encoded size of each key and value
        // Note: Iteration order doesn't matter for size calculation.
        for (k, v) in self {
            size += k.encode_size();
            size += v.encode_size();
        }
        size
    }
}

// Read implementation for HashMap
impl<K: Read + Clone + Ord + Hash + Eq, V: Read + Clone> Read for HashMap<K, V> {
    type Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg));

    fn read_cfg(buf: &mut impl Buf, (range, (k_cfg, v_cfg)): &Self::Cfg) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len = usize::read_cfg(buf, range)?;
        let mut map = HashMap::with_capacity(len);

        // Read items in ascending order
        read_ordered_map(
            buf,
            len,
            k_cfg,
            v_cfg,
            |k, v| map.insert(k, v),
            HASHMAP_TYPE,
        )?;

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, Encode, FixedSize};
    use bytes::{Bytes, BytesMut};
    use std::fmt::Debug;

    // Manual round trip test function for HashMap with non-default configs
    fn round_trip_hash<K, V, KCfg, VCfg>(
        map: &HashMap<K, V>,
        range_cfg: RangeCfg<usize>,
        k_cfg: KCfg,
        v_cfg: VCfg,
    ) where
        K: Write + EncodeSize + Read<Cfg = KCfg> + Clone + Ord + Hash + Eq + PartialEq + Debug,
        V: Write + EncodeSize + Read<Cfg = VCfg> + Clone + PartialEq + Debug,
        HashMap<K, V>: Read<Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg))>
            + Decode<Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg))>
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = map.encode();
        assert_eq!(encoded.len(), map.encode_size());
        let config_tuple = (range_cfg, (k_cfg, v_cfg));
        let decoded = HashMap::<K, V>::decode_cfg(encoded, &config_tuple)
            .expect("decode_cfg failed for HashMap");
        assert_eq!(map, &decoded);
    }

    // --- HashMap Tests ---

    #[test]
    fn test_empty_hashmap() {
        let map = HashMap::<u32, u64>::new();
        round_trip_hash(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1);
        let encoded = map.encode();
        assert_eq!(encoded, 0usize.encode());
    }

    #[test]
    fn test_simple_hashmap_u32_u64() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);
        map.insert(2u32, 200u64);
        round_trip_hash(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1 + 3 * (u32::SIZE + u64::SIZE));
    }

    #[test]
    fn test_large_hashmap() {
        // Fixed-size items
        let mut map = HashMap::new();
        for i in 0..1000 {
            map.insert(i as u16, i as u64 * 2);
        }
        round_trip_hash(&map, (0..=1000).into(), (), ());

        // Variable-size items
        let mut map = HashMap::new();
        for i in 0..1000usize {
            map.insert(i, 1000usize + i);
        }
        round_trip_hash(
            &map,
            (0..=1000).into(),
            (..=1000).into(),
            (1000..=2000).into(),
        );
    }

    #[test]
    fn test_hashmap_with_variable_values() {
        let mut map = HashMap::new();
        map.insert(Bytes::from_static(b"apple"), vec![1, 2]);
        map.insert(Bytes::from_static(b"banana"), vec![3, 4, 5]);
        map.insert(Bytes::from_static(b"cherry"), vec![]);

        let map_range = RangeCfg::from(0..=10);
        let key_range = RangeCfg::from(..=10);
        let val_range = RangeCfg::from(0..=100);

        round_trip_hash(&map, map_range, key_range, (val_range, ()));
    }

    #[test]
    fn test_hashmap_decode_length_limit_exceeded() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let encoded = map.encode();
        let config_tuple = ((0..=1).into(), ((), ()));

        let result = HashMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_hashmap_decode_value_length_limit_exceeded() {
        let mut map = HashMap::new();
        map.insert(Bytes::from_static(b"key1"), vec![1u8, 2u8, 3u8, 4u8, 5u8]);

        let key_range = RangeCfg::from(..=10);
        let map_range = RangeCfg::from(0..=10);
        let restrictive_val_range = RangeCfg::from(0..=3);

        let encoded = map.encode();
        let config_tuple = (map_range, (key_range, (restrictive_val_range, ())));
        let result = HashMap::<Bytes, Vec<u8>>::decode_cfg(encoded, &config_tuple);

        assert!(matches!(result, Err(Error::InvalidLength(5))));
    }

    #[test]
    fn test_hashmap_decode_invalid_key_order() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Map length = 2
        5u32.write(&mut encoded); // Key 5
        500u64.write(&mut encoded); // Value 500
        2u32.write(&mut encoded); // Key 2 (out of order)
        200u64.write(&mut encoded); // Value 200

        let range = (..).into();
        let config_tuple = (range, ((), ()));

        let result = HashMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashMap", "Keys must ascend"))
        ));
    }

    #[test]
    fn test_hashmap_decode_duplicate_key() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Map length = 2
        1u32.write(&mut encoded); // Key 1
        100u64.write(&mut encoded); // Value 100
        1u32.write(&mut encoded); // Duplicate Key 1
        200u64.write(&mut encoded); // Value 200

        let range = (..).into();
        let config_tuple = (range, ((), ()));

        let result = HashMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashMap", "Duplicate key"))
        ));
    }

    #[test]
    fn test_hashmap_decode_end_of_buffer_key() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let mut encoded = map.encode();
        encoded.truncate(map.encode_size() - 10); // Truncate during last key/value pair

        let range = (..).into();
        let config_tuple = (range, ((), ()));
        let result = HashMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_hashmap_decode_end_of_buffer_value() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let mut encoded = map.encode();
        encoded.truncate(map.encode_size() - 4); // Truncate during last value

        let range = RangeCfg::from(..);
        let config_tuple = (range, ((), ()));
        let result = HashMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_hashmap_decode_extra_data() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);

        let mut encoded = map.encode();
        encoded.put_u8(0xFF); // Add extra byte

        // Use decode_cfg which enforces buffer is fully consumed
        let config_tuple = ((..).into(), ((), ()));
        let result = HashMap::<u32, u64>::decode_cfg(encoded.clone(), &config_tuple);
        assert!(matches!(result, Err(Error::ExtraData(1))));

        // Verify that read_cfg would succeed (doesn't check for extra data)
        let read_result = HashMap::<u32, u64>::read_cfg(&mut encoded, &config_tuple);
        assert!(read_result.is_ok());
        let decoded_map = read_result.unwrap();
        assert_eq!(decoded_map.len(), 1);
        assert_eq!(decoded_map.get(&1u32), Some(&100u64));
    }

    #[test]
    fn test_hashmap_deterministic_encoding() {
        // In-order
        let mut map2 = HashMap::new();
        (0..=1000u32).for_each(|i| {
            map2.insert(i, i * 2);
        });

        // Reverse order
        let mut map1 = HashMap::new();
        (0..=1000u32).rev().for_each(|i| {
            map1.insert(i, i * 2);
        });

        assert_eq!(map1.encode(), map2.encode());
    }

    #[test]
    fn test_hashmap_conformity() {
        // Case 1: Empty HashMap<u8, u16>
        let map1 = HashMap::<u8, u16>::new();
        let mut expected1 = BytesMut::new();
        0usize.write(&mut expected1); // Length 0
        assert_eq!(map1.encode(), expected1.freeze());

        // Case 2: Simple HashMap<u8, u16>
        // Keys are sorted for encoding: 1, 2
        let mut map2 = HashMap::<u8, u16>::new();
        map2.insert(2u8, 0xBBBBu16); // Inserted out of order
        map2.insert(1u8, 0xAAAAu16);

        let mut expected2 = BytesMut::new();
        2usize.write(&mut expected2); // Length 2
        1u8.write(&mut expected2); // Key 1
        0xAAAAu16.write(&mut expected2); // Value for key 1
        2u8.write(&mut expected2); // Key 2
        0xBBBBu16.write(&mut expected2); // Value for key 2
        assert_eq!(map2.encode(), expected2.freeze());

        // Case 3: HashMap<u16, bool>
        // Keys are sorted for encoding: 0x0101, 0x0202, 0x0303
        let mut map3 = HashMap::<u16, bool>::new();
        map3.insert(0x0303u16, true);
        map3.insert(0x0101u16, false);
        map3.insert(0x0202u16, true);

        let mut expected3 = BytesMut::new();
        3usize.write(&mut expected3); // Length 3
        0x0101u16.write(&mut expected3); // Key 0x0101
        false.write(&mut expected3); // Value false (0x00)
        0x0202u16.write(&mut expected3); // Key 0x0202
        true.write(&mut expected3); // Value true (0x01)
        0x0303u16.write(&mut expected3); // Key 0x0303
        true.write(&mut expected3); // Value true (0x01)
        assert_eq!(map3.encode(), expected3.freeze());

        // Case 4: HashMap with Bytes as key and Vec<u8> as value
        // Keys are sorted for encoding: "a", "b"
        let mut map4 = HashMap::<Bytes, Vec<u8>>::new();
        map4.insert(Bytes::from_static(b"b"), vec![20u8, 21u8]);
        map4.insert(Bytes::from_static(b"a"), vec![10u8]);

        let mut expected4 = BytesMut::new();
        2usize.write(&mut expected4); // Map length = 2

        // Key "a" (length 1, 'a')
        Bytes::from_static(b"a").write(&mut expected4);
        // Value vec![10u8] (length 1, 10u8)
        vec![10u8].write(&mut expected4);

        // Key "b" (length 1, 'b')
        Bytes::from_static(b"b").write(&mut expected4);
        // Value vec![20u8, 21u8] (length 2, 20u8, 21u8)
        vec![20u8, 21u8].write(&mut expected4);

        assert_eq!(map4.encode(), expected4.freeze());
    }
}
