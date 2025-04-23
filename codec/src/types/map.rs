//! Codec implementations for various map types.
//!
//! For portability and consistency between architectures,
//! the size of the map must fit within a [`u32`].

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    RangeCfg,
};
use bytes::{Buf, BufMut};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

// ---------- BTreeMap ----------

impl<K: Ord + Hash + Eq + Write, V: Write> Write for BTreeMap<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);

        // Keys are already sorted in BTreeMap, so we can iterate directly
        for (key, value) in self {
            key.write(buf);
            value.write(buf);
        }
    }
}

impl<K: Ord + Hash + Eq + EncodeSize, V: EncodeSize> EncodeSize for BTreeMap<K, V> {
    fn encode_size(&self) -> usize {
        // Start with the varint size of the length
        let mut size = self.len().encode_size();

        // Add the encoded size of each key and value
        for (key, value) in self {
            size += key.encode_size();
            size += value.encode_size();
        }
        size
    }
}

impl<K: Read + Clone + Ord + Hash + Eq, V: Read + Clone> Read for BTreeMap<K, V> {
    type Cfg = (RangeCfg, (K::Cfg, V::Cfg));

    fn read_cfg(buf: &mut impl Buf, (range, (k_cfg, v_cfg)): &Self::Cfg) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len = usize::read_cfg(buf, range)?;
        let mut map = BTreeMap::new(); // BTreeMap does not have a capacity method

        // Keep track of the last key read
        let mut last_key: Option<K> = None;

        // Read each key-value pair
        for _ in 0..len {
            let key = K::read_cfg(buf, k_cfg)?;

            // Check if keys are in ascending order relative to the previous key
            if let Some(ref last) = last_key {
                match key.cmp(last) {
                    Ordering::Equal => return Err(Error::Invalid("HashMap", "Duplicate key")),
                    Ordering::Less => return Err(Error::Invalid("HashMap", "Keys must ascend")),
                    _ => {}
                }
            }
            last_key = Some(key.clone());

            let value = V::read_cfg(buf, v_cfg)?;
            map.insert(key, value);
        }

        Ok(map)
    }
}

// ---------- HashMap ----------

impl<K: Ord + Hash + Eq + Write, V: Write> Write for HashMap<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);

        // Sort the keys to ensure deterministic encoding
        let mut keys: Vec<_> = self.keys().collect();
        keys.sort();
        for key in keys {
            key.write(buf);
            self.get(key).unwrap().write(buf);
        }
    }
}

impl<K: Ord + Hash + Eq + EncodeSize, V: EncodeSize> EncodeSize for HashMap<K, V> {
    fn encode_size(&self) -> usize {
        // Start with the size of the length prefix
        let mut size = self.len().encode_size();

        // Add the encoded size of each key and value
        // Note: Iteration order doesn't matter for size calculation.
        for (key, value) in self {
            size += key.encode_size();
            size += value.encode_size();
        }
        size
    }
}

// Read implementation for HashMap
impl<K: Read + Clone + Ord + Hash + Eq, V: Read + Clone> Read for HashMap<K, V> {
    type Cfg = (RangeCfg, (K::Cfg, V::Cfg));

    fn read_cfg(buf: &mut impl Buf, (range, (k_cfg, v_cfg)): &Self::Cfg) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len = usize::read_cfg(buf, range)?;
        let mut map = HashMap::with_capacity(len);

        // Keep track of the last key read
        let mut last_key: Option<K> = None;

        // Read each key-value pair
        for _ in 0..len {
            let key = K::read_cfg(buf, k_cfg)?;

            // Check if keys are in ascending order relative to the previous key
            if let Some(ref last) = last_key {
                match key.cmp(last) {
                    Ordering::Equal => return Err(Error::Invalid("HashMap", "Duplicate key")),
                    Ordering::Less => return Err(Error::Invalid("HashMap", "Keys must ascend")),
                    _ => {}
                }
            }
            last_key = Some(key.clone());

            let value = V::read_cfg(buf, v_cfg)?;
            map.insert(key, value);
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, Encode, FixedSize};
    use bytes::{Bytes, BytesMut};
    use std::fmt::Debug;

    // Manual round trip test function for BTreeMap with non-default configs
    fn round_trip_btree<K, V, KCfg, VCfg>(
        map: &BTreeMap<K, V>,
        range_cfg: RangeCfg,
        k_cfg: KCfg,
        v_cfg: VCfg,
    ) where
        K: Write + EncodeSize + Read<Cfg = KCfg> + Clone + Ord + Hash + Eq + PartialEq + Debug,
        V: Write + EncodeSize + Read<Cfg = VCfg> + Clone + PartialEq + Debug,
        BTreeMap<K, V>: Read<Cfg = (RangeCfg, (K::Cfg, V::Cfg))>
            + Decode<Cfg = (RangeCfg, (K::Cfg, V::Cfg))>
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = map.encode();
        let config_tuple = (range_cfg, (k_cfg, v_cfg));
        let decoded = BTreeMap::<K, V>::decode_cfg(encoded, &config_tuple)
            .expect("decode_cfg failed for BTreeMap");
        assert_eq!(map, &decoded);
    }

    fn round_trip_hash<K, V, KCfg, VCfg>(
        map: &HashMap<K, V>,
        range_cfg: RangeCfg,
        k_cfg: KCfg,
        v_cfg: VCfg,
    ) where
        K: Write + EncodeSize + Read<Cfg = KCfg> + Clone + Ord + Hash + Eq + PartialEq + Debug,
        V: Write + EncodeSize + Read<Cfg = VCfg> + Clone + PartialEq + Debug,
        HashMap<K, V>: Read<Cfg = (RangeCfg, (K::Cfg, V::Cfg))>
            + Decode<Cfg = (RangeCfg, (K::Cfg, V::Cfg))>
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = map.encode();
        let config_tuple = (range_cfg, (k_cfg, v_cfg));
        let decoded = HashMap::<K, V>::decode_cfg(encoded, &config_tuple)
            .expect("decode_cfg failed for HashMap");
        assert_eq!(map, &decoded);
    }

    // Manual round trip test function for non-default configs
    fn round_trip<K, V>(map: &HashMap<K, V>, range_cfg: RangeCfg, k_cfg: K::Cfg, v_cfg: V::Cfg)
    where
        K: Write + EncodeSize + Read + Clone + Ord + Hash + Eq + PartialEq + Debug,
        V: Write + EncodeSize + Read + Clone + PartialEq + Debug,
        HashMap<K, V>: Read<Cfg = (RangeCfg, (K::Cfg, V::Cfg))> + PartialEq + Write + EncodeSize,
    {
        let encoded = map.encode();
        let config_tuple = (range_cfg, (k_cfg, v_cfg));
        let decoded = HashMap::<K, V>::decode_cfg(encoded, &config_tuple)
            .expect("decode_cfg failed for HashMap");
        assert_eq!(map, &decoded);
    }

    // --- BTreeMap Tests ---

    #[test]
    fn test_empty_btree_map() {
        let map = BTreeMap::<u32, u64>::new();
        round_trip_btree(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1); // varint 0
        let encoded = map.encode();
        assert_eq!(encoded, Bytes::from_static(&[0]));
    }

    #[test]
    fn test_simple_btree_map_u32_u64() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);
        map.insert(2u32, 200u64);
        round_trip_btree(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1 + 3 * (u32::SIZE + u64::SIZE));
        // Check encoding order (BTreeMap guarantees sorted keys: 1, 2, 5)
        let mut expected = BytesMut::new();
        3usize.write(&mut expected);
        1u32.write(&mut expected);
        100u64.write(&mut expected);
        2u32.write(&mut expected);
        200u64.write(&mut expected);
        5u32.write(&mut expected);
        500u64.write(&mut expected);
        assert_eq!(map.encode(), expected.freeze());
    }

    #[test]
    fn test_large_btree_map() {
        let mut map = BTreeMap::new();
        for i in 0..1000 {
            map.insert(i as u16, i as u64 * 2);
        }
        round_trip_btree(&map, (0..=1000).into(), (), ());
    }

    #[test]
    fn test_btree_map_with_variable_values() {
        let mut map = BTreeMap::new();
        map.insert(Bytes::from_static(b"apple"), vec![1, 2]);
        map.insert(Bytes::from_static(b"banana"), vec![3, 4, 5]);
        map.insert(Bytes::from_static(b"cherry"), vec![]);

        let map_range = 0..=10;
        let key_range = ..=10;
        let val_range = 0..=100;

        round_trip_btree(
            &map,
            map_range.into(),
            key_range.into(),
            (val_range.into(), ()),
        );
    }

    #[test]
    fn test_btree_decode_length_limit_exceeded() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let encoded = map.encode();
        let config_tuple = ((0..=1).into(), ((), ()));

        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_btree_decode_value_length_limit_exceeded() {
        let mut map = BTreeMap::new();
        map.insert(Bytes::from_static(b"key1"), vec![1, 2, 3, 4, 5]);

        let key_range = ..=10;
        let map_range = 0..=10;
        let restrictive_val_range = 0..=3;

        let encoded = map.encode();
        let config_tuple = (
            map_range.into(),
            (key_range.into(), (restrictive_val_range.into(), ())),
        );
        let result = BTreeMap::<Bytes, Vec<u8>>::decode_cfg(encoded, &config_tuple);

        assert!(matches!(result, Err(Error::InvalidLength(5))));
    }

    #[test]
    fn test_btree_decode_invalid_key_order() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Map length = 2
        5u32.write(&mut encoded); // Key 5
        500u64.write(&mut encoded); // Value 500
        2u32.write(&mut encoded); // Key 2 (out of order)
        200u64.write(&mut encoded); // Value 200

        let range = (..).into();
        let config_tuple = (range, ((), ()));

        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        // Note: Error message uses HashMap currently, should ideally be BTreeMap
        assert!(matches!(
            result,
            Err(Error::Invalid("HashMap", "Keys must ascend"))
        ));
    }

    #[test]
    fn test_btree_decode_duplicate_key() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Map length = 2
        1u32.write(&mut encoded); // Key 1
        100u64.write(&mut encoded); // Value 100
        1u32.write(&mut encoded); // Duplicate Key 1
        200u64.write(&mut encoded); // Value 200

        let range = (..).into();
        let config_tuple = (range, ((), ()));

        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        // Note: Error message uses HashMap currently, should ideally be BTreeMap
        assert!(matches!(
            result,
            Err(Error::Invalid("HashMap", "Duplicate key"))
        ));
    }

    #[test]
    fn test_btree_decode_end_of_buffer_key() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let mut encoded = map.encode();
        encoded.truncate(map.encode_size() - 10); // Truncate during last key/value pair (key 5)

        let range = (..).into();
        let config_tuple = (range, ((), ()));
        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_btree_decode_end_of_buffer_value() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let mut encoded = map.encode();
        encoded.truncate(map.encode_size() - 4); // Truncate during last value (for key 5)

        let range = (..).into();
        let config_tuple = (range, ((), ()));
        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_btree_decode_extra_data() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);

        let mut encoded = map.encode();
        encoded.put_u8(0xFF); // Add extra byte

        // Use decode_cfg which enforces buffer is fully consumed
        let config_tuple = ((..).into(), ((), ()));
        let result = BTreeMap::<u32, u64>::decode_cfg(encoded.clone(), &config_tuple);
        assert!(matches!(result, Err(Error::ExtraData(1))));

        // Verify that read_cfg would succeed (doesn't check for extra data)
        let read_result = BTreeMap::<u32, u64>::read_cfg(&mut encoded.clone(), &config_tuple);
        assert!(read_result.is_ok());
        let decoded_map = read_result.unwrap();
        assert_eq!(decoded_map.len(), 1);
        assert_eq!(decoded_map.get(&1u32), Some(&100u64));
    }

    // --- HashMap Tests ---

    #[test]
    fn test_empty_map() {
        let map = HashMap::<u32, u64>::new();
        round_trip_hash(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1);
        let encoded = map.encode();
        assert_eq!(encoded, 0usize.encode());
    }

    #[test]
    fn test_simple_map_u32_u64() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);
        map.insert(2u32, 200u64);
        round_trip(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1 + 3 * (u32::SIZE + u64::SIZE));
    }

    #[test]
    fn test_large_map() {
        let mut map = HashMap::new();
        for i in 0..1000 {
            map.insert(i, i as u64 * 2);
        }
        round_trip(&map, (..=1000).into(), (), ());
    }

    #[test]
    fn test_map_with_variable_values() {
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
    fn test_decode_length_limit_exceeded() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let encoded = map.encode();
        let config_tuple = ((0..=1).into(), ((), ()));

        let result = HashMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_decode_value_length_limit_exceeded() {
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
    fn test_decode_invalid_key_order() {
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
    fn test_decode_duplicate_key() {
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
    fn test_decode_end_of_buffer_key() {
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
    fn test_decode_end_of_buffer_value() {
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
    fn test_decode_extra_data() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);

        let mut encoded = map.encode();
        encoded.put_u8(0xFF); // Add extra byte

        let range = RangeCfg::from(..);
        let config_tuple = (range, ((), ()));

        // Use decode_cfg which enforces buffer is fully consumed
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
    fn test_conformity() {
        let mut map1 = HashMap::<u8, u16>::new();
        assert_eq!(map1.encode(), &[0x00][..]); // Empty map

        map1.insert(1u8, 0xAAAAu16);
        map1.insert(2u8, 0xBBBBu16);
        // Expected: len=2 (0x02)
        // Key 1 (0x01), Value 0xAAAA (0xAA, 0xAA)
        // Key 2 (0x02), Value 0xBBBB (0xBB, 0xBB)
        // Keys are sorted for encoding.
        assert_eq!(
            map1.encode(),
            &[0x02, 0x01, 0xAA, 0xAA, 0x02, 0xBB, 0xBB][..]
        );

        let mut map2 = HashMap::<u16, bool>::new();
        map2.insert(0x0303u16, true);
        map2.insert(0x0101u16, false);
        map2.insert(0x0202u16, true);
        // Expected: len=3 (0x03)
        // Key 0x0101, Value false (0x00)
        // Key 0x0202, Value true (0x01)
        // Key 0x0303, Value true (0x01)
        assert_eq!(
            map2.encode(),
            &[0x03, 0x01, 0x01, 0x00, 0x02, 0x02, 0x01, 0x03, 0x03, 0x01][..]
        );

        // Map with Bytes as key and Vec<u8> as value
        let mut map3 = HashMap::<Bytes, Vec<u8>>::new();
        map3.insert(Bytes::from_static(b"b"), vec![20u8, 21u8]);
        map3.insert(Bytes::from_static(b"a"), vec![10u8]);
        // Expected: len=2 (0x02)
        // Key "a": len=1 (0x01), 'a' (0x61)
        // Value vec![10u8]: len=1 (0x01), 10u8 (0x0A)
        // Key "b": len=1 (0x01), 'b' (0x62)
        // Value vec![20u8, 21u8]: len=2 (0x02), 20u8 (0x14), 21u8 (0x15)
        let mut expected_map3 = vec![0x02]; // Map length
        expected_map3.extend_from_slice(&[0x01, 0x61]); // Key "a"
        expected_map3.extend_from_slice(&[0x01, 0x0A]); // Value vec![10u8]
        expected_map3.extend_from_slice(&[0x01, 0x62]); // Key "b"
        expected_map3.extend_from_slice(&[0x02, 0x14, 0x15]); // Value vec![20u8, 21u8]
        assert_eq!(map3.encode(), expected_map3.as_slice());
    }
}
