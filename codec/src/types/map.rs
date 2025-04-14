//! Codec implementations for HashMap.
//!
//! For portability and consistency between architectures,
//! the size of the map must fit within a [`u32`].

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    varint, Config, Pair, RangeConfig,
};
use bytes::{Buf, BufMut};
use std::{collections::HashMap, hash::Hash};

// Write implementation for HashMap
impl<K: Ord + Hash + Eq + Write, V: Write> Write for HashMap<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        let len = u32::try_from(self.len()).expect("HashMap length exceeds u32::MAX");
        varint::write(len, buf);

        // Sort the keys to ensure deterministic encoding
        let mut keys: Vec<_> = self.keys().collect();
        keys.sort();
        for key in keys {
            key.write(buf);
            self.get(key).unwrap().write(buf);
        }
    }
}

// EncodeSize implementation for HashMap
impl<K: Ord + Hash + Eq + EncodeSize, V: EncodeSize> EncodeSize for HashMap<K, V> {
    fn encode_size(&self) -> usize {
        // Start with the varint size of the length
        let len = u32::try_from(self.len()).expect("HashMap length exceeds u32::MAX");
        let mut size = varint::size(len);

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
impl<
        R: RangeConfig,
        KCfg: Config,
        VCfg: Config,
        K: Read<KCfg> + Clone + Ord + Hash + Eq,
        V: Read<VCfg> + Clone,
    > Read<Pair<R, Pair<KCfg, VCfg>>> for HashMap<K, V>
{
    fn read_cfg(
        buf: &mut impl Buf,
        Pair(range, Pair(k_cfg, v_cfg)): Pair<R, Pair<KCfg, VCfg>>,
    ) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len32 = varint::read::<u32>(buf)?;
        let len = usize::try_from(len32).map_err(|_| Error::InvalidVarint)?;
        if !range.contains(&len) {
            return Err(Error::InvalidLength(len));
        }
        let mut map = HashMap::with_capacity(len);

        // Keep track of the last key read
        let mut last_key: Option<K> = None;

        // Read each key-value pair
        for _ in 0..len {
            let key = K::read_cfg(buf, k_cfg)?;

            // Check if keys are in ascending order relative to the previous key
            if let Some(ref last) = last_key {
                use std::cmp::Ordering;
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
    use crate::{
        codec::{Decode, Encode, EncodeSize, FixedSize, Read, Write},
        error::Error,
        varint, Config, DecodeRangeExt, RangeConfig, ReadRangeExt,
    };
    use bytes::{BufMut, Bytes, BytesMut};
    use std::{collections::HashMap, fmt::Debug, hash::Hash};

    // Manual round trip test function for non-default configs
    fn round_trip<K, V, R, KCfg, VCfg>(map: &HashMap<K, V>, range_cfg: R, k_cfg: KCfg, v_cfg: VCfg)
    where
        K: Write + EncodeSize + Read<KCfg> + Clone + Ord + Hash + Eq + Debug + PartialEq,
        V: Write + EncodeSize + Read<VCfg> + Clone + Debug + PartialEq,
        R: RangeConfig + Clone,
        KCfg: Config + Clone,
        VCfg: Config + Clone,
        HashMap<K, V>: Read<Pair<R, Pair<KCfg, VCfg>>>
            + Decode<Pair<R, Pair<KCfg, VCfg>>>
            + Debug
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = map.encode();
        let config_tuple = Pair(range_cfg, Pair(k_cfg, v_cfg));
        let decoded =
            HashMap::<K, V>::decode_cfg(encoded, config_tuple).expect("decode_cfg failed");
        assert_eq!(map, &decoded);
    }

    #[test]
    fn test_empty_map() {
        let map = HashMap::<u32, u64>::new();
        round_trip(&map, .., (), ());
        assert_eq!(map.encode_size(), 1);
        let encoded = map.encode();
        assert_eq!(encoded, Bytes::from_static(&[0])); // varint 0
    }

    #[test]
    fn test_simple_map_u32_u64() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);
        map.insert(2u32, 200u64);
        round_trip(&map, .., (), ());
        assert_eq!(map.encode_size(), 1 + 3 * (u32::SIZE + u64::SIZE));
    }

    #[test]
    fn test_large_map() {
        let mut map = HashMap::new();
        for i in 0..1000 {
            map.insert(i, i as u64 * 2);
        }
        round_trip(&map, 0..=1000, (), ());
    }

    #[test]
    fn test_map_with_variable_values() {
        let mut map = HashMap::new();
        map.insert(Bytes::from_static(b"apple"), vec![1, 2]);
        map.insert(Bytes::from_static(b"banana"), vec![3, 4, 5]);
        map.insert(Bytes::from_static(b"cherry"), vec![]);

        let map_range = 0..=10;
        let key_range = ..=10;
        let val_range = 0..=100;

        round_trip(&map, map_range, key_range, Pair(val_range, ()));
    }

    #[test]
    fn test_decode_length_limit_exceeded() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let encoded = map.encode();
        let result = HashMap::<u32, u64>::decode_range(encoded, 0..=1);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_decode_value_length_limit_exceeded() {
        let mut map = HashMap::new();
        map.insert(Bytes::from_static(b"key1"), vec![1, 2, 3, 4, 5]);

        let encoded = map.encode();
        let config_tuple = Pair(&.., Pair(&.., Pair(0..=3, ())));
        let result = HashMap::<Bytes, Vec<u8>>::decode_cfg(encoded, config_tuple);

        assert!(matches!(result, Err(Error::InvalidLength(5))));
    }

    #[test]
    fn test_decode_invalid_key_order() {
        let mut encoded = BytesMut::new();
        varint::write(2u32, &mut encoded); // Map length = 2
        5u32.write(&mut encoded); // Key 5
        500u64.write(&mut encoded); // Value 500
        2u32.write(&mut encoded); // Key 2 (out of order)
        200u64.write(&mut encoded); // Value 200

        let result = HashMap::<u32, u64>::decode_range(encoded, ..);
        assert!(matches!(
            result,
            Err(Error::Invalid("HashMap", "Keys must ascend"))
        ));
    }

    #[test]
    fn test_decode_duplicate_key() {
        let mut encoded = BytesMut::new();
        varint::write(2u32, &mut encoded); // Map length = 2
        1u32.write(&mut encoded); // Key 1
        100u64.write(&mut encoded); // Value 100
        1u32.write(&mut encoded); // Duplicate Key 1
        200u64.write(&mut encoded); // Value 200

        let result = HashMap::<u32, u64>::decode_range(encoded, ..);
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

        let result = HashMap::<u32, u64>::decode_range(encoded, ..);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_decode_end_of_buffer_value() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let mut encoded = map.encode();
        encoded.truncate(map.encode_size() - 4); // Truncate during last value

        let result = HashMap::<u32, u64>::decode_range(encoded, ..);
        assert!(matches!(result, Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_decode_extra_data() {
        let mut map = HashMap::new();
        map.insert(1u32, 100u64);

        let mut encoded = map.encode();
        encoded.put_u8(0xFF); // Add extra byte

        // Use decode_cfg which enforces buffer is fully consumed
        let result = HashMap::<u32, u64>::decode_range(encoded.clone(), ..);
        assert!(matches!(result, Err(Error::ExtraData(1))));

        // Verify that read_cfg would succeed (doesn't check for extra data)
        let read_result = HashMap::<u32, u64>::read_range(&mut encoded, ..);
        assert!(read_result.is_ok());
        let decoded_map = read_result.unwrap();
        assert_eq!(decoded_map.len(), 1);
        assert_eq!(decoded_map.get(&1u32), Some(&100u64));
    }
}
