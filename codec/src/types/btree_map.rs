//! Codec implementations for no_std compatible map types.
//!
//! For portability and consistency between architectures,
//! the size of the map must fit within a [u32].

extern crate alloc;

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    RangeCfg,
};
use alloc::collections::BTreeMap;
use bytes::{Buf, BufMut};
use core::cmp::Ordering;

const BTREEMAP_TYPE: &str = "BTreeMap";

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

// ---------- BTreeMap ----------

impl<K: Ord + Eq + Write, V: Write> Write for BTreeMap<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);

        // Keys are already sorted in BTreeMap, so we can iterate directly
        for (k, v) in self {
            k.write(buf);
            v.write(buf);
        }
    }
}

impl<K: Ord + Eq + EncodeSize, V: EncodeSize> EncodeSize for BTreeMap<K, V> {
    fn encode_size(&self) -> usize {
        // Start with the size of the length prefix
        let mut size = self.len().encode_size();

        // Add the encoded size of each key and value
        for (k, v) in self {
            size += k.encode_size();
            size += v.encode_size();
        }
        size
    }
}

impl<K: Read + Clone + Ord + Eq, V: Read + Clone> Read for BTreeMap<K, V> {
    type Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg));

    fn read_cfg(buf: &mut impl Buf, (range, (k_cfg, v_cfg)): &Self::Cfg) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len = usize::read_cfg(buf, range)?;
        let mut map = Self::new();

        // Read items in ascending order
        read_ordered_map(
            buf,
            len,
            k_cfg,
            v_cfg,
            |k, v| map.insert(k, v),
            BTREEMAP_TYPE,
        )?;

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, Encode, FixedSize};
    use bytes::{Bytes, BytesMut};
    use core::fmt::Debug;

    // Manual round trip test function for BTreeMap with non-default configs
    fn round_trip_btree<K, V, KCfg, VCfg>(
        map: &BTreeMap<K, V>,
        range_cfg: RangeCfg<usize>,
        k_cfg: KCfg,
        v_cfg: VCfg,
    ) where
        K: Write + EncodeSize + Read<Cfg = KCfg> + Clone + Ord + Eq + PartialEq + Debug,
        V: Write + EncodeSize + Read<Cfg = VCfg> + Clone + PartialEq + Debug,
        BTreeMap<K, V>: Read<Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg))>
            + Decode<Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg))>
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = map.encode();
        assert_eq!(encoded.len(), map.encode_size());
        let config_tuple = (range_cfg, (k_cfg, v_cfg));
        let decoded = BTreeMap::<K, V>::decode_cfg(encoded, &config_tuple)
            .expect("decode_cfg failed for BTreeMap");
        assert_eq!(map, &decoded);
    }

    #[test]
    fn test_empty_btreemap() {
        let map = BTreeMap::<u32, u64>::new();
        round_trip_btree(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1); // varint 0
        let encoded = map.encode();
        assert_eq!(encoded, Bytes::from_static(&[0]));
    }

    #[test]
    fn test_simple_btreemap_u32_u64() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);
        map.insert(2u32, 200u64);
        round_trip_btree(&map, (..).into(), (), ());
        assert_eq!(map.encode_size(), 1 + 3 * (u32::SIZE + u64::SIZE));
        // Check encoding order (BTreeMap guarantees sorted keys: 1, 2, 5)
        let mut expected = BytesMut::new();
        3usize.write(&mut expected); // Map length = 3
        1u32.write(&mut expected);
        100u64.write(&mut expected);
        2u32.write(&mut expected);
        200u64.write(&mut expected);
        5u32.write(&mut expected);
        500u64.write(&mut expected);
        assert_eq!(map.encode(), expected.freeze());
    }

    #[test]
    fn test_large_btreemap() {
        // Fixed-size items
        let mut map = BTreeMap::new();
        for i in 0..1000 {
            map.insert(i as u16, i as u64 * 2);
        }
        round_trip_btree(&map, (0..=1000).into(), (), ());

        // Variable-size items
        let mut map = BTreeMap::new();
        for i in 0..1000usize {
            map.insert(i, 1000usize + i);
        }
        round_trip_btree(
            &map,
            (0..=1000).into(),
            (..=1000).into(),
            (1000..=2000).into(),
        );
    }

    #[test]
    fn test_btreemap_decode_length_limit_exceeded() {
        let mut map = BTreeMap::new();
        map.insert(1u32, 100u64);
        map.insert(5u32, 500u64);

        let encoded = map.encode();
        let config_tuple = ((0..=1).into(), ((), ()));

        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_btreemap_decode_invalid_key_order() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Map length = 2
        5u32.write(&mut encoded); // Key 5
        500u64.write(&mut encoded); // Value 500
        2u32.write(&mut encoded); // Key 2 (out of order)
        200u64.write(&mut encoded); // Value 200

        let range = (..).into();
        let config_tuple = (range, ((), ()));

        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("BTreeMap", "Keys must ascend"))
        ));
    }

    #[test]
    fn test_btreemap_decode_duplicate_key() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Map length = 2
        1u32.write(&mut encoded); // Key 1
        100u64.write(&mut encoded); // Value 100
        1u32.write(&mut encoded); // Duplicate Key 1
        200u64.write(&mut encoded); // Value 200

        let range = (..).into();
        let config_tuple = (range, ((), ()));

        let result = BTreeMap::<u32, u64>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("BTreeMap", "Duplicate key"))
        ));
    }

    #[test]
    fn test_btreemap_deterministic_encoding() {
        // In-order
        let mut map2 = BTreeMap::new();
        (0..=1000u32).for_each(|i| {
            map2.insert(i, i * 2);
        });

        // Reverse order
        let mut map1 = BTreeMap::new();
        (0..=1000u32).rev().for_each(|i| {
            map1.insert(i, i * 2);
        });

        assert_eq!(map1.encode(), map2.encode());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;

        crate::conformance_tests! {
            BTreeMap<u32, u32>,
        }
    }
}
