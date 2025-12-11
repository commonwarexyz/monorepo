//! Codec implementations for no_std compatible set types.
//!
//! For portability and consistency between architectures,
//! the size of the set must fit within a [u32].

extern crate alloc;

use crate::{
    codec::{EncodeSize, Read, Write},
    error::Error,
    RangeCfg,
};
use alloc::collections::BTreeSet;
use bytes::{Buf, BufMut};
use core::cmp::Ordering;

const BTREESET_TYPE: &str = "BTreeSet";

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

// ---------- BTreeSet ----------

impl<K: Ord + Eq + Write> Write for BTreeSet<K> {
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);

        // Items are already sorted in BTreeSet, so we can iterate directly
        for item in self {
            item.write(buf);
        }
    }
}

impl<K: Ord + Eq + EncodeSize> EncodeSize for BTreeSet<K> {
    fn encode_size(&self) -> usize {
        let mut size = self.len().encode_size();
        for item in self {
            size += item.encode_size();
        }
        size
    }
}

impl<K: Read + Clone + Ord + Eq> Read for BTreeSet<K> {
    type Cfg = (RangeCfg<usize>, K::Cfg);

    fn read_cfg(buf: &mut impl Buf, (range, cfg): &Self::Cfg) -> Result<Self, Error> {
        // Read and validate the length prefix
        let len = usize::read_cfg(buf, range)?;
        let mut set = Self::new();

        // Read items in ascending order
        read_ordered_set(buf, len, cfg, |item| set.insert(item), BTREESET_TYPE)?;

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
    use core::fmt::Debug;

    // Generic round trip test function for BTreeSet
    fn round_trip_btree<K>(set: &BTreeSet<K>, range_cfg: RangeCfg<usize>, item_cfg: K::Cfg)
    where
        K: Write + EncodeSize + Read + Clone + Ord + Eq + Debug + PartialEq,
        BTreeSet<K>: Read<Cfg = (RangeCfg<usize>, K::Cfg)>
            + Decode<Cfg = (RangeCfg<usize>, K::Cfg)>
            + Debug
            + PartialEq
            + Write
            + EncodeSize,
    {
        let encoded = set.encode();
        assert_eq!(set.encode_size(), encoded.len());
        let config_tuple = (range_cfg, item_cfg);
        let decoded = BTreeSet::<K>::decode_cfg(encoded, &config_tuple).expect("decode_cfg failed");
        assert_eq!(set, &decoded);
    }

    #[test]
    fn test_empty_btreeset() {
        let set = BTreeSet::<u32>::new();
        round_trip_btree(&set, (..).into(), ());
        assert_eq!(set.encode_size(), 1); // varint 0
        let encoded = set.encode();
        assert_eq!(encoded, Bytes::from_static(&[0]));
    }

    #[test]
    fn test_simple_btreeset_u32() {
        let mut set = BTreeSet::new();
        set.insert(1u32);
        set.insert(5u32);
        set.insert(2u32);
        round_trip_btree(&set, (..).into(), ());
        assert_eq!(set.encode_size(), 1 + 3 * u32::SIZE);
    }

    #[test]
    fn test_large_btreeset() {
        // Fixed-size items
        let set: BTreeSet<_> = (0..1000u16).collect();
        round_trip_btree(&set, (1000..=1000).into(), ());

        // Variable-size items
        let set: BTreeSet<_> = (0..1000usize).collect();
        round_trip_btree(&set, (1000..=1000).into(), (..=1000).into());
    }

    #[test]
    fn test_btreeset_decode_length_limit_exceeded() {
        let mut set = BTreeSet::new();
        set.insert(1u32);
        set.insert(5u32);
        let encoded = set.encode();

        let config_tuple = ((0..=1).into(), ());
        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(result, Err(Error::InvalidLength(2))));
    }

    #[test]
    fn test_btreeset_decode_invalid_item_order() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Set length = 2
        5u32.write(&mut encoded); // Item 5
        2u32.write(&mut encoded); // Item 2 (out of order)

        let config_tuple = ((..).into(), ());
        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("BTreeSet", "Items must ascend"))
        ));
    }

    #[test]
    fn test_btreeset_decode_duplicate_item() {
        let mut encoded = BytesMut::new();
        2usize.write(&mut encoded); // Set length = 2
        1u32.write(&mut encoded); // Item 1
        1u32.write(&mut encoded); // Duplicate Item 1

        let config_tuple = ((..).into(), ());
        let result = BTreeSet::<u32>::decode_cfg(encoded, &config_tuple);
        assert!(matches!(
            result,
            Err(Error::Invalid("BTreeSet", "Duplicate item"))
        ));
    }

    #[test]
    fn test_btreeset_deterministic_encoding() {
        let mut set1 = BTreeSet::new();
        (0..1000u32).for_each(|i| {
            set1.insert(i);
        });

        let mut set2 = BTreeSet::new();
        (0..1000u32).rev().for_each(|i| {
            set2.insert(i);
        });

        assert_eq!(set1.encode(), set2.encode());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;

        crate::conformance_tests! {
            BTreeSet<u8>,
        }
    }
}
