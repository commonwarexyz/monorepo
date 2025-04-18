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
