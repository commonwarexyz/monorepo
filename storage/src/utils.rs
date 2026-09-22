//! Utilities for storage tests and fuzz targets.

#[cfg(test)]
pub(crate) mod codec;
#[cfg(test)]
pub(crate) mod detached;

#[cfg(test)]
use commonware_runtime::telemetry::metrics::{GaugeValue, metric_samples};
use commonware_utils::bitmap::BitMap;
use std::{collections::BTreeMap, num::NonZeroU64};

/// Tracked backing the storage pool has created, weighted by size class. Returned buffers are
/// reused before new ones are created, so each class contributes its allocation high-water mark.
#[cfg(test)]
pub(crate) fn created_bytes(metrics: &str) -> usize {
    metric_samples(metrics, "storage_buffer_pool_buffer_pool_created")
        .map(|(labels, count)| {
            let size = labels
                .strip_prefix("size_class=\"")
                .and_then(|size| size.strip_suffix('"'))
                .expect("invalid size class");
            let size = usize::try_from(size.parse::<u64>().unwrap()).unwrap();
            let count = usize::try_from(count.parse::<GaugeValue>().unwrap()).unwrap();
            size * count
        })
        .sum()
}

/// Build ordinal recovery bitmaps from absolute item indices.
///
/// Each index maps to blob `index / items_per_blob` and sets bit
/// `index % items_per_blob` in that blob's bitmap of `items_per_blob` bits.
pub fn bits_for_indices<const N: usize>(
    items_per_blob: NonZeroU64,
    indices: impl IntoIterator<Item = u64>,
) -> BTreeMap<u64, Option<BitMap<N>>> {
    let items_per_blob = items_per_blob.get();
    let mut bits = BTreeMap::new();
    for index in indices {
        let blob = index / items_per_blob;
        let offset = index % items_per_blob;
        bits.entry(blob)
            .or_insert_with(|| Some(BitMap::zeroes(items_per_blob)))
            .as_mut()
            .unwrap()
            .set(offset, true);
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    #[test]
    fn test_bits_for_indices() {
        let empty = bits_for_indices::<1>(NZU64!(10), core::iter::empty());
        assert!(empty.is_empty());

        let bits = bits_for_indices::<1>(NZU64!(10), [0, 1, 9, 10, 25]);
        assert_eq!(bits.len(), 3);

        let blob_0 = bits.get(&0).unwrap().as_ref().unwrap();
        assert_eq!(blob_0.len(), 10);
        assert_eq!(blob_0.count_ones(), 3);
        assert!(blob_0.get(0));
        assert!(blob_0.get(1));
        assert!(blob_0.get(9));

        let blob_1 = bits.get(&1).unwrap().as_ref().unwrap();
        assert_eq!(blob_1.len(), 10);
        assert_eq!(blob_1.count_ones(), 1);
        assert!(blob_1.get(0));

        let blob_2 = bits.get(&2).unwrap().as_ref().unwrap();
        assert_eq!(blob_2.len(), 10);
        assert_eq!(blob_2.count_ones(), 1);
        assert!(blob_2.get(5));
    }
}
