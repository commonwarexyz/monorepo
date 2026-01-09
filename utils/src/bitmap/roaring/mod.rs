//! 64-bit roaring-style compressed bitmap.
//!
//! Provides a memory-efficient representation for sets of 64-bit integers using
//! run-length encoding and adaptive container types. This implementation partitions
//! integers into chunks of 2^16 values using the high 48 bits as the chunk key,
//! with each chunk stored in one of three container types optimized for different
//! data densities.
//!
//! # Architecture
//!
//! Each 64-bit value is split into a high 48-bit key (selecting a container) and
//! a low 16-bit index (stored within that container):
//!
//! ```text
//! 64-bit value
//! +-----------------------------------------------+---------------+
//! |            high 48 bits (key)                 | low 16 bits   |
//! +-----------------------------------------------+---------------+
//!                      |                                 |
//!                      v                                 v
//!               BTreeMap key                     Container index
//! ```
//!
//! The bitmap stores containers in a sorted map, where each container holds
//! values in the range `[key * 2^16, (key + 1) * 2^16)`:
//!
//! ```text
//! RoaringBitmap
//! +------------------------------------------------------------------+
//! |                     BTreeMap<u64, Container>                     |
//! +------------------------------------------------------------------+
//! |  Key 0          |  Key 1          |  Key 2          |    ...     |
//! |  [0, 65535]     |  [65536, 131071]|  [131072, ...]  |            |
//! +-----------------+-----------------+-----------------+------------+
//!         |                 |                 |
//!         v                 v                 v
//! +--------------+  +--------------+  +--------------+
//! |    Array     |  |    Bitmap    |  |     Run      |
//! | [3, 7, 42,   |  | 1011010...   |  | [0-65535]    |
//! |  100, 8000]  |  | (8KB bits)   |  | (full range) |
//! +--------------+  +--------------+  +--------------+
//!   Sparse data       Dense data      Consecutive
//!   <= 4096 vals    4096 < n < 65536   n == 65536
//! ```
//!
//! # Container Types
//!
//! | Type | Use Case | Storage | Threshold |
//! |------|----------|---------|-----------|
//! | Array | Sparse data | Sorted `Vec<u16>` | cardinality <= 4096 |
//! | Bitmap | Dense data | `[u64; 1024]` (8KB) | 4096 < cardinality < 65536 |
//! | Run | Consecutive sequences | `BTreeMap<start, end>` | cardinality == 65536 |
//!
//! Containers automatically convert between types during insertion to maintain
//! optimal memory usage:
//!
//! ```text
//! Array --[> 4096 values]--> Bitmap --[fully saturated]--> Run
//! ```
//!
//! # References
//!
//! * <https://arxiv.org/pdf/1402.6407>: Better bitmap performance with Roaring bitmaps
//! * <https://github.com/RoaringBitmap/RoaringFormatSpec>: Roaring Bitmap Format Specification
//! * <https://github.com/RoaringBitmap/roaring-rs>: roaring-rs Crate

pub mod container;
mod ops;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
pub use container::{Array, Bitmap, Container, Run};
pub use ops::{difference, intersection, union};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Extracts the high 48 bits (container key) from a 64-bit value.
#[inline]
const fn high_bits(value: u64) -> u64 {
    value >> 16
}

/// Extracts the low 16 bits (container index) from a 64-bit value.
#[inline]
const fn low_bits(value: u64) -> u16 {
    value as u16
}

/// Combines a container key and index into a 64-bit value.
#[inline]
const fn combine(key: u64, index: u16) -> u64 {
    (key << 16) | (index as u64)
}

/// A 64-bit roaring-style compressed bitmap.
///
/// This is an append-only data structure optimized for memory efficiency and
/// fast set operations. Values can be inserted but not removed.
///
/// # Example
///
/// ```
/// use commonware_utils::bitmap::roaring::RoaringBitmap;
///
/// let mut bitmap = RoaringBitmap::new();
/// bitmap.insert(42);
/// bitmap.insert(100);
/// bitmap.insert_range(1000, 2000);
///
/// assert!(bitmap.contains(42));
/// assert!(bitmap.contains(1500));
/// assert!(!bitmap.contains(500));
///
/// // Iterate over values
/// for value in bitmap.iter().take(10) {
///     println!("{}", value);
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoaringBitmap {
    /// Map from high 48 bits to container storing low 16 bits.
    containers: BTreeMap<u64, Container>,
}

impl RoaringBitmap {
    /// Creates an empty roaring bitmap.
    #[inline]
    pub const fn new() -> Self {
        Self {
            containers: BTreeMap::new(),
        }
    }

    /// Returns the number of values in the bitmap.
    pub fn len(&self) -> u64 {
        self.containers.values().map(|c| c.len() as u64).sum()
    }

    /// Returns whether the bitmap is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }

    /// Returns the number of containers in the bitmap.
    #[inline]
    pub fn container_count(&self) -> usize {
        self.containers.len()
    }

    /// Clears all values from the bitmap.
    #[inline]
    pub fn clear(&mut self) {
        self.containers.clear();
    }

    /// Checks if the bitmap contains the given value.
    #[inline]
    pub fn contains(&self, value: u64) -> bool {
        let key = high_bits(value);
        let index = low_bits(value);
        self.containers.get(&key).is_some_and(|c| c.contains(index))
    }

    /// Inserts a value into the bitmap.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    #[inline]
    pub fn insert(&mut self, value: u64) -> bool {
        let key = high_bits(value);
        let index = low_bits(value);
        self.containers.entry(key).or_default().insert(index)
    }

    /// Inserts a range of values [start, end) into the bitmap.
    ///
    /// Returns the number of values newly inserted.
    #[inline]
    pub fn insert_range(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }

        let start_key = high_bits(start);
        let end_key = high_bits(end.saturating_sub(1));

        // Fast path: entire range fits in a single container
        if start_key == end_key {
            let container_start = low_bits(start);
            let last_value = low_bits(end.saturating_sub(1));

            // Handle the case where the range ends at u16::MAX
            // We can't represent container_end = 65536 in u16, so we need
            // to insert the range [start, 65535) plus 65535 separately
            if last_value == u16::MAX {
                let container = self.containers.entry(start_key).or_default();
                let mut inserted = container.insert_range(container_start, u16::MAX) as u64;
                if container.insert(u16::MAX) {
                    inserted += 1;
                }
                return inserted;
            }

            let container_end = last_value.saturating_add(1);
            return self
                .containers
                .entry(start_key)
                .or_default()
                .insert_range(container_start, container_end) as u64;
        }

        // Multi-container case
        let mut inserted = 0u64;

        for key in start_key..=end_key {
            let container_start = if key == start_key { low_bits(start) } else { 0 };

            // Determine if this is a "full container" case (insert all 65536 values)
            // This happens for middle containers, or the end container when end
            // is exactly on a container boundary (low_bits(end) == 0)
            let is_full_container = if key == end_key {
                low_bits(end) == 0
            } else {
                key != start_key
            };

            let container = self.containers.entry(key).or_default();
            if is_full_container {
                // Insert full range [container_start, 65535] for this container
                inserted += container.insert_range(container_start, u16::MAX) as u64;
                if container.insert(u16::MAX) {
                    inserted += 1;
                }
            } else if key == end_key {
                // End container with partial range
                let container_end = low_bits(end.saturating_sub(1)).saturating_add(1);
                inserted += container.insert_range(container_start, container_end) as u64;
            } else {
                // Start container (key == start_key && key != end_key already handled)
                inserted += container.insert_range(container_start, u16::MAX) as u64;
                if container.insert(u16::MAX) {
                    inserted += 1;
                }
            }
        }

        inserted
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.containers
            .iter()
            .flat_map(|(&key, container)| container.iter().map(move |index| combine(key, index)))
    }

    /// Returns an iterator over the values in the range [start, end) in sorted order.
    pub fn iter_range(&self, start: u64, end: u64) -> impl Iterator<Item = u64> + '_ {
        let start_key = high_bits(start);
        let end_key = if end == 0 { 0 } else { high_bits(end - 1) };

        self.containers
            .range(start_key..=end_key)
            .flat_map(move |(&key, container)| {
                container.iter().filter_map(move |index| {
                    let value = combine(key, index);
                    if value >= start && value < end {
                        Some(value)
                    } else {
                        None
                    }
                })
            })
    }

    /// Returns the minimum value in the bitmap, if any.
    pub fn min(&self) -> Option<u64> {
        self.containers
            .first_key_value()
            .and_then(|(&key, container)| container.min().map(|index| combine(key, index)))
    }

    /// Returns the maximum value in the bitmap, if any.
    pub fn max(&self) -> Option<u64> {
        self.containers
            .last_key_value()
            .and_then(|(&key, container)| container.max().map(|index| combine(key, index)))
    }

    /// Returns a reference to the internal containers map.
    ///
    /// This is useful for implementing custom operations or serialization.
    #[inline]
    pub const fn containers(&self) -> &BTreeMap<u64, Container> {
        &self.containers
    }

    /// Creates a bitmap from a containers map.
    ///
    /// This is useful for deserialization or custom construction.
    #[inline]
    pub const fn from_containers(containers: BTreeMap<u64, Container>) -> Self {
        Self { containers }
    }

    /// Creates a bitmap with a single container.
    ///
    /// More efficient than `from_containers` for single-container results.
    #[inline]
    pub fn from_single_container(key: u64, container: Container) -> Self {
        let mut containers = BTreeMap::new();
        containers.insert(key, container);
        Self { containers }
    }
}

impl Write for RoaringBitmap {
    fn write(&self, buf: &mut impl BufMut) {
        self.containers.write(buf);
    }
}

impl EncodeSize for RoaringBitmap {
    fn encode_size(&self) -> usize {
        self.containers.encode_size()
    }
}

impl Read for RoaringBitmap {
    /// Configuration for decoding: range limit on number of containers.
    ///
    /// Use `RangeCfg::new(..=max_containers)` to limit memory allocation.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        // Use BTreeMap's codec which validates sorted/unique keys and bounds count
        let containers = BTreeMap::<u64, Container>::read_cfg(buf, &(*cfg, ((), ())))?;
        Ok(Self { containers })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for RoaringBitmap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Maximum container key (high 48 bits of a u64).
        const MAX_KEY: u64 = (1u64 << 48) - 1;

        let num_containers = u.int_in_range(0..=1000)?;
        let mut containers = BTreeMap::new();
        let mut prev_key = 0u64;

        for _ in 0..num_containers {
            // Generate increasing keys
            let key = if containers.is_empty() {
                u.int_in_range(0..=MAX_KEY)?
            } else {
                let remaining = MAX_KEY - prev_key;
                if remaining == 0 {
                    break;
                }
                prev_key.saturating_add(u.int_in_range(1..=remaining)?)
            };
            if key > MAX_KEY {
                break;
            }
            containers.insert(key, Container::arbitrary(u)?);
            prev_key = key;
        }

        Ok(Self { containers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_empty() {
        let bitmap = RoaringBitmap::new();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.len(), 0);
        assert_eq!(bitmap.container_count(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut bitmap = RoaringBitmap::new();

        assert!(bitmap.insert(42));
        assert!(bitmap.insert(100));
        assert!(bitmap.insert(1000000));
        assert!(!bitmap.insert(42)); // Duplicate

        assert_eq!(bitmap.len(), 3);
        assert!(bitmap.contains(42));
        assert!(bitmap.contains(100));
        assert!(bitmap.contains(1000000));
        assert!(!bitmap.contains(50));
    }

    #[test]
    fn test_insert_range() {
        let mut bitmap = RoaringBitmap::new();

        let inserted = bitmap.insert_range(100, 200);
        assert_eq!(inserted, 100);
        assert_eq!(bitmap.len(), 100);

        for i in 100..200 {
            assert!(bitmap.contains(i), "missing value {}", i);
        }
        assert!(!bitmap.contains(99));
        assert!(!bitmap.contains(200));
    }

    #[test]
    fn test_insert_range_spanning_containers() {
        let mut bitmap = RoaringBitmap::new();

        // Insert range that spans multiple containers
        let start = 65530; // Near end of first container
        let end = 65550; // Into second container
        let inserted = bitmap.insert_range(start, end);
        assert_eq!(inserted, 20);

        for i in start..end {
            assert!(bitmap.contains(i), "missing value {}", i);
        }
    }

    #[test]
    fn test_iterator() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(100);
        bitmap.insert(10);
        bitmap.insert(1000);
        bitmap.insert(5);

        let values: Vec<_> = bitmap.iter().collect();
        assert_eq!(values, vec![5, 10, 100, 1000]);
    }

    #[test]
    fn test_iter_range() {
        let mut bitmap = RoaringBitmap::new();
        for i in 0..100 {
            bitmap.insert(i);
        }

        let values: Vec<_> = bitmap.iter_range(25, 75).collect();
        assert_eq!(values.len(), 50);
        assert_eq!(values[0], 25);
        assert_eq!(values[49], 74);
    }

    #[test]
    fn test_min_max() {
        let mut bitmap = RoaringBitmap::new();
        assert_eq!(bitmap.min(), None);
        assert_eq!(bitmap.max(), None);

        bitmap.insert(50);
        bitmap.insert(10);
        bitmap.insert(100);

        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(100));
    }

    #[test]
    fn test_clear() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(1);
        bitmap.insert(2);
        bitmap.insert(3);

        bitmap.clear();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.len(), 0);
    }

    #[test]
    fn test_high_low_bits() {
        // Test boundary values
        assert_eq!(high_bits(0), 0);
        assert_eq!(low_bits(0), 0);

        assert_eq!(high_bits(65535), 0);
        assert_eq!(low_bits(65535), 65535);

        assert_eq!(high_bits(65536), 1);
        assert_eq!(low_bits(65536), 0);

        assert_eq!(high_bits(u64::MAX), (1u64 << 48) - 1);
        assert_eq!(low_bits(u64::MAX), u16::MAX);
    }

    #[test]
    fn test_combine() {
        assert_eq!(combine(0, 0), 0);
        assert_eq!(combine(0, 65535), 65535);
        assert_eq!(combine(1, 0), 65536);
        assert_eq!(combine(1, 1), 65537);
    }

    #[test]
    fn test_large_values() {
        let mut bitmap = RoaringBitmap::new();

        let large_value = 1u64 << 40;
        bitmap.insert(large_value);
        bitmap.insert(large_value + 1);
        bitmap.insert(large_value + 1000);

        assert!(bitmap.contains(large_value));
        assert!(bitmap.contains(large_value + 1));
        assert!(bitmap.contains(large_value + 1000));
        assert!(!bitmap.contains(large_value + 2));
    }

    #[test]
    fn test_codec_roundtrip_empty() {
        use commonware_codec::{Decode, Encode};

        let bitmap = RoaringBitmap::new();
        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_sparse() {
        use commonware_codec::{Decode, Encode};

        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(42);
        bitmap.insert(100);
        bitmap.insert(1000000);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_dense() {
        use commonware_codec::{Decode, Encode};

        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(0, 5000);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_multiple_containers() {
        use commonware_codec::{Decode, Encode};

        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(0, 100);
        bitmap.insert_range(65536, 65636);
        bitmap.insert(1u64 << 40);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_container_limit() {
        use commonware_codec::{Decode, Encode, Error};

        let mut bitmap = RoaringBitmap::new();
        // Create 3 containers
        bitmap.insert(0);
        bitmap.insert(65536);
        bitmap.insert(131072);
        assert_eq!(bitmap.container_count(), 3);

        let encoded = bitmap.encode();

        // Should succeed with limit >= 3
        let decoded = RoaringBitmap::decode_cfg(encoded.clone(), &(..=3).into()).unwrap();
        assert_eq!(bitmap, decoded);

        // Should fail with limit < 3
        let result = RoaringBitmap::decode_cfg(encoded, &(..=2).into());
        assert!(matches!(result, Err(Error::InvalidLength(3))));
    }

    #[test]
    fn test_insert_range_at_container_boundary_regression() {
        // Regression test for bug where insert_range failed when the range
        // ended exactly at a container boundary (low_bits(end-1) == u16::MAX).
        // The bug was that saturating_add(1) on u16::MAX saturates to u16::MAX
        // instead of wrapping to 0, causing incorrect range insertion.
        //
        // Original crash input: InsertRange { start: 18446744071497449473, len: 65535 }

        // Test case 1: Range ending at first container boundary (65535)
        let mut bitmap = RoaringBitmap::new();
        let inserted = bitmap.insert_range(0, 65536);
        assert_eq!(inserted, 65536);
        assert_eq!(bitmap.len(), 65536);
        for i in 0u64..65536 {
            assert!(bitmap.contains(i), "missing value {}", i);
        }
        assert!(!bitmap.contains(65536));

        // Test case 2: Range ending at container boundary within a single container
        let mut bitmap = RoaringBitmap::new();
        let inserted = bitmap.insert_range(65000, 65536);
        assert_eq!(inserted, 536);
        assert_eq!(bitmap.len(), 536);
        for i in 65000u64..65536 {
            assert!(bitmap.contains(i), "missing value {}", i);
        }

        // Test case 3: Range spanning containers ending at boundary
        let mut bitmap = RoaringBitmap::new();
        let inserted = bitmap.insert_range(65530, 131072);
        assert_eq!(inserted, 65542);
        assert_eq!(bitmap.len(), 65542);
        for i in 65530u64..131072 {
            assert!(bitmap.contains(i), "missing value {}", i);
        }

        // Test case 4: The actual fuzzer crash input (large values near u64::MAX)
        let start: u64 = 18446744071497449473;
        let len: u16 = 65535;
        let end = start.saturating_add(len as u64);
        let expected_len = end - start;

        let mut bitmap = RoaringBitmap::new();
        let inserted = bitmap.insert_range(start, end);
        assert_eq!(inserted, expected_len);
        assert_eq!(bitmap.len(), expected_len);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::RoaringBitmap>,
        }
    }
}
