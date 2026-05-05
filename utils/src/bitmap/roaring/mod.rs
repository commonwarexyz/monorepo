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
//! Bitmap
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
//! | [3, 7, 42,   |  | 1011010...   |  | [(0, 4095),  |
//! |  100, 8000]  |  | (8KB bits)   |  |  (8200, ..)] |
//! +--------------+  +--------------+  +--------------+
//!   Sparse data       Dense data      Few runs
//!   (<= 4096 vals)    (many runs)     (any density)
//! ```
//!
//! # Container Types
//!
//! | Type   | Use Case                                 | Storage                  |
//! |--------|------------------------------------------|--------------------------|
//! | Array  | Sparse data                              | Sorted `Vec<u16>`        |
//! | Bitmap | Dense data with many disjoint runs       | `[u64; 1024]` (8 KB)     |
//! | Run    | Data with few maximal runs (any density) | Sorted `Vec<(u16, u16)>` |
//!
//! Containers automatically convert between variants on each `insert` /
//! `insert_range` to maintain a compact representation. The Bitmap→Run
//! transition uses a hysteresis band on the bitmap's run count, so a container
//! that hovers near break-even doesn't thrash between variants. See the container module
//! for the full transition table and threshold values.
//!
//! ```text
//! Array --[> 4096 values]--> Bitmap <--[run-count threshold]--> Run
//! ```
//!
//! # References
//!
//! * <https://arxiv.org/pdf/1402.6407>: Better bitmap performance with Roaring bitmaps
//! * <https://github.com/RoaringBitmap/RoaringFormatSpec>: Roaring Bitmap Format Specification
//! * <https://github.com/RoaringBitmap/roaring-rs>: roaring-rs Crate

mod container;
#[cfg(any(test, feature = "fuzz"))]
commonware_macros::stability_mod!(ALPHA, pub mod fuzz);
mod ops;
mod prunable;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use container::Container;
use core::ops::Range;
pub use prunable::Prunable;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Maximum container key (high 48 bits of a u64).
const MAX_KEY: u64 = (1u64 << 48) - 1;

/// Extracts the high 48 bits (container key) from a 64-bit value.
const fn high_bits(value: u64) -> u64 {
    value >> 16
}

/// Extracts the low 16 bits (container index) from a 64-bit value.
const fn low_bits(value: u64) -> u16 {
    value as u16
}

/// Combines a container key and index into a 64-bit value.
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
/// use commonware_utils::bitmap::roaring::Bitmap;
///
/// let mut bitmap = Bitmap::new();
/// bitmap.insert(42);
/// bitmap.insert(100);
/// bitmap.insert_range(1000..2000);
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
pub struct Bitmap {
    /// Map from high 48 bits to container storing low 16 bits.
    containers: BTreeMap<u64, Container>,
}

impl Bitmap {
    fn from_containers(containers: BTreeMap<u64, Container>) -> Result<Self, CodecError> {
        if let Some((&max_key, _)) = containers.last_key_value() {
            if max_key > MAX_KEY {
                return Err(CodecError::Invalid(
                    "Bitmap",
                    "container key exceeds 48-bit range",
                ));
            }
        }

        if containers.values().any(|c| c.is_empty()) {
            return Err(CodecError::Invalid("Bitmap", "empty container"));
        }

        Ok(Self { containers })
    }

    /// Creates an empty roaring bitmap.
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
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }

    /// Returns the number of containers in the bitmap.
    pub fn container_count(&self) -> usize {
        self.containers.len()
    }

    /// Clears all values from the bitmap.
    pub fn clear(&mut self) {
        self.containers.clear();
    }

    /// Checks if the bitmap contains the given value.
    pub fn contains(&self, value: u64) -> bool {
        let key = high_bits(value);
        let index = low_bits(value);
        self.containers.get(&key).is_some_and(|c| c.contains(index))
    }

    /// Inserts a value into the bitmap.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    pub fn insert(&mut self, value: u64) -> bool {
        let key = high_bits(value);
        let index = low_bits(value);
        self.containers.entry(key).or_default().insert(index)
    }

    /// Inserts a range of values into the bitmap.
    ///
    /// Returns the number of values newly inserted.
    pub fn insert_range(&mut self, range: Range<u64>) -> u64 {
        let Range { start, end } = range;
        if start >= end {
            return 0;
        }

        let start_key = high_bits(start);
        let end_key = high_bits(end - 1);
        let mut inserted = 0u64;

        for key in start_key..=end_key {
            let container_start = if key == start_key { low_bits(start) } else { 0 };
            let container_end = if key == end_key {
                let last_value = low_bits(end - 1);
                if last_value == u16::MAX {
                    None
                } else {
                    Some(last_value + 1)
                }
            } else {
                None
            };

            let container = self.containers.entry(key).or_default();
            if container_start == 0 && container_end.is_none() {
                inserted += container::bitmap::BITS as u64 - container.len() as u64;
                *container = Container::Run(container::Run::full());
                continue;
            }
            match container_end {
                Some(container_end) => {
                    inserted += container.insert_range(container_start..container_end) as u64;
                }
                None => {
                    inserted += container.insert_range(container_start..u16::MAX) as u64;
                    if container.insert(u16::MAX) {
                        inserted += 1;
                    }
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

    /// Returns an iterator over the values in the range in sorted order.
    pub fn iter_range(&self, range: Range<u64>) -> impl Iterator<Item = u64> + '_ {
        let Range { start, end } = range;
        let start_key = high_bits(start);
        let end_key_exclusive = if start >= end {
            start_key
        } else {
            high_bits(end - 1) + 1
        };
        let end_key = end_key_exclusive.saturating_sub(1);

        self.containers
            .range(start_key..end_key_exclusive)
            .flat_map(move |(&key, container)| {
                let container_start = if key == start_key { low_bits(start) } else { 0 };
                let container_end = if key == end_key {
                    low_bits(end - 1) as u32 + 1
                } else {
                    container::bitmap::BITS
                };
                container
                    .iter_range(container_start as u32..container_end)
                    .map(move |index| combine(key, index))
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

    #[cfg(test)]
    const fn containers(&self) -> &BTreeMap<u64, Container> {
        &self.containers
    }

    /// Drops all containers whose key is strictly less than `target_key`.
    fn truncate_containers_below(&mut self, target_key: u64) {
        // BTreeMap::split_off returns the half with keys >= target_key.
        let kept = self.containers.split_off(&target_key);
        self.containers = kept;
    }

    /// Returns counts of Array, Bitmap, and Run containers.
    ///
    /// Available only for tests and analysis benchmarks.
    #[cfg(any(test, feature = "analysis"))]
    pub fn container_variant_counts(&self) -> (usize, usize, usize) {
        let mut counts = (0, 0, 0);
        for container in self.containers.values() {
            match container {
                Container::Array(_) => counts.0 += 1,
                Container::Bitmap(_) => counts.1 += 1,
                Container::Run(_) => counts.2 += 1,
            }
        }
        counts
    }
}

impl Extend<u64> for Bitmap {
    fn extend<I: IntoIterator<Item = u64>>(&mut self, iter: I) {
        for value in iter {
            self.insert(value);
        }
    }
}

impl FromIterator<u64> for Bitmap {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        let mut bitmap = Self::new();
        bitmap.extend(iter);
        bitmap
    }
}

impl Write for Bitmap {
    fn write(&self, buf: &mut impl BufMut) {
        self.containers.write(buf);
    }
}

impl EncodeSize for Bitmap {
    fn encode_size(&self) -> usize {
        self.containers.encode_size()
    }
}

impl Read for Bitmap {
    /// Configuration for decoding: range limit on number of containers.
    ///
    /// Use `RangeCfg::new(..=max_containers)` to limit memory allocation.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        // Use BTreeMap's codec which validates sorted/unique keys and bounds count.
        let containers = BTreeMap::<u64, Container>::read_cfg(buf, &(*cfg, ((), ())))?;
        Self::from_containers(containers)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Bitmap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
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
            // `Container::arbitrary` can produce an empty container (zero-length
            // Array/Run, all-zero Bitmap). Bitmap rejects empty containers via
            // `try_from` and the decoder, so skip them here to keep generated
            // values round-trippable through encode/decode.
            let container = Container::arbitrary(u)?;
            if container.is_empty() {
                continue;
            }
            containers.insert(key, container);
            prev_key = key;
        }

        Ok(Self { containers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;

    #[test]
    fn test_new_and_empty() {
        let bitmap = Bitmap::new();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.len(), 0);
        assert_eq!(bitmap.container_count(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut bitmap = Bitmap::new();

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
        let mut bitmap = Bitmap::new();

        let inserted = bitmap.insert_range(100..200);
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
        let mut bitmap = Bitmap::new();

        // Insert range that spans multiple containers
        let start = 65530; // Near end of first container
        let end = 65550; // Into second container
        let inserted = bitmap.insert_range(start..end);
        assert_eq!(inserted, 20);

        for i in start..end {
            assert!(bitmap.contains(i), "missing value {}", i);
        }
    }

    #[test]
    fn test_iterator() {
        let mut bitmap = Bitmap::new();
        bitmap.insert(100);
        bitmap.insert(10);
        bitmap.insert(1000);
        bitmap.insert(5);

        let values: Vec<_> = bitmap.iter().collect();
        assert_eq!(values, vec![5, 10, 100, 1000]);
    }

    #[test]
    fn test_iter_range() {
        let mut bitmap = Bitmap::new();
        for i in 0..100 {
            bitmap.insert(i);
        }

        let values: Vec<_> = bitmap.iter_range(25..75).collect();
        assert_eq!(values.len(), 50);
        assert_eq!(values[0], 25);
        assert_eq!(values[49], 74);
    }

    #[test]
    fn test_iter_range_reversed_cross_container_empty() {
        let mut bitmap = Bitmap::new();
        bitmap.insert(1);
        bitmap.insert(70_000);

        let start = 70_000;
        let end = 10;
        let values: Vec<_> = bitmap.iter_range(start..end).collect();
        assert!(values.is_empty());
    }

    #[test]
    fn test_min_max() {
        let mut bitmap = Bitmap::new();
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
        let mut bitmap = Bitmap::new();
        bitmap.insert(1);
        bitmap.insert(2);
        bitmap.insert(3);

        bitmap.clear();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.len(), 0);
    }

    #[test]
    fn test_from_iter_empty() {
        let bitmap: Bitmap = core::iter::empty::<u64>().collect();
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_from_iter_basic() {
        let bitmap: Bitmap = [5u64, 10, 15, 100].into_iter().collect();
        assert_eq!(bitmap.len(), 4);
        let values: Vec<_> = bitmap.iter().collect();
        assert_eq!(values, vec![5, 10, 15, 100]);
    }

    #[test]
    fn test_from_iter_unsorted_with_duplicates() {
        // Verifies the iterator order doesn't matter and duplicates dedup.
        let bitmap: Bitmap = [100u64, 5, 100, 50, 5, 10].into_iter().collect();
        assert_eq!(bitmap.len(), 4);
        let values: Vec<_> = bitmap.iter().collect();
        assert_eq!(values, vec![5, 10, 50, 100]);
    }

    #[test]
    fn test_from_iter_range_expression() {
        // The motivating ergonomic case: collect a Range directly.
        let bitmap: Bitmap = (0u64..1000).collect();
        assert_eq!(bitmap.len(), 1000);
        assert!(bitmap.contains(0));
        assert!(bitmap.contains(999));
        assert!(!bitmap.contains(1000));
    }

    #[test]
    fn test_from_iter_multi_container() {
        // Spans multiple 16-bit container shelves.
        let bitmap: Bitmap = [1u64, 65_537, 131_073, 1_000_000].into_iter().collect();
        assert_eq!(bitmap.len(), 4);
        assert_eq!(bitmap.container_count(), 4);
    }

    #[test]
    fn test_extend_into_existing() {
        let mut bitmap: Bitmap = [1u64, 2, 3].into_iter().collect();
        bitmap.extend([3u64, 4, 5]);
        let values: Vec<_> = bitmap.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4, 5]);
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
        let mut bitmap = Bitmap::new();

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

        let bitmap = Bitmap::new();
        let encoded = bitmap.encode();
        let decoded = Bitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_sparse() {
        use commonware_codec::{Decode, Encode};

        let mut bitmap = Bitmap::new();
        bitmap.insert(42);
        bitmap.insert(100);
        bitmap.insert(1000000);

        let encoded = bitmap.encode();
        let decoded = Bitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_dense() {
        use commonware_codec::{Decode, Encode};

        let mut bitmap = Bitmap::new();
        bitmap.insert_range(0..5000);

        let encoded = bitmap.encode();
        let decoded = Bitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_multiple_containers() {
        use commonware_codec::{Decode, Encode};

        let mut bitmap = Bitmap::new();
        bitmap.insert_range(0..100);
        bitmap.insert_range(65536..65636);
        bitmap.insert(1u64 << 40);

        let encoded = bitmap.encode();
        let decoded = Bitmap::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(bitmap, decoded);
    }

    #[test]
    fn test_codec_roundtrip_large_mixed_variants() {
        // Exercises BTreeMap-codec scaling and confirms all three Container variants
        // roundtrip correctly when packed into one bitmap. 600 containers across
        // disjoint shelves: 200 sparse (Array), 200 dense alternating (Bitmap),
        // 200 contiguous ranges (Run).
        use commonware_codec::{Decode, Encode};

        let mut bitmap = Bitmap::new();

        // Sparse shelves: 100 values each, well below MAX_CARDINALITY.
        for shelf in 0..200u64 {
            let base = shelf * 65_536;
            for i in 0..100u64 {
                bitmap.insert(base + i * 500);
            }
        }

        // Dense shelves: 5000 alternating values. Above MAX_CARDINALITY (Array→Bitmap)
        // with run count above the Run-conversion threshold so they stay Bitmap.
        for shelf in 200..400u64 {
            let base = shelf * 65_536;
            for i in 0..5_000u64 {
                bitmap.insert(base + i * 2);
            }
        }

        // Run shelves: one contiguous range. After Array→Bitmap conversion at
        // MAX_CARDINALITY, the single-run state triggers Bitmap→Run.
        for shelf in 400..600u64 {
            let base = shelf * 65_536;
            bitmap.insert_range(base..base + 50_000);
        }

        assert_eq!(bitmap.container_count(), 600);

        let (arrays, bitmaps, runs) = bitmap.container_variant_counts();
        assert!(
            arrays > 0 && bitmaps > 0 && runs > 0,
            "expected all three variants, got A={arrays} B={bitmaps} R={runs}"
        );

        let encoded = bitmap.encode();
        let decoded = Bitmap::decode_cfg(encoded, &(..=1000usize).into()).unwrap();
        assert_eq!(decoded, bitmap);
    }

    #[test]
    fn test_codec_container_limit() {
        use commonware_codec::{Decode, Encode, Error};

        let mut bitmap = Bitmap::new();
        // Create 3 containers
        bitmap.insert(0);
        bitmap.insert(65536);
        bitmap.insert(131072);
        assert_eq!(bitmap.container_count(), 3);

        let encoded = bitmap.encode();

        // Should succeed with limit >= 3
        let decoded = Bitmap::decode_cfg(encoded.clone(), &(..=3).into()).unwrap();
        assert_eq!(bitmap, decoded);

        // Should fail with limit < 3
        let result = Bitmap::decode_cfg(encoded, &(..=2).into());
        assert!(matches!(result, Err(Error::InvalidLength(3))));
    }

    #[test]
    fn test_from_containers_rejects_out_of_range_key() {
        use commonware_codec::Error;

        let mut malformed: BTreeMap<u64, Container> = BTreeMap::new();
        let mut container = Container::new();
        container.insert(0);
        malformed.insert(1u64 << 48, container);

        let result = Bitmap::from_containers(malformed);
        assert!(
            matches!(
                result,
                Err(Error::Invalid("Bitmap", msg)) if msg.contains("48-bit")
            ),
            "expected Invalid(\"Bitmap\", ...), got {result:?}"
        );
    }

    #[test]
    fn test_from_containers_accepts_in_range_keys() {
        let mut map: BTreeMap<u64, Container> = BTreeMap::new();
        let mut container = Container::new();
        container.insert(42);
        map.insert(MAX_KEY, container);

        let bm = Bitmap::from_containers(map).unwrap();
        assert!(bm.contains(combine(MAX_KEY, 42)));
    }

    #[test]
    fn test_from_containers_rejects_empty_container() {
        // An empty container has no values to find via iteration, but the key still
        // shows up in `container_count()` and confuses `min`/`max`. Reject at
        // construction before decode can accept it.
        use commonware_codec::Error;

        let mut map: BTreeMap<u64, Container> = BTreeMap::new();
        map.insert(0, Container::new());

        let result = Bitmap::from_containers(map);
        assert!(
            matches!(result, Err(Error::Invalid("Bitmap", "empty container"))),
            "expected Invalid(\"Bitmap\", \"empty container\"), got {result:?}"
        );
    }

    #[test]
    fn test_decode_rejects_out_of_range_key() {
        use commonware_codec::{Decode, Encode, Error};

        let mut malformed: BTreeMap<u64, Container> = BTreeMap::new();
        let mut container = Container::new();
        container.insert(0);
        malformed.insert(1u64 << 48, container);

        // BTreeMap shares its codec format with `Bitmap`, so we can encode directly.
        let bytes = malformed.encode();

        let result = Bitmap::decode_cfg(bytes, &(..=10usize).into());
        assert!(
            matches!(
                result,
                Err(Error::Invalid("Bitmap", msg)) if msg.contains("48-bit")
            ),
            "expected Invalid(\"Bitmap\", ...), got {result:?}"
        );
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
        let mut bitmap = Bitmap::new();
        let inserted = bitmap.insert_range(0..65536);
        assert_eq!(inserted, 65536);
        assert_eq!(bitmap.len(), 65536);
        for i in 0u64..65536 {
            assert!(bitmap.contains(i), "missing value {}", i);
        }
        assert!(!bitmap.contains(65536));

        // Test case 2: Range ending at container boundary within a single container
        let mut bitmap = Bitmap::new();
        let inserted = bitmap.insert_range(65000..65536);
        assert_eq!(inserted, 536);
        assert_eq!(bitmap.len(), 536);
        for i in 65000u64..65536 {
            assert!(bitmap.contains(i), "missing value {}", i);
        }

        // Test case 3: Range spanning containers ending at boundary
        let mut bitmap = Bitmap::new();
        let inserted = bitmap.insert_range(65530..131072);
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

        let mut bitmap = Bitmap::new();
        let inserted = bitmap.insert_range(start..end);
        assert_eq!(inserted, expected_len);
        assert_eq!(bitmap.len(), expected_len);
    }

    #[test]
    fn test_encode_size_empty() {
        let bm = Bitmap::new();
        assert_eq!(bm.encode_size(), bm.encode().len());
    }

    #[test]
    fn test_encode_size_grows_with_containers() {
        let mut bm = Bitmap::new();
        let s0 = bm.encode_size();
        // Three values in three different high-48-bit shelves => three containers.
        bm.insert(0);
        bm.insert(65_536);
        bm.insert(131_072);
        let s3 = bm.encode_size();
        assert_eq!(bm.container_count(), 3);
        assert!(s3 > s0);
        assert_eq!(s3, bm.encode().len());
    }

    #[test]
    fn test_encode_size_dense_uses_bitmap_container() {
        // Force a single container past the Array→Bitmap threshold AND keep it there by
        // using alternating values that produce many runs, defeating the Bitmap→Run
        // auto-conversion (which fires only when run_count is below the threshold).
        let mut bm = Bitmap::new();
        for i in 0u64..5000 {
            bm.insert(i * 2);
        }
        // Bitmap container alone is ~8 KB.
        assert!(bm.encode_size() >= 8192);
        assert_eq!(bm.encode_size(), bm.encode().len());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Bitmap>,
        }
    }
}
