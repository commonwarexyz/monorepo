//! Container-aligned prunable wrapper around [`Bitmap`].
//!
//! [`Prunable`] adds a "pruned-below" watermark to a [`Bitmap`]. Values strictly less
//! than the watermark are guaranteed not to exist in the bitmap, and querying or inserting
//! such values is treated as a programming bug and panics.
//!
//! # Granularity
//!
//! Pruning is **container-aligned**: thresholds are rounded down to the nearest multiple of
//! 65536 (the size of a roaring container). [`Prunable::prune`] returns the threshold
//! actually applied, which the caller can inspect via [`Prunable::pruned_below`].
//!
//! For example, `prune(70_000)` will:
//!
//! - Drop the container at key `0` (covering values `0..65536`).
//! - Keep the container at key `1` (covering values `65536..131072`) entirely, including
//!   any values in the range `65536..70000` that the caller asked to prune.
//! - Set `pruned_below()` to `65536`.
//!
//! In other words, some values "below" the requested threshold may linger in the boundary
//! container. Callers wanting strict semantics can pass a container-aligned threshold
//! (e.g. `threshold & !0xFFFF` or rounded up to the next boundary).
//!
//! # Invariant
//!
//! After construction or any operation, the underlying bitmap contains no values
//! `< pruned_below`. The [`Read`] impl validates this on decode.

use super::Bitmap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use core::ops::Range;

/// Number of values per container. Pruning aligns to multiples of this value.
const CONTAINER_SIZE: u64 = 1 << 16;

/// Mask for extracting the within-container index from a value.
const CONTAINER_MASK: u64 = CONTAINER_SIZE - 1;

/// A [`Bitmap`] paired with a "pruned-below" watermark.
///
/// See the module-level documentation for semantics and granularity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prunable {
    /// The underlying bitmap. Invariant: contains no values `< pruned_below`.
    bitmap: Bitmap,

    /// The lowest value that may exist in the bitmap. Always a multiple of 65536.
    pruned_below: u64,
}

impl Prunable {
    /// Creates an empty prunable bitmap with no pruning applied.
    pub const fn new() -> Self {
        Self {
            bitmap: Bitmap::new(),
            pruned_below: 0,
        }
    }

    /// Returns the cardinality (number of values currently in the set).
    ///
    /// Pruning subtracts from this: dropping a container with N values reduces `len()` by N.
    /// This differs from [`super::super::Prunable::len`] (the dense `BitMap<N>` wrapper),
    /// which preserves length across pruning because positions are meaningful in a sequential
    /// bit array. Here, only present values are counted.
    pub fn len(&self) -> u64 {
        self.bitmap.len()
    }

    /// Returns whether the bitmap is empty.
    pub fn is_empty(&self) -> bool {
        self.bitmap.is_empty()
    }

    /// Returns the current pruning watermark.
    ///
    /// Always a multiple of 65536. No value `< pruned_below` exists in the bitmap.
    pub const fn pruned_below(&self) -> u64 {
        self.pruned_below
    }

    /// Inserts a value into the bitmap. Returns `true` if newly inserted.
    ///
    /// # Panics
    ///
    /// Panics if `value < pruned_below()`.
    pub fn insert(&mut self, value: u64) -> bool {
        assert!(
            value >= self.pruned_below,
            "value pruned: {value} < pruned_below {}",
            self.pruned_below
        );
        self.bitmap.insert(value)
    }

    /// Inserts a range of values into the bitmap. Returns the number of values newly inserted.
    ///
    /// # Panics
    ///
    /// Panics if `start < pruned_below()`.
    pub fn insert_range(&mut self, range: Range<u64>) -> u64 {
        let Range { start, end } = range;
        if start >= end {
            return 0;
        }
        assert!(
            start >= self.pruned_below,
            "start pruned: {start} < pruned_below {}",
            self.pruned_below
        );
        self.bitmap.insert_range(start..end)
    }

    /// Checks if the bitmap contains the given value.
    ///
    /// # Panics
    ///
    /// Panics if `value < pruned_below()`.
    pub fn contains(&self, value: u64) -> bool {
        assert!(
            value >= self.pruned_below,
            "value pruned: {value} < pruned_below {}",
            self.pruned_below
        );
        self.bitmap.contains(value)
    }

    /// Prunes all values strictly less than `threshold`, rounding down to the nearest
    /// container boundary (multiple of 65536).
    ///
    /// Returns the threshold actually applied (the rounded-down value), which is also the
    /// new value of [`Self::pruned_below`].
    ///
    /// No-op if the rounded threshold is `<= pruned_below()`.
    pub fn prune(&mut self, threshold: u64) -> u64 {
        let aligned = threshold & !CONTAINER_MASK;
        if aligned <= self.pruned_below {
            return self.pruned_below;
        }
        let target_key = aligned >> 16;
        self.bitmap.truncate_containers_below(target_key);
        self.pruned_below = aligned;
        aligned
    }

    /// Returns the minimum value in the bitmap, if any.
    pub fn min(&self) -> Option<u64> {
        self.bitmap.min()
    }

    /// Returns the maximum value in the bitmap, if any.
    pub fn max(&self) -> Option<u64> {
        self.bitmap.max()
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.bitmap.iter()
    }

    /// Returns an iterator over the values in the range in sorted order.
    ///
    /// # Panics
    ///
    /// Panics if `start < pruned_below()`.
    pub fn iter_range(&self, range: Range<u64>) -> impl Iterator<Item = u64> + '_ {
        let Range { start, end } = range;
        if start >= end {
            return self.bitmap.iter_range(0..0);
        }
        assert!(
            start >= self.pruned_below,
            "start pruned: {start} < pruned_below {}",
            self.pruned_below
        );
        self.bitmap.iter_range(start..end)
    }

    /// Clears all values from the bitmap. Does not reset [`Self::pruned_below`].
    pub fn clear(&mut self) {
        self.bitmap.clear();
    }
}

impl Extend<u64> for Prunable {
    /// Inserts each value from the iterator. Panics if any value is below
    /// [`Self::pruned_below`], matching [`Self::insert`].
    fn extend<I: IntoIterator<Item = u64>>(&mut self, iter: I) {
        for value in iter {
            self.insert(value);
        }
    }
}

impl FromIterator<u64> for Prunable {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        let mut p = Self::new();
        p.extend(iter);
        p
    }
}

impl Write for Prunable {
    fn write(&self, buf: &mut impl BufMut) {
        self.pruned_below.write(buf);
        self.bitmap.write(buf);
    }
}

impl EncodeSize for Prunable {
    fn encode_size(&self) -> usize {
        self.pruned_below.encode_size() + self.bitmap.encode_size()
    }
}

impl Read for Prunable {
    /// Configuration for decoding: range limit on number of containers (passed through to
    /// the underlying [`Bitmap`]).
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let pruned_below = u64::read(buf)?;
        if pruned_below & CONTAINER_MASK != 0 {
            return Err(CodecError::Invalid(
                "Prunable",
                "pruned_below must be a multiple of 65536",
            ));
        }

        // Validate invariant: no container key < pruned_below >> 16.
        let bitmap = Bitmap::read_cfg(buf, cfg)?;
        let target_key = pruned_below >> 16;
        if let Some((&first_key, _)) = bitmap.containers.first_key_value() {
            if first_key < target_key {
                return Err(CodecError::Invalid(
                    "Prunable",
                    "container key below pruned_below",
                ));
            }
        }
        Ok(Self {
            bitmap,
            pruned_below,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Prunable {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut p = Self {
            bitmap: Bitmap::arbitrary(u)?,
            pruned_below: 0,
        };

        // Pick an arbitrary threshold within the bitmap's value range and apply it.
        // `prune` itself enforces the invariant.
        let max = p.bitmap.max().unwrap_or(0);
        let threshold = u.int_in_range(0..=max)?;
        p.prune(threshold);
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_new_and_empty() {
        let p = Prunable::new();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
        assert_eq!(p.pruned_below(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut p = Prunable::new();
        assert!(p.insert(42));
        assert!(p.insert(1_000_000));
        assert!(!p.insert(42));
        assert!(p.contains(42));
        assert!(p.contains(1_000_000));
        assert!(!p.contains(43));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn test_prune_drops_containers() {
        let mut p = Prunable::new();
        p.insert(100); // container 0
        p.insert(70_000); // container 1
        p.insert(140_000); // container 2
        p.insert(330_000); // container 5
        assert_eq!(p.len(), 4);

        // Prune at the start of container 2 (boundary = 2 * 65536 = 131_072).
        let returned = p.prune(131_072);
        assert_eq!(returned, 131_072);
        assert_eq!(p.pruned_below(), 131_072);
        assert_eq!(p.len(), 2);
        assert!(p.contains(140_000));
        assert!(p.contains(330_000));
    }

    #[test]
    fn test_prune_rounds_down() {
        let mut p = Prunable::new();
        p.insert(100); // container 0
        p.insert(70_000); // container 1

        // Threshold lies inside container 1 (boundary = 65_536).
        // Container 0 dropped; container 1 (with 70_000) preserved.
        let returned = p.prune(70_000);
        assert_eq!(returned, 65_536);
        assert_eq!(p.pruned_below(), 65_536);
        assert_eq!(p.len(), 1);
        assert!(p.contains(70_000));
    }

    #[test]
    fn test_prune_partial_container_lingers() {
        let mut p = Prunable::new();
        p.insert(65_500); // container 0, near top
        p.insert(70_000); // container 1, near bottom

        // prune(70_000) rounds down to 65_536, drops container 0 only.
        p.prune(70_000);
        // 65_500 (was in dropped container 0) is gone.
        // We can't call contains(65_500) directly (it'd panic), so check the inner bitmap.
        assert!(!p.bitmap.contains(65_500));
        // 70_000 is still in container 1.
        assert!(p.contains(70_000));
    }

    #[test]
    fn test_prune_idempotent_below_watermark() {
        let mut p = Prunable::new();
        p.insert(70_000);
        p.prune(65_536);
        assert_eq!(p.pruned_below(), 65_536);
        // Calling with a smaller threshold returns the existing watermark.
        let returned = p.prune(0);
        assert_eq!(returned, 65_536);
        assert_eq!(p.pruned_below(), 65_536);
    }

    #[test]
    fn test_prune_then_insert_above() {
        let mut p = Prunable::new();
        p.prune(131_072);
        p.insert(200_000);
        assert!(p.contains(200_000));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn test_prune_zero_no_op() {
        let mut p = Prunable::new();
        p.insert(100);
        let returned = p.prune(0);
        assert_eq!(returned, 0);
        assert_eq!(p.pruned_below(), 0);
        assert_eq!(p.len(), 1);
    }

    #[test]
    #[should_panic(expected = "value pruned")]
    fn test_panic_on_insert_below_pruned() {
        let mut p = Prunable::new();
        p.prune(131_072);
        p.insert(50);
    }

    #[test]
    #[should_panic(expected = "value pruned")]
    fn test_panic_on_contains_below_pruned() {
        let mut p = Prunable::new();
        p.prune(131_072);
        let _ = p.contains(50);
    }

    #[test]
    #[should_panic(expected = "start pruned")]
    fn test_panic_on_insert_range_below_pruned() {
        let mut p = Prunable::new();
        p.prune(131_072);
        p.insert_range(50..100);
    }

    #[test]
    #[should_panic(expected = "start pruned")]
    fn test_panic_on_iter_range_below_pruned() {
        let mut p = Prunable::new();
        p.prune(131_072);
        let _ = p.iter_range(50..200_000);
    }

    #[test]
    fn test_empty_insert_ranges_below_pruned_are_no_ops() {
        let mut p = Prunable::new();
        p.insert(200_000);
        p.prune(131_072);

        assert_eq!(p.insert_range(50..50), 0);
        let start = 50u64;
        let end = 10u64;
        assert_eq!(p.insert_range(start..end), 0);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn test_empty_iter_ranges_below_pruned_are_empty() {
        let mut p = Prunable::new();
        p.insert(200_000);
        p.prune(131_072);

        assert!(p.iter_range(50..50).next().is_none());
        let start = 50u64;
        let end = 10u64;
        assert!(p.iter_range(start..end).next().is_none());
    }

    #[test]
    fn test_iter() {
        let mut p = Prunable::new();
        for v in [200_000u64, 100, 70_000, 5] {
            p.insert(v);
        }
        p.prune(131_072);
        let collected: Vec<u64> = p.iter().collect();
        assert_eq!(collected, vec![200_000]);
    }

    #[test]
    fn test_clear_preserves_pruned_below() {
        let mut p = Prunable::new();
        p.insert(200_000);
        p.prune(131_072);
        p.clear();
        assert!(p.is_empty());
        assert_eq!(p.pruned_below(), 131_072);
    }

    #[test]
    fn test_from_iter_basic() {
        let p: Prunable = [5u64, 10, 100, 65_537].into_iter().collect();
        assert_eq!(p.len(), 4);
        assert_eq!(p.pruned_below(), 0);
        assert!(p.contains(5));
        assert!(p.contains(65_537));
    }

    #[test]
    fn test_from_iter_empty() {
        let p: Prunable = core::iter::empty::<u64>().collect();
        assert!(p.is_empty());
        assert_eq!(p.pruned_below(), 0);
    }

    #[test]
    fn test_extend_after_pruning() {
        let mut p = Prunable::new();
        p.insert(200_000);
        p.prune(131_072);

        // All values >= pruned_below, so extend works.
        p.extend([200_001u64, 300_000]);
        assert_eq!(p.len(), 3);
        assert!(p.contains(200_001));
    }

    #[test]
    #[should_panic(expected = "value pruned")]
    fn test_extend_below_pruned_panics() {
        let mut p = Prunable::new();
        p.prune(131_072);
        // 50 is below pruned_below; should panic via insert.
        p.extend([200_000u64, 50]);
    }

    #[test]
    fn test_codec_roundtrip_empty() {
        let p = Prunable::new();
        let encoded = p.encode();
        let decoded = Prunable::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn test_codec_roundtrip_with_pruning() {
        let mut p = Prunable::new();
        p.insert(200_000);
        p.insert(300_000);
        p.insert(1_000_000);
        p.prune(131_072);
        let encoded = p.encode();
        let decoded = Prunable::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn test_codec_rejects_misaligned_pruned_below() {
        use bytes::BytesMut;
        let mut buf = BytesMut::new();
        // Not a multiple of 65536.
        100u64.write(&mut buf);
        // Append an empty bitmap encoding.
        Bitmap::new().write(&mut buf);
        let result = Prunable::decode_cfg(buf.freeze(), &(..).into());
        assert!(matches!(
            result,
            Err(CodecError::Invalid("Prunable", msg))
                if msg.contains("multiple of 65536")
        ));
    }

    #[test]
    fn test_codec_rejects_container_below_pruned() {
        use bytes::BytesMut;
        let mut buf = BytesMut::new();
        // pruned_below = 131_072 (container 2 boundary).
        131_072u64.write(&mut buf);
        // Bitmap has a value in container 0, violating the invariant.
        let mut bitmap = Bitmap::new();
        bitmap.insert(50);
        bitmap.write(&mut buf);
        let result = Prunable::decode_cfg(buf.freeze(), &(..).into());
        assert!(matches!(
            result,
            Err(CodecError::Invalid("Prunable", msg))
                if msg.contains("container key below pruned_below")
        ));
    }

    #[test]
    fn test_encode_size_empty() {
        let p = Prunable::new();
        assert_eq!(
            p.encode_size(),
            0u64.encode_size() + Bitmap::new().encode_size()
        );
    }

    #[test]
    fn test_encode_size_grows_with_data() {
        let s0 = Prunable::new().encode_size();
        let mut p = Prunable::new();
        p.insert(100);
        p.insert(65_537);
        p.insert(131_073);
        assert!(p.encode_size() > s0);
    }

    #[test]
    fn test_encode_size_unaffected_by_pruning_alone() {
        // Pruning that removes nothing (threshold below all data) should not change encoding.
        let mut p = Prunable::new();
        p.insert(200_000);
        let before = p.encode_size();
        p.prune(0);
        assert_eq!(p.encode_size(), before);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Prunable>,
        }
    }
}
