//! Container types for roaring bitmaps.
//!
//! Each container stores values in the range `[0, 65535]` using one of three
//! representations optimized for different data densities:
//!
//! - [`Array`]: Sorted `Vec<u16>` for sparse data (cardinality up to 4096).
//! - [`Bitmap`]: Fixed 8 KB bit array for dense data with many runs.
//! - [`Run`]: Run-length encoded `Vec<(u16, u16)>` for data with few runs.
//!
//! # Auto-conversion
//!
//! Containers automatically convert between variants on each `insert` / `insert_range`
//! call to maintain the most compact representation:
//!
//! | From    | To      | Trigger                                         |
//! |---------|---------|-------------------------------------------------|
//! | Array   | Bitmap  | `Array::len() > 4096` (full)                    |
//! | Bitmap  | Run     | `Bitmap::run_count() < BITMAP_TO_RUN_THRESHOLD` |
//! | Run     | Bitmap  | `Run::run_count() > RUN_TO_BITMAP_THRESHOLD`    |
//!
//! The Bitmap-Run thresholds form a hysteresis around the ~2048-run break-even point so
//! that small run-count fluctuations near break-even do not cause thrashing.
//!
//! [`Bitmap::run_count`] is maintained incrementally on `insert` (O(1) per call) and
//! recomputed via a single word scan on bulk paths (`insert_range`, AND/OR/XOR ops).
//! Auto-conversion adds only a constant-time threshold compare per insert in the steady
//! state, so callers never need to call an explicit `optimize()` — there is no such API.
//!
//! Decoded shapes from peer-supplied wire data are validated and then normalized through the
//! same threshold rules used by mutation paths. Codec bounds (per-container `MAX_RUNS`,
//! top-level `RangeCfg`) enforce DOS resistance independently.

pub mod array;
pub mod bitmap;
pub mod run;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
pub use array::Array;
pub use bitmap::Bitmap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use core::ops::Range;
pub use run::Run;

/// A container that stores u16 values using the most efficient representation.
///
/// Automatically converts between container types during insertion:
/// - Array -> Bitmap when cardinality exceeds 4096
/// - Bitmap -> Run when container becomes fully saturated (65536 values)
#[derive(Clone, Debug)]
pub enum Container {
    /// Sparse container using a sorted array.
    Array(Array),
    /// Dense container using a fixed-size bit array (boxed to reduce enum size).
    Bitmap(Box<Bitmap>),
    /// Run-length encoded container for consecutive sequences.
    Run(Run),
}

impl Default for Container {
    fn default() -> Self {
        Self::Array(Array::new())
    }
}

impl Container {
    /// Creates a new empty container (as an Array).
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cardinality (number of values) in the container.
    pub fn len(&self) -> u32 {
        match self {
            Self::Array(a) => a.len() as u32,
            Self::Bitmap(b) => b.len(),
            Self::Run(r) => r.len(),
        }
    }

    /// Returns whether the container is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Array(a) => a.is_empty(),
            Self::Bitmap(b) => b.is_empty(),
            Self::Run(r) => r.is_empty(),
        }
    }

    /// Checks if the container contains the given value.
    pub fn contains(&self, value: u16) -> bool {
        match self {
            Self::Array(a) => a.contains(value),
            Self::Bitmap(b) => b.contains(value),
            Self::Run(r) => r.contains(value),
        }
    }

    /// Inserts a value into the container.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    ///
    /// Automatically converts the container type if needed; see the [module
    /// documentation](self) for the full transition table.
    pub fn insert(&mut self, value: u16) -> bool {
        match self {
            Self::Array(a) => {
                let inserted = a.insert(value);
                if a.len() > array::MAX_CARDINALITY {
                    self.convert_array_to_bitmap();
                }
                inserted
            }
            Self::Bitmap(b) => {
                let inserted = b.insert(value);
                if (b.run_count() as usize) < BITMAP_TO_RUN_THRESHOLD {
                    self.convert_bitmap_to_run();
                }
                inserted
            }
            Self::Run(r) => {
                let inserted = r.insert(value);
                if r.run_count() > RUN_TO_BITMAP_THRESHOLD {
                    self.convert_run_to_bitmap();
                }
                inserted
            }
        }
    }

    /// Inserts a range of values into the container.
    ///
    /// Returns the number of values newly inserted.
    ///
    /// Automatically converts the container type if needed; see the [module
    /// documentation](self) for the full transition table.
    pub fn insert_range(&mut self, range: Range<u16>) -> u32 {
        let Range { start, end } = range;
        if start >= end {
            return 0;
        }

        match self {
            Self::Array(a) => {
                let range_len = (end - start) as usize;

                // Fast path: empty array with consecutive range - use Run container
                // directly. Run stores `(start, end)` pairs, so a single range is just
                // 4 bytes vs Array which would be 2 bytes per value.
                if a.is_empty() && range_len >= 64 {
                    let mut run = Run::new();
                    let inserted = run.insert_range(start..end);
                    *self = Self::Run(run);
                    return inserted;
                }

                // If result would exceed array capacity, convert to bitmap.
                if a.len() + range_len > array::MAX_CARDINALITY {
                    self.convert_array_to_bitmap();
                    return self.insert_range(start..end);
                }

                a.insert_range(start..end) as u32
            }
            Self::Bitmap(b) => {
                let inserted = b.insert_range(start..end);
                if (b.run_count() as usize) < BITMAP_TO_RUN_THRESHOLD {
                    self.convert_bitmap_to_run();
                }
                inserted
            }
            Self::Run(r) => {
                let inserted = r.insert_range(start..end);
                if r.run_count() > RUN_TO_BITMAP_THRESHOLD {
                    self.convert_run_to_bitmap();
                }
                inserted
            }
        }
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> Iter<'_> {
        match self {
            Self::Array(a) => Iter::Array(a.iter()),
            Self::Bitmap(b) => Iter::Bitmap(b.iter()),
            Self::Run(r) => Iter::Run(r.iter()),
        }
    }

    /// Returns an iterator over values in the range.
    pub fn iter_range(&self, range: Range<u32>) -> RangeIter<'_> {
        let start = range.start.min(bitmap::BITS);
        let end = range.end.min(bitmap::BITS);
        match self {
            Self::Array(a) => {
                let values = a.as_slice();
                let start_pos = values.partition_point(|&value| (value as u32) < start);
                let end_pos = values.partition_point(|&value| (value as u32) < end);
                let end_pos = end_pos.max(start_pos);
                RangeIter::Array(values[start_pos..end_pos].iter().copied())
            }
            Self::Bitmap(b) => RangeIter::Bitmap(b.iter_range(start..end)),
            Self::Run(r) => RangeIter::Run(r.iter_range(start..end)),
        }
    }

    /// Returns the minimum value in the container, if any.
    pub fn min(&self) -> Option<u16> {
        match self {
            Self::Array(a) => a.min(),
            Self::Bitmap(b) => b.min(),
            Self::Run(r) => r.min(),
        }
    }

    /// Returns the maximum value in the container, if any.
    pub fn max(&self) -> Option<u16> {
        match self {
            Self::Array(a) => a.max(),
            Self::Bitmap(b) => b.max(),
            Self::Run(r) => r.max(),
        }
    }

    /// Copies at most `limit` values from the container.
    ///
    /// Returns the truncated container and the number of copied values.
    pub fn limit(&self, limit: u64) -> (Self, u64) {
        let len = self.len() as u64;
        if len <= limit {
            return (self.clone(), len);
        }

        let mut result = Self::new();
        let mut remaining = limit;
        for value in self.iter() {
            if remaining == 0 {
                break;
            }
            result.insert(value);
            remaining -= 1;
        }
        (result, limit - remaining)
    }

    /// Computes the union of two containers, returning at most `limit` values.
    ///
    /// Returns the result container and the number of values in it.
    pub fn union(&self, other: &Self, limit: u64) -> (Self, u64) {
        if let (Self::Array(a), Self::Array(b)) = (self, other) {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let (result, count) = a.union(b, limit);
            if result.len() > array::MAX_CARDINALITY {
                let bitmap = Bitmap::from(&result);
                return (Self::Bitmap(Box::new(bitmap)), count as u64);
            }
            return (Self::Array(result), count as u64);
        }

        if let (Self::Bitmap(a), Self::Bitmap(b)) = (self, other) {
            let result = Bitmap::or_new(a, b);
            let len = result.len() as u64;
            if len <= limit {
                return (Self::Bitmap(Box::new(result)), len);
            }
            return Self::Bitmap(Box::new(result)).limit(limit);
        }

        let mut result = Self::new();
        let mut remaining = limit;
        let mut a_iter = self.iter().peekable();
        let mut b_iter = other.iter().peekable();

        while remaining > 0 {
            match (a_iter.peek(), b_iter.peek()) {
                (Some(&a_value), Some(&b_value)) => {
                    if a_value < b_value {
                        result.insert(a_value);
                        a_iter.next();
                    } else if b_value < a_value {
                        result.insert(b_value);
                        b_iter.next();
                    } else {
                        result.insert(a_value);
                        a_iter.next();
                        b_iter.next();
                    }
                }
                (Some(&value), None) => {
                    result.insert(value);
                    a_iter.next();
                }
                (None, Some(&value)) => {
                    result.insert(value);
                    b_iter.next();
                }
                (None, None) => break,
            }
            remaining -= 1;
        }

        (result, limit - remaining)
    }

    /// Computes the intersection of two containers, returning at most `limit` values.
    ///
    /// Returns the result container and the number of values in it.
    pub fn intersection(&self, other: &Self, limit: u64) -> (Self, u64) {
        if let (Self::Array(a), Self::Array(b)) = (self, other) {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let (result, count) = a.intersection(b, limit);
            return (Self::Array(result), count as u64);
        }

        if let (Self::Bitmap(a), Self::Bitmap(b)) = (self, other) {
            let result = Bitmap::and_new(a, b);
            let len = result.len() as u64;
            if len <= limit {
                return (Self::Bitmap(Box::new(result)), len);
            }
            return Self::Bitmap(Box::new(result)).limit(limit);
        }

        let (smaller, larger) = if self.len() <= other.len() {
            (self, other)
        } else {
            (other, self)
        };

        let mut result = Self::new();
        let mut remaining = limit;
        for value in smaller.iter() {
            if remaining == 0 {
                break;
            }
            if larger.contains(value) {
                result.insert(value);
                remaining -= 1;
            }
        }

        (result, limit - remaining)
    }

    /// Computes the difference `self - other`, returning at most `limit` values.
    ///
    /// Returns the result container and the number of values in it.
    pub fn difference(&self, other: &Self, limit: u64) -> (Self, u64) {
        if let (Self::Array(a), Self::Array(b)) = (self, other) {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let (result, count) = a.difference(b, limit);
            return (Self::Array(result), count as u64);
        }

        if let (Self::Bitmap(a), Self::Bitmap(b)) = (self, other) {
            let result = Bitmap::and_not_new(a, b);
            let len = result.len() as u64;
            if len <= limit {
                return (Self::Bitmap(Box::new(result)), len);
            }
            return Self::Bitmap(Box::new(result)).limit(limit);
        }

        let mut result = Self::new();
        let mut remaining = limit;
        for value in self.iter() {
            if remaining == 0 {
                break;
            }
            if !other.contains(value) {
                result.insert(value);
                remaining -= 1;
            }
        }

        (result, limit - remaining)
    }

    /// Returns `true` if every value in this container is present in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        if self.len() > other.len() {
            return false;
        }
        self.iter().all(|value| other.contains(value))
    }

    /// Returns `true` if the containers share at least one value.
    pub fn intersects(&self, other: &Self) -> bool {
        let (smaller, larger) = if self.len() <= other.len() {
            (self, other)
        } else {
            (other, self)
        };
        smaller.iter().any(|value| larger.contains(value))
    }

    /// Returns the approximate total memory footprint of this `Container` in bytes
    /// (stack + heap).
    ///
    /// `size_of::<Self>()` covers the enum discriminant plus inline storage for the
    /// largest variant. The match arm adds heap allocations specific to the active
    /// variant: `Array`'s `Vec` buffer, the boxed `Bitmap`, or `Run`'s `BTreeMap`
    /// nodes. The `Run` component is approximate (see [`Run::byte_size`]). Available
    /// only for tests and the `analysis` feature; not compiled into production builds.
    #[cfg(any(test, feature = "analysis"))]
    pub fn byte_size(&self) -> usize {
        core::mem::size_of::<Self>()
            + match self {
                // The Vec header is inline in the enum; only its heap buffer counts here.
                Self::Array(a) => a.byte_size() - core::mem::size_of::<Array>(),
                // The whole Bitmap struct lives on the heap behind the Box.
                Self::Bitmap(b) => b.byte_size(),
                // The BTreeMap header is inline in the enum; only its heap nodes count here.
                Self::Run(r) => r.byte_size() - core::mem::size_of::<Run>(),
            }
    }

    /// Converts an Array container to a Bitmap container.
    fn convert_array_to_bitmap(&mut self) {
        if let Self::Array(a) = self {
            *self = Self::Bitmap(Box::new(Bitmap::from(&*a)));
        }
    }

    /// Converts a Bitmap container to an Array container.
    fn convert_bitmap_to_array(&mut self) {
        if let Self::Bitmap(b) = self {
            let values: Vec<u16> = b.iter().collect();
            *self = Self::Array(Array::try_from(values).expect("bitmap values are sorted"));
        }
    }

    /// Converts a Bitmap container to a Run container.
    fn convert_bitmap_to_run(&mut self) {
        if let Self::Bitmap(b) = self {
            *self = Self::Run(Run::from(b.as_ref()));
        }
    }

    /// Converts a Run container to a Bitmap container. Used when a Run grows past the
    /// hysteresis upper bound and a Bitmap becomes the more compact representation.
    fn convert_run_to_bitmap(&mut self) {
        if let Self::Run(r) = self {
            *self = Self::Bitmap(Box::new(Bitmap::from(&*r)));
        }
    }

    /// Applies the same representation thresholds used by mutation paths.
    fn normalize(&mut self) {
        if self.is_empty() {
            *self = Self::Array(Array::new());
            return;
        }

        match self {
            Self::Array(_) => {}
            Self::Bitmap(b) if b.len() as usize <= array::MAX_CARDINALITY => {
                self.convert_bitmap_to_array();
            }
            Self::Bitmap(b) if (b.run_count() as usize) < BITMAP_TO_RUN_THRESHOLD => {
                self.convert_bitmap_to_run();
            }
            Self::Run(r) if r.run_count() > RUN_TO_BITMAP_THRESHOLD => {
                self.convert_run_to_bitmap();
            }
            _ => {}
        }
    }
}

impl PartialEq for Container {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for Container {}

/// Convert a Bitmap to a Run when the run count drops below this threshold.
///
/// At ~4 bytes per Run entry vs 8192 bytes for a Bitmap, the break-even is roughly 2048.
/// We pick 1500 (a 50% buffer below break-even) so that crossing the threshold is a clear
/// memory win rather than a marginal one. Paired with [`RUN_TO_BITMAP_THRESHOLD`] for
/// hysteresis: the gap between the two thresholds prevents thrashing when run count
/// hovers near break-even.
const BITMAP_TO_RUN_THRESHOLD: usize = 1500;

/// Convert a Run to a Bitmap when the run count exceeds this threshold.
///
/// Mirror of [`BITMAP_TO_RUN_THRESHOLD`], placed 50% above the ~2048 break-even so a
/// container near the break-even doesn't bounce between variants on each insert.
const RUN_TO_BITMAP_THRESHOLD: usize = 2500;

/// Iterator over values in a container.
pub enum Iter<'a> {
    /// Iterator over an Array container.
    Array(core::iter::Copied<core::slice::Iter<'a, u16>>),
    /// Iterator over a Bitmap container.
    Bitmap(bitmap::Iter<'a>),
    /// Iterator over a Run container.
    Run(run::Iter<'a>),
}

impl Iterator for Iter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(iter) => iter.next(),
            Self::Bitmap(iter) => iter.next(),
            Self::Run(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Array(iter) => iter.size_hint(),
            Self::Bitmap(iter) => iter.size_hint(),
            Self::Run(iter) => iter.size_hint(),
        }
    }
}

impl ExactSizeIterator for Iter<'_> {}

/// Iterator over a range of values in a container.
pub enum RangeIter<'a> {
    /// Iterator over an Array container.
    Array(core::iter::Copied<core::slice::Iter<'a, u16>>),
    /// Iterator over a Bitmap container.
    Bitmap(bitmap::Iter<'a>),
    /// Iterator over a Run container.
    Run(run::Iter<'a>),
}

impl Iterator for RangeIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(iter) => iter.next(),
            Self::Bitmap(iter) => iter.next(),
            Self::Run(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Array(iter) => iter.size_hint(),
            Self::Bitmap(iter) => iter.size_hint(),
            Self::Run(iter) => iter.size_hint(),
        }
    }
}

impl ExactSizeIterator for RangeIter<'_> {}

/// Container type tags for serialization.
const CONTAINER_TYPE_ARRAY: u8 = 0;
const CONTAINER_TYPE_BITMAP: u8 = 1;
const CONTAINER_TYPE_RUN: u8 = 2;

impl Write for Container {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Array(a) => {
                CONTAINER_TYPE_ARRAY.write(buf);
                a.write(buf);
            }
            Self::Bitmap(b) => {
                CONTAINER_TYPE_BITMAP.write(buf);
                b.write(buf);
            }
            Self::Run(r) => {
                CONTAINER_TYPE_RUN.write(buf);
                r.write(buf);
            }
        }
    }
}

impl EncodeSize for Container {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Array(a) => a.encode_size(),
            Self::Bitmap(b) => b.encode_size(),
            Self::Run(r) => r.encode_size(),
        }
    }
}

impl Read for Container {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let container_type = u8::read(buf)?;
        let mut container = match container_type {
            CONTAINER_TYPE_ARRAY => Ok(Self::Array(Array::read(buf)?)),
            CONTAINER_TYPE_BITMAP => Ok(Self::Bitmap(Box::new(Bitmap::read(buf)?))),
            CONTAINER_TYPE_RUN => Ok(Self::Run(Run::read(buf)?)),
            _ => Err(CodecError::InvalidEnum(container_type)),
        }?;
        container.normalize();
        Ok(container)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Container {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=2)?;
        match variant {
            0 => Ok(Self::Array(Array::arbitrary(u)?)),
            1 => Ok(Self::Bitmap(Box::new(Bitmap::arbitrary(u)?))),
            _ => Ok(Self::Run(Run::arbitrary(u)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_new_container() {
        let container = Container::new();
        assert!(container.is_empty());
        assert_eq!(container.len(), 0);
        assert!(matches!(container, Container::Array(_)));
    }

    #[test]
    fn test_insert_and_contains() {
        let mut container = Container::new();

        assert!(container.insert(5));
        assert!(container.insert(3));
        assert!(container.insert(7));
        assert!(!container.insert(5)); // Duplicate

        assert_eq!(container.len(), 3);
        assert!(container.contains(3));
        assert!(container.contains(5));
        assert!(container.contains(7));
        assert!(!container.contains(4));
    }

    #[test]
    fn test_equality_ignores_representation() {
        let mut array = Array::new();
        for value in [1, 3, 5] {
            array.insert(value);
        }

        let bitmap = Bitmap::from(&array);
        let mut run = Run::new();
        for value in [1, 3, 5] {
            run.insert(value);
        }

        assert_eq!(
            Container::Array(array.clone()),
            Container::Bitmap(Box::new(bitmap))
        );
        assert_eq!(Container::Array(array), Container::Run(run));
    }

    #[test]
    fn test_decode_normalizes_sparse_bitmap_container() {
        let mut bitmap = Bitmap::new();
        bitmap.insert(1);
        bitmap.insert(3);
        bitmap.insert(5);
        let encoded = Container::Bitmap(Box::new(bitmap)).encode();

        let decoded = Container::decode_cfg(encoded, &()).unwrap();
        assert!(matches!(decoded, Container::Array(_)));
    }

    #[test]
    fn test_decode_normalizes_full_bitmap_container() {
        let encoded = Container::Bitmap(Box::new(Bitmap::from([!0u64; bitmap::WORDS]))).encode();

        let decoded = Container::decode_cfg(encoded, &()).unwrap();
        assert!(matches!(decoded, Container::Run(_)));
    }

    #[test]
    fn test_auto_convert_array_to_bitmap() {
        let mut container = Container::new();

        // Insert alternating values past the Array→Bitmap threshold.
        // Using `i * 2` produces isolated singletons, so the resulting Bitmap has many
        // runs (one per inserted value) and stays in Bitmap form rather than auto-
        // converting to Run.
        for i in 0..=array::MAX_CARDINALITY as u16 {
            container.insert(i * 2);
        }

        // Should have converted to bitmap.
        assert!(matches!(container, Container::Bitmap(_)));
        assert_eq!(container.len(), (array::MAX_CARDINALITY + 1) as u32);
    }

    #[test]
    fn test_array_stays_array_at_max_cardinality() {
        let mut container = Container::new();

        for i in 0..array::MAX_CARDINALITY as u16 {
            assert!(container.insert(i * 2));
        }

        assert!(matches!(container, Container::Array(_)));
        assert_eq!(container.len(), array::MAX_CARDINALITY as u32);
        assert!(!container.insert(0));
        assert!(matches!(container, Container::Array(_)));
    }

    #[test]
    fn test_auto_convert_bitmap_to_run() {
        let mut container = Container::Bitmap(Box::default());

        // Fill the entire container
        for i in 0..=u16::MAX {
            container.insert(i);
        }

        // Should have converted to run
        assert!(matches!(container, Container::Run(_)));
        assert_eq!(container.len(), 65536);
    }

    #[test]
    fn test_insert_range() {
        let mut container = Container::new();

        let inserted = container.insert_range(5..10);
        assert_eq!(inserted, 5);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_iterator() {
        let mut container = Container::new();
        container.insert(10);
        container.insert(5);
        container.insert(15);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 10, 15]);
    }

    #[test]
    fn test_min_max() {
        let mut container = Container::new();
        assert_eq!(container.min(), None);
        assert_eq!(container.max(), None);

        container.insert(50);
        container.insert(10);
        container.insert(100);

        assert_eq!(container.min(), Some(10));
        assert_eq!(container.max(), Some(100));
    }

    #[test]
    fn test_byte_size_array_variant() {
        let mut c = Container::new();
        c.insert(5);
        assert!(matches!(c, Container::Array(_)));
        // Sanity floor: at least the enum's stack footprint.
        assert!(c.byte_size() >= core::mem::size_of::<Container>());
        // Sanity ceiling: a 1-value Array has at most a small Vec capacity.
        assert!(c.byte_size() <= core::mem::size_of::<Container>() + 64);
    }

    #[test]
    fn test_byte_size_bitmap_variant() {
        // Force conversion to Bitmap (cardinality > 4096) AND keep it there by inserting
        // alternating values (many isolated runs) so auto-conversion to Run doesn't fire.
        let mut c = Container::new();
        for i in 0..=array::MAX_CARDINALITY as u16 {
            c.insert(i * 2);
        }
        assert!(matches!(c, Container::Bitmap(_)));
        // Boxed Bitmap is roughly 8 KB on top of the enum's own stack.
        assert!(c.byte_size() >= core::mem::size_of::<Container>() + 8192);
    }

    #[test]
    fn test_byte_size_run_variant() {
        let mut c = Container::Run(Run::full());
        c.insert(0); // already there, no growth
                     // Run with one full-saturation entry.
        assert!(c.byte_size() >= core::mem::size_of::<Container>());
        // Should be far smaller than a Bitmap variant.
        assert!(c.byte_size() < 1024);
    }

    // -----------------------------------------------------------------------------
    // Auto-conversion (Bitmap <-> Run) tests
    // -----------------------------------------------------------------------------

    #[test]
    fn test_bitmap_auto_converts_to_run_after_filling_gaps() {
        // Get into Bitmap form first by inserting alternating values past the Array
        // threshold. This produces a Bitmap with many isolated runs.
        let mut c = Container::new();
        for i in 0..=array::MAX_CARDINALITY as u16 {
            c.insert(i * 2);
        }
        assert!(matches!(c, Container::Bitmap(_)));

        // insert_range over a contiguous span absorbs all the singletons into one run,
        // dropping run_count to 1 — well under BITMAP_TO_RUN_THRESHOLD. The bitmap should
        // auto-convert to Run.
        c.insert_range(0..u16::MAX);
        assert!(matches!(c, Container::Run(_)));
    }

    #[test]
    fn test_run_auto_converts_to_bitmap_when_runs_grow() {
        // Start in Run form via the empty-array + large-range fast path in insert_range.
        let mut c = Container::new();
        c.insert_range(0..5_000);
        assert!(matches!(c, Container::Run(_)));

        // Insert ~3000 isolated, non-adjacent values to push run_count past
        // RUN_TO_BITMAP_THRESHOLD (= 2500). Use values >= 10_000 with gaps so they don't
        // merge with the existing [0, 4999] run or each other.
        let mut value = 10_000u16;
        for _ in 0..3_000 {
            c.insert(value);
            value += 2; // gap of 1 between successive inserts to keep them disjoint.
        }

        // Should have flipped to Bitmap once run_count crossed 2500.
        assert!(matches!(c, Container::Bitmap(_)));
    }

    #[test]
    fn test_no_thrash_in_hysteresis_band() {
        // Inside [BITMAP_TO_RUN_THRESHOLD, RUN_TO_BITMAP_THRESHOLD], neither conversion
        // direction triggers. We construct a Bitmap with run_count squarely inside the
        // band and verify a series of small fluctuations does not flip variants.
        let mut c = Container::new();
        // 2000 isolated singletons → forces conversion to Bitmap (Array overflows at
        // 4096). Run count = 2000, comfortably between 1500 and 2500.
        for i in 0..2_000u16 {
            c.insert(i * 3); // gaps of 2 keep them isolated
        }
        // Past 4096? No — 2000 values is < 4096, so we're still in Array.
        // Push past Array threshold with more isolated values.
        for i in 2_000..5_000u16 {
            c.insert(i * 3);
        }
        // 5000 isolated values → run_count == 5000 → in Bitmap with run_count > 2500.
        assert!(matches!(c, Container::Bitmap(_)));
        // Now collapse some runs to bring run_count into the hysteresis band.
        // Bridging adjacent singletons: insert i*3 + 1 for some i to merge with neighbor.
        // We want to land run_count ~2000.
        // Each bridge between singletons (i*3) and ((i+1)*3) requires filling i*3+1 and
        // i*3+2. Each bridge removes 1 run net. To go from 5000 → 2000, do ~3000 bridges.
        for i in 0..3_000u16 {
            c.insert(i * 3 + 1);
            c.insert(i * 3 + 2);
        }
        // Now run_count is around 2000-ish, in the hysteresis band.
        assert!(matches!(c, Container::Bitmap(_)));

        // Add a few more inserts that touch run_count up and down by small amounts.
        // None should flip the variant.
        for i in 3_000..3_010u16 {
            c.insert(i * 3 + 1); // bridges another pair → run_count -= 1 each time
        }
        assert!(matches!(c, Container::Bitmap(_)));
        for i in 6_000..6_010u16 {
            c.insert(i * 3); // adds an isolated singleton → run_count += 1 each time
        }
        assert!(matches!(c, Container::Bitmap(_)));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Container>,
        }
    }
}
