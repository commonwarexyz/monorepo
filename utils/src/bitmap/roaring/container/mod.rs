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
//! call to maintain a compact in-memory representation with hysteresis:
//!
//! | From    | To      | Trigger                                         |
//! |---------|---------|-------------------------------------------------|
//! | Array   | Bitmap  | `Array::len() > 4096`                           |
//! | Bitmap  | Run     | `Bitmap::run_count() < BITMAP_TO_RUN_THRESHOLD` |
//! | Run     | Bitmap  | `Run::run_count() > RUN_TO_BITMAP_THRESHOLD`    |
//!
//! The Bitmap-Run thresholds form a hysteresis band around the ~2048-run break-even
//! point so small fluctuations do not cause variant thrashing while mutating.
//!
//! Serialization uses a canonical wire form chosen by encoded size with a deterministic
//! tie-breaker `Array > Run > Bitmap`. Canonical selection uses metadata and closed-form
//! size math:
//! - Array size: `varint(cardinality) + 2 * cardinality`
//! - Run size: `varint(run_count) + 4 * run_count`
//! - Bitmap size: fixed 8192 bytes
//!
//! Decoded shapes from peer-supplied wire data are validated and preserved as provided.
//! Codec bounds (per-container `MAX_RUNS`,
//! top-level `RangeCfg`) enforce DOS resistance independently.

pub mod array;
pub mod bitmap;
pub mod run;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
pub use array::Array;
pub use bitmap::Bitmap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use core::ops::Range;
pub use run::Run;

/// A container that stores u16 values using an adaptive representation.
///
/// Automatically converts between container types during insertion:
/// - Array -> Bitmap when cardinality exceeds 4096
/// - Bitmap <-> Run based on run-count hysteresis thresholds
///
/// Serialization emits a canonical representation chosen by encoded size.
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
        let inserted = match self {
            Self::Array(a) => a.insert(value),
            Self::Bitmap(b) => b.insert(value),
            Self::Run(r) => r.insert(value),
        };
        self.normalize_in_memory();
        inserted
    }

    /// Inserts a range of values into the container.
    ///
    /// Returns the number of values newly inserted.
    ///
    /// Automatically converts the container type if needed; see the [module
    /// documentation](self) for the full transition table.
    pub fn insert_range(&mut self, range: Range<u16>) -> u32 {
        if range.is_empty() {
            return 0;
        }

        match self {
            Self::Array(a) => {
                let range_len = range.len();

                // Fast path: empty array with consecutive range - use Run container
                // directly. Run stores `(start, end)` pairs, so a single range is just
                // 4 bytes vs Array which would be 2 bytes per value.
                if a.is_empty() && range_len >= 64 {
                    let mut run = Run::new();
                    let inserted = run.insert_range(range);
                    *self = Self::Run(run);
                    return inserted;
                }

                // Convert only if the range would add enough NEW values to overflow
                // array capacity.
                let new_values = range_len - a.count_in_range(&range);
                if a.len() + new_values > array::MAX_CARDINALITY {
                    self.convert_array_to_bitmap();
                    return self.insert_range(range);
                }

                let inserted = a.insert_range(range) as u32;
                self.normalize_in_memory();
                inserted
            }
            Self::Bitmap(b) => {
                let inserted = b.insert_range(range);
                self.normalize_in_memory();
                inserted
            }
            Self::Run(r) => {
                let inserted = r.insert_range(range);
                self.normalize_in_memory();
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
            let mut container = Self::Array(result);
            container.normalize_in_memory();
            return (container, count as u64);
        }

        if let (Self::Bitmap(a), Self::Bitmap(b)) = (self, other) {
            let result = Bitmap::or_new(a, b);
            let len = result.len() as u64;
            if len <= limit {
                let mut container = Self::Bitmap(Box::new(result));
                container.normalize_in_memory();
                return (container, len);
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
                let mut container = Self::Bitmap(Box::new(result));
                container.normalize_in_memory();
                return (container, len);
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
                let mut container = Self::Bitmap(Box::new(result));
                container.normalize_in_memory();
                return (container, len);
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

        match (self, other) {
            (Self::Array(a), Self::Array(b)) => return a.is_subset(b),
            (Self::Bitmap(a), Self::Bitmap(b)) => return a.is_subset(b),
            (Self::Run(a), Self::Run(b)) => return a.is_subset(b),
            _ => {}
        }

        self.iter().all(|value| other.contains(value))
    }

    /// Returns `true` if the containers share at least one value.
    pub fn intersects(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Array(a), Self::Array(b)) => return a.intersects(b),
            (Self::Bitmap(a), Self::Bitmap(b)) => return a.intersects(b),
            (Self::Run(a), Self::Run(b)) => return a.intersects(b),
            _ => {}
        }

        let (smaller, larger) = if self.len() <= other.len() {
            (self, other)
        } else {
            (other, self)
        };
        smaller.iter().any(|value| larger.contains(value))
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
            *self = Self::Array(Array::from(values));
        }
    }

    /// Converts a Bitmap container to a Run container.
    fn convert_bitmap_to_run(&mut self) {
        if let Self::Bitmap(b) = self {
            *self = Self::Run(Run::from(b.as_ref()));
        }
    }

    /// Converts a Run container to a Bitmap container.
    fn convert_run_to_bitmap(&mut self) {
        if let Self::Run(r) = self {
            *self = Self::Bitmap(Box::new(Bitmap::from(&*r)));
        }
    }

    /// Returns the run count for the current container representation.
    fn run_count(&self) -> usize {
        match self {
            Self::Array(a) => a.run_count(),
            Self::Bitmap(b) => b.run_count() as usize,
            Self::Run(r) => r.run_count(),
        }
    }

    /// Returns the canonical container type for current values:
    /// smallest encoded size, with deterministic tie-breaker Array > Run > Bitmap.
    fn canonical_kind(&self) -> CanonicalKind {
        if self.is_empty() {
            return CanonicalKind::Array;
        }

        let cardinality = self.len() as usize;
        let run_count = self.run_count();

        let run_size = run_count.encode_size() + run_count * RUN_ENCODED_BYTES;
        let mut best_kind = CanonicalKind::Run;
        let mut best_size = run_size;

        if cardinality <= array::MAX_CARDINALITY {
            let array_size = cardinality.encode_size() + cardinality * ARRAY_VALUE_ENCODED_BYTES;
            if array_size <= best_size {
                best_kind = CanonicalKind::Array;
                best_size = array_size;
            }
        }

        if BITMAP_ENCODED_BYTES < best_size {
            best_kind = CanonicalKind::Bitmap;
        }

        best_kind
    }

    /// Applies in-memory representation normalization with hysteresis.
    fn normalize_in_memory(&mut self) {
        if self.is_empty() {
            *self = Self::Array(Array::new());
            return;
        }

        loop {
            match self {
                Self::Array(a) => {
                    if a.len() > array::MAX_CARDINALITY {
                        self.convert_array_to_bitmap();
                        continue;
                    }
                    return;
                }
                Self::Bitmap(b) => {
                    if b.len() as usize <= array::MAX_CARDINALITY {
                        self.convert_bitmap_to_array();
                        return;
                    }
                    if (b.run_count() as usize) < BITMAP_TO_RUN_THRESHOLD {
                        self.convert_bitmap_to_run();
                        continue;
                    }
                    return;
                }
                Self::Run(r) => {
                    if r.run_count() > RUN_TO_BITMAP_THRESHOLD {
                        self.convert_run_to_bitmap();
                        continue;
                    }
                    return;
                }
            }
        }
    }
}

impl PartialEq for Container {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        match (self, other) {
            (Self::Array(a), Self::Array(b)) => a == b,
            (Self::Bitmap(a), Self::Bitmap(b)) => a == b,
            (Self::Run(a), Self::Run(b)) => a == b,
            _ => self.iter().eq(other.iter()),
        }
    }
}

impl Eq for Container {}

/// Convert a Bitmap to a Run when run count drops below this threshold.
///
/// The Bitmap/Run break-even is near 2048 runs (8192 bytes / 4 bytes per run
/// entry), so this lower threshold introduces slack to avoid representation
/// thrashing on small local updates.
const BITMAP_TO_RUN_THRESHOLD: usize = 1500;

/// Convert a Run to a Bitmap when run count exceeds this threshold.
///
/// This upper threshold pairs with [`BITMAP_TO_RUN_THRESHOLD`] to maintain a
/// hysteresis band around break-even.
const RUN_TO_BITMAP_THRESHOLD: usize = 2500;

/// Fixed-size bitmap payload: 1024 u64 words.
const BITMAP_ENCODED_BYTES: usize = bitmap::WORDS * core::mem::size_of::<u64>();

/// Array payload stores one u16 per value.
const ARRAY_VALUE_ENCODED_BYTES: usize = core::mem::size_of::<u16>();

/// Run payload stores one (start, end) pair per run.
const RUN_ENCODED_BYTES: usize = core::mem::size_of::<(u16, u16)>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalKind {
    Array,
    Bitmap,
    Run,
}

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
        match self.canonical_kind() {
            CanonicalKind::Array => {
                CONTAINER_TYPE_ARRAY.write(buf);

                match self {
                    Self::Array(a) => a.write(buf),
                    Self::Bitmap(b) => Array::from(b.iter().collect()).write(buf),
                    Self::Run(r) => Array::from(r.iter().collect()).write(buf),
                }
            }
            CanonicalKind::Bitmap => {
                CONTAINER_TYPE_BITMAP.write(buf);

                match self {
                    Self::Array(a) => Bitmap::from(a).write(buf),
                    Self::Bitmap(b) => b.write(buf),
                    Self::Run(r) => Bitmap::from(r).write(buf),
                }
            }
            CanonicalKind::Run => {
                CONTAINER_TYPE_RUN.write(buf);

                match self {
                    Self::Array(a) => Run::from(a).write(buf),
                    Self::Bitmap(b) => Run::from(b.as_ref()).write(buf),
                    Self::Run(r) => r.write(buf),
                }
            }
        }
    }
}

impl EncodeSize for Container {
    fn encode_size(&self) -> usize {
        let cardinality = self.len() as usize;
        let run_count = self.run_count();

        let payload_size = match self.canonical_kind() {
            CanonicalKind::Array => {
                cardinality.encode_size() + cardinality * ARRAY_VALUE_ENCODED_BYTES
            }
            CanonicalKind::Bitmap => BITMAP_ENCODED_BYTES,
            CanonicalKind::Run => run_count.encode_size() + run_count * RUN_ENCODED_BYTES,
        };

        1 + payload_size
    }
}

impl Read for Container {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let container_type = u8::read(buf)?;
        let container = match container_type {
            CONTAINER_TYPE_ARRAY => Ok(Self::Array(Array::read(buf)?)),
            CONTAINER_TYPE_BITMAP => Ok(Self::Bitmap(Box::new(Bitmap::read(buf)?))),
            CONTAINER_TYPE_RUN => {
                let run_count = usize::read_cfg(buf, &RangeCfg::new(..=run::MAX_RUNS))?;

                // If run payload is already larger than bitmap payload, this can never be
                // canonical and we can reject before reading all run entries.
                let run_payload_size = run_count.encode_size() + run_count * RUN_ENCODED_BYTES;
                if run_payload_size > BITMAP_ENCODED_BYTES {
                    return Err(CodecError::Invalid(
                        "Container",
                        "container type is not canonical for payload",
                    ));
                }

                let mut runs = Vec::with_capacity(run_count);
                for _ in 0..run_count {
                    runs.push(<(u16, u16)>::read_cfg(buf, &((), ()))?);
                }
                Ok(Self::Run(Run::from_runs_checked(runs)?))
            }
            _ => Err(CodecError::InvalidEnum(container_type)),
        }?;

        let expected = match container.canonical_kind() {
            CanonicalKind::Array => CONTAINER_TYPE_ARRAY,
            CanonicalKind::Bitmap => CONTAINER_TYPE_BITMAP,
            CanonicalKind::Run => CONTAINER_TYPE_RUN,
        };

        if container_type != expected {
            return Err(CodecError::Invalid(
                "Container",
                "container type is not canonical for payload",
            ));
        }

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
    use bytes::BytesMut;
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
    fn test_decode_rejects_noncanonical_sparse_bitmap_container() {
        let mut bitmap = Bitmap::new();
        bitmap.insert(1);
        bitmap.insert(3);
        bitmap.insert(5);

        let mut encoded = BytesMut::new();
        CONTAINER_TYPE_BITMAP.write(&mut encoded);
        bitmap.write(&mut encoded);

        let decoded = Container::decode_cfg(encoded, &());
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid(
                "Container",
                "container type is not canonical for payload"
            ))
        ));
    }

    #[test]
    fn test_decode_rejects_noncanonical_full_bitmap_container() {
        let bitmap = Bitmap::from([!0u64; bitmap::WORDS]);

        let mut encoded = BytesMut::new();
        CONTAINER_TYPE_BITMAP.write(&mut encoded);
        bitmap.write(&mut encoded);

        let decoded = Container::decode_cfg(encoded, &());
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid(
                "Container",
                "container type is not canonical for payload"
            ))
        ));
    }

    #[test]
    fn test_encode_canonicalizes_sparse_bitmap_container() {
        let mut bitmap = Bitmap::new();
        bitmap.insert(1);
        bitmap.insert(3);
        bitmap.insert(5);

        let encoded = Container::Bitmap(Box::new(bitmap)).encode();
        let decoded = Container::decode_cfg(encoded, &()).unwrap();

        assert!(matches!(decoded, Container::Array(_)));
    }

    #[test]
    fn test_encode_canonicalizes_full_bitmap_container() {
        let encoded = Container::Bitmap(Box::new(Bitmap::from([!0u64; bitmap::WORDS]))).encode();
        let decoded = Container::decode_cfg(encoded, &()).unwrap();

        assert!(matches!(decoded, Container::Run(_)));
    }

    #[test]
    fn test_decode_normalization_is_idempotent_after_run_to_bitmap() {
        let mut run = Run::new();
        for i in 0..=RUN_TO_BITMAP_THRESHOLD as u16 {
            assert!(run.insert(i * 2));
        }
        assert_eq!(run.run_count(), RUN_TO_BITMAP_THRESHOLD + 1);
        assert!(run.len() as usize <= array::MAX_CARDINALITY);

        let mut decoded_once = Container::decode_cfg(Container::Run(run).encode(), &()).unwrap();
        decoded_once.normalize_in_memory();

        let encoded_once = decoded_once.encode();
        let decoded_twice = Container::decode_cfg(encoded_once.clone(), &()).unwrap();

        assert_eq!(encoded_once, decoded_twice.encode());
    }

    #[test]
    fn test_auto_convert_array_to_bitmap() {
        let mut container = Container::new();

        // Insert alternating values past the Array->Bitmap threshold.
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
    fn test_max_cardinality_serializes_as_bitmap() {
        let mut container = Container::new();
        for i in 0..array::MAX_CARDINALITY as u16 {
            assert!(container.insert(i * 2));
        }

        assert!(matches!(container, Container::Array(_)));

        let encoded = container.encode();
        let decoded = Container::decode_cfg(encoded, &()).unwrap();
        assert!(matches!(decoded, Container::Bitmap(_)));
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
    fn test_insert_range_overlap_noop_does_not_force_bitmap_conversion() {
        let mut container = Container::new();
        assert!(container.insert(0));
        assert_eq!(container.insert_range(1..4000), 3999);
        assert!(matches!(container, Container::Array(_)));

        // Fully overlapped insertion is a no-op and should not trigger Array->Bitmap.
        assert_eq!(container.insert_range(0..1000), 0);
        assert!(matches!(container, Container::Array(_)));
        assert_eq!(container.len(), 4000);
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
    fn test_encode_size_array_variant() {
        let mut c = Container::new();
        c.insert(5);
        assert!(matches!(c, Container::Array(_)));
        assert_eq!(
            c.encode_size(),
            1 + 1usize.encode_size() + ARRAY_VALUE_ENCODED_BYTES
        );
    }

    #[test]
    fn test_encode_size_bitmap_variant() {
        // Force conversion to Bitmap (cardinality > 4096) AND keep it there by inserting
        // alternating values (many isolated runs) so auto-conversion to Run doesn't fire.
        let mut c = Container::new();
        for i in 0..=array::MAX_CARDINALITY as u16 {
            c.insert(i * 2);
        }
        assert!(matches!(c, Container::Bitmap(_)));
        assert_eq!(c.encode_size(), 1 + BITMAP_ENCODED_BYTES);
    }

    #[test]
    fn test_encode_size_run_variant() {
        let mut c = Container::Run(Run::full());
        c.insert(0); // already there, no growth
        assert_eq!(
            c.encode_size(),
            1 + 1usize.encode_size() + RUN_ENCODED_BYTES
        );
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
        // dropping run_count to 1 - well below BITMAP_TO_RUN_THRESHOLD - so the
        // container should convert to Run.
        c.insert_range(0..u16::MAX);
        assert!(matches!(c, Container::Run(_)));
    }

    #[test]
    fn test_run_auto_converts_to_bitmap_when_runs_grow() {
        // Start in Run form via the empty-array + large-range fast path in insert_range.
        let mut c = Container::new();
        c.insert_range(0..5_000);
        assert!(matches!(c, Container::Run(_)));

        // Insert many isolated, non-adjacent values. This inflates run_count so Run
        // grows past the Run->Bitmap hysteresis threshold and should flip to Bitmap.
        // Use values >= 10_000 with gaps so they don't merge with the existing
        // [0, 4999] run or each other.
        let mut value = 10_000u16;
        for _ in 0..3_000 {
            c.insert(value);
            value += 2; // gap of 1 between successive inserts to keep them disjoint.
        }

        // Should have flipped to Bitmap once run_count crossed the upper threshold.
        assert!(matches!(c, Container::Bitmap(_)));
    }

    #[test]
    fn test_no_thrash_in_hysteresis_band() {
        // Inside [BITMAP_TO_RUN_THRESHOLD, RUN_TO_BITMAP_THRESHOLD], neither
        // conversion direction triggers. We construct a Bitmap with run_count
        // inside the band and verify small fluctuations do not flip variants.
        let mut c = Container::new();
        for i in 0..2_000u16 {
            c.insert(i * 3);
        }
        for i in 2_000..5_000u16 {
            c.insert(i * 3);
        }
        assert!(matches!(c, Container::Bitmap(_)));

        for i in 0..3_000u16 {
            c.insert(i * 3 + 1);
            c.insert(i * 3 + 2);
        }
        assert!(matches!(c, Container::Bitmap(_)));

        for i in 3_000..3_010u16 {
            c.insert(i * 3 + 1);
        }
        assert!(matches!(c, Container::Bitmap(_)));

        for i in 6_000..6_010u16 {
            c.insert(i * 3);
        }
        assert!(matches!(c, Container::Bitmap(_)));
    }

    #[test]
    fn test_union_bitmap_fast_path_normalizes_to_run() {
        let mut bitmap = Bitmap::new();
        assert_eq!(bitmap.insert_range(0..5_000), 5_000);
        let left = Container::Bitmap(Box::new(bitmap.clone()));
        let right = Container::Bitmap(Box::new(bitmap));

        let (result, count) = left.union(&right, u64::MAX);
        assert_eq!(count, 5_000);
        assert!(matches!(result, Container::Run(_)));
    }

    #[test]
    fn test_intersection_bitmap_fast_path_normalizes_to_array_when_sparse() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..=array::MAX_CARDINALITY as u16 {
            assert!(a.insert(i * 2));
            assert!(b.insert(i * 2 + 1));
        }
        assert!(b.insert(42));

        let left = Container::Bitmap(Box::new(a));
        let right = Container::Bitmap(Box::new(b));
        let (result, count) = left.intersection(&right, u64::MAX);
        assert_eq!(count, 1);
        assert!(matches!(result, Container::Array(_)));
        assert_eq!(result.iter().collect::<Vec<_>>(), vec![42]);
    }

    #[test]
    fn test_difference_bitmap_fast_path_normalizes_to_array_when_sparse() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();
        for i in 0..=array::MAX_CARDINALITY as u16 {
            assert!(a.insert(i * 2));
            assert!(b.insert(i * 2));
        }
        assert!(a.insert(9_999));

        let left = Container::Bitmap(Box::new(a));
        let right = Container::Bitmap(Box::new(b));
        let (result, count) = left.difference(&right, u64::MAX);
        assert_eq!(count, 1);
        assert!(matches!(result, Container::Array(_)));
        assert_eq!(result.iter().collect::<Vec<_>>(), vec![9_999]);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::{conformance::CodecConformance, Decode, Encode};
        use commonware_conformance::Conformance;

        struct ContainerTransitionsConformance;

        fn variant_tag(container: &super::Container) -> u8 {
            match container {
                super::Container::Array(_) => 0,
                super::Container::Bitmap(_) => 1,
                super::Container::Run(_) => 2,
            }
        }

        fn append_snapshot(out: &mut Vec<u8>, container: &super::Container) {
            let encoded = container.encode();
            let decoded = super::Container::decode_cfg(encoded.clone(), &())
                .expect("container snapshot must roundtrip through canonical decode");
            assert_eq!(
                encoded,
                decoded.encode(),
                "canonical encode/decode must be idempotent"
            );

            out.push(variant_tag(container));
            out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            out.extend_from_slice(&encoded);
        }

        impl Conformance for ContainerTransitionsConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut out = Vec::new();

                // Start from a dense contiguous range so in-memory normalization picks Run.
                let mut up = super::Container::new();
                let dense_span = 5_000u16 + (seed % 1_000) as u16;
                up.insert_range(0..dense_span);
                assert!(matches!(up, super::Container::Run(_)));
                append_snapshot(&mut out, &up);

                // Increase run count above the hysteresis upper bound to force Run -> Bitmap.
                let extra_runs = super::RUN_TO_BITMAP_THRESHOLD + 64 + (seed as usize % 128);
                let mut value = 10_001u16;
                for _ in 0..extra_runs {
                    up.insert(value);
                    value += 2;
                }
                assert!(matches!(up, super::Container::Bitmap(_)));
                append_snapshot(&mut out, &up);

                // Fill almost the full shelf so run count collapses and Bitmap -> Run fires.
                up.insert_range(0..u16::MAX);
                assert!(matches!(up, super::Container::Run(_)));
                append_snapshot(&mut out, &up);

                // Start from a sparse alternating pattern that normalizes to Bitmap.
                let mut down = super::Container::new();
                for i in 0..=super::array::MAX_CARDINALITY as u16 {
                    down.insert(i * 2);
                }
                assert!(matches!(down, super::Container::Bitmap(_)));
                append_snapshot(&mut out, &down);

                // Decrease run count by filling gaps, forcing Bitmap -> Run.
                down.insert_range(0..u16::MAX);
                assert!(matches!(down, super::Container::Run(_)));
                append_snapshot(&mut out, &down);

                out
            }
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Container>,
            ContainerTransitionsConformance => 1024,
        }
    }
}
