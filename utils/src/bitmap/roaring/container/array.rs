//! Array container for sparse data.
//!
//! Stores up to 4096 sorted u16 values. When the cardinality exceeds this
//! threshold, the container should be converted to a `Bitmap`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use core::ops::Range;

/// Maximum cardinality before converting to a bitmap container.
pub const MAX_CARDINALITY: usize = 4096;

/// A container that stores sparse u16 values in a sorted array.
///
/// This is efficient for containers with cardinality <= 4096, as it uses
/// less memory than a full bitmap (which requires 8KB regardless of density).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Array {
    /// Sorted values stored in the container.
    values: Vec<u16>,
}

impl Default for Array {
    fn default() -> Self {
        Self::new()
    }
}

impl Array {
    /// Creates an empty array container.
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Creates an array from values that are expected to already be valid.
    ///
    /// In debug builds, this asserts the same invariants enforced by decoding:
    /// values must be sorted, unique, and `len <= MAX_CARDINALITY`.
    pub(super) fn from(values: Vec<u16>) -> Self {
        debug_assert!(
            validate_values(&values).is_ok(),
            "Array::from requires sorted unique values with len <= MAX_CARDINALITY"
        );
        Self { values }
    }

    /// Returns the number of values in the container.
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the container is empty.
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Checks if the container contains the given value.
    pub fn contains(&self, value: u16) -> bool {
        self.values.binary_search(&value).is_ok()
    }

    /// Returns how many existing values fall within `range`.
    pub fn count_in_range(&self, range: &Range<u16>) -> usize {
        if range.is_empty() || self.values.is_empty() {
            return 0;
        }

        let start = range.start;
        let end = range.end;
        let start_pos = self.values.partition_point(|&x| x < start);
        let end_pos = self.values.partition_point(|&x| x < end);
        end_pos.saturating_sub(start_pos)
    }

    /// Returns the number of maximal consecutive runs in the stored values.
    pub(super) fn run_count(&self) -> usize {
        if self.values.is_empty() {
            return 0;
        }

        let mut runs = 1usize;
        for pair in self.values.windows(2) {
            if (pair[1] as u32) != (pair[0] as u32) + 1 {
                runs += 1;
            }
        }
        runs
    }

    /// Inserts a value into the container.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    ///
    /// # Note
    ///
    /// After insertion, convert to `Bitmap` if the cardinality exceeds
    /// [`MAX_CARDINALITY`].
    pub fn insert(&mut self, value: u16) -> bool {
        match self.values.binary_search(&value) {
            Ok(_) => false,
            Err(pos) => {
                self.values.insert(pos, value);
                true
            }
        }
    }

    /// Inserts a range of values into the container.
    ///
    /// Returns the number of values newly inserted.
    ///
    /// # Note
    ///
    /// After insertion, convert to `Bitmap` if the cardinality exceeds
    /// [`MAX_CARDINALITY`].
    pub fn insert_range(&mut self, range: Range<u16>) -> usize {
        if range.is_empty() {
            return 0;
        }

        let range_len = range.len();
        let start = range.start;
        let end = range.end;

        // Fast path for empty array
        let Some(&last) = self.values.last() else {
            self.values = range.collect();
            return range_len;
        };

        // Fast path: range is entirely after all existing values
        if start > last {
            self.values.extend(range);
            return range_len;
        }

        // Fast path: range is entirely before all existing values
        if end <= self.values[0] {
            let mut new_vec = Vec::with_capacity(range_len + self.values.len());
            new_vec.extend(range);
            new_vec.extend_from_slice(&self.values);
            self.values = new_vec;
            return range_len;
        }

        // General case: range overlaps with existing values
        let start_pos = self.values.partition_point(|&x| x < start);
        let end_pos = self.values[start_pos..].partition_point(|&x| x < end) + start_pos;

        let existing_in_range = end_pos - start_pos;
        let new_values = range_len - existing_in_range;
        if new_values == 0 {
            return 0;
        }

        let new_len = self.values.len() + new_values;
        let mut new_vec = Vec::with_capacity(new_len);

        new_vec.extend_from_slice(&self.values[..start_pos]);

        let mut range_val = start;
        let mut exist_idx = start_pos;

        // Invariant: start_pos/end_pos partitioning guarantees range_val <= e at the
        // top of every iteration, so the only two reachable cases are equal and less.
        while range_val < end && exist_idx < end_pos {
            let e = self.values[exist_idx];
            if range_val == e {
                new_vec.push(range_val);
                range_val += 1;
                exist_idx += 1;
            } else {
                debug_assert!(range_val < e);
                new_vec.push(range_val);
                range_val += 1;
            }
        }
        debug_assert!(exist_idx == end_pos);

        while range_val < end {
            new_vec.push(range_val);
            range_val += 1;
        }

        new_vec.extend_from_slice(&self.values[end_pos..]);

        self.values = new_vec;
        new_values
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> core::iter::Copied<core::slice::Iter<'_, u16>> {
        self.values.iter().copied()
    }

    /// Returns the underlying values as a slice.
    pub fn as_slice(&self) -> &[u16] {
        &self.values
    }

    /// Returns the minimum value in the container, if any.
    pub fn min(&self) -> Option<u16> {
        self.values.first().copied()
    }

    /// Returns the maximum value in the container, if any.
    pub fn max(&self) -> Option<u16> {
        self.values.last().copied()
    }

    /// Computes the union of two arrays.
    ///
    /// `limit` caps the number of values copied into the result.
    ///
    /// Returns the result array and the number of values in it.
    pub fn union(&self, other: &Self, limit: usize) -> (Self, usize) {
        let a = &self.values;
        let b = &other.values;
        let max_size = a.len() + b.len();

        // Fast path: unlimited results (common case)
        if limit >= max_size {
            let mut result = Vec::with_capacity(max_size);
            let a_len = a.len();
            let b_len = b.len();

            let mut i = 0;
            let mut j = 0;

            while i < a_len && j < b_len {
                let av = a[i];
                let bv = b[j];
                match av.cmp(&bv) {
                    core::cmp::Ordering::Less => {
                        result.push(av);
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(bv);
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        result.push(av);
                        i += 1;
                        j += 1;
                    }
                }
            }

            // Copy remaining elements
            result.extend_from_slice(&a[i..]);
            result.extend_from_slice(&b[j..]);

            let count = result.len();
            return (Self { values: result }, count);
        }

        // Limited case: need to check limit
        let mut result = Vec::with_capacity(max_size.min(limit));
        let mut i = 0;
        let mut j = 0;

        while i < a.len() && j < b.len() && result.len() < limit {
            let av = a[i];
            let bv = b[j];
            if av < bv {
                result.push(av);
                i += 1;
            } else if bv < av {
                result.push(bv);
                j += 1;
            } else {
                result.push(av);
                i += 1;
                j += 1;
            }
        }

        let remaining = limit - result.len();
        if remaining > 0 && i < a.len() {
            let take = remaining.min(a.len() - i);
            result.extend_from_slice(&a[i..i + take]);
        }
        let remaining = limit - result.len();
        if remaining > 0 && j < b.len() {
            let take = remaining.min(b.len() - j);
            result.extend_from_slice(&b[j..j + take]);
        }

        let count = result.len();
        (Self { values: result }, count)
    }

    /// Computes the intersection of two arrays.
    ///
    /// `limit` caps the number of values copied into the result.
    ///
    /// Returns the result array and the number of values in it.
    pub fn intersection(&self, other: &Self, limit: usize) -> (Self, usize) {
        let a = &self.values;
        let b = &other.values;
        let min_size = a.len().min(b.len());

        // Fast path: unlimited results (common case)
        if limit >= min_size {
            let mut result = Vec::with_capacity(min_size);
            let a_len = a.len();
            let b_len = b.len();

            let mut i = 0;
            let mut j = 0;

            while i < a_len && j < b_len {
                let av = a[i];
                let bv = b[j];
                match av.cmp(&bv) {
                    core::cmp::Ordering::Less => {
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        result.push(av);
                        i += 1;
                        j += 1;
                    }
                }
            }

            let count = result.len();
            return (Self { values: result }, count);
        }

        // Limited case: need to check limit
        let mut result = Vec::with_capacity(limit);
        let mut i = 0;
        let mut j = 0;

        while i < a.len() && j < b.len() && result.len() < limit {
            let av = a[i];
            let bv = b[j];
            if av < bv {
                i += 1;
            } else if bv < av {
                j += 1;
            } else {
                result.push(av);
                i += 1;
                j += 1;
            }
        }

        let count = result.len();
        (Self { values: result }, count)
    }

    /// Computes the difference (self - other).
    ///
    /// `limit` caps the number of values copied into the result.
    ///
    /// Returns the result array and the number of values in it.
    pub fn difference(&self, other: &Self, limit: usize) -> (Self, usize) {
        let a = &self.values;
        let b = &other.values;

        // Fast path: other is empty, return copy of self
        if b.is_empty() {
            if limit >= a.len() {
                return (Self { values: a.clone() }, a.len());
            }
            let values: Vec<u16> = a[..limit].to_vec();
            let count = values.len();
            return (Self { values }, count);
        }

        // Fast path: unlimited results (common case)
        if limit >= a.len() {
            let mut result = Vec::with_capacity(a.len());
            let a_len = a.len();
            let b_len = b.len();

            let mut i = 0;
            let mut j = 0;

            while i < a_len && j < b_len {
                let av = a[i];
                let bv = b[j];
                match av.cmp(&bv) {
                    core::cmp::Ordering::Less => {
                        result.push(av);
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        i += 1;
                        j += 1;
                    }
                }
            }

            // Copy remaining elements from a
            result.extend_from_slice(&a[i..]);

            let count = result.len();
            return (Self { values: result }, count);
        }

        // Limited case: need to check limit
        let mut result = Vec::with_capacity(limit);
        let mut i = 0;
        let mut j = 0;

        while i < a.len() && result.len() < limit {
            let av = a[i];
            if j >= b.len() {
                let remaining = limit - result.len();
                let take = remaining.min(a.len() - i);
                result.extend_from_slice(&a[i..i + take]);
                break;
            }
            let bv = b[j];
            if av < bv {
                result.push(av);
                i += 1;
            } else if av > bv {
                j += 1;
            } else {
                i += 1;
                j += 1;
            }
        }

        let count = result.len();
        (Self { values: result }, count)
    }

    /// Returns `true` if every value in this array is present in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        if self.values.len() > other.values.len() {
            return false;
        }

        let mut i = 0usize;
        let mut j = 0usize;
        while i < self.values.len() && j < other.values.len() {
            let a = self.values[i];
            let b = other.values[j];
            if a == b {
                i += 1;
                j += 1;
            } else if a > b {
                j += 1;
            } else {
                return false;
            }
        }

        i == self.values.len()
    }

    /// Returns `true` if this array shares at least one value with `other`.
    pub fn intersects(&self, other: &Self) -> bool {
        let mut i = 0usize;
        let mut j = 0usize;
        while i < self.values.len() && j < other.values.len() {
            let a = self.values[i];
            let b = other.values[j];
            if a == b {
                return true;
            }
            if a < b {
                i += 1;
            } else {
                j += 1;
            }
        }
        false
    }
}

impl Write for Array {
    fn write(&self, buf: &mut impl BufMut) {
        self.values.as_slice().write(buf);
    }
}

impl EncodeSize for Array {
    fn encode_size(&self) -> usize {
        self.values.as_slice().encode_size()
    }
}

impl Read for Array {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let values = Vec::<u16>::read_cfg(buf, &(RangeCfg::new(..=MAX_CARDINALITY), ()))?;

        validate_values(&values)?;
        Ok(Self::from(values))
    }
}

impl TryFrom<Vec<u16>> for Array {
    type Error = CodecError;

    fn try_from(values: Vec<u16>) -> Result<Self, Self::Error> {
        validate_values(&values)?;
        Ok(Self::from(values))
    }
}

fn validate_values(values: &[u16]) -> Result<(), CodecError> {
    if values.len() > MAX_CARDINALITY {
        return Err(CodecError::InvalidLength(values.len()));
    }
    if values.windows(2).any(|w| w[0] >= w[1]) {
        return Err(CodecError::Invalid(
            "Array",
            "values must be sorted and unique",
        ));
    }
    Ok(())
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Array {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=MAX_CARDINALITY)?;
        let mut values = Vec::with_capacity(len);
        let mut min = 0u32;
        for i in 0..len {
            let remaining = len - i - 1;
            let max = u16::MAX as u32 - remaining as u32;
            let value = u.int_in_range(min..=max)? as u16;
            values.push(value);
            min = value as u32 + 1;
        }

        Self::try_from(values).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_empty() {
        let container = Array::new();
        assert!(container.is_empty());
        assert_eq!(container.len(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut container = Array::new();

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
    fn test_sorted_order() {
        let mut container = Array::new();
        container.insert(10);
        container.insert(5);
        container.insert(15);
        container.insert(1);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![1, 5, 10, 15]);
    }

    #[test]
    fn test_insert_range() {
        let mut container = Array::new();

        let inserted = container.insert_range(5..10);
        assert_eq!(inserted, 5);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);

        // Overlapping range
        let inserted = container.insert_range(8..12);
        assert_eq!(inserted, 2); // Only 10, 11 are new
        assert_eq!(container.len(), 7);
    }

    #[test]
    fn test_try_from_sorted_vec() {
        let values = vec![1, 5, 10, 100];
        let container = Array::try_from(values.clone()).unwrap();
        assert_eq!(container.len(), 4);
        assert_eq!(container.as_slice(), &values[..]);
    }

    #[test]
    fn test_min_max() {
        let mut container = Array::new();
        assert_eq!(container.min(), None);
        assert_eq!(container.max(), None);

        container.insert(50);
        container.insert(10);
        container.insert(100);

        assert_eq!(container.min(), Some(10));
        assert_eq!(container.max(), Some(100));
    }

    #[test]
    fn test_intersection() {
        let values_a = vec![1, 3, 5, 7, 9];
        let values_b = vec![2, 3, 4, 5, 6];

        let container_a = Array::try_from(values_a).unwrap();
        let container_b = Array::try_from(values_b).unwrap();

        // unlimited case
        let (result, count) = container_a.intersection(&container_b, usize::MAX);
        assert_eq!(result.as_slice(), &[3, 5]);
        assert_eq!(count, 2);

        // limited case
        let (result, count) = container_a.intersection(&container_b, 1);
        assert_eq!(result.as_slice(), &[3]);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_difference() {
        let values_a = vec![1, 3, 5, 7, 9];
        let values_b = vec![2, 3, 4, 5, 6];

        let empty = Array::new();
        let container_a = Array::try_from(values_a.clone()).unwrap();
        let container_b = Array::try_from(values_b).unwrap();

        // difference with empty: unlimited
        let (result, count) = container_a.difference(&empty, usize::MAX);
        assert_eq!(result.as_slice(), &values_a[..]);
        assert_eq!(count, values_a.len());

        // difference with empty: limited
        let (result, count) = container_a.difference(&empty, 3);
        assert_eq!(result.as_slice(), &[1, 3, 5]);
        assert_eq!(count, 3);

        // unlimited case
        let (result, count) = container_a.difference(&container_b, usize::MAX);
        assert_eq!(result.as_slice(), &[1, 7, 9]);
        assert_eq!(count, 3);

        // limited case
        let (result, count) = container_a.difference(&container_b, 2);
        assert_eq!(result.as_slice(), &[1, 7]);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_is_subset() {
        let a = Array::try_from(vec![1, 3, 5]).unwrap();
        let b = Array::try_from(vec![0, 1, 2, 3, 4, 5, 6]).unwrap();
        let c = Array::try_from(vec![1, 3, 6]).unwrap();

        assert!(a.is_subset(&b));
        assert!(!a.is_subset(&c));
    }

    #[test]
    fn test_intersects() {
        let a = Array::try_from(vec![1, 3, 5]).unwrap();
        let b = Array::try_from(vec![2, 4, 6]).unwrap();
        let c = Array::try_from(vec![0, 3, 8]).unwrap();

        assert!(!a.intersects(&b));
        assert!(a.intersects(&c));
    }

    #[test]
    fn test_encode_size_empty() {
        let a = Array::new();
        assert_eq!(a.encode_size(), 0usize.encode_size());
    }

    #[test]
    fn test_encode_size_with_values() {
        let mut a = Array::new();
        for i in 0..100u16 {
            a.insert(i);
        }
        assert_eq!(
            a.encode_size(),
            100usize.encode_size() + 100 * core::mem::size_of::<u16>()
        );
    }

    #[test]
    fn test_encode_size_grows_with_inserts() {
        let mut a = Array::new();
        let s0 = a.encode_size();
        for i in 0..1000u16 {
            a.insert(i);
        }
        let s1 = a.encode_size();
        assert!(s1 > s0);
        assert_eq!(
            s1,
            1000usize.encode_size() + 1000 * core::mem::size_of::<u16>()
        );
    }

    #[test]
    fn test_insert_range_appends_after_existing() {
        // Fast path: incoming range starts strictly above the largest existing value.
        let mut a = Array::new();
        a.insert(10);
        a.insert(20);
        let inserted = a.insert_range(100..105);
        assert_eq!(inserted, 5);
        assert_eq!(a.as_slice(), &[10, 20, 100, 101, 102, 103, 104]);
    }

    #[test]
    fn test_insert_range_prepends_before_existing() {
        // Fast path: incoming range ends at-or-before the smallest existing value.
        let mut a = Array::new();
        a.insert(50);
        a.insert(60);
        // end (=20) <= first (=50), so prepend.
        let inserted = a.insert_range(10..20);
        assert_eq!(inserted, 10);
        assert_eq!(
            a.as_slice(),
            &[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 50, 60]
        );
    }

    #[test]
    fn test_insert_range_prepends_adjacent_to_existing() {
        // Boundary case for the prepend fast path: `end == first` (range ends right
        // before the existing minimum). Triggers the `end <= first` branch via
        // equality.
        let mut a = Array::new();
        a.insert(5);
        let inserted = a.insert_range(0..5);
        assert_eq!(inserted, 5);
        assert_eq!(a.as_slice(), &[0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_default() {
        let a: Array = Default::default();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn test_insert_range_general_case_with_gaps() {
        // Existing values inside the incoming range act as "matched" landmarks while
        // surrounding integers are filled in. Covers the `range_val < e` branch of
        // the general-case main loop (the existing test only exercises the equal arm).
        let mut a = Array::new();
        a.insert(5);
        let inserted = a.insert_range(3..8);
        assert_eq!(inserted, 4); // 3, 4, 6, 7 are new; 5 already existed
        assert_eq!(a.as_slice(), &[3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_union_disjoint_unlimited() {
        // b is entirely after a: exercises the unlimited fast path's tail-copy
        // of b after a's iterator runs out.
        let a = Array::try_from(vec![1, 2, 3]).unwrap();
        let b = Array::try_from(vec![10, 11, 12]).unwrap();

        let (result, count) = a.union(&b, usize::MAX);
        assert_eq!(result.as_slice(), &[1, 2, 3, 10, 11, 12]);
        assert_eq!(count, 6);
    }

    #[test]
    fn test_union_with_overlap_unlimited() {
        // Equal elements advance both indices and are pushed once; covers the
        // Ordering::Equal arm of the unlimited fast path.
        let a = Array::try_from(vec![1, 3, 5, 7]).unwrap();
        let b = Array::try_from(vec![3, 5, 9]).unwrap();

        let (result, count) = a.union(&b, usize::MAX);
        assert_eq!(result.as_slice(), &[1, 3, 5, 7, 9]);
        assert_eq!(count, 5);
    }

    #[test]
    fn test_union_limited_truncates_during_merge() {
        // Limit is hit while both sides still have elements: the tail-extend
        // blocks are reached but contribute nothing.
        let a = Array::try_from(vec![1, 3, 5]).unwrap();
        let b = Array::try_from(vec![2, 4, 6]).unwrap();

        let (result, count) = a.union(&b, 3);
        assert_eq!(result.as_slice(), &[1, 2, 3]);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_union_limited_one_side_consumed_first() {
        // b runs out before the limit is reached; the remaining capacity is
        // filled by extending from a's tail.
        let a = Array::try_from(vec![1, 2, 3, 4, 5]).unwrap();
        let b = Array::try_from(vec![1]).unwrap();

        let (result, count) = a.union(&b, 4);
        assert_eq!(result.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(count, 4);
    }

    #[test]
    fn test_insert_range_subsumed_returns_zero() {
        // Range is entirely contained in existing values: general path computes
        // new_values == 0 and returns early without rebuilding the buffer.
        let mut a = Array::new();
        for i in 0..10u16 {
            a.insert(i);
        }
        let inserted = a.insert_range(2..5);
        assert_eq!(inserted, 0);
        assert_eq!(a.len(), 10);
        assert_eq!(a.as_slice(), &(0..10).collect::<Vec<u16>>()[..]);
    }

    #[test]
    fn test_codec_rejects_unsorted_values() {
        // Decoder must reject a Vec<u16> that violates the sorted/unique invariant.
        // Build a buffer using the codec's own slice encoding, with values that are
        // out of order, then call decode and assert the typed error fires.
        use bytes::BytesMut;
        use commonware_codec::{Decode, Write};

        // Out of order: 10 > 5 in adjacent positions.
        let unsorted: Vec<u16> = vec![3, 10, 5];
        let mut buf = BytesMut::new();
        unsorted.as_slice().write(&mut buf);

        let result = Array::decode_cfg(buf.freeze(), &());
        assert!(
            matches!(
                result,
                Err(CodecError::Invalid("Array", msg)) if msg.contains("sorted and unique")
            ),
            "expected Invalid(\"Array\", ...) error, got {result:?}"
        );
    }

    #[test]
    fn test_codec_rejects_duplicate_values() {
        // The same validation also rejects duplicates (`w[0] >= w[1]` covers equal).
        use bytes::BytesMut;
        use commonware_codec::{Decode, Write};

        let with_duplicate: Vec<u16> = vec![1, 5, 5, 10];
        let mut buf = BytesMut::new();
        with_duplicate.as_slice().write(&mut buf);

        let result = Array::decode_cfg(buf.freeze(), &());
        assert!(
            matches!(
                result,
                Err(CodecError::Invalid("Array", msg)) if msg.contains("sorted and unique")
            ),
            "expected Invalid(\"Array\", ...) error, got {result:?}"
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Array>,
        }
    }
}
