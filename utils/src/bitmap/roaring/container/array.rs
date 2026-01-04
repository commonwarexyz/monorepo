//! Array container for sparse data.
//!
//! Stores up to 4096 sorted u16 values. When the cardinality exceeds this
//! threshold, the container should be converted to a `Bitmap`.
//!
//! # References
//!
//! - [Roaring Bitmap Paper](https://arxiv.org/pdf/1402.6407)
//! - [Roaring Bitmap Format Specification](https://github.com/RoaringBitmap/RoaringFormatSpec)

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};

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
    #[inline]
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Creates an array container with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity.min(MAX_CARDINALITY)),
        }
    }

    /// Creates an array container from a sorted, deduplicated vector.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if the values are not sorted or contain duplicates,
    /// or if the length exceeds `MAX_CARDINALITY`.
    #[inline]
    pub fn from_sorted_vec(values: Vec<u16>) -> Self {
        debug_assert!(
            values.len() <= MAX_CARDINALITY,
            "array container too large: {} > {}",
            values.len(),
            MAX_CARDINALITY
        );
        debug_assert!(
            values.is_empty() || values.windows(2).all(|w| w[0] < w[1]),
            "values must be sorted and unique"
        );
        Self { values }
    }

    /// Returns the number of values in the container.
    #[inline]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the container is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns whether the container is at maximum capacity.
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.values.len() >= MAX_CARDINALITY
    }

    /// Checks if the container contains the given value.
    #[inline]
    pub fn contains(&self, value: u16) -> bool {
        self.values.binary_search(&value).is_ok()
    }

    /// Inserts a value into the container.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    ///
    /// # Note
    ///
    /// After insertion, check [`is_full`](Self::is_full) to determine if the
    /// container should be converted to a `Bitmap`.
    #[inline]
    pub fn insert(&mut self, value: u16) -> bool {
        match self.values.binary_search(&value) {
            Ok(_) => false,
            Err(pos) => {
                self.values.insert(pos, value);
                true
            }
        }
    }

    /// Inserts a range of values [start, end) into the container.
    ///
    /// Returns the number of values newly inserted.
    ///
    /// # Note
    ///
    /// After insertion, check [`is_full`](Self::is_full) to determine if the
    /// container should be converted to a `Bitmap`.
    pub fn insert_range(&mut self, start: u16, end: u16) -> usize {
        if start >= end {
            return 0;
        }

        let range_len = (end - start) as usize;

        // Fast path for empty array
        if self.values.is_empty() {
            self.values = (start..end).collect();
            return range_len;
        }

        // Fast path: range is entirely after all existing values
        if start > *self.values.last().unwrap() {
            self.values.extend(start..end);
            return range_len;
        }

        // Fast path: range is entirely before all existing values
        if end <= *self.values.first().unwrap() {
            let mut new_vec: Vec<u16> = (start..end).collect();
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

        while range_val < end && exist_idx < end_pos {
            let e = self.values[exist_idx];
            if range_val < e {
                new_vec.push(range_val);
                range_val += 1;
            } else if range_val == e {
                new_vec.push(range_val);
                range_val += 1;
                exist_idx += 1;
            } else {
                new_vec.push(e);
                exist_idx += 1;
            }
        }

        while range_val < end {
            new_vec.push(range_val);
            range_val += 1;
        }

        while exist_idx < end_pos {
            new_vec.push(self.values[exist_idx]);
            exist_idx += 1;
        }

        new_vec.extend_from_slice(&self.values[end_pos..]);

        self.values = new_vec;
        new_values
    }

    /// Returns an iterator over the values in sorted order.
    #[inline]
    pub fn iter(&self) -> core::iter::Copied<core::slice::Iter<'_, u16>> {
        self.values.iter().copied()
    }

    /// Returns the underlying values as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u16] {
        &self.values
    }

    /// Consumes the container and returns the underlying vector.
    #[inline]
    pub fn into_vec(self) -> Vec<u16> {
        self.values
    }

    /// Returns the minimum value in the container, if any.
    #[inline]
    pub fn min(&self) -> Option<u16> {
        self.values.first().copied()
    }

    /// Returns the maximum value in the container, if any.
    #[inline]
    pub fn max(&self) -> Option<u16> {
        self.values.last().copied()
    }

    /// Computes the union of two arrays.
    ///
    /// Returns a new array containing all values from both, with optional limit.
    #[inline]
    pub fn union(&self, other: &Self, limit: usize) -> (Self, usize) {
        let a = &self.values;
        let b = &other.values;
        let max_size = a.len() + b.len();

        // Fast path: unlimited results (common case)
        if limit >= max_size {
            let mut result = Vec::with_capacity(max_size);
            let mut i = 0;
            let mut j = 0;

            while i < a.len() && j < b.len() {
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

            // Extend with remaining elements
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
    /// Returns a new array containing values present in both, with optional limit.
    #[inline]
    pub fn intersection(&self, other: &Self, limit: usize) -> (Self, usize) {
        let a = &self.values;
        let b = &other.values;
        let min_size = a.len().min(b.len());

        // Fast path: unlimited results (common case)
        if limit >= min_size {
            let mut result = Vec::with_capacity(min_size);
            let mut i = 0;
            let mut j = 0;

            while i < a.len() && j < b.len() {
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
            return (Self { values: result }, count);
        }

        // Limited case: need to check limit
        let mut result = Vec::with_capacity(min_size.min(limit));
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
    /// Returns a new array containing values in self but not in other, with optional limit.
    #[inline]
    pub fn difference(&self, other: &Self, limit: usize) -> (Self, usize) {
        let a = &self.values;
        let b = &other.values;

        // Fast path: unlimited results (common case)
        if limit >= a.len() {
            let mut result = Vec::with_capacity(a.len());
            let mut i = 0;
            let mut j = 0;

            while i < a.len() && j < b.len() {
                let av = a[i];
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
            // Remaining elements from a are all in the difference
            result.extend_from_slice(&a[i..]);

            let count = result.len();
            return (Self { values: result }, count);
        }

        // Limited case: need to check limit
        let mut result = Vec::with_capacity(a.len().min(limit));
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

        // Validate sorted and unique
        if values.windows(2).any(|w| w[0] >= w[1]) {
            return Err(CodecError::Invalid(
                "Array",
                "values must be sorted and unique",
            ));
        }

        Ok(Self { values })
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
        assert!(!container.is_full());
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

        let inserted = container.insert_range(5, 10);
        assert_eq!(inserted, 5);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);

        // Overlapping range
        let inserted = container.insert_range(8, 12);
        assert_eq!(inserted, 2); // Only 10, 11 are new
        assert_eq!(container.len(), 7);
    }

    #[test]
    fn test_from_sorted_vec() {
        let values = vec![1, 5, 10, 100];
        let container = Array::from_sorted_vec(values.clone());
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
    fn test_is_full() {
        let values: Vec<u16> = (0..MAX_CARDINALITY as u16).collect();
        let container = Array::from_sorted_vec(values);
        assert!(container.is_full());
    }
}
