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

        // Find insertion point for start value
        let start_pos = match self.values.binary_search(&start) {
            Ok(pos) => pos,
            Err(pos) => pos,
        };

        // Find position after end-1 value
        let end_pos = match self.values[start_pos..].binary_search(&(end - 1)) {
            Ok(pos) => start_pos + pos + 1,
            Err(pos) => start_pos + pos,
        };

        // Count existing values in range [start, end)
        let existing_in_range = end_pos - start_pos;

        // Calculate how many new values will be inserted
        let new_values = range_len - existing_in_range;
        if new_values == 0 {
            return 0;
        }

        // Build new values vector efficiently
        let new_len = self.values.len() + new_values;
        let mut new_vec = Vec::with_capacity(new_len);

        // Copy prefix (values before start)
        new_vec.extend_from_slice(&self.values[..start_pos]);

        // Merge range with existing values in range using two-pointer approach
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

        // Push remaining range values
        while range_val < end {
            new_vec.push(range_val);
            range_val += 1;
        }

        // Push remaining existing values in range (shouldn't happen if logic is correct)
        while exist_idx < end_pos {
            new_vec.push(self.values[exist_idx]);
            exist_idx += 1;
        }

        // Copy suffix (values after end-1)
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
    pub fn union(&self, other: &Self, limit: usize) -> (Self, usize) {
        let mut result = Vec::with_capacity((self.len() + other.len()).min(limit));
        let mut a_iter = self.values.iter().peekable();
        let mut b_iter = other.values.iter().peekable();

        while result.len() < limit {
            match (a_iter.peek(), b_iter.peek()) {
                (Some(&&a), Some(&&b)) => {
                    if a < b {
                        result.push(a);
                        a_iter.next();
                    } else if b < a {
                        result.push(b);
                        b_iter.next();
                    } else {
                        result.push(a);
                        a_iter.next();
                        b_iter.next();
                    }
                }
                (Some(&&a), None) => {
                    result.push(a);
                    a_iter.next();
                }
                (None, Some(&&b)) => {
                    result.push(b);
                    b_iter.next();
                }
                (None, None) => break,
            }
        }

        let count = result.len();
        (Self { values: result }, count)
    }

    /// Computes the intersection of two arrays.
    ///
    /// Returns a new array containing values present in both, with optional limit.
    pub fn intersection(&self, other: &Self, limit: usize) -> (Self, usize) {
        let mut result = Vec::with_capacity(self.len().min(other.len()).min(limit));
        let mut a_iter = self.values.iter().peekable();
        let mut b_iter = other.values.iter().peekable();

        while result.len() < limit {
            match (a_iter.peek(), b_iter.peek()) {
                (Some(&&a), Some(&&b)) => {
                    if a < b {
                        a_iter.next();
                    } else if b < a {
                        b_iter.next();
                    } else {
                        result.push(a);
                        a_iter.next();
                        b_iter.next();
                    }
                }
                _ => break,
            }
        }

        let count = result.len();
        (Self { values: result }, count)
    }

    /// Computes the difference (self - other).
    ///
    /// Returns a new array containing values in self but not in other, with optional limit.
    pub fn difference(&self, other: &Self, limit: usize) -> (Self, usize) {
        let mut result = Vec::with_capacity(self.len().min(limit));
        let mut a_iter = self.values.iter().peekable();
        let mut b_iter = other.values.iter().peekable();

        while result.len() < limit {
            match (a_iter.peek(), b_iter.peek()) {
                (Some(&&a), Some(&&b)) => {
                    if a < b {
                        result.push(a);
                        a_iter.next();
                    } else if b < a {
                        b_iter.next();
                    } else {
                        a_iter.next();
                        b_iter.next();
                    }
                }
                (Some(&&a), None) => {
                    result.push(a);
                    a_iter.next();
                }
                _ => break,
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
