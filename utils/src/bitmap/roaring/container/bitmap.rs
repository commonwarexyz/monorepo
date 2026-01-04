//! Bitmap container for dense data.
//!
//! Stores values using a fixed 8KB bit array (65536 bits). This is efficient
//! for containers with cardinality > 4096, where an array container would
//! use more memory than the fixed bitmap overhead.
//!
//! When the container becomes fully saturated (cardinality == 65536), it
//! should be converted to a `Run` with a single run \[0, 65535\].
//!
//! # References
//!
//! - [Roaring Bitmap Paper](https://arxiv.org/pdf/1402.6407)
//! - [Roaring Bitmap Format Specification](https://github.com/RoaringBitmap/RoaringFormatSpec)

use super::array;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};

/// Number of 64-bit words needed to store 65536 bits.
pub const WORDS: usize = 1024;

/// Total number of bits in a bitmap container.
pub const BITS: u32 = 65536;

/// A container that stores values using a fixed-size bit array.
///
/// Uses 8KB of memory regardless of cardinality. Efficient for dense data
/// (cardinality > 4096).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    /// Bit array storing 65536 bits.
    words: [u64; WORDS],
    /// Cached cardinality for O(1) len() queries.
    cardinality: u32,
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl Bitmap {
    /// Creates an empty bitmap container.
    #[inline]
    pub const fn new() -> Self {
        Self {
            words: [0; WORDS],
            cardinality: 0,
        }
    }

    /// Creates a bitmap container from an array of words.
    ///
    /// # Panics
    ///
    /// Panics if the provided slice length doesn't match `WORDS`.
    pub fn from_words(words: [u64; WORDS]) -> Self {
        let cardinality = words.iter().map(|w| w.count_ones()).sum();
        Self { words, cardinality }
    }

    /// Creates a bitmap container from an array container.
    pub fn from_array(array: &array::Array) -> Self {
        let mut container = Self::new();
        for value in array.iter() {
            container.insert(value);
        }
        container
    }

    /// Returns the number of values in the container.
    #[inline]
    pub const fn len(&self) -> u32 {
        self.cardinality
    }

    /// Returns whether the container is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.cardinality == 0
    }

    /// Returns whether the container is fully saturated.
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.cardinality == BITS
    }

    /// Returns whether this container should be an array container instead.
    ///
    /// An array container is more memory-efficient when cardinality <= 4096.
    #[inline]
    pub const fn should_be_array(&self) -> bool {
        (self.cardinality as usize) <= array::MAX_CARDINALITY
    }

    /// Checks if the container contains the given value.
    #[inline]
    pub const fn contains(&self, value: u16) -> bool {
        let word_idx = (value >> 6) as usize;
        let bit_idx = value & 63;
        (self.words[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Inserts a value into the container.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    ///
    /// # Note
    ///
    /// After insertion, check [`is_full`](Self::is_full) to determine if the
    /// container should be converted to a `Run`.
    #[inline]
    pub const fn insert(&mut self, value: u16) -> bool {
        let word_idx = (value >> 6) as usize;
        let bit_idx = value & 63;
        let mask = 1u64 << bit_idx;

        if (self.words[word_idx] & mask) == 0 {
            self.words[word_idx] |= mask;
            self.cardinality += 1;
            true
        } else {
            false
        }
    }

    /// Inserts a range of values [start, end) into the container.
    ///
    /// Returns the number of values newly inserted.
    ///
    /// # Note
    ///
    /// After insertion, check [`is_full`](Self::is_full) to determine if the
    /// container should be converted to a `Run`.
    pub fn insert_range(&mut self, start: u16, end: u16) -> u32 {
        if start >= end {
            return 0;
        }

        let start_word = (start >> 6) as usize;
        let end_word = ((end - 1) >> 6) as usize;
        let start_bit = start & 63;
        let end_bit = (end - 1) & 63;

        let mut inserted = 0u32;

        if start_word == end_word {
            // Range fits in a single word
            let mask = ((1u64 << (end_bit - start_bit + 1)) - 1) << start_bit;
            let old_count = self.words[start_word].count_ones();
            self.words[start_word] |= mask;
            inserted = self.words[start_word].count_ones() - old_count;
        } else {
            // First word (partial)
            let first_mask = !0u64 << start_bit;
            let old_count = self.words[start_word].count_ones();
            self.words[start_word] |= first_mask;
            inserted += self.words[start_word].count_ones() - old_count;

            // Middle words (full)
            for word in &mut self.words[start_word + 1..end_word] {
                let old_count = word.count_ones();
                *word = !0u64;
                inserted += 64 - old_count;
            }

            // Last word (partial)
            let last_mask = (1u64 << (end_bit + 1)) - 1;
            let old_count = self.words[end_word].count_ones();
            self.words[end_word] |= last_mask;
            inserted += self.words[end_word].count_ones() - old_count;
        }

        self.cardinality += inserted;
        inserted
    }

    /// Returns an iterator over the values in sorted order.
    pub const fn iter(&self) -> Iter<'_> {
        Iter {
            words: &self.words,
            word_idx: 0,
            current_word: self.words[0],
        }
    }

    /// Returns the underlying words array.
    #[inline]
    pub const fn words(&self) -> &[u64; WORDS] {
        &self.words
    }

    /// Returns a mutable reference to the underlying words array.
    ///
    /// # Safety
    ///
    /// After modifying words directly, you must call [`recalculate_cardinality`](Self::recalculate_cardinality).
    #[inline]
    pub const fn words_mut(&mut self) -> &mut [u64; WORDS] {
        &mut self.words
    }

    /// Recalculates the cardinality from the words array.
    ///
    /// Call this after modifying words directly via [`words_mut`](Self::words_mut).
    #[inline]
    pub fn recalculate_cardinality(&mut self) {
        self.cardinality = self.words.iter().map(|w| w.count_ones()).sum();
    }

    /// Returns the minimum value in the container, if any.
    pub fn min(&self) -> Option<u16> {
        for (word_idx, &word) in self.words.iter().enumerate() {
            if word != 0 {
                let bit_idx = word.trailing_zeros();
                return Some((word_idx as u16) << 6 | bit_idx as u16);
            }
        }
        None
    }

    /// Returns the maximum value in the container, if any.
    pub fn max(&self) -> Option<u16> {
        for (word_idx, &word) in self.words.iter().enumerate().rev() {
            if word != 0 {
                let bit_idx = 63 - word.leading_zeros();
                return Some((word_idx as u16) << 6 | bit_idx as u16);
            }
        }
        None
    }

    /// Performs a bitwise OR with another bitmap container.
    #[inline]
    pub fn or(&mut self, other: &Self) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a |= *b;
        }
        self.recalculate_cardinality();
    }

    /// Performs a bitwise AND with another bitmap container.
    #[inline]
    pub fn and(&mut self, other: &Self) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a &= *b;
        }
        self.recalculate_cardinality();
    }

    /// Performs a bitwise AND-NOT (difference) with another bitmap container.
    #[inline]
    pub fn and_not(&mut self, other: &Self) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a &= !*b;
        }
        self.recalculate_cardinality();
    }
}

impl Write for Bitmap {
    fn write(&self, buf: &mut impl BufMut) {
        // Write all words directly (fixed 8KB)
        for &word in &self.words {
            word.write(buf);
        }
    }
}

impl EncodeSize for Bitmap {
    fn encode_size(&self) -> usize {
        WORDS * 8 // 1024 * 8 = 8KB
    }
}

impl Read for Bitmap {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let mut words = [0u64; WORDS];
        for word in &mut words {
            *word = u64::read(buf)?;
        }
        let container = Self::from_words(words);

        // Validate cardinality is > 4096 (otherwise should be Array)
        if container.should_be_array() {
            return Err(CodecError::Invalid(
                "Bitmap",
                "cardinality too low, should be Array container",
            ));
        }

        Ok(container)
    }
}

/// Iterator over values in a bitmap container.
pub struct Iter<'a> {
    words: &'a [u64; WORDS],
    word_idx: usize,
    current_word: u64,
}

impl Iterator for Iter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_word != 0 {
                let bit_idx = self.current_word.trailing_zeros();
                self.current_word &= self.current_word - 1; // Clear lowest bit
                return Some((self.word_idx as u16) << 6 | bit_idx as u16);
            }

            self.word_idx += 1;
            if self.word_idx >= WORDS {
                return None;
            }
            self.current_word = self.words[self.word_idx];
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining: u32 = self.current_word.count_ones()
            + self.words[self.word_idx + 1..]
                .iter()
                .map(|w| w.count_ones())
                .sum::<u32>();
        (remaining as usize, Some(remaining as usize))
    }
}

impl ExactSizeIterator for Iter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_empty() {
        let container = Bitmap::new();
        assert!(container.is_empty());
        assert_eq!(container.len(), 0);
        assert!(!container.is_full());
    }

    #[test]
    fn test_insert_and_contains() {
        let mut container = Bitmap::new();

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
    fn test_insert_range_single_word() {
        let mut container = Bitmap::new();

        let inserted = container.insert_range(5, 10);
        assert_eq!(inserted, 5);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_insert_range_multiple_words() {
        let mut container = Bitmap::new();

        // Range spanning multiple words (64 bits each)
        let inserted = container.insert_range(60, 130);
        assert_eq!(inserted, 70);
        assert_eq!(container.len(), 70);

        for i in 60..130 {
            assert!(container.contains(i), "missing value {}", i);
        }
    }

    #[test]
    fn test_iterator() {
        let mut container = Bitmap::new();
        container.insert(100);
        container.insert(10);
        container.insert(1000);
        container.insert(5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 10, 100, 1000]);
    }

    #[test]
    fn test_min_max() {
        let mut container = Bitmap::new();
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
        let words = [!0u64; WORDS];
        let container = Bitmap::from_words(words);
        assert!(container.is_full());
        assert_eq!(container.len(), BITS);
    }

    #[test]
    fn test_bitwise_operations() {
        let mut a = Bitmap::new();
        let mut b = Bitmap::new();

        a.insert(1);
        a.insert(2);
        a.insert(3);

        b.insert(2);
        b.insert(3);
        b.insert(4);

        // Test AND
        let mut result = a.clone();
        result.and(&b);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![2, 3]);

        // Test OR
        let mut result = a.clone();
        result.or(&b);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4]);

        // Test AND-NOT (difference)
        let mut result = a.clone();
        result.and_not(&b);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1]);
    }

    #[test]
    fn test_from_array() {
        let mut array = array::Array::new();
        array.insert(5);
        array.insert(10);
        array.insert(15);

        let bitmap = Bitmap::from_array(&array);
        assert_eq!(bitmap.len(), 3);
        assert!(bitmap.contains(5));
        assert!(bitmap.contains(10));
        assert!(bitmap.contains(15));
    }

    #[test]
    fn test_should_be_array() {
        let mut container = Bitmap::new();
        assert!(container.should_be_array());

        for i in 0..=array::MAX_CARDINALITY as u16 {
            container.insert(i);
        }
        assert!(!container.should_be_array());
    }
}
