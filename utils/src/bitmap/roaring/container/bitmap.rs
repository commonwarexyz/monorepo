//! Bitmap container for dense data.
//!
//! Stores values as a fixed 8 KB bit array (65,536 bits packed into 1024
//! `u64` words). Cheaper than an [`Array`](super::array::Array) container
//! above ~4,096 values, since Array storage scales with cardinality while
//! the Bitmap's footprint is fixed.
//!
//! Tracks `run_count` (the number of maximal consecutive 1-bit sequences)
//! incrementally on insert. The auto-conversion logic in [`super`] reads
//! this to decide when to switch to a [`Run`](super::run::Run)
//! representation; the transition is governed by a hysteresis band on
//! run count rather than by cardinality alone, so a near-saturated bitmap
//! with few gaps converts to Run while a dense one with many isolated
//! runs stays as Bitmap.

use super::{array, run};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use core::ops::Range;

/// Number of 64-bit words needed to store 65536 bits.
pub const WORDS: usize = 1024;

/// Encoded byte length of a bitmap container.
const ENCODED_BYTES: usize = WORDS * core::mem::size_of::<u64>();

/// Total number of bits in a bitmap container.
pub const BITS: u32 = WORDS as u32 * 64;

/// A container that stores values using a fixed-size bit array.
///
/// Uses 8KB of memory regardless of cardinality. Efficient for dense data
/// (cardinality > 4096).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    /// Bit array storing 65536 bits.
    words: [u64; WORDS],
    /// Cached cardinality for O(1) `len()` queries.
    cardinality: u32,
    /// Cached run count (number of consecutive `1`-bit sequences). Used by the
    /// `Container` auto-conversion logic to decide when to switch to a `Run` variant.
    ///
    /// Max possible value is 32768 (alternating bit pattern), which fits in `u16`.
    run_count: u16,
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&array::Array> for Bitmap {
    fn from(array: &array::Array) -> Self {
        let mut words = [0u64; WORDS];
        for value in array.iter() {
            let word_idx = (value >> 6) as usize;
            let bit_idx = value & 63;
            words[word_idx] |= 1u64 << bit_idx;
        }
        Self {
            words,
            cardinality: array.len() as u32,
            run_count: count_runs(&words),
        }
    }
}

impl From<[u64; WORDS]> for Bitmap {
    fn from(words: [u64; WORDS]) -> Self {
        let cardinality = words.iter().map(|w| w.count_ones()).sum();
        let run_count = count_runs(&words);
        Self {
            words,
            cardinality,
            run_count,
        }
    }
}

/// Sets each `[start, end]` range from the source `Run` directly via word-level mask
/// operations, then assigns `run_count` from the source's exact run count (the source
/// runs are guaranteed disjoint and non-adjacent, so they map 1:1 to runs in the
/// resulting bitmap). Faster than calling [`Self::insert_range`] per source range
/// because it avoids the per-range run-count rescan.
impl From<&run::Run> for Bitmap {
    fn from(run: &run::Run) -> Self {
        let mut bitmap = Self::new();
        let mut cardinality = 0u32;
        for (start, end_inclusive) in run.runs() {
            bitmap.fill_range_unchecked(start, end_inclusive);
            cardinality += (end_inclusive - start) as u32 + 1;
        }
        bitmap.cardinality = cardinality;
        // The source Run is sorted, disjoint, and non-adjacent, so its run count exactly
        // equals the number of maximal `1`-runs in the resulting bitmap.
        bitmap.run_count = run.run_count() as u16;
        bitmap
    }
}

impl Bitmap {
    /// Creates an empty bitmap container.
    pub const fn new() -> Self {
        Self {
            words: [0; WORDS],
            cardinality: 0,
            run_count: 0,
        }
    }

    /// Sets every bit in `[start, end_inclusive]` without updating `cardinality` or
    /// `run_count`. Internal helper for the `From<&Run>` impl; callers must restore those
    /// fields themselves.
    fn fill_range_unchecked(&mut self, start: u16, end_inclusive: u16) {
        let start_word = (start >> 6) as usize;
        let end_word = (end_inclusive >> 6) as usize;
        let start_bit = start & 63;
        let end_bit = end_inclusive & 63;

        if start_word == end_word {
            let num_bits = end_bit - start_bit + 1;
            let mask = if num_bits == 64 {
                !0u64
            } else {
                ((1u64 << num_bits) - 1) << start_bit
            };
            self.words[start_word] |= mask;
        } else {
            self.words[start_word] |= !0u64 << start_bit;
            for word in &mut self.words[start_word + 1..end_word] {
                *word = !0u64;
            }
            let last_mask = if end_bit == 63 {
                !0u64
            } else {
                (1u64 << (end_bit + 1)) - 1
            };
            self.words[end_word] |= last_mask;
        }
    }

    /// Returns the number of maximal consecutive `1`-bit sequences.
    ///
    /// Used by the [`super::Container`] auto-conversion logic to decide when to switch
    /// to a [`super::Run`] variant. Maintained incrementally on `insert` and recomputed
    /// via a single-pass word scan on bulk operations.
    pub const fn run_count(&self) -> u16 {
        self.run_count
    }

    /// Returns the number of values in the container.
    pub const fn len(&self) -> u32 {
        self.cardinality
    }

    /// Returns whether the container is empty.
    pub const fn is_empty(&self) -> bool {
        self.cardinality == 0
    }

    /// Returns whether the container is fully saturated.
    pub const fn is_full(&self) -> bool {
        self.cardinality == BITS
    }

    /// Checks if the container contains the given value.
    pub const fn contains(&self, value: u16) -> bool {
        let word_idx = (value >> 6) as usize;
        let bit_idx = value & 63;
        (self.words[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Inserts a value into the container.
    ///
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    pub const fn insert(&mut self, value: u16) -> bool {
        let word_idx = (value >> 6) as usize;
        let bit_idx = value & 63;
        let mask = 1u64 << bit_idx;

        if (self.words[word_idx] & mask) != 0 {
            return false;
        }

        // Examine neighbor bits BEFORE flipping `value`'s bit. Each neighbor that is `1`
        // means we're extending an existing run on that side rather than creating a new
        // boundary.
        let left_set = if value == 0 {
            false
        } else {
            let lv = value - 1;
            (self.words[(lv >> 6) as usize] & (1u64 << (lv & 63))) != 0
        };
        let right_set = if value == u16::MAX {
            false
        } else {
            let rv = value + 1;
            (self.words[(rv >> 6) as usize] & (1u64 << (rv & 63))) != 0
        };

        // Flip the bit and update cardinality.
        self.words[word_idx] |= mask;
        self.cardinality += 1;

        // run_count delta: +1 for new isolated run, 0 for one-side extension, -1 for bridge.
        match (left_set, right_set) {
            (false, false) => self.run_count += 1,
            (true, false) | (false, true) => {}
            (true, true) => self.run_count -= 1,
        }
        true
    }

    /// Inserts a range of values into the container.
    ///
    /// Returns the number of values newly inserted.
    pub fn insert_range(&mut self, range: Range<u16>) -> u32 {
        let Range { start, end } = range;
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
            let num_bits = end_bit - start_bit + 1;
            let mask = if num_bits == 64 {
                !0u64
            } else {
                ((1u64 << num_bits) - 1) << start_bit
            };
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
            let last_mask = if end_bit == 63 {
                !0u64
            } else {
                (1u64 << (end_bit + 1)) - 1
            };
            let old_count = self.words[end_word].count_ones();
            self.words[end_word] |= last_mask;
            inserted += self.words[end_word].count_ones() - old_count;
        }

        // Recompute run_count after a bulk modification. Single pass over WORDS = 1024
        // u64 words; cheap relative to insert_range itself.
        self.cardinality += inserted;
        self.run_count = count_runs(&self.words);
        inserted
    }

    /// Returns an iterator over the values in sorted order.
    pub const fn iter(&self) -> Iter<'_> {
        Iter {
            words: &self.words,
            word_idx: 0,
            end_word: WORDS - 1,
            end_mask: !0u64,
            current_word: self.words[0],
        }
    }

    /// Returns an iterator over values in the range.
    pub fn iter_range(&self, range: Range<u32>) -> Iter<'_> {
        let start = range.start.min(BITS);
        let end = range.end.min(BITS);
        if start >= end {
            return Iter::empty(&self.words);
        }

        let start_word = (start >> 6) as usize;
        let end_word = ((end - 1) >> 6) as usize;
        let start_mask = !0u64 << (start & 63);
        let end_bit = (end - 1) & 63;
        let end_mask = if end_bit == 63 {
            !0u64
        } else {
            (1u64 << (end_bit + 1)) - 1
        };

        let mut current_word = self.words[start_word] & start_mask;
        if start_word == end_word {
            current_word &= end_mask;
        }

        Iter {
            words: &self.words,
            word_idx: start_word,
            end_word,
            end_mask,
            current_word,
        }
    }

    /// Returns the underlying words array.
    pub const fn words(&self) -> &[u64; WORDS] {
        &self.words
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

    /// Creates a new bitmap that is the OR of two bitmaps.
    /// Computes cardinality in the same pass as the bitwise operation.
    pub fn or_new(a: &Self, b: &Self) -> Self {
        let mut words = [0u64; WORDS];
        let mut cardinality = 0u32;
        for i in (0..WORDS).step_by(4) {
            let w0 = a.words[i] | b.words[i];
            let w1 = a.words[i + 1] | b.words[i + 1];
            let w2 = a.words[i + 2] | b.words[i + 2];
            let w3 = a.words[i + 3] | b.words[i + 3];
            words[i] = w0;
            words[i + 1] = w1;
            words[i + 2] = w2;
            words[i + 3] = w3;
            cardinality += w0.count_ones() + w1.count_ones() + w2.count_ones() + w3.count_ones();
        }
        let run_count = count_runs(&words);
        Self {
            words,
            cardinality,
            run_count,
        }
    }

    /// Creates a new bitmap that is the AND of two bitmaps.
    /// Computes cardinality in the same pass as the bitwise operation.
    pub fn and_new(a: &Self, b: &Self) -> Self {
        let mut words = [0u64; WORDS];
        let mut cardinality = 0u32;
        for i in (0..WORDS).step_by(4) {
            let w0 = a.words[i] & b.words[i];
            let w1 = a.words[i + 1] & b.words[i + 1];
            let w2 = a.words[i + 2] & b.words[i + 2];
            let w3 = a.words[i + 3] & b.words[i + 3];
            words[i] = w0;
            words[i + 1] = w1;
            words[i + 2] = w2;
            words[i + 3] = w3;
            cardinality += w0.count_ones() + w1.count_ones() + w2.count_ones() + w3.count_ones();
        }
        let run_count = count_runs(&words);
        Self {
            words,
            cardinality,
            run_count,
        }
    }

    /// Creates a new bitmap that is a AND-NOT b (difference).
    /// Computes cardinality in the same pass as the bitwise operation.
    pub fn and_not_new(a: &Self, b: &Self) -> Self {
        let mut words = [0u64; WORDS];
        let mut cardinality = 0u32;
        for i in (0..WORDS).step_by(4) {
            let w0 = a.words[i] & !b.words[i];
            let w1 = a.words[i + 1] & !b.words[i + 1];
            let w2 = a.words[i + 2] & !b.words[i + 2];
            let w3 = a.words[i + 3] & !b.words[i + 3];
            words[i] = w0;
            words[i + 1] = w1;
            words[i + 2] = w2;
            words[i + 3] = w3;
            cardinality += w0.count_ones() + w1.count_ones() + w2.count_ones() + w3.count_ones();
        }
        let run_count = count_runs(&words);
        Self {
            words,
            cardinality,
            run_count,
        }
    }

    /// Returns the total memory footprint of this `Bitmap` in bytes.
    ///
    /// All storage is inline (no heap allocations), so this is just `size_of::<Self>()`,
    /// which is approximately 8 KB regardless of cardinality. Available only for tests
    /// and the `analysis` feature; not compiled into production builds.
    #[cfg(any(test, feature = "analysis"))]
    pub const fn byte_size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

/// Counts the number of maximal consecutive `1`-bit sequences in the bitmap, in a single
/// O(`WORDS`) pass. Used by the bulk-construction paths to keep `run_count` in sync.
///
/// Algorithm: for each word `w`, treat the bit just below position 0 as the last bit of
/// the previous word (or `0` for the first word). A run "starts" at any position where
/// `w[i] == 1` and `extended[i] == 0`, where `extended` is `w` shifted left by 1 with the
/// virtual previous bit shifted in. Counting via `popcount(w & !extended)` is exact and
/// branch-free.
fn count_runs(words: &[u64; WORDS]) -> u16 {
    let mut runs: u32 = 0;
    let mut prev_bit: u64 = 0;
    for &w in words.iter() {
        let extended = (w << 1) | prev_bit;
        runs += (w & !extended).count_ones();
        prev_bit = w >> 63;
    }
    // Maximum possible value is 32768 (alternating bit pattern), which fits in u16.
    runs as u16
}

impl Write for Bitmap {
    fn write(&self, buf: &mut impl BufMut) {
        // Preserve the codec's big-endian word order while collapsing 1024 small
        // `put_slice` calls into one bulk write.
        let mut bytes = [0u8; ENCODED_BYTES];
        for (dst, &word) in bytes.chunks_exact_mut(8).zip(self.words.iter()) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
        buf.put_slice(&bytes);
    }
}

impl EncodeSize for Bitmap {
    fn encode_size(&self) -> usize {
        ENCODED_BYTES
    }
}

impl Read for Bitmap {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let mut words = [0u64; WORDS];
        for word in &mut words {
            *word = u64::read(buf)?;
        }
        Ok(Self::from(words))
    }
}

/// Iterator over values in a bitmap container.
pub struct Iter<'a> {
    words: &'a [u64; WORDS],
    word_idx: usize,
    end_word: usize,
    end_mask: u64,
    current_word: u64,
}

impl<'a> Iter<'a> {
    const fn empty(words: &'a [u64; WORDS]) -> Self {
        Self {
            words,
            word_idx: WORDS,
            end_word: 0,
            end_mask: 0,
            current_word: 0,
        }
    }
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

            if self.word_idx >= self.end_word {
                return None;
            }

            self.word_idx += 1;
            self.current_word = self.words[self.word_idx];
            if self.word_idx == self.end_word {
                self.current_word &= self.end_mask;
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.word_idx >= WORDS || self.word_idx > self.end_word {
            return (0, Some(0));
        }

        let mut remaining = self.current_word.count_ones();
        if self.word_idx < self.end_word {
            remaining += self.words[self.word_idx + 1..self.end_word]
                .iter()
                .map(|w| w.count_ones())
                .sum::<u32>();
            remaining += (self.words[self.end_word] & self.end_mask).count_ones();
        }
        (remaining as usize, Some(remaining as usize))
    }
}

impl ExactSizeIterator for Iter<'_> {}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Bitmap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut words = [0u64; WORDS];
        for word in &mut words {
            *word = u.arbitrary()?;
        }
        Ok(Self::from(words))
    }
}

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

        let inserted = container.insert_range(5..10);
        assert_eq!(inserted, 5);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_insert_range_multiple_words() {
        let mut container = Bitmap::new();

        // Range spanning multiple words (64 bits each)
        let inserted = container.insert_range(60..130);
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
    fn test_iterator_size_hint_after_exhaustion_regression() {
        // Regression test: size_hint() used to panic when called after iterator
        // exhaustion because it accessed words[word_idx + 1..] where word_idx
        // could be WORDS (1024), causing an out-of-bounds slice access.

        // Test with non-empty bitmap
        let mut container = Bitmap::new();
        container.insert(5);
        container.insert(100);

        let mut iter = container.iter();
        assert_eq!(iter.size_hint(), (2, Some(2)));

        // Exhaust the iterator
        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.size_hint(), (1, Some(1)));
        assert_eq!(iter.next(), Some(100));
        assert_eq!(iter.size_hint(), (0, Some(0)));
        assert_eq!(iter.next(), None);

        // This used to panic - now should return (0, Some(0))
        assert_eq!(iter.size_hint(), (0, Some(0)));

        // Test with empty bitmap
        let empty = Bitmap::new();
        let mut iter = empty.iter();
        assert_eq!(iter.size_hint(), (0, Some(0)));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.size_hint(), (0, Some(0)));
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
        let container = Bitmap::from(words);
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
        let result = Bitmap::and_new(&a, &b);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![2, 3]);

        // Test OR
        let result = Bitmap::or_new(&a, &b);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4]);

        // Test AND-NOT (difference)
        let result = Bitmap::and_not_new(&a, &b);
        let values: Vec<_> = result.iter().collect();
        assert_eq!(values, vec![1]);
    }

    #[test]
    fn test_from_array() {
        let mut array = array::Array::new();
        array.insert(5);
        array.insert(10);
        array.insert(15);

        let bitmap = Bitmap::from(&array);
        assert_eq!(bitmap.len(), 3);
        assert!(bitmap.contains(5));
        assert!(bitmap.contains(10));
        assert!(bitmap.contains(15));
    }

    #[test]
    fn test_insert_range_shift_overflow_regression() {
        // Regression test for bug where insert_range caused shift overflow panic.
        // The bug was that computing masks like `1u64 << 64` or `1u64 << (end_bit + 1)`
        // when end_bit == 63 causes overflow. Fixed by checking for these cases
        // and using `!0u64` instead.

        // Test case 1: Full word range (bits 0-63, num_bits == 64)
        let mut container = Bitmap::new();
        let inserted = container.insert_range(0..64);
        assert_eq!(inserted, 64);
        assert_eq!(container.len(), 64);
        for i in 0..64 {
            assert!(container.contains(i), "missing value {}", i);
        }

        // Test case 2: Range ending at bit 63 (end_bit == 63)
        let mut container = Bitmap::new();
        let inserted = container.insert_range(32..64);
        assert_eq!(inserted, 32);
        for i in 32..64 {
            assert!(container.contains(i), "missing value {}", i);
        }

        // Test case 3: Range spanning multiple words ending at word boundary
        let mut container = Bitmap::new();
        let inserted = container.insert_range(60..128);
        assert_eq!(inserted, 68);
        for i in 60..128 {
            assert!(container.contains(i), "missing value {}", i);
        }

        // Test case 4: Full container range requires inserting up to u16::MAX
        // Since insert_range is [start, end), we insert [0, u16::MAX) then add u16::MAX
        let mut container = Bitmap::new();
        let inserted = container.insert_range(0..u16::MAX);
        assert_eq!(inserted, 65535);
        container.insert(u16::MAX);
        assert!(container.is_full());
        assert_eq!(container.len(), BITS);

        // Test case 5: Range at end of container (ending at u16::MAX)
        let mut container = Bitmap::new();
        let inserted = container.insert_range(65500..u16::MAX);
        assert_eq!(inserted, 35);
        for i in 65500..u16::MAX {
            assert!(container.contains(i), "missing value {}", i);
        }

        // Test case 6: Single full word in middle of container
        let mut container = Bitmap::new();
        let inserted = container.insert_range(64..128);
        assert_eq!(inserted, 64);
        for i in 64..128 {
            assert!(container.contains(i), "missing value {}", i);
        }

        // Test case 7: Range ending exactly at word boundary (last bit of word)
        let mut container = Bitmap::new();
        let inserted = container.insert_range(0..64);
        assert_eq!(inserted, 64);
        // Ensure bit 63 (the last bit of the first word) is set
        assert!(container.contains(63));

        // Test case 8: Range from middle to end of a word
        let mut container = Bitmap::new();
        let inserted = container.insert_range(48..64);
        assert_eq!(inserted, 16);
        for i in 48..64 {
            assert!(container.contains(i), "missing value {}", i);
        }
    }

    #[test]
    fn test_byte_size() {
        let b = Bitmap::new();
        // Bitmap is fully inline: no heap.
        assert_eq!(b.byte_size(), core::mem::size_of::<Bitmap>());
        // Sanity: at least the 1024 u64 inline storage (8 KB).
        assert!(b.byte_size() >= 8192);
    }

    #[test]
    fn test_byte_size_independent_of_cardinality() {
        // A Bitmap's footprint does not change as values are added.
        let empty_size = Bitmap::new().byte_size();
        let mut full = Bitmap::new();
        for i in 0..=u16::MAX {
            full.insert(i);
        }
        assert_eq!(full.byte_size(), empty_size);
    }

    // -----------------------------------------------------------------------------
    // run_count tracking
    // -----------------------------------------------------------------------------

    #[test]
    fn test_run_count_empty() {
        let b = Bitmap::new();
        assert_eq!(b.run_count(), 0);
    }

    #[test]
    fn test_run_count_single_insert() {
        let mut b = Bitmap::new();
        b.insert(42);
        assert_eq!(b.run_count(), 1);
    }

    #[test]
    fn test_run_count_extends_left() {
        // Inserting adjacent-from-the-right of an existing bit extends that bit's run.
        let mut b = Bitmap::new();
        b.insert(10);
        b.insert(11);
        assert_eq!(b.run_count(), 1);
    }

    #[test]
    fn test_run_count_extends_right() {
        // Inserting adjacent-from-the-left of an existing bit extends that bit's run.
        let mut b = Bitmap::new();
        b.insert(10);
        b.insert(9);
        assert_eq!(b.run_count(), 1);
    }

    #[test]
    fn test_run_count_isolated_inserts() {
        let mut b = Bitmap::new();
        b.insert(0);
        b.insert(100);
        b.insert(1000);
        assert_eq!(b.run_count(), 3);
    }

    #[test]
    fn test_run_count_bridge_decrements() {
        // Filling a gap between two existing runs merges them.
        let mut b = Bitmap::new();
        b.insert(10);
        b.insert(12);
        assert_eq!(b.run_count(), 2);
        b.insert(11); // bridges (10) and (12)
        assert_eq!(b.run_count(), 1);
    }

    #[test]
    fn test_run_count_idempotent_on_duplicate() {
        let mut b = Bitmap::new();
        b.insert(42);
        let before = b.run_count();
        b.insert(42); // already set
        assert_eq!(b.run_count(), before);
    }

    #[test]
    fn test_run_count_at_boundaries() {
        let mut b = Bitmap::new();
        // Value 0 has no left neighbor — should still create a new run.
        b.insert(0);
        assert_eq!(b.run_count(), 1);
        // Value u16::MAX has no right neighbor — should still create a new run.
        b.insert(u16::MAX);
        assert_eq!(b.run_count(), 2);
        // Adjacent to the existing top: extends, doesn't add.
        b.insert(u16::MAX - 1);
        assert_eq!(b.run_count(), 2);
        // Adjacent to bottom: extends.
        b.insert(1);
        assert_eq!(b.run_count(), 2);
    }

    #[test]
    fn test_run_count_after_insert_range() {
        let mut b = Bitmap::new();
        // Sparse isolated bits -> many runs.
        for i in 0u16..100 {
            b.insert(i * 2);
        }
        assert_eq!(b.run_count(), 100);
        // insert_range over the full span absorbs all the singletons into one run.
        b.insert_range(0..200);
        assert_eq!(b.run_count(), 1);
    }

    #[test]
    fn test_run_count_matches_scan_after_random_inserts() {
        // Property: incremental run_count tracking from `insert` must agree with the
        // bulk `count_runs` scan over the same word array.
        use crate::test_rng;
        use rand::Rng;

        let mut rng = test_rng();
        let mut b = Bitmap::new();
        for _ in 0..2000 {
            let v: u16 = rng.gen();
            b.insert(v);
        }
        // The cached field is what callers see; the scan is the ground truth.
        assert_eq!(b.run_count(), super::count_runs(b.words()));
    }

    #[test]
    fn test_from_words_run_count_matches_scan() {
        let mut words = [0u64; WORDS];
        words[0] = 0xAAAA_AAAA_AAAA_AAAA;

        let b = Bitmap::from(words);
        assert_eq!(b.run_count(), super::count_runs(b.words()));

        // Alternating bits: 32 set bits, all isolated.
        assert_eq!(b.run_count(), 32);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Bitmap>,
        }
    }
}
