//! Run container for consecutive sequences.
//!
//! Stores values as run-length encoded ranges using a BTreeMap. This is
//! efficient for data with many consecutive values, and is the most compact
//! representation for fully saturated containers.
//!
//! Uses an auto-merge approach: adjacent and overlapping runs are
//! automatically merged during insertion.
//!
//! # References
//!
//! - [Roaring Bitmap Paper](https://arxiv.org/pdf/1402.6407)
//! - [Roaring Bitmap Format Specification](https://github.com/RoaringBitmap/RoaringFormatSpec)

use super::bitmap;
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// A container that stores values as run-length encoded ranges.
///
/// Each entry in the BTreeMap represents an inclusive range `[start, end]`.
/// Ranges are automatically merged when they become adjacent or overlapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// Map from range start to range end (inclusive).
    runs: BTreeMap<u16, u16>,
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}

impl Run {
    /// Creates an empty run container.
    #[inline]
    pub const fn new() -> Self {
        Self {
            runs: BTreeMap::new(),
        }
    }

    /// Creates a run container representing a fully saturated container [0, 65535].
    #[inline]
    pub fn full() -> Self {
        let mut runs = BTreeMap::new();
        runs.insert(0, u16::MAX);
        Self { runs }
    }

    /// Creates a run container from a bitmap container.
    pub fn from_bitmap(bitmap: &bitmap::Bitmap) -> Self {
        // Fast path for full bitmap
        if bitmap.is_full() {
            return Self::full();
        }

        let mut container = Self::new();
        let mut run_start: Option<u16> = None;

        for (word_idx, &word) in bitmap.words().iter().enumerate() {
            let base = (word_idx as u16) << 6;

            if word == 0 {
                // All zeros - end any active run
                if let Some(s) = run_start {
                    container.runs.insert(s, base - 1);
                    run_start = None;
                }
            } else if word == !0u64 {
                // All ones - extend or start run
                if run_start.is_none() {
                    run_start = Some(base);
                }
            } else {
                // Mixed word - process bit by bit
                let mut bit_idx = 0u16;
                while bit_idx < 64 {
                    let value = base | bit_idx;
                    let is_set = (word & (1u64 << bit_idx)) != 0;

                    match (is_set, run_start) {
                        (true, None) => run_start = Some(value),
                        (false, Some(s)) => {
                            container.runs.insert(s, value - 1);
                            run_start = None;
                        }
                        _ => {}
                    }
                    bit_idx += 1;
                }
            }
        }

        // Handle final run
        if let Some(s) = run_start {
            container.runs.insert(s, u16::MAX);
        }

        container
    }

    /// Returns the number of runs in the container.
    #[inline]
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Returns the cardinality (number of values) in the container.
    pub fn len(&self) -> u32 {
        self.runs
            .iter()
            .map(|(&start, &end)| (end - start) as u32 + 1)
            .sum()
    }

    /// Returns whether the container is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Returns whether the container is fully saturated (contains all 65536 values).
    #[inline]
    pub fn is_full(&self) -> bool {
        self.runs.len() == 1 && self.runs.first_key_value() == Some((&0, &u16::MAX))
    }

    /// Checks if the container contains the given value.
    pub fn contains(&self, value: u16) -> bool {
        if let Some((&start, &end)) = self.runs.range(..=value).next_back() {
            value <= end && value >= start
        } else {
            false
        }
    }

    /// Inserts a value into the container.
    ///
    /// Automatically merges with adjacent runs.
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    pub fn insert(&mut self, value: u16) -> bool {
        // Find previous and next ranges
        let prev_opt = self.runs.range(..=value).next_back().map(|(&s, &e)| (s, e));
        let next_opt = if value == u16::MAX {
            None
        } else {
            self.runs.range(value + 1..).next().map(|(&s, &e)| (s, e))
        };

        match (prev_opt, next_opt) {
            (Some((p_start, p_end)), Some((n_start, n_end))) => {
                if value <= p_end {
                    // Value is within prev range
                    return false;
                }
                if value == p_end + 1 && value + 1 == n_start {
                    // Value bridges prev and next
                    self.runs.remove(&p_start);
                    self.runs.remove(&n_start);
                    self.runs.insert(p_start, n_end);
                } else if value == p_end + 1 {
                    // Value is adjacent to prev's end
                    self.runs.remove(&p_start);
                    self.runs.insert(p_start, value);
                } else if value + 1 == n_start {
                    // Value is adjacent to next's start
                    self.runs.remove(&n_start);
                    self.runs.insert(value, n_end);
                } else {
                    // New isolated range
                    self.runs.insert(value, value);
                }
            }
            (Some((p_start, p_end)), None) => {
                if value <= p_end {
                    // Value is within prev range
                    return false;
                }
                if value == p_end + 1 {
                    // Value is adjacent to prev's end
                    self.runs.remove(&p_start);
                    self.runs.insert(p_start, value);
                } else {
                    // New isolated range
                    self.runs.insert(value, value);
                }
            }
            (None, Some((n_start, n_end))) => {
                if value + 1 == n_start {
                    // Value is adjacent to next's start
                    self.runs.remove(&n_start);
                    self.runs.insert(value, n_end);
                } else {
                    // New isolated range
                    self.runs.insert(value, value);
                }
            }
            (None, None) => {
                // Map is empty or value is isolated
                self.runs.insert(value, value);
            }
        }
        true
    }

    /// Inserts a range of values [start, end) into the container.
    ///
    /// Returns the number of values newly inserted.
    pub fn insert_range(&mut self, start: u16, end: u16) -> u32 {
        if start >= end {
            return 0;
        }

        let end_inclusive = end - 1;
        let range_size = (end - start) as u32;

        // Find all runs that overlap or are adjacent to [start, end_inclusive]
        let mut to_remove = Vec::new();
        let mut new_start = start;
        let mut new_end = end_inclusive;
        let mut existing_coverage = 0u32;

        for (&r_start, &r_end) in self.runs.iter() {
            // Check if this run overlaps or is adjacent to our range
            let overlaps =
                r_start <= end_inclusive.saturating_add(1) && r_end.saturating_add(1) >= start;

            if overlaps {
                to_remove.push(r_start);
                // Calculate how much of this run overlaps with [start, end_inclusive]
                let overlap_start = r_start.max(start);
                let overlap_end = r_end.min(end_inclusive);
                if overlap_start <= overlap_end {
                    existing_coverage += (overlap_end - overlap_start) as u32 + 1;
                }
                new_start = new_start.min(r_start);
                new_end = new_end.max(r_end);
            }
        }

        let inserted = range_size.saturating_sub(existing_coverage);
        if inserted == 0 && to_remove.is_empty() {
            return 0;
        }

        // Remove old overlapping runs
        for r_start in to_remove {
            self.runs.remove(&r_start);
        }

        // Insert merged run
        self.runs.insert(new_start, new_end);

        inserted
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> Iter<'_> {
        let mut runs_iter = self.runs.iter();
        let current_run = runs_iter.next().map(|(&s, &e)| (s, e));
        Iter {
            runs_iter,
            current_run,
            current_value: current_run.map(|(s, _)| s),
        }
    }

    /// Returns an iterator over the runs as (start, end) pairs (inclusive).
    pub fn runs(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        self.runs.iter().map(|(&s, &e)| (s, e))
    }

    /// Returns the minimum value in the container, if any.
    #[inline]
    pub fn min(&self) -> Option<u16> {
        self.runs.first_key_value().map(|(&start, _)| start)
    }

    /// Returns the maximum value in the container, if any.
    #[inline]
    pub fn max(&self) -> Option<u16> {
        self.runs.last_key_value().map(|(_, &end)| end)
    }
}

impl Write for Run {
    fn write(&self, buf: &mut impl BufMut) {
        // Write as Vec of (start, end) pairs
        let runs: Vec<(u16, u16)> = self.runs.iter().map(|(&s, &e)| (s, e)).collect();
        runs.as_slice().write(buf);
    }
}

impl EncodeSize for Run {
    fn encode_size(&self) -> usize {
        // Length varint + 4 bytes per run (2 u16s)
        (self.runs.len() as u32).encode_size() + self.runs.len() * 4
    }
}

impl Read for Run {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        // Read as Vec of (start, end) pairs
        let pairs = Vec::<(u16, u16)>::read_cfg(buf, &(RangeCfg::new(..), ((), ())))?;

        let mut runs = BTreeMap::new();
        let mut prev_end: Option<u16> = None;

        for (start, end) in pairs {
            // Validate start <= end
            if start > end {
                return Err(CodecError::Invalid("Run", "start must be <= end"));
            }
            // Validate sorted and non-overlapping/non-adjacent
            if let Some(p) = prev_end {
                if start <= p.saturating_add(1) {
                    return Err(CodecError::Invalid(
                        "Run",
                        "runs must be sorted, non-overlapping, and non-adjacent",
                    ));
                }
            }
            runs.insert(start, end);
            prev_end = Some(end);
        }

        Ok(Self { runs })
    }
}

/// Iterator over values in a run container.
pub struct Iter<'a> {
    runs_iter: std::collections::btree_map::Iter<'a, u16, u16>,
    current_run: Option<(u16, u16)>,
    current_value: Option<u16>,
}

impl Iterator for Iter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (_, end) = self.current_run?;
            let value = self.current_value?;

            if value <= end {
                // Advance to next value in current run
                if value == u16::MAX {
                    self.current_value = None;
                } else {
                    self.current_value = Some(value + 1);
                }
                return Some(value);
            }

            // Move to next run
            self.current_run = self.runs_iter.next().map(|(&s, &e)| (s, e));
            self.current_value = self.current_run.map(|(s, _)| s);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match (self.current_run, self.current_value) {
            (Some((_, end)), Some(value)) if value <= end => {
                let in_current = (end - value + 1) as usize;
                let in_remaining: usize = self
                    .runs_iter
                    .clone()
                    .map(|(&s, &e)| (e - s + 1) as usize)
                    .sum();
                in_current + in_remaining
            }
            _ => 0,
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Iter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_empty() {
        let container = Run::new();
        assert!(container.is_empty());
        assert_eq!(container.len(), 0);
        assert_eq!(container.run_count(), 0);
        assert!(!container.is_full());
    }

    #[test]
    fn test_full() {
        let container = Run::full();
        assert!(!container.is_empty());
        assert_eq!(container.len(), 65536);
        assert_eq!(container.run_count(), 1);
        assert!(container.is_full());
    }

    #[test]
    fn test_insert_and_contains() {
        let mut container = Run::new();

        assert!(container.insert(5));
        assert!(container.insert(3));
        assert!(container.insert(7));
        assert!(!container.insert(5)); // Duplicate

        assert_eq!(container.run_count(), 3);
        assert!(container.contains(3));
        assert!(container.contains(5));
        assert!(container.contains(7));
        assert!(!container.contains(4));
    }

    #[test]
    fn test_auto_merge_adjacent() {
        let mut container = Run::new();

        container.insert(5);
        container.insert(6);
        assert_eq!(container.run_count(), 1);

        container.insert(4);
        assert_eq!(container.run_count(), 1);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![4, 5, 6]);
    }

    #[test]
    fn test_auto_merge_bridge() {
        let mut container = Run::new();

        container.insert(1);
        container.insert(2);
        container.insert(5);
        container.insert(6);
        assert_eq!(container.run_count(), 2);

        // Insert 3 to extend first run
        container.insert(3);
        assert_eq!(container.run_count(), 2);

        // Insert 4 to bridge runs
        container.insert(4);
        assert_eq!(container.run_count(), 1);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_insert_range() {
        let mut container = Run::new();

        let inserted = container.insert_range(5, 10);
        assert_eq!(inserted, 5);
        assert_eq!(container.run_count(), 1);
        assert_eq!(container.len(), 5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_insert_range_merge() {
        let mut container = Run::new();

        container.insert_range(1, 4); // [1, 2, 3]
        container.insert_range(6, 9); // [6, 7, 8]
        assert_eq!(container.run_count(), 2);

        // Insert overlapping range that bridges
        container.insert_range(3, 7); // [3, 4, 5, 6]
        assert_eq!(container.run_count(), 1);
        assert_eq!(container.len(), 8);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_iterator() {
        let mut container = Run::new();
        container.insert(100);
        container.insert(10);
        container.insert(1000);
        container.insert(5);

        let values: Vec<_> = container.iter().collect();
        assert_eq!(values, vec![5, 10, 100, 1000]);
    }

    #[test]
    fn test_min_max() {
        let mut container = Run::new();
        assert_eq!(container.min(), None);
        assert_eq!(container.max(), None);

        container.insert(50);
        container.insert(10);
        container.insert(100);

        assert_eq!(container.min(), Some(10));
        assert_eq!(container.max(), Some(100));
    }

    #[test]
    fn test_runs_iterator() {
        let mut container = Run::new();
        container.insert_range(1, 4);
        container.insert_range(10, 13);

        let runs: Vec<_> = container.runs().collect();
        assert_eq!(runs, vec![(1, 3), (10, 12)]);
    }

    #[test]
    fn test_boundary_values() {
        let mut container = Run::new();

        container.insert(0);
        container.insert(u16::MAX);
        assert_eq!(container.run_count(), 2);
        assert!(container.contains(0));
        assert!(container.contains(u16::MAX));

        // Test adjacent to max
        container.insert(u16::MAX - 1);
        assert_eq!(container.run_count(), 2);
        assert!(container.contains(u16::MAX - 1));
    }

    #[test]
    fn test_from_full_bitmap() {
        let words = [!0u64; bitmap::WORDS];
        let bm = bitmap::Bitmap::from_words(words);
        let run = Run::from_bitmap(&bm);

        assert!(run.is_full());
        assert_eq!(run.run_count(), 1);
        assert_eq!(run.len(), 65536);
    }
}
