//! Roaring Bitmap implementation.
//!
//! A roaring bitmap is a compressed bitmap that efficiently stores sets of 64-bit unsigned
//! integers. It divides the 64-bit space into containers of 2^16 integers each, using different
//! storage strategies based on container density:
//!
//! - **Array containers**: For sparse containers (fewer elements), stores the actual u16 values.
//! - **Bitmap containers**: For dense containers (many elements), uses a traditional 8KB bitmap.
//! - **Run containers**: For data with consecutive runs, stores (start, end) pairs.
//!
//! # Example
//!
//! ```
//! use commonware_utils::bitmap::RoaringBitmap;
//!
//! let mut bitmap = RoaringBitmap::new();
//! bitmap.insert(10);
//! bitmap.insert(1000);
//! bitmap.insert(100_000);
//! bitmap.insert(1_000_000_000_000); // Large u64 value
//!
//! assert!(bitmap.contains(10));
//! assert!(bitmap.contains(1000));
//! assert!(!bitmap.contains(50));
//! assert!(bitmap.contains(1_000_000_000_000));
//!
//! assert_eq!(bitmap.len(), 4);
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{util::at_least, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use core::fmt::{self, Formatter};
use core::ops::{Bound, RangeBounds};
use rand::Rng;

/// The threshold at which we switch from array to bitmap container.
/// Below this cardinality, an array container is more space-efficient.
/// At or above this cardinality, a bitmap container is more space-efficient.
///
/// Array container size: 2 bytes per element
/// Bitmap container size: 8192 bytes (fixed)
/// Crossover point: 8192 / 2 = 4096 elements
const ARRAY_TO_BITMAP_THRESHOLD: usize = 4096;

/// Size of a bitmap container in bytes (2^16 bits = 8192 bytes).
const BITMAP_CONTAINER_SIZE: usize = 8192;

/// Maximum number of runs before a run container should convert to bitmap.
/// Run container size: 4 bytes per run
/// Bitmap container size: 8192 bytes
/// Crossover: 8192 / 4 = 2048 runs
const MAX_RUNS_BEFORE_BITMAP: usize = 2048;

/// A container that stores a subset of values within a 16-bit range.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Container {
    /// Sorted array of u16 values. Used for sparse data.
    Array(Vec<u16>),
    /// Bitmap with 2^16 bits. Used for dense data.
    Bitmap(Vec<u64>),
    /// Run-length encoded container. Each (start, end) pair represents
    /// all values from start to end inclusive. Runs are sorted and non-overlapping.
    Run(Vec<(u16, u16)>),
}

impl Container {
    /// Creates a new empty array container.
    const fn new_array() -> Self {
        Self::Array(Vec::new())
    }

    /// Returns the number of elements in this container.
    fn len(&self) -> usize {
        match self {
            Self::Array(arr) => arr.len(),
            Self::Bitmap(bits) => bits.iter().map(|w| w.count_ones() as usize).sum(),
            Self::Run(runs) => runs
                .iter()
                .map(|&(start, end)| (end - start) as usize + 1)
                .sum(),
        }
    }

    /// Returns true if the container is empty.
    fn is_empty(&self) -> bool {
        match self {
            Self::Array(arr) => arr.is_empty(),
            Self::Bitmap(bits) => bits.iter().all(|&w| w == 0),
            Self::Run(runs) => runs.is_empty(),
        }
    }

    /// Returns the number of runs in a run container, or estimates runs for other types.
    fn num_runs(&self) -> usize {
        match self {
            Self::Array(arr) => {
                if arr.is_empty() {
                    return 0;
                }
                let mut runs = 1;
                for i in 1..arr.len() {
                    if arr[i] != arr[i - 1] + 1 {
                        runs += 1;
                    }
                }
                runs
            }
            Self::Bitmap(bits) => {
                let mut runs = 0;
                let mut in_run = false;
                for &word in bits {
                    for bit in 0..64 {
                        let is_set = (word & (1u64 << bit)) != 0;
                        if is_set && !in_run {
                            runs += 1;
                            in_run = true;
                        } else if !is_set {
                            in_run = false;
                        }
                    }
                }
                runs
            }
            Self::Run(runs) => runs.len(),
        }
    }

    /// Checks if the given value (low 16 bits) is present.
    fn contains(&self, value: u16) -> bool {
        match self {
            Self::Array(arr) => arr.binary_search(&value).is_ok(),
            Self::Bitmap(bits) => {
                let word_idx = value as usize / 64;
                let bit_idx = value as usize % 64;
                (bits[word_idx] & (1u64 << bit_idx)) != 0
            }
            Self::Run(runs) => {
                // Binary search for the run that might contain this value
                runs.binary_search_by(|&(start, end)| {
                    if value < start {
                        core::cmp::Ordering::Greater
                    } else if value > end {
                        core::cmp::Ordering::Less
                    } else {
                        core::cmp::Ordering::Equal
                    }
                })
                .is_ok()
            }
        }
    }

    /// Inserts a value (low 16 bits). Returns true if the value was newly inserted.
    fn insert(&mut self, value: u16) -> bool {
        match self {
            Self::Array(arr) => match arr.binary_search(&value) {
                Ok(_) => false, // Already present
                Err(pos) => {
                    arr.insert(pos, value);
                    true
                }
            },
            Self::Bitmap(bits) => {
                let word_idx = value as usize / 64;
                let bit_idx = value as usize % 64;
                let mask = 1u64 << bit_idx;
                let was_set = (bits[word_idx] & mask) != 0;
                bits[word_idx] |= mask;
                !was_set
            }
            Self::Run(runs) => {
                // Find where this value should go
                let pos = runs.partition_point(|&(_, end)| end < value);

                // Check if value is already in a run
                if pos < runs.len() && runs[pos].0 <= value && value <= runs[pos].1 {
                    return false; // Already present
                }

                // Check if we can extend the previous run
                let extend_prev = pos > 0 && runs[pos - 1].1 + 1 == value;
                // Check if we can extend the next run
                let extend_next = pos < runs.len() && runs[pos].0 == value + 1;

                if extend_prev && extend_next {
                    // Merge previous and next runs
                    let new_end = runs[pos].1;
                    runs[pos - 1].1 = new_end;
                    runs.remove(pos);
                } else if extend_prev {
                    runs[pos - 1].1 = value;
                } else if extend_next {
                    runs[pos].0 = value;
                } else {
                    // Create a new single-element run
                    runs.insert(pos, (value, value));
                }
                true
            }
        }
    }

    /// Removes a value (low 16 bits). Returns true if the value was present.
    fn remove(&mut self, value: u16) -> bool {
        match self {
            Self::Array(arr) => arr.binary_search(&value).is_ok_and(|pos| {
                arr.remove(pos);
                true
            }),
            Self::Bitmap(bits) => {
                let word_idx = value as usize / 64;
                let bit_idx = value as usize % 64;
                let mask = 1u64 << bit_idx;
                let was_set = (bits[word_idx] & mask) != 0;
                bits[word_idx] &= !mask;
                was_set
            }
            Self::Run(runs) => {
                // Find the run containing this value
                let pos = match runs.binary_search_by(|&(start, end)| {
                    if value < start {
                        core::cmp::Ordering::Greater
                    } else if value > end {
                        core::cmp::Ordering::Less
                    } else {
                        core::cmp::Ordering::Equal
                    }
                }) {
                    Ok(pos) => pos,
                    Err(_) => return false, // Not found
                };

                let (start, end) = runs[pos];
                if start == end {
                    // Single-element run, remove it
                    runs.remove(pos);
                } else if value == start {
                    // Remove from start
                    runs[pos].0 = start + 1;
                } else if value == end {
                    // Remove from end
                    runs[pos].1 = end - 1;
                } else {
                    // Split the run
                    runs[pos].1 = value - 1;
                    runs.insert(pos + 1, (value + 1, end));
                }
                true
            }
        }
    }

    /// Converts from array to bitmap if the threshold is exceeded.
    fn maybe_convert_to_bitmap(&mut self) {
        if let Self::Array(arr) = self {
            if arr.len() >= ARRAY_TO_BITMAP_THRESHOLD {
                let mut bits = vec![0u64; BITMAP_CONTAINER_SIZE / 8];
                for &value in arr.iter() {
                    let word_idx = value as usize / 64;
                    let bit_idx = value as usize % 64;
                    bits[word_idx] |= 1u64 << bit_idx;
                }
                *self = Self::Bitmap(bits);
            }
        }
    }

    /// Converts from bitmap to array if cardinality drops below threshold.
    fn maybe_convert_to_array(&mut self) {
        if let Self::Bitmap(bits) = self {
            let cardinality: usize = bits.iter().map(|w| w.count_ones() as usize).sum();
            if cardinality < ARRAY_TO_BITMAP_THRESHOLD {
                let mut arr = Vec::with_capacity(cardinality);
                for (word_idx, &word) in bits.iter().enumerate() {
                    if word == 0 {
                        continue;
                    }
                    for bit_idx in 0..64 {
                        if (word & (1u64 << bit_idx)) != 0 {
                            arr.push((word_idx * 64 + bit_idx) as u16);
                        }
                    }
                }
                *self = Self::Array(arr);
            }
        }
    }

    /// Converts to run container if it would be more efficient.
    fn maybe_convert_to_run(&mut self) {
        let num_runs = self.num_runs();
        let cardinality = self.len();

        // Run is better than array when: 4 * num_runs < 2 * cardinality
        // Run is better than bitmap when: 4 * num_runs < 8192 (i.e., num_runs < 2048)
        let run_size = 4 * num_runs;
        let current_size = match self {
            Self::Array(_) => 2 * cardinality,
            Self::Bitmap(_) => BITMAP_CONTAINER_SIZE,
            Self::Run(_) => return, // Already a run container
        };

        if run_size < current_size && num_runs < MAX_RUNS_BEFORE_BITMAP {
            let runs = self.to_runs();
            *self = Self::Run(runs);
        }
    }

    /// Converts a run container to array or bitmap if more efficient.
    fn maybe_convert_from_run(&mut self) {
        if let Self::Run(runs) = self {
            let num_runs = runs.len();
            let cardinality: usize = runs
                .iter()
                .map(|&(start, end)| (end - start) as usize + 1)
                .sum();

            let run_size = 4 * num_runs;
            let array_size = 2 * cardinality;
            let bitmap_size = BITMAP_CONTAINER_SIZE;

            if array_size <= run_size && array_size < bitmap_size {
                // Convert to array
                let mut arr = Vec::with_capacity(cardinality);
                for &(start, end) in runs.iter() {
                    for v in start..=end {
                        arr.push(v);
                    }
                }
                *self = Self::Array(arr);
            } else if bitmap_size < run_size {
                // Convert to bitmap
                let mut bits = vec![0u64; BITMAP_CONTAINER_SIZE / 8];
                for &(start, end) in runs.iter() {
                    for v in start..=end {
                        let word_idx = v as usize / 64;
                        let bit_idx = v as usize % 64;
                        bits[word_idx] |= 1u64 << bit_idx;
                    }
                }
                *self = Self::Bitmap(bits);
            }
        }
    }

    /// Converts the container to a run representation.
    fn to_runs(&self) -> Vec<(u16, u16)> {
        match self {
            Self::Array(arr) => {
                if arr.is_empty() {
                    return Vec::new();
                }
                let mut runs = Vec::new();
                let mut run_start = arr[0];
                let mut run_end = arr[0];
                for &v in arr.iter().skip(1) {
                    if v == run_end + 1 {
                        run_end = v;
                    } else {
                        runs.push((run_start, run_end));
                        run_start = v;
                        run_end = v;
                    }
                }
                runs.push((run_start, run_end));
                runs
            }
            Self::Bitmap(bits) => {
                let mut runs = Vec::new();
                let mut run_start: Option<u16> = None;
                let mut run_end: u16 = 0;

                for (word_idx, &word) in bits.iter().enumerate() {
                    for bit_idx in 0..64 {
                        let value = (word_idx * 64 + bit_idx) as u16;
                        let is_set = (word & (1u64 << bit_idx)) != 0;

                        if is_set {
                            match run_start {
                                None => {
                                    run_start = Some(value);
                                    run_end = value;
                                }
                                Some(_) if value == run_end + 1 => {
                                    run_end = value;
                                }
                                Some(start) => {
                                    runs.push((start, run_end));
                                    run_start = Some(value);
                                    run_end = value;
                                }
                            }
                        }
                    }
                }
                if let Some(start) = run_start {
                    runs.push((start, run_end));
                }
                runs
            }
            Self::Run(runs) => runs.clone(),
        }
    }

    /// Converts this container to a bitmap.
    fn to_bitmap(&self) -> Vec<u64> {
        match self {
            Self::Array(arr) => {
                let mut bits = vec![0u64; BITMAP_CONTAINER_SIZE / 8];
                for &value in arr {
                    let word_idx = value as usize / 64;
                    let bit_idx = value as usize % 64;
                    bits[word_idx] |= 1u64 << bit_idx;
                }
                bits
            }
            Self::Bitmap(bits) => bits.clone(),
            Self::Run(runs) => {
                let mut bits = vec![0u64; BITMAP_CONTAINER_SIZE / 8];
                for &(start, end) in runs {
                    for v in start..=end {
                        let word_idx = v as usize / 64;
                        let bit_idx = v as usize % 64;
                        bits[word_idx] |= 1u64 << bit_idx;
                    }
                }
                bits
            }
        }
    }

    /// Returns an iterator over all values in this container.
    fn iter(&self) -> ContainerIter<'_> {
        match self {
            Self::Array(arr) => ContainerIter::Array(arr.iter()),
            Self::Bitmap(bits) => ContainerIter::Bitmap {
                bits,
                word_idx: 0,
                bit_idx: 0,
            },
            Self::Run(runs) => ContainerIter::Run {
                runs,
                run_idx: 0,
                current: 0,
            },
        }
    }

    /// Creates a new container with all 2^16 bits set.
    fn new_full() -> Self {
        // A single run is most efficient for a full container
        Self::Run(vec![(0, u16::MAX)])
    }

    /// Inserts all values in the range [start, end] (inclusive).
    /// Returns the number of newly inserted values.
    fn insert_range(&mut self, start: u16, end: u16) -> u64 {
        if start > end {
            return 0;
        }

        let range_size = (end - start) as usize + 1;

        // For large ranges, convert to run container which handles ranges efficiently
        if range_size > 64 && !matches!(self, Self::Run(_)) {
            // Convert to run container for efficient range insertion
            let runs = self.to_runs();
            *self = Self::Run(runs);
        }

        // If inserting a large range into an array, convert to bitmap first
        if let Self::Array(arr) = self {
            if arr.len() + range_size >= ARRAY_TO_BITMAP_THRESHOLD {
                self.maybe_convert_to_bitmap();
                // Force conversion by temporarily making it look large
                if matches!(self, Self::Array(_)) {
                    let mut bits = vec![0u64; BITMAP_CONTAINER_SIZE / 8];
                    if let Self::Array(arr) = self {
                        for &value in arr.iter() {
                            let word_idx = value as usize / 64;
                            let bit_idx = value as usize % 64;
                            bits[word_idx] |= 1u64 << bit_idx;
                        }
                    }
                    *self = Self::Bitmap(bits);
                }
            }
        }

        match self {
            Self::Array(arr) => {
                let mut inserted = 0u64;
                for value in start..=end {
                    if arr.binary_search(&value).is_err() {
                        inserted += 1;
                    }
                }
                // Rebuild the array with the range
                let mut new_arr: Vec<u16> = arr
                    .iter()
                    .copied()
                    .filter(|&v| v < start || v > end)
                    .collect();
                new_arr.extend(start..=end);
                new_arr.sort_unstable();
                *arr = new_arr;
                self.maybe_convert_to_bitmap();
                inserted
            }
            Self::Bitmap(bits) => {
                let mut inserted = 0u64;

                let start_word = start as usize / 64;
                let end_word = end as usize / 64;
                let start_bit = start as usize % 64;
                let end_bit = end as usize % 64;

                if start_word == end_word {
                    // Range fits in a single word
                    let width = end_bit - start_bit + 1;
                    let mask = if width == 64 {
                        u64::MAX
                    } else {
                        ((1u64 << width) - 1) << start_bit
                    };
                    inserted += (mask & !bits[start_word]).count_ones() as u64;
                    bits[start_word] |= mask;
                } else {
                    // First partial word
                    let first_mask = !0u64 << start_bit;
                    inserted += (first_mask & !bits[start_word]).count_ones() as u64;
                    bits[start_word] |= first_mask;

                    // Full words in between
                    for word in bits.iter_mut().take(end_word).skip(start_word + 1) {
                        inserted += (!*word).count_ones() as u64;
                        *word = u64::MAX;
                    }

                    // Last partial word
                    let last_mask = if end_bit == 63 {
                        u64::MAX
                    } else {
                        (1u64 << (end_bit + 1)) - 1
                    };
                    inserted += (last_mask & !bits[end_word]).count_ones() as u64;
                    bits[end_word] |= last_mask;
                }

                inserted
            }
            Self::Run(runs) => {
                // Count values that will be newly inserted
                let mut inserted = (end - start + 1) as u64;

                // Find overlapping runs and count existing values
                for &(rs, re) in runs.iter() {
                    if rs > end || re < start {
                        continue; // No overlap
                    }
                    // Calculate overlap
                    let overlap_start = rs.max(start);
                    let overlap_end = re.min(end);
                    inserted -= (overlap_end - overlap_start + 1) as u64;
                }

                // Now merge the new run with existing runs
                let mut new_runs = Vec::new();
                let mut merged_start = start;
                let mut merged_end = end;
                let mut merged = false;

                for &(rs, re) in runs.iter() {
                    // Check if this run overlaps or is adjacent to our range
                    let overlaps = !(re + 1 < start || rs > end + 1);

                    if overlaps {
                        // Extend the merged range
                        merged_start = merged_start.min(rs);
                        merged_end = merged_end.max(re);
                        merged = true;
                    } else if rs > merged_end + 1 && merged {
                        // This run is after our merged range, output merged and continue
                        new_runs.push((merged_start, merged_end));
                        new_runs.push((rs, re));
                        merged = false;
                    } else if rs > end + 1 && !merged {
                        // This run is after our range and we haven't merged yet
                        new_runs.push((start, end));
                        new_runs.push((rs, re));
                        merged = true; // Mark as handled
                        merged_start = rs; // Won't be used but set for safety
                        merged_end = re;
                    } else {
                        new_runs.push((rs, re));
                    }
                }

                // Handle case where we still need to add the merged run
                if !merged || new_runs.last().is_none_or(|&(_, e)| e < merged_end) {
                    // Remove any runs that are now part of the merged range
                    new_runs.retain(|&(s, e)| e < merged_start || s > merged_end);
                    // Find insertion point
                    let pos = new_runs.partition_point(|&(_, e)| e < merged_start);
                    new_runs.insert(pos, (merged_start, merged_end));
                }

                *runs = new_runs;

                // Check if we have too many runs
                if runs.len() >= MAX_RUNS_BEFORE_BITMAP {
                    self.maybe_convert_from_run();
                }

                inserted
            }
        }
    }

    /// Removes all values in the range [start, end] (inclusive).
    /// Returns the number of removed values.
    fn remove_range(&mut self, start: u16, end: u16) -> u64 {
        if start > end {
            return 0;
        }

        match self {
            Self::Array(arr) => {
                let original_len = arr.len();
                arr.retain(|&v| v < start || v > end);
                (original_len - arr.len()) as u64
            }
            Self::Bitmap(bits) => {
                let mut removed = 0u64;

                let start_word = start as usize / 64;
                let end_word = end as usize / 64;
                let start_bit = start as usize % 64;
                let end_bit = end as usize % 64;

                if start_word == end_word {
                    // Range fits in a single word
                    let width = end_bit - start_bit + 1;
                    let mask = if width == 64 {
                        u64::MAX
                    } else {
                        ((1u64 << width) - 1) << start_bit
                    };
                    removed += (mask & bits[start_word]).count_ones() as u64;
                    bits[start_word] &= !mask;
                } else {
                    // First partial word
                    let first_mask = !0u64 << start_bit;
                    removed += (first_mask & bits[start_word]).count_ones() as u64;
                    bits[start_word] &= !first_mask;

                    // Full words in between
                    for word in bits.iter_mut().take(end_word).skip(start_word + 1) {
                        removed += word.count_ones() as u64;
                        *word = 0;
                    }

                    // Last partial word
                    let last_mask = if end_bit == 63 {
                        u64::MAX
                    } else {
                        (1u64 << (end_bit + 1)) - 1
                    };
                    removed += (last_mask & bits[end_word]).count_ones() as u64;
                    bits[end_word] &= !last_mask;
                }

                self.maybe_convert_to_array();
                removed
            }
            Self::Run(runs) => {
                let mut removed = 0u64;
                let mut new_runs = Vec::new();

                for &(rs, re) in runs.iter() {
                    if re < start || rs > end {
                        // No overlap - keep this run
                        new_runs.push((rs, re));
                    } else if rs >= start && re <= end {
                        // Entire run is removed
                        removed += (re - rs + 1) as u64;
                    } else if rs < start && re > end {
                        // Range is in the middle - split the run
                        new_runs.push((rs, start - 1));
                        new_runs.push((end + 1, re));
                        removed += (end - start + 1) as u64;
                    } else if rs < start {
                        // Overlap at the end of this run
                        new_runs.push((rs, start - 1));
                        removed += (re - start + 1) as u64;
                    } else {
                        // Overlap at the start of this run (rs <= end < re)
                        new_runs.push((end + 1, re));
                        removed += (end - rs + 1) as u64;
                    }
                }

                *runs = new_runs;
                self.maybe_convert_from_run();
                removed
            }
        }
    }
}

/// Iterator over values in a container.
enum ContainerIter<'a> {
    Array(core::slice::Iter<'a, u16>),
    Bitmap {
        bits: &'a [u64],
        word_idx: usize,
        bit_idx: usize,
    },
    Run {
        runs: &'a [(u16, u16)],
        run_idx: usize,
        current: u16,
    },
}

impl Iterator for ContainerIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ContainerIter::Array(iter) => iter.next().copied(),
            ContainerIter::Bitmap {
                bits,
                word_idx,
                bit_idx,
            } => {
                while *word_idx < bits.len() {
                    while *bit_idx < 64 {
                        let current_bit = *bit_idx;
                        *bit_idx += 1;
                        if (bits[*word_idx] & (1u64 << current_bit)) != 0 {
                            return Some((*word_idx * 64 + current_bit) as u16);
                        }
                    }
                    *word_idx += 1;
                    *bit_idx = 0;
                }
                None
            }
            ContainerIter::Run {
                runs,
                run_idx,
                current,
            } => {
                if *run_idx >= runs.len() {
                    return None;
                }
                let (start, end) = runs[*run_idx];
                if *current == 0 && *run_idx == 0 {
                    // First call - initialize to start of first run
                    *current = start;
                }
                if *current <= end {
                    let result = *current;
                    if *current == end {
                        // Move to next run
                        *run_idx += 1;
                        if *run_idx < runs.len() {
                            *current = runs[*run_idx].0;
                        }
                    } else {
                        *current += 1;
                    }
                    Some(result)
                } else {
                    None
                }
            }
        }
    }
}

impl fmt::Debug for Container {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Array(arr) => write!(f, "Array({} elements)", arr.len()),
            Self::Bitmap(_) => write!(f, "Bitmap({} elements)", self.len()),
            Self::Run(runs) => write!(f, "Run({} runs, {} elements)", runs.len(), self.len()),
        }
    }
}

/// A roaring bitmap for efficiently storing sets of 64-bit unsigned integers.
///
/// Roaring bitmaps partition the 64-bit integer space into containers of 2^16 values.
/// Each container uses either a sorted array (for sparse data) or a bitmap (for dense data)
/// based on the cardinality, ensuring optimal memory usage.
///
/// The high 48 bits of each value determine which container it belongs to, while the
/// low 16 bits determine its position within that container.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RoaringBitmap {
    /// Containers indexed by the high 48 bits of the values they contain.
    /// Stored as (high_bits, container) pairs, sorted by high_bits.
    containers: Vec<(u64, Container)>,
}

impl RoaringBitmap {
    /// Creates a new empty roaring bitmap.
    pub const fn new() -> Self {
        Self {
            containers: Vec::new(),
        }
    }

    /// Creates a new empty roaring bitmap with the specified capacity.
    ///
    /// The capacity is the expected number of containers, not individual values.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            containers: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of values in the bitmap.
    pub fn len(&self) -> u64 {
        self.containers.iter().map(|(_, c)| c.len() as u64).sum()
    }

    /// Returns true if the bitmap contains no values.
    pub fn is_empty(&self) -> bool {
        self.containers.iter().all(|(_, c)| c.is_empty())
    }

    /// Returns the number of containers in the bitmap.
    pub const fn num_containers(&self) -> usize {
        self.containers.len()
    }

    /// Splits a 64-bit value into high 48 bits and low 16 bits.
    #[inline]
    const fn split(value: u64) -> (u64, u16) {
        (value >> 16, value as u16)
    }

    /// Combines high 48 bits and low 16 bits into a 64-bit value.
    #[inline]
    const fn combine(high: u64, low: u16) -> u64 {
        (high << 16) | (low as u64)
    }

    /// Finds the container for the given high bits, returning its index.
    fn find_container(&self, high: u64) -> Result<usize, usize> {
        self.containers.binary_search_by_key(&high, |(h, _)| *h)
    }

    /// Checks if the given value is present in the bitmap.
    pub fn contains(&self, value: u64) -> bool {
        let (high, low) = Self::split(value);
        self.find_container(high)
            .is_ok_and(|idx| self.containers[idx].1.contains(low))
    }

    /// Inserts a value into the bitmap. Returns true if the value was newly inserted.
    pub fn insert(&mut self, value: u64) -> bool {
        let (high, low) = Self::split(value);
        match self.find_container(high) {
            Ok(idx) => {
                let inserted = self.containers[idx].1.insert(low);
                if inserted {
                    self.containers[idx].1.maybe_convert_to_bitmap();
                }
                inserted
            }
            Err(idx) => {
                let mut container = Container::new_array();
                container.insert(low);
                self.containers.insert(idx, (high, container));
                true
            }
        }
    }

    /// Removes a value from the bitmap. Returns true if the value was present.
    pub fn remove(&mut self, value: u64) -> bool {
        let (high, low) = Self::split(value);
        match self.find_container(high) {
            Ok(idx) => {
                let removed = self.containers[idx].1.remove(low);
                if removed {
                    if self.containers[idx].1.is_empty() {
                        self.containers.remove(idx);
                    } else {
                        self.containers[idx].1.maybe_convert_to_array();
                    }
                }
                removed
            }
            Err(_) => false,
        }
    }

    /// Clears all values from the bitmap.
    pub fn clear(&mut self) {
        self.containers.clear();
    }

    /// Inserts all values in the given range.
    ///
    /// Returns the number of values that were newly inserted.
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_utils::bitmap::RoaringBitmap;
    ///
    /// let mut bitmap = RoaringBitmap::new();
    /// bitmap.insert_range(10..20);  // Insert 10..19
    /// assert_eq!(bitmap.len(), 10);
    ///
    /// bitmap.insert_range(15..=25); // Insert 15..25 (inclusive)
    /// assert_eq!(bitmap.len(), 16); // 10..25 inclusive
    /// ```
    pub fn insert_range<R: core::ops::RangeBounds<u64>>(&mut self, range: R) -> u64 {
        let start = match range.start_bound() {
            core::ops::Bound::Included(&n) => n,
            core::ops::Bound::Excluded(&n) => n.saturating_add(1),
            core::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            core::ops::Bound::Included(&n) => n,
            core::ops::Bound::Excluded(&n) => n.saturating_sub(1),
            core::ops::Bound::Unbounded => u64::MAX,
        };

        if start > end {
            return 0;
        }

        let (start_high, start_low) = Self::split(start);
        let (end_high, end_low) = Self::split(end);

        let mut total_inserted = 0u64;

        for high in start_high..=end_high {
            let container_start = if high == start_high { start_low } else { 0 };
            let container_end = if high == end_high { end_low } else { u16::MAX };

            match self.find_container(high) {
                Ok(idx) => {
                    total_inserted +=
                        self.containers[idx].1.insert_range(container_start, container_end);
                }
                Err(idx) => {
                    // Create new container
                    let container = if container_start == 0 && container_end == u16::MAX {
                        // Full container
                        total_inserted += 65536;
                        Container::new_full()
                    } else {
                        let mut container = Container::new_array();
                        total_inserted += container.insert_range(container_start, container_end);
                        container
                    };
                    self.containers.insert(idx, (high, container));
                }
            }
        }

        total_inserted
    }

    /// Removes all values in the given range.
    ///
    /// Returns the number of values that were removed.
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_utils::bitmap::RoaringBitmap;
    ///
    /// let mut bitmap = RoaringBitmap::new();
    /// bitmap.insert_range(0..100);
    /// assert_eq!(bitmap.len(), 100);
    ///
    /// bitmap.remove_range(25..75);
    /// assert_eq!(bitmap.len(), 50); // 0..24 and 75..99 remain
    /// ```
    pub fn remove_range<R: core::ops::RangeBounds<u64>>(&mut self, range: R) -> u64 {
        let start = match range.start_bound() {
            core::ops::Bound::Included(&n) => n,
            core::ops::Bound::Excluded(&n) => n.saturating_add(1),
            core::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            core::ops::Bound::Included(&n) => n,
            core::ops::Bound::Excluded(&n) => n.saturating_sub(1),
            core::ops::Bound::Unbounded => u64::MAX,
        };

        if start > end {
            return 0;
        }

        let (start_high, start_low) = Self::split(start);
        let (end_high, end_low) = Self::split(end);

        let mut total_removed = 0u64;
        let mut containers_to_remove = Vec::new();

        for high in start_high..=end_high {
            let container_start = if high == start_high { start_low } else { 0 };
            let container_end = if high == end_high { end_low } else { u16::MAX };

            if let Ok(idx) = self.find_container(high) {
                if container_start == 0 && container_end == u16::MAX {
                    // Remove entire container
                    total_removed += self.containers[idx].1.len() as u64;
                    containers_to_remove.push(high);
                } else {
                    total_removed +=
                        self.containers[idx].1.remove_range(container_start, container_end);
                    if self.containers[idx].1.is_empty() {
                        containers_to_remove.push(high);
                    }
                }
            }
        }

        // Remove empty containers (in reverse order to preserve indices)
        for high in containers_to_remove.into_iter().rev() {
            if let Ok(idx) = self.find_container(high) {
                self.containers.remove(idx);
            }
        }

        total_removed
    }

    /// Returns the minimum value in the bitmap, or None if empty.
    pub fn min(&self) -> Option<u64> {
        self.containers.first().and_then(|(high, container)| {
            container.iter().next().map(|low| Self::combine(*high, low))
        })
    }

    /// Returns the maximum value in the bitmap, or None if empty.
    pub fn max(&self) -> Option<u64> {
        self.containers.last().and_then(|(high, container)| {
            let low: Option<u16> = match container {
                Container::Array(arr) => arr.last().copied(),
                Container::Bitmap(bits) => {
                    // Find the last set bit
                    bits.iter()
                        .enumerate()
                        .rev()
                        .find(|(_, &word)| word != 0)
                        .map(|(word_idx, &word)| {
                            let bit_idx = 63 - word.leading_zeros();
                            (word_idx * 64 + bit_idx as usize) as u16
                        })
                }
                Container::Run(runs) => runs.last().map(|&(_, end)| end),
            };
            low.map(|low| Self::combine(*high, low))
        })
    }

    /// Returns an iterator over all values in the bitmap in ascending order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            containers: &self.containers,
            container_idx: 0,
            container_iter: None,
        }
    }

    /// Performs a bitwise AND with another bitmap, modifying self in place.
    pub fn and(&mut self, other: &Self) {
        let mut result = Vec::new();
        let mut self_idx = 0;
        let mut other_idx = 0;

        while self_idx < self.containers.len() && other_idx < other.containers.len() {
            let (self_high, _) = &self.containers[self_idx];
            let (other_high, _) = &other.containers[other_idx];

            match self_high.cmp(other_high) {
                core::cmp::Ordering::Less => {
                    // Container only in self, skip it
                    self_idx += 1;
                }
                core::cmp::Ordering::Greater => {
                    // Container only in other, skip it
                    other_idx += 1;
                }
                core::cmp::Ordering::Equal => {
                    // Container in both, AND them
                    let high = *self_high;
                    let new_container = and_containers(
                        &self.containers[self_idx].1,
                        &other.containers[other_idx].1,
                    );
                    if !new_container.is_empty() {
                        result.push((high, new_container));
                    }
                    self_idx += 1;
                    other_idx += 1;
                }
            }
        }

        self.containers = result;
    }

    /// Performs a bitwise OR with another bitmap, modifying self in place.
    pub fn or(&mut self, other: &Self) {
        let mut result = Vec::new();
        let mut self_idx = 0;
        let mut other_idx = 0;

        while self_idx < self.containers.len() || other_idx < other.containers.len() {
            let self_item = self.containers.get(self_idx);
            let other_item = other.containers.get(other_idx);

            match (self_item, other_item) {
                (Some((self_high, _)), Some((other_high, _))) => match self_high.cmp(other_high) {
                    core::cmp::Ordering::Less => {
                        result.push(self.containers[self_idx].clone());
                        self_idx += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(other.containers[other_idx].clone());
                        other_idx += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        let high = *self_high;
                        let new_container = or_containers(
                            &self.containers[self_idx].1,
                            &other.containers[other_idx].1,
                        );
                        result.push((high, new_container));
                        self_idx += 1;
                        other_idx += 1;
                    }
                },
                (Some(_), None) => {
                    result.push(self.containers[self_idx].clone());
                    self_idx += 1;
                }
                (None, Some(_)) => {
                    result.push(other.containers[other_idx].clone());
                    other_idx += 1;
                }
                (None, None) => break,
            }
        }

        self.containers = result;
    }

    /// Performs a bitwise XOR with another bitmap, modifying self in place.
    pub fn xor(&mut self, other: &Self) {
        let mut result = Vec::new();
        let mut self_idx = 0;
        let mut other_idx = 0;

        while self_idx < self.containers.len() || other_idx < other.containers.len() {
            let self_item = self.containers.get(self_idx);
            let other_item = other.containers.get(other_idx);

            match (self_item, other_item) {
                (Some((self_high, _)), Some((other_high, _))) => match self_high.cmp(other_high) {
                    core::cmp::Ordering::Less => {
                        result.push(self.containers[self_idx].clone());
                        self_idx += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(other.containers[other_idx].clone());
                        other_idx += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        let high = *self_high;
                        let new_container = xor_containers(
                            &self.containers[self_idx].1,
                            &other.containers[other_idx].1,
                        );
                        if !new_container.is_empty() {
                            result.push((high, new_container));
                        }
                        self_idx += 1;
                        other_idx += 1;
                    }
                },
                (Some(_), None) => {
                    result.push(self.containers[self_idx].clone());
                    self_idx += 1;
                }
                (None, Some(_)) => {
                    result.push(other.containers[other_idx].clone());
                    other_idx += 1;
                }
                (None, None) => break,
            }
        }

        self.containers = result;
    }

    /// Returns the intersection of two bitmaps as a new bitmap.
    pub fn intersection(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.and(other);
        result
    }

    /// Returns the union of two bitmaps as a new bitmap.
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.or(other);
        result
    }

    /// Returns the symmetric difference of two bitmaps as a new bitmap.
    pub fn symmetric_difference(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.xor(other);
        result
    }

    /// Returns a random contiguous run of values that are in `other` but not in `self`.
    ///
    /// This is useful for peer synchronization: when helping a peer catch up, you can request
    /// a random subset of missing items. By using different random seeds, multiple peers can
    /// work on different portions of the missing data concurrently.
    ///
    /// # Arguments
    ///
    /// * `other` - The reference bitmap containing values we might be missing
    /// * `size_range` - Bounds on the number of items to return (min..max or min..=max)
    /// * `rng` - Random number generator for selecting the starting position
    ///
    /// # Returns
    ///
    /// A vector of consecutive missing values, or an empty vector if:
    /// - There are no missing values
    /// - No contiguous run meets the minimum size requirement
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_utils::bitmap::RoaringBitmap;
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    ///
    /// let mut have = RoaringBitmap::new();
    /// have.insert_range(0..50);
    /// have.insert_range(100..150);
    ///
    /// let mut want = RoaringBitmap::new();
    /// want.insert_range(0..200);
    ///
    /// let mut rng = StdRng::seed_from_u64(42);
    /// let missing = have.random_missing_run(&want, 1..=20, &mut rng);
    ///
    /// // Returns up to 20 consecutive values from ranges 50..100 or 150..200
    /// assert!(!missing.is_empty());
    /// assert!(missing.len() <= 20);
    /// ```
    pub fn random_missing_run<R: RangeBounds<usize>>(
        &self,
        other: &Self,
        size_range: R,
        rng: &mut impl Rng,
    ) -> Vec<u64> {
        let min_size = match size_range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.saturating_add(1),
            Bound::Unbounded => 1,
        };
        let max_size = match size_range.end_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.saturating_sub(1),
            Bound::Unbounded => usize::MAX,
        };

        if min_size == 0 || max_size == 0 || min_size > max_size {
            return Vec::new();
        }

        // Two-pass algorithm to avoid storing all runs:
        // Pass 1: Count valid starting positions
        // Pass 2: Find the randomly selected position

        let mut valid_positions: u64 = 0;
        let min_size_u64 = min_size as u64;

        // Pass 1: Count valid starting positions
        for_each_missing_run(self, other, |run_len| {
            if run_len >= min_size_u64 {
                valid_positions += run_len - min_size_u64 + 1;
            }
        });

        if valid_positions == 0 {
            return Vec::new();
        }

        // Pick a random starting position
        let target_pos = rng.gen_range(0..valid_positions);

        // Pass 2: Find the run containing our target position
        let mut pos_counter: u64 = 0;
        let mut result = Vec::new();

        for_each_missing_run_with_values(self, other, |run_start, run_len| {
            if run_len >= min_size_u64 {
                let positions_in_run = run_len - min_size_u64 + 1;
                if target_pos < pos_counter + positions_in_run {
                    // Found the run - extract values
                    let offset = target_pos - pos_counter;
                    let actual_start = run_start + offset;
                    let items_available = run_len - offset;
                    let items_to_take = core::cmp::min(items_available, max_size as u64);

                    result.reserve(items_to_take as usize);
                    for v in actual_start..actual_start + items_to_take {
                        result.push(v);
                    }
                    return true; // Stop iteration
                }
                pos_counter += positions_in_run;
            }
            false // Continue iteration
        });

        result
    }
}

/// Iterates over runs of consecutive missing values (in `other` but not in `have`),
/// calling the callback with just the run length. Used for counting.
fn for_each_missing_run(have: &RoaringBitmap, other: &RoaringBitmap, mut callback: impl FnMut(u64)) {
    for_each_missing_run_with_values(have, other, |_start, len| {
        callback(len);
        false // Continue iteration
    });
}

/// Iterates over runs of consecutive missing values (in `other` but not in `have`),
/// calling the callback with (run_start, run_length). Returns early if callback returns true.
///
/// Works at the container level for efficiency:
/// - Containers only in `other`: all values are missing
/// - Containers in both: compute difference and find runs within
fn for_each_missing_run_with_values(
    have: &RoaringBitmap,
    other: &RoaringBitmap,
    mut callback: impl FnMut(u64, u64) -> bool,
) {
    let mut have_idx = 0;
    let mut current_run_start: Option<u64> = None;
    let mut current_run_end: u64 = 0;

    // Helper to finalize a run and call callback
    let finalize_run = |start: &mut Option<u64>, end: u64, cb: &mut dyn FnMut(u64, u64) -> bool| -> bool {
        if let Some(s) = start.take() {
            let len = end - s + 1;
            if cb(s, len) {
                return true; // Early exit requested
            }
        }
        false
    };

    for (other_high, other_container) in &other.containers {
        // Skip have containers that are before this other container
        while have_idx < have.containers.len() && have.containers[have_idx].0 < *other_high {
            have_idx += 1;
        }

        let base = *other_high << 16;

        if have_idx < have.containers.len() && have.containers[have_idx].0 == *other_high {
            // Both have this container - find missing values within
            let have_container = &have.containers[have_idx].1;

            for value_u16 in other_container.iter() {
                let value = base | (value_u16 as u64);
                if !have_container.contains(value_u16) {
                    // This value is missing
                    match current_run_start {
                        None => {
                            current_run_start = Some(value);
                            current_run_end = value;
                        }
                        Some(_) if value == current_run_end + 1 => {
                            current_run_end = value;
                        }
                        Some(_) => {
                            // Gap - finalize current run
                            if finalize_run(&mut current_run_start, current_run_end, &mut callback) {
                                return;
                            }
                            current_run_start = Some(value);
                            current_run_end = value;
                        }
                    }
                }
            }
        } else {
            // Container only in other - all values are missing
            // Iterate through the container's values
            for value_u16 in other_container.iter() {
                let value = base | (value_u16 as u64);
                match current_run_start {
                    None => {
                        current_run_start = Some(value);
                        current_run_end = value;
                    }
                    Some(_) if value == current_run_end + 1 => {
                        current_run_end = value;
                    }
                    Some(_) => {
                        // Gap within container (sparse array container)
                        if finalize_run(&mut current_run_start, current_run_end, &mut callback) {
                            return;
                        }
                        current_run_start = Some(value);
                        current_run_end = value;
                    }
                }
            }
        }

        // Check for gap between containers
        if current_run_start.is_some() {
            // Peek at next other container to see if there's a gap
            // The gap check happens naturally in the next iteration when we see
            // a non-consecutive value
        }
    }

    // Finalize last run
    if current_run_start.is_some() {
        finalize_run(&mut current_run_start, current_run_end, &mut callback);
    }
}

/// AND two containers together.
fn and_containers(a: &Container, b: &Container) -> Container {
    // Handle Run containers by converting to bitmap for the operation
    match (a, b) {
        (Container::Run(_), _) => {
            let bits_a = a.to_bitmap();
            and_containers(&Container::Bitmap(bits_a), b)
        }
        (_, Container::Run(_)) => {
            let bits_b = b.to_bitmap();
            and_containers(a, &Container::Bitmap(bits_b))
        }
        (Container::Array(arr_a), Container::Array(arr_b)) => {
            // Intersection of two sorted arrays
            let mut result = Vec::new();
            let mut i = 0;
            let mut j = 0;
            while i < arr_a.len() && j < arr_b.len() {
                match arr_a[i].cmp(&arr_b[j]) {
                    core::cmp::Ordering::Less => i += 1,
                    core::cmp::Ordering::Greater => j += 1,
                    core::cmp::Ordering::Equal => {
                        result.push(arr_a[i]);
                        i += 1;
                        j += 1;
                    }
                }
            }
            Container::Array(result)
        }
        (Container::Bitmap(bits_a), Container::Bitmap(bits_b)) => {
            let bits: Vec<u64> = bits_a
                .iter()
                .zip(bits_b.iter())
                .map(|(&a, &b)| a & b)
                .collect();
            let mut container = Container::Bitmap(bits);
            container.maybe_convert_to_array();
            container.maybe_convert_to_run();
            container
        }
        (Container::Array(arr), Container::Bitmap(bits))
        | (Container::Bitmap(bits), Container::Array(arr)) => {
            let result: Vec<u16> = arr
                .iter()
                .copied()
                .filter(|&v| {
                    let word_idx = v as usize / 64;
                    let bit_idx = v as usize % 64;
                    (bits[word_idx] & (1u64 << bit_idx)) != 0
                })
                .collect();
            Container::Array(result)
        }
    }
}

/// OR two containers together.
fn or_containers(a: &Container, b: &Container) -> Container {
    // Handle Run containers by converting to bitmap for the operation
    match (a, b) {
        (Container::Run(_), _) => {
            let bits_a = a.to_bitmap();
            or_containers(&Container::Bitmap(bits_a), b)
        }
        (_, Container::Run(_)) => {
            let bits_b = b.to_bitmap();
            or_containers(a, &Container::Bitmap(bits_b))
        }
        (Container::Array(arr_a), Container::Array(arr_b)) => {
            // Union of two sorted arrays
            let mut result = Vec::with_capacity(arr_a.len() + arr_b.len());
            let mut i = 0;
            let mut j = 0;
            while i < arr_a.len() && j < arr_b.len() {
                match arr_a[i].cmp(&arr_b[j]) {
                    core::cmp::Ordering::Less => {
                        result.push(arr_a[i]);
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(arr_b[j]);
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        result.push(arr_a[i]);
                        i += 1;
                        j += 1;
                    }
                }
            }
            result.extend_from_slice(&arr_a[i..]);
            result.extend_from_slice(&arr_b[j..]);

            let mut container = Container::Array(result);
            container.maybe_convert_to_bitmap();
            container.maybe_convert_to_run();
            container
        }
        (Container::Bitmap(bits_a), Container::Bitmap(bits_b)) => {
            let bits: Vec<u64> = bits_a
                .iter()
                .zip(bits_b.iter())
                .map(|(&a, &b)| a | b)
                .collect();
            let mut container = Container::Bitmap(bits);
            container.maybe_convert_to_run();
            container
        }
        (Container::Array(arr), Container::Bitmap(bits))
        | (Container::Bitmap(bits), Container::Array(arr)) => {
            let mut new_bits = bits.clone();
            for &v in arr {
                let word_idx = v as usize / 64;
                let bit_idx = v as usize % 64;
                new_bits[word_idx] |= 1u64 << bit_idx;
            }
            let mut container = Container::Bitmap(new_bits);
            container.maybe_convert_to_run();
            container
        }
    }
}

/// XOR two containers together.
fn xor_containers(a: &Container, b: &Container) -> Container {
    // Handle Run containers by converting to bitmap for the operation
    match (a, b) {
        (Container::Run(_), _) => {
            let bits_a = a.to_bitmap();
            xor_containers(&Container::Bitmap(bits_a), b)
        }
        (_, Container::Run(_)) => {
            let bits_b = b.to_bitmap();
            xor_containers(a, &Container::Bitmap(bits_b))
        }
        (Container::Array(arr_a), Container::Array(arr_b)) => {
            // Symmetric difference of two sorted arrays
            let mut result = Vec::with_capacity(arr_a.len() + arr_b.len());
            let mut i = 0;
            let mut j = 0;
            while i < arr_a.len() && j < arr_b.len() {
                match arr_a[i].cmp(&arr_b[j]) {
                    core::cmp::Ordering::Less => {
                        result.push(arr_a[i]);
                        i += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        result.push(arr_b[j]);
                        j += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        // Skip elements that are in both
                        i += 1;
                        j += 1;
                    }
                }
            }
            result.extend_from_slice(&arr_a[i..]);
            result.extend_from_slice(&arr_b[j..]);

            let mut container = Container::Array(result);
            container.maybe_convert_to_bitmap();
            container.maybe_convert_to_run();
            container
        }
        (Container::Bitmap(bits_a), Container::Bitmap(bits_b)) => {
            let bits: Vec<u64> = bits_a
                .iter()
                .zip(bits_b.iter())
                .map(|(&a, &b)| a ^ b)
                .collect();
            let mut container = Container::Bitmap(bits);
            container.maybe_convert_to_array();
            container.maybe_convert_to_run();
            container
        }
        (Container::Array(arr), Container::Bitmap(bits))
        | (Container::Bitmap(bits), Container::Array(arr)) => {
            let mut new_bits = bits.clone();
            for &v in arr {
                let word_idx = v as usize / 64;
                let bit_idx = v as usize % 64;
                new_bits[word_idx] ^= 1u64 << bit_idx;
            }
            let mut container = Container::Bitmap(new_bits);
            container.maybe_convert_to_array();
            container.maybe_convert_to_run();
            container
        }
    }
}

impl Default for RoaringBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RoaringBitmap {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RoaringBitmap {{ len: {}, containers: {} }}",
            self.len(),
            self.num_containers()
        )
    }
}

/// Iterator over values in a RoaringBitmap.
pub struct Iter<'a> {
    containers: &'a [(u64, Container)],
    container_idx: usize,
    container_iter: Option<(u64, ContainerIter<'a>)>,
}

impl Iterator for Iter<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next value from current container
            if let Some((high, ref mut iter)) = self.container_iter {
                if let Some(low) = iter.next() {
                    return Some(RoaringBitmap::combine(high, low));
                }
            }

            // Move to next container
            if self.container_idx >= self.containers.len() {
                return None;
            }

            let (high, container) = &self.containers[self.container_idx];
            self.container_iter = Some((*high, container.iter()));
            self.container_idx += 1;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Calculate remaining elements
        let remaining: usize = self.containers[self.container_idx..]
            .iter()
            .map(|(_, c)| c.len())
            .sum();
        (remaining, Some(remaining))
    }
}

impl<'a> IntoIterator for &'a RoaringBitmap {
    type Item = u64;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<u64> for RoaringBitmap {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        let mut bitmap = Self::new();
        for value in iter {
            bitmap.insert(value);
        }
        bitmap
    }
}

impl Extend<u64> for RoaringBitmap {
    fn extend<I: IntoIterator<Item = u64>>(&mut self, iter: I) {
        for value in iter {
            self.insert(value);
        }
    }
}

// Container type tag for serialization
const CONTAINER_TYPE_ARRAY: u8 = 0;
const CONTAINER_TYPE_BITMAP: u8 = 1;
const CONTAINER_TYPE_RUN: u8 = 2;

impl Write for Container {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Array(arr) => {
                CONTAINER_TYPE_ARRAY.write(buf);
                (arr.len() as u16).write(buf);
                for &value in arr {
                    value.write(buf);
                }
            }
            Self::Bitmap(bits) => {
                CONTAINER_TYPE_BITMAP.write(buf);
                for &word in bits {
                    word.write(buf);
                }
            }
            Self::Run(runs) => {
                CONTAINER_TYPE_RUN.write(buf);
                (runs.len() as u16).write(buf);
                for &(start, end) in runs {
                    start.write(buf);
                    end.write(buf);
                }
            }
        }
    }
}

impl Read for Container {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let container_type = u8::read(buf)?;
        match container_type {
            CONTAINER_TYPE_ARRAY => {
                let len = u16::read(buf)? as usize;
                at_least(buf, len * 2)?;
                let mut arr = Vec::with_capacity(len);
                for _ in 0..len {
                    arr.push(u16::read(buf)?);
                }
                Ok(Self::Array(arr))
            }
            CONTAINER_TYPE_BITMAP => {
                at_least(buf, BITMAP_CONTAINER_SIZE)?;
                let mut bits = Vec::with_capacity(BITMAP_CONTAINER_SIZE / 8);
                for _ in 0..BITMAP_CONTAINER_SIZE / 8 {
                    bits.push(u64::read(buf)?);
                }
                Ok(Self::Bitmap(bits))
            }
            CONTAINER_TYPE_RUN => {
                let num_runs = u16::read(buf)? as usize;
                at_least(buf, num_runs * 4)?;
                let mut runs = Vec::with_capacity(num_runs);
                for _ in 0..num_runs {
                    let start = u16::read(buf)?;
                    let end = u16::read(buf)?;
                    if start > end {
                        return Err(CodecError::Invalid(
                            "Container",
                            "Invalid run: start > end",
                        ));
                    }
                    runs.push((start, end));
                }
                Ok(Self::Run(runs))
            }
            _ => Err(CodecError::Invalid(
                "Container",
                "Invalid container type tag",
            )),
        }
    }
}

impl EncodeSize for Container {
    fn encode_size(&self) -> usize {
        match self {
            Self::Array(arr) => {
                1 // type tag
                + 2 // length
                + arr.len() * 2 // values
            }
            Self::Bitmap(_) => {
                1 // type tag
                + BITMAP_CONTAINER_SIZE // bitmap data
            }
            Self::Run(runs) => {
                1 // type tag
                + 2 // num runs
                + runs.len() * 4 // (start, end) pairs
            }
        }
    }
}

impl Write for RoaringBitmap {
    fn write(&self, buf: &mut impl BufMut) {
        // Write number of containers
        (self.containers.len() as u64).write(buf);

        // Write each container with its high bits key
        for (high, container) in &self.containers {
            high.write(buf);
            container.write(buf);
        }
    }
}

impl Read for RoaringBitmap {
    type Cfg = u64; // Max number of containers

    fn read_cfg(buf: &mut impl Buf, max_containers: &Self::Cfg) -> Result<Self, CodecError> {
        let num_containers = u64::read(buf)?;
        if num_containers > *max_containers {
            return Err(CodecError::InvalidLength(num_containers as usize));
        }

        let mut containers = Vec::with_capacity(num_containers as usize);
        let mut last_high: Option<u64> = None;

        for _ in 0..num_containers {
            let high = u64::read(buf)?;

            // Verify containers are in sorted order and unique
            if let Some(last) = last_high {
                if high <= last {
                    return Err(CodecError::Invalid(
                        "RoaringBitmap",
                        "Containers must be in ascending order with unique keys",
                    ));
                }
            }
            last_high = Some(high);

            let container = Container::read(buf)?;
            if container.is_empty() {
                return Err(CodecError::Invalid(
                    "RoaringBitmap",
                    "Empty containers are not allowed",
                ));
            }
            containers.push((high, container));
        }

        Ok(Self { containers })
    }
}

impl EncodeSize for RoaringBitmap {
    fn encode_size(&self) -> usize {
        8 // number of containers (u64)
        + self.containers.iter().map(|(_, c)| 8 + c.encode_size()).sum::<usize>()
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for RoaringBitmap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let size = u.int_in_range(0..=1024)?;
        let mut bitmap = Self::new();
        for _ in 0..size {
            bitmap.insert(u.arbitrary::<u64>()?);
        }
        Ok(bitmap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode, Error as CodecError, Write};

    #[test]
    fn test_new() {
        let bitmap = RoaringBitmap::new();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.len(), 0);
        assert_eq!(bitmap.num_containers(), 0);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut bitmap = RoaringBitmap::new();

        // Insert some values
        assert!(bitmap.insert(10));
        assert!(bitmap.insert(100));
        assert!(bitmap.insert(1000));
        assert!(bitmap.insert(100_000));

        // Verify they are present
        assert!(bitmap.contains(10));
        assert!(bitmap.contains(100));
        assert!(bitmap.contains(1000));
        assert!(bitmap.contains(100_000));

        // Verify non-existent values
        assert!(!bitmap.contains(11));
        assert!(!bitmap.contains(99));
        assert!(!bitmap.contains(50_000));

        // Insert duplicate returns false
        assert!(!bitmap.insert(10));
        assert_eq!(bitmap.len(), 4);
    }

    #[test]
    fn test_large_u64_values() {
        let mut bitmap = RoaringBitmap::new();

        // Test with large u64 values
        let large_values = [
            1_000_000_000_000u64,
            u64::MAX - 100,
            u64::MAX,
            1u64 << 48,
            (1u64 << 48) + 1,
        ];

        for &value in &large_values {
            assert!(bitmap.insert(value));
        }

        for &value in &large_values {
            assert!(bitmap.contains(value), "Missing value: {}", value);
        }

        assert_eq!(bitmap.len(), large_values.len() as u64);
    }

    #[test]
    fn test_remove() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(10);
        bitmap.insert(20);
        bitmap.insert(30);

        assert_eq!(bitmap.len(), 3);

        // Remove existing value
        assert!(bitmap.remove(20));
        assert!(!bitmap.contains(20));
        assert_eq!(bitmap.len(), 2);

        // Remove non-existent value
        assert!(!bitmap.remove(20));
        assert!(!bitmap.remove(40));
        assert_eq!(bitmap.len(), 2);

        // Remove remaining values
        assert!(bitmap.remove(10));
        assert!(bitmap.remove(30));
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_min_max() {
        let mut bitmap = RoaringBitmap::new();

        assert_eq!(bitmap.min(), None);
        assert_eq!(bitmap.max(), None);

        bitmap.insert(100);
        assert_eq!(bitmap.min(), Some(100));
        assert_eq!(bitmap.max(), Some(100));

        bitmap.insert(10);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(100));

        bitmap.insert(1000);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(1000));

        // Add values in different containers
        bitmap.insert(100_000);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(100_000));

        // Test with large u64 values
        bitmap.insert(u64::MAX);
        assert_eq!(bitmap.min(), Some(10));
        assert_eq!(bitmap.max(), Some(u64::MAX));
    }

    #[test]
    fn test_iterator() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(5);
        bitmap.insert(10);
        bitmap.insert(70_000);
        bitmap.insert(15);

        let values: Vec<u64> = bitmap.iter().collect();
        assert_eq!(values, vec![5, 10, 15, 70_000]);
    }

    #[test]
    fn test_from_iterator() {
        let values = vec![100u64, 50, 200, 50, 75];
        let bitmap: RoaringBitmap = values.into_iter().collect();

        assert_eq!(bitmap.len(), 4); // 50 is duplicate
        assert!(bitmap.contains(50));
        assert!(bitmap.contains(75));
        assert!(bitmap.contains(100));
        assert!(bitmap.contains(200));
    }

    #[test]
    fn test_extend() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(1);
        bitmap.extend([2u64, 3, 4]);
        assert_eq!(bitmap.len(), 4);
    }

    #[test]
    fn test_array_to_bitmap_conversion() {
        let mut bitmap = RoaringBitmap::new();

        // Insert enough values to trigger conversion
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            bitmap.insert(i);
        }

        assert_eq!(bitmap.len(), ARRAY_TO_BITMAP_THRESHOLD as u64);

        // Verify all values are still present
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
    }

    #[test]
    fn test_multiple_containers() {
        let mut bitmap = RoaringBitmap::new();

        // Insert values in different containers (different high 48 bits)
        bitmap.insert(0);
        bitmap.insert(65_536); // Container 1
        bitmap.insert(131_072); // Container 2
        bitmap.insert(196_608); // Container 3

        assert_eq!(bitmap.num_containers(), 4);
        assert_eq!(bitmap.len(), 4);

        assert!(bitmap.contains(0));
        assert!(bitmap.contains(65_536));
        assert!(bitmap.contains(131_072));
        assert!(bitmap.contains(196_608));
    }

    #[test]
    fn test_and() {
        let mut a = RoaringBitmap::new();
        a.insert(1);
        a.insert(2);
        a.insert(3);
        a.insert(100_000);

        let mut b = RoaringBitmap::new();
        b.insert(2);
        b.insert(3);
        b.insert(4);
        b.insert(100_000);

        a.and(&b);

        assert_eq!(a.len(), 3);
        assert!(!a.contains(1));
        assert!(a.contains(2));
        assert!(a.contains(3));
        assert!(!a.contains(4));
        assert!(a.contains(100_000));
    }

    #[test]
    fn test_or() {
        let mut a = RoaringBitmap::new();
        a.insert(1);
        a.insert(2);

        let mut b = RoaringBitmap::new();
        b.insert(2);
        b.insert(3);

        a.or(&b);

        assert_eq!(a.len(), 3);
        assert!(a.contains(1));
        assert!(a.contains(2));
        assert!(a.contains(3));
    }

    #[test]
    fn test_xor() {
        let mut a = RoaringBitmap::new();
        a.insert(1);
        a.insert(2);
        a.insert(3);

        let mut b = RoaringBitmap::new();
        b.insert(2);
        b.insert(3);
        b.insert(4);

        a.xor(&b);

        assert_eq!(a.len(), 2);
        assert!(a.contains(1));
        assert!(!a.contains(2));
        assert!(!a.contains(3));
        assert!(a.contains(4));
    }

    #[test]
    fn test_intersection() {
        let mut a = RoaringBitmap::new();
        a.extend([1u64, 2, 3, 4]);

        let mut b = RoaringBitmap::new();
        b.extend([3u64, 4, 5, 6]);

        let c = a.intersection(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(3));
        assert!(c.contains(4));

        // Original unchanged
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn test_union() {
        let mut a = RoaringBitmap::new();
        a.extend([1u64, 2]);

        let mut b = RoaringBitmap::new();
        b.extend([2u64, 3]);

        let c = a.union(&b);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn test_symmetric_difference() {
        let mut a = RoaringBitmap::new();
        a.extend([1u64, 2, 3]);

        let mut b = RoaringBitmap::new();
        b.extend([2u64, 3, 4]);

        let c = a.symmetric_difference(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(1));
        assert!(c.contains(4));
    }

    #[test]
    fn test_clear() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3, 100_000]);

        bitmap.clear();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.num_containers(), 0);
    }

    #[test]
    fn test_codec_empty() {
        let bitmap = RoaringBitmap::new();
        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_codec_array_container() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 5, 10, 100, 1000]);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), bitmap.len());
        for value in bitmap.iter() {
            assert!(decoded.contains(value));
        }
    }

    #[test]
    fn test_codec_bitmap_container() {
        let mut bitmap = RoaringBitmap::new();
        // Insert enough to create a bitmap container
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            bitmap.insert(i);
        }

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), bitmap.len());
        for i in 0..ARRAY_TO_BITMAP_THRESHOLD as u64 {
            assert!(decoded.contains(i));
        }
    }

    #[test]
    fn test_codec_multiple_containers() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(10);
        bitmap.insert(65_536 + 20);
        bitmap.insert(2 * 65_536 + 30);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.num_containers(), 3);
        assert!(decoded.contains(10));
        assert!(decoded.contains(65_536 + 20));
        assert!(decoded.contains(2 * 65_536 + 30));
    }

    #[test]
    fn test_codec_large_u64_values() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(1_000_000_000_000u64);
        bitmap.insert(u64::MAX);
        bitmap.insert(1u64 << 48);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), 3);
        assert!(decoded.contains(1_000_000_000_000u64));
        assert!(decoded.contains(u64::MAX));
        assert!(decoded.contains(1u64 << 48));
    }

    #[test]
    fn test_codec_max_containers_exceeded() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert(0);
        bitmap.insert(65_536);
        bitmap.insert(2 * 65_536);

        let encoded = bitmap.encode();
        let result = RoaringBitmap::decode_cfg(encoded, &2);
        assert!(result.is_err());
    }

    #[test]
    fn test_codec_truncated_buffer() {
        // Empty buffer
        let result = RoaringBitmap::decode_cfg(&[][..], &100);
        assert!(result.is_err());

        // Buffer too short for container count
        let result = RoaringBitmap::decode_cfg(&[0u8; 4][..], &100);
        assert!(result.is_err());

        // Claims 1 container but no container data
        let mut buf = BytesMut::new();
        1u64.write(&mut buf);
        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(result.is_err());

        // Has container key but no container data
        let mut buf = BytesMut::new();
        1u64.write(&mut buf); // 1 container
        0u64.write(&mut buf); // container key
        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(result.is_err());

        // Has container type but truncated array length
        let mut buf = BytesMut::new();
        1u64.write(&mut buf); // 1 container
        0u64.write(&mut buf); // container key
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(result.is_err());

        // Has array length but not enough values
        let mut buf = BytesMut::new();
        1u64.write(&mut buf); // 1 container
        0u64.write(&mut buf); // container key
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        5u16.write(&mut buf); // claims 5 values
        1u16.write(&mut buf); // only 1 value
        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(result.is_err());

        // Truncated bitmap container
        let mut buf = BytesMut::new();
        1u64.write(&mut buf); // 1 container
        0u64.write(&mut buf); // container key
        CONTAINER_TYPE_BITMAP.write(&mut buf);
        // Only write partial bitmap data (should be 8192 bytes)
        for _ in 0..100 {
            0u64.write(&mut buf);
        }
        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(result.is_err());
    }

    #[test]
    fn test_codec_invalid_container_type() {
        let mut buf = BytesMut::new();
        1u64.write(&mut buf); // 1 container
        0u64.write(&mut buf); // container key
        99u8.write(&mut buf); // invalid container type (not 0 or 1)

        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(matches!(
            result,
            Err(CodecError::Invalid("Container", "Invalid container type tag"))
        ));
    }

    #[test]
    fn test_codec_unsorted_containers() {
        // Create a manually encoded bitmap with unsorted container keys
        let mut buf = BytesMut::new();
        2u64.write(&mut buf); // 2 containers

        // First container with key 100
        100u64.write(&mut buf);
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        1u16.write(&mut buf); // 1 value
        42u16.write(&mut buf);

        // Second container with key 50 (out of order!)
        50u64.write(&mut buf);
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        1u16.write(&mut buf);
        10u16.write(&mut buf);

        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "RoaringBitmap",
                "Containers must be in ascending order with unique keys"
            ))
        ));
    }

    #[test]
    fn test_codec_duplicate_container_keys() {
        // Create a manually encoded bitmap with duplicate container keys
        let mut buf = BytesMut::new();
        2u64.write(&mut buf); // 2 containers

        // First container with key 50
        50u64.write(&mut buf);
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        1u16.write(&mut buf);
        42u16.write(&mut buf);

        // Second container also with key 50 (duplicate!)
        50u64.write(&mut buf);
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        1u16.write(&mut buf);
        10u16.write(&mut buf);

        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "RoaringBitmap",
                "Containers must be in ascending order with unique keys"
            ))
        ));
    }

    #[test]
    fn test_codec_empty_container() {
        // Create a manually encoded bitmap with an empty array container
        let mut buf = BytesMut::new();
        1u64.write(&mut buf); // 1 container
        0u64.write(&mut buf); // container key
        CONTAINER_TYPE_ARRAY.write(&mut buf);
        0u16.write(&mut buf); // 0 values (empty container)

        let result = RoaringBitmap::decode_cfg(buf.freeze(), &100);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "RoaringBitmap",
                "Empty containers are not allowed"
            ))
        ));
    }

    #[test]
    fn test_encode_size() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3]);

        let encoded = bitmap.encode();
        assert_eq!(encoded.len(), bitmap.encode_size());
    }

    #[test]
    fn test_debug() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3]);
        let debug_str = format!("{:?}", bitmap);
        assert!(debug_str.contains("RoaringBitmap"));
        assert!(debug_str.contains("len: 3"));
    }

    #[test]
    fn test_default() {
        let bitmap: RoaringBitmap = Default::default();
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_clone_and_eq() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.extend([1u64, 2, 3, 100_000]);

        let cloned = bitmap.clone();
        assert_eq!(bitmap, cloned);

        // Modify original
        bitmap.insert(4);
        assert_ne!(bitmap, cloned);
    }

    #[test]
    fn test_boundary_values() {
        let mut bitmap = RoaringBitmap::new();

        // Test boundary values
        bitmap.insert(0);
        bitmap.insert(u64::MAX);
        bitmap.insert(65_535); // Last value in container 0
        bitmap.insert(65_536); // First value in container 1

        assert!(bitmap.contains(0));
        assert!(bitmap.contains(u64::MAX));
        assert!(bitmap.contains(65_535));
        assert!(bitmap.contains(65_536));

        assert_eq!(bitmap.min(), Some(0));
        assert_eq!(bitmap.max(), Some(u64::MAX));
    }

    #[test]
    fn test_sparse_values() {
        let mut bitmap = RoaringBitmap::new();

        // Insert values spread across many containers
        for i in 0..100u64 {
            bitmap.insert(i * 65_536);
        }

        assert_eq!(bitmap.num_containers(), 100);
        assert_eq!(bitmap.len(), 100);

        for i in 0..100u64 {
            assert!(bitmap.contains(i * 65_536));
        }
    }

    #[test]
    fn test_high_bit_containers() {
        let mut bitmap = RoaringBitmap::new();

        // Test values that differ only in high bits
        let base = 1u64 << 48;
        bitmap.insert(base);
        bitmap.insert(base + 1);
        bitmap.insert(base + 65_536);

        assert_eq!(bitmap.num_containers(), 2); // Two different high-48-bit groups
        assert!(bitmap.contains(base));
        assert!(bitmap.contains(base + 1));
        assert!(bitmap.contains(base + 65_536));
    }

    #[test]
    fn test_insert_range_exclusive() {
        let mut bitmap = RoaringBitmap::new();

        // Exclusive range
        let inserted = bitmap.insert_range(10..20);
        assert_eq!(inserted, 10);
        assert_eq!(bitmap.len(), 10);

        for i in 10..20 {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
        assert!(!bitmap.contains(9));
        assert!(!bitmap.contains(20));
    }

    #[test]
    fn test_insert_range_inclusive() {
        let mut bitmap = RoaringBitmap::new();

        // Inclusive range
        let inserted = bitmap.insert_range(10..=20);
        assert_eq!(inserted, 11);
        assert_eq!(bitmap.len(), 11);

        for i in 10..=20 {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
    }

    #[test]
    fn test_insert_range_overlapping() {
        let mut bitmap = RoaringBitmap::new();

        bitmap.insert_range(10..20);
        assert_eq!(bitmap.len(), 10);

        // Overlapping range should only insert new values
        let inserted = bitmap.insert_range(15..=25);
        assert_eq!(inserted, 6); // 20..25 are new
        assert_eq!(bitmap.len(), 16); // 10..25 inclusive
    }

    #[test]
    fn test_insert_range_spanning_containers() {
        let mut bitmap = RoaringBitmap::new();

        // Range spanning multiple containers
        let start = 65_530u64;
        let end = 65_550u64;
        let inserted = bitmap.insert_range(start..=end);
        assert_eq!(inserted, 21);
        assert_eq!(bitmap.num_containers(), 2);

        for i in start..=end {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
    }

    #[test]
    fn test_insert_range_full_container() {
        let mut bitmap = RoaringBitmap::new();

        // Insert a full container's worth
        let inserted = bitmap.insert_range(0..65536);
        assert_eq!(inserted, 65536);
        assert_eq!(bitmap.len(), 65536);
        assert_eq!(bitmap.num_containers(), 1);
    }

    #[test]
    fn test_insert_range_large() {
        let mut bitmap = RoaringBitmap::new();

        // Insert a large range spanning multiple containers
        let inserted = bitmap.insert_range(0..200_000);
        assert_eq!(inserted, 200_000);
        assert_eq!(bitmap.len(), 200_000);

        // Should have multiple containers
        assert!(bitmap.num_containers() > 1);

        // Verify some values
        assert!(bitmap.contains(0));
        assert!(bitmap.contains(100_000));
        assert!(bitmap.contains(199_999));
        assert!(!bitmap.contains(200_000));
    }

    #[test]
    fn test_run_container_compression() {
        let mut bitmap = RoaringBitmap::new();

        // Insert a large contiguous range - should use run container
        bitmap.insert_range(0u64..1_000_000);

        // Verify the data is correct
        assert_eq!(bitmap.len(), 1_000_000);
        assert!(bitmap.contains(0));
        assert!(bitmap.contains(500_000));
        assert!(bitmap.contains(999_999));
        assert!(!bitmap.contains(1_000_000));

        // The encode size should be small due to run compression
        // Without run containers: 1M values * 2 bytes = 2MB minimum
        // With run containers: ~16 containers * (1 byte tag + 2 bytes num_runs + 4 bytes per run) ≈ very small
        let encoded_size = bitmap.encode_size();

        // Should be much smaller than 2MB (the array representation would be huge)
        // Run container should bring this down to hundreds of bytes
        assert!(
            encoded_size < 10_000,
            "Expected small encoded size due to run compression, got {}",
            encoded_size
        );

        // Verify roundtrip
        let decoded = RoaringBitmap::decode_cfg(bitmap.encode(), &1000).unwrap();
        assert_eq!(decoded.len(), 1_000_000);
        assert!(decoded.contains(0));
        assert!(decoded.contains(999_999));
    }

    #[test]
    fn test_run_container_roundtrip() {
        let mut bitmap = RoaringBitmap::new();

        // Create a bitmap with multiple runs
        bitmap.insert_range(100u64..200);
        bitmap.insert_range(300u64..400);
        bitmap.insert_range(1000u64..2000);

        let encoded = bitmap.encode();
        let decoded = RoaringBitmap::decode_cfg(encoded, &1000).unwrap();

        assert_eq!(decoded.len(), bitmap.len());
        assert!(decoded.contains(100));
        assert!(decoded.contains(199));
        assert!(!decoded.contains(200));
        assert!(decoded.contains(300));
        assert!(decoded.contains(1500));
    }

    #[test]
    fn test_remove_range_basic() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(0..100);

        let removed = bitmap.remove_range(25..75);
        assert_eq!(removed, 50);
        assert_eq!(bitmap.len(), 50);

        // Check remaining values
        for i in 0..25 {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
        for i in 25..75 {
            assert!(!bitmap.contains(i), "Should be removed: {}", i);
        }
        for i in 75..100 {
            assert!(bitmap.contains(i), "Missing value: {}", i);
        }
    }

    #[test]
    fn test_remove_range_spanning_containers() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(0..200_000);

        let removed = bitmap.remove_range(50_000..150_000);
        assert_eq!(removed, 100_000);
        assert_eq!(bitmap.len(), 100_000);

        assert!(bitmap.contains(0));
        assert!(bitmap.contains(49_999));
        assert!(!bitmap.contains(50_000));
        assert!(!bitmap.contains(100_000));
        assert!(!bitmap.contains(149_999));
        assert!(bitmap.contains(150_000));
        assert!(bitmap.contains(199_999));
    }

    #[test]
    fn test_remove_range_entire_container() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(0..65536);
        bitmap.insert_range(65536..131072);
        assert_eq!(bitmap.num_containers(), 2);

        // Remove entire first container
        let removed = bitmap.remove_range(0..65536);
        assert_eq!(removed, 65536);
        assert_eq!(bitmap.num_containers(), 1);
        assert_eq!(bitmap.len(), 65536);
    }

    #[test]
    fn test_remove_range_empty() {
        let mut bitmap = RoaringBitmap::new();
        bitmap.insert_range(100..200);

        // Remove range that doesn't exist
        let removed = bitmap.remove_range(0..50);
        assert_eq!(removed, 0);
        assert_eq!(bitmap.len(), 100);

        // Remove range beyond existing values
        let removed = bitmap.remove_range(300..400);
        assert_eq!(removed, 0);
        assert_eq!(bitmap.len(), 100);
    }

    #[test]
    fn test_range_with_large_values() {
        let mut bitmap = RoaringBitmap::new();

        // Insert range with large u64 values
        let start = 1_000_000_000_000u64;
        let end = start + 1000;
        let inserted = bitmap.insert_range(start..end);
        assert_eq!(inserted, 1000);

        for i in start..end {
            assert!(bitmap.contains(i));
        }

        // Remove part of it
        let removed = bitmap.remove_range(start + 500..end);
        assert_eq!(removed, 500);
        assert_eq!(bitmap.len(), 500);
    }

    #[test]
    fn test_random_missing_run_basic() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut have = RoaringBitmap::new();
        have.insert_range(0..50);
        have.insert_range(100..150);

        let mut want = RoaringBitmap::new();
        want.insert_range(0..200);

        let mut rng = StdRng::seed_from_u64(42);
        let missing = have.random_missing_run(&want, 1..=20, &mut rng);

        // Should return values from 50..100 or 150..200
        assert!(!missing.is_empty());
        assert!(missing.len() <= 20);

        // All returned values should be missing from 'have'
        for v in &missing {
            assert!(!have.contains(*v));
            assert!(want.contains(*v));
        }

        // Values should be consecutive
        for i in 1..missing.len() {
            assert_eq!(missing[i], missing[i - 1] + 1);
        }
    }

    #[test]
    fn test_random_missing_run_no_missing() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut have = RoaringBitmap::new();
        have.insert_range(0..100);

        let mut want = RoaringBitmap::new();
        want.insert_range(0..100);

        let mut rng = StdRng::seed_from_u64(42);
        let missing = have.random_missing_run(&want, 1..=20, &mut rng);

        // No missing values
        assert!(missing.is_empty());
    }

    #[test]
    fn test_random_missing_run_min_size_not_met() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut have = RoaringBitmap::new();
        have.insert_range(0..100);
        // Missing: 100, 101, 102 (only 3 items)
        have.insert_range(103..200);

        let mut want = RoaringBitmap::new();
        want.insert_range(0..200);

        let mut rng = StdRng::seed_from_u64(42);

        // Request minimum of 10, but only 3 consecutive missing items exist
        let missing = have.random_missing_run(&want, 10..=20, &mut rng);
        assert!(missing.is_empty());

        // Request minimum of 3 should work
        let missing = have.random_missing_run(&want, 3..=20, &mut rng);
        assert_eq!(missing.len(), 3);
        assert_eq!(missing, vec![100, 101, 102]);
    }

    #[test]
    fn test_random_missing_run_max_size_respected() {
        use rand::{rngs::StdRng, SeedableRng};

        let have = RoaringBitmap::new(); // Have nothing

        let mut want = RoaringBitmap::new();
        want.insert_range(0..1000);

        let mut rng = StdRng::seed_from_u64(42);
        let missing = have.random_missing_run(&want, 1..=10, &mut rng);

        // Should respect max_size
        assert!(!missing.is_empty());
        assert!(missing.len() <= 10);
    }

    #[test]
    fn test_random_missing_run_deterministic() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut have = RoaringBitmap::new();
        have.insert_range(0..50);

        let mut want = RoaringBitmap::new();
        want.insert_range(0..100);

        // Same seed should give same result
        let mut rng1 = StdRng::seed_from_u64(123);
        let mut rng2 = StdRng::seed_from_u64(123);

        let result1 = have.random_missing_run(&want, 1..=20, &mut rng1);
        let result2 = have.random_missing_run(&want, 1..=20, &mut rng2);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_random_missing_run_multiple_gaps() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut have = RoaringBitmap::new();
        have.insert_range(0..100);
        // Gap: 100..200
        have.insert_range(200..300);
        // Gap: 300..400
        have.insert_range(400..500);

        let mut want = RoaringBitmap::new();
        want.insert_range(0..500);

        // With different seeds, should sometimes pick different gaps
        let mut seen_starts: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for seed in 0..100 {
            let mut rng = StdRng::seed_from_u64(seed);
            let missing = have.random_missing_run(&want, 1..=10, &mut rng);
            if !missing.is_empty() {
                seen_starts.insert(missing[0]);
            }
        }

        // Should have seen starts in multiple gaps
        // Gap 1: 100..200, Gap 2: 300..400
        let in_gap1 = seen_starts.iter().any(|&v| (100..200).contains(&v));
        let in_gap2 = seen_starts.iter().any(|&v| (300..400).contains(&v));
        assert!(in_gap1 && in_gap2, "Should randomly select from different gaps");
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)] // Intentionally testing edge case
    fn test_random_missing_run_empty_range() {
        use rand::{rngs::StdRng, SeedableRng};

        let have = RoaringBitmap::new();
        let mut want = RoaringBitmap::new();
        want.insert_range(0..100);

        let mut rng = StdRng::seed_from_u64(42);

        // Invalid range: min > max
        let missing = have.random_missing_run(&want, 20..=10, &mut rng);
        assert!(missing.is_empty());

        // Zero size
        let missing = have.random_missing_run(&want, 0..=0, &mut rng);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_random_missing_run_spanning_containers() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut have = RoaringBitmap::new();
        have.insert_range(0..65530);

        let mut want = RoaringBitmap::new();
        want.insert_range(0..66000);

        // Missing: 65530..66000 (spans container boundary at 65536)
        let mut rng = StdRng::seed_from_u64(42);
        let missing = have.random_missing_run(&want, 1..=100, &mut rng);

        assert!(!missing.is_empty());
        for v in &missing {
            assert!(*v >= 65530);
            assert!(*v < 66000);
            assert!(!have.contains(*v));
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::RoaringBitmap>,
        }
    }
}
