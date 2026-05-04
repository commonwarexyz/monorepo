//! Run container for consecutive sequences.
//!
//! Stores values as run-length encoded ranges in a sorted `Vec<(u16, u16)>`. This is
//! efficient for data with many consecutive values, and is the most compact representation
//! for fully saturated containers.
//!
//! Each entry is an inclusive range `[start, end]`. The vector is kept sorted by `start`,
//! with all ranges disjoint and non-adjacent — adjacent and overlapping runs are
//! automatically merged during insertion. Lookups use binary search.

use super::bitmap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};

/// Maximum number of runs in a Run container.
///
/// The theoretical maximum is 32768 (alternating single values: 0, 2, 4, ..., 65534).
pub const MAX_RUNS: usize = 32768;

/// A container that stores values as run-length encoded ranges.
///
/// Each entry is an inclusive range `[start, end]`. Entries are sorted by `start` and
/// kept disjoint and non-adjacent: adjacent or overlapping runs are merged on insertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// Sorted vector of `(start, end)` inclusive ranges.
    ///
    /// Invariant: for any consecutive entries `(s1, e1)` and `(s2, e2)`, `e1 + 1 < s2`
    /// (non-overlapping AND non-adjacent — adjacent runs would have been merged).
    runs: Vec<(u16, u16)>,
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&bitmap::Bitmap> for Run {
    fn from(bitmap: &bitmap::Bitmap) -> Self {
        // Fast path for full bitmap.
        if bitmap.is_full() {
            return Self::full();
        }

        let mut runs: Vec<(u16, u16)> = Vec::new();
        let mut run_start: Option<u16> = None;

        for (word_idx, &word) in bitmap.words().iter().enumerate() {
            let base = (word_idx as u16) << 6;

            if word == 0 {
                // All zeros - end any active run.
                if let Some(s) = run_start {
                    runs.push((s, base - 1));
                    run_start = None;
                }
            } else if word == !0u64 {
                // All ones - extend or start run.
                if run_start.is_none() {
                    run_start = Some(base);
                }
            } else {
                // Mixed word - process bit by bit.
                let mut bit_idx = 0u16;
                while bit_idx < 64 {
                    let value = base | bit_idx;
                    let is_set = (word & (1u64 << bit_idx)) != 0;

                    match (is_set, run_start) {
                        (true, None) => run_start = Some(value),
                        (false, Some(s)) => {
                            runs.push((s, value - 1));
                            run_start = None;
                        }
                        _ => {}
                    }
                    bit_idx += 1;
                }
            }
        }

        // Handle final run.
        if let Some(s) = run_start {
            runs.push((s, u16::MAX));
        }

        Self { runs }
    }
}

impl Run {
    /// Creates an empty run container.
    pub const fn new() -> Self {
        Self { runs: Vec::new() }
    }

    /// Creates a run container representing a fully saturated container [0, 65535].
    pub fn full() -> Self {
        Self {
            runs: Vec::from([(0, u16::MAX)]),
        }
    }

    /// Returns the number of runs in the container.
    pub const fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Returns the cardinality (number of values) in the container.
    pub fn len(&self) -> u32 {
        self.runs
            .iter()
            .map(|&(start, end)| (end - start) as u32 + 1)
            .sum()
    }

    /// Returns whether the container is empty.
    pub const fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Checks if the container contains the given value.
    pub fn contains(&self, value: u16) -> bool {
        // partition_point returns the index of the first run whose start > value, so the
        // run at-or-before `value` is at index `p - 1` (if any).
        let p = self.runs.partition_point(|&(s, _)| s <= value);
        if p == 0 {
            return false;
        }
        let (_, end) = self.runs[p - 1];
        value <= end
    }

    /// Inserts a value into the container.
    ///
    /// Automatically merges with adjacent runs.
    /// Returns `true` if the value was newly inserted, `false` if it already existed.
    pub fn insert(&mut self, value: u16) -> bool {
        // p = first index with start > value. Run at p-1 (if any) is the candidate "prev"
        // run that may contain or be adjacent-from-below to `value`. Run at p (if any) is
        // the candidate "next" run that may be adjacent-from-above.
        let p = self.runs.partition_point(|&(s, _)| s <= value);

        let prev = (p > 0).then(|| (p - 1, self.runs[p - 1]));
        let next = (p < self.runs.len()).then(|| (p, self.runs[p]));

        match (prev, next) {
            (Some((p_idx, (_, p_end))), Some((n_idx, (n_start, n_end)))) => {
                if value <= p_end {
                    // Already inside prev.
                    return false;
                }
                let extends_prev = value == p_end + 1;
                let extends_next = value + 1 == n_start;
                match (extends_prev, extends_next) {
                    (true, true) => {
                        // Bridges prev and next: extend prev to absorb next, drop next.
                        self.runs[p_idx].1 = n_end;
                        self.runs.remove(n_idx);
                    }
                    (true, false) => self.runs[p_idx].1 = value,
                    (false, true) => self.runs[n_idx].0 = value,
                    (false, false) => self.runs.insert(p, (value, value)),
                }
            }
            (Some((p_idx, (_, p_end))), None) => {
                if value <= p_end {
                    return false;
                }
                if value == p_end + 1 {
                    self.runs[p_idx].1 = value;
                } else {
                    self.runs.push((value, value));
                }
            }
            (None, Some((n_idx, (n_start, _)))) => {
                if value + 1 == n_start {
                    self.runs[n_idx].0 = value;
                } else {
                    self.runs.insert(0, (value, value));
                }
            }
            (None, None) => self.runs.push((value, value)),
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

        // First overlapping/adjacent run: smallest index `i` where `runs[i].end + 1 >= start`,
        // i.e. the run is not entirely before [start, end_inclusive].
        // partition_point returns the first index where the predicate is false.
        let first = self.runs.partition_point(|&(_, e)| {
            // overflow-safe: e + 1 < start  <=>  e < start - 1 (when start > 0).
            // when start == 0 the predicate is always false, so first = 0.
            start > 0 && e < start - 1
        });

        // One past the last overlapping/adjacent run: smallest `i` where
        // `runs[i].start > end_inclusive + 1`. With overflow care for end_inclusive == MAX.
        let last_plus_one = self.runs.partition_point(|&(s, _)| {
            if end_inclusive == u16::MAX {
                // All subsequent runs satisfy s <= u16::MAX; predicate always true.
                true
            } else {
                s <= end_inclusive + 1
            }
        });

        let mut new_start = start;
        let mut new_end = end_inclusive;
        let mut existing_coverage = 0u32;

        for &(r_start, r_end) in &self.runs[first..last_plus_one] {
            new_start = new_start.min(r_start);
            new_end = new_end.max(r_end);
            let overlap_start = r_start.max(start);
            let overlap_end = r_end.min(end_inclusive);
            if overlap_start <= overlap_end {
                existing_coverage += (overlap_end - overlap_start) as u32 + 1;
            }
        }

        // Replace the slice [first..last_plus_one] with the merged run.
        // Splice handles the empty-slice case correctly: it inserts without removing.
        self.runs
            .splice(first..last_plus_one, [(new_start, new_end)]);

        range_size - existing_coverage
    }

    /// Returns an iterator over the values in sorted order.
    pub fn iter(&self) -> Iter<'_> {
        Iter::new(&self.runs, 0, bitmap::BITS)
    }

    /// Returns an iterator over values in `[start, end)`.
    pub fn iter_range(&self, start: u16, end: u32) -> Iter<'_> {
        Iter::new(&self.runs, start, end)
    }

    /// Returns an iterator over the runs as (start, end) pairs (inclusive).
    pub fn runs(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        self.runs.iter().copied()
    }

    /// Returns the minimum value in the container, if any.
    pub fn min(&self) -> Option<u16> {
        self.runs.first().map(|&(start, _)| start)
    }

    /// Returns the maximum value in the container, if any.
    pub fn max(&self) -> Option<u16> {
        self.runs.last().map(|&(_, end)| end)
    }

    /// Returns the approximate total memory footprint of this `Run` in bytes.
    ///
    /// Counts the inline `Vec` header plus the heap-allocated buffer at full `capacity`.
    /// Each entry costs [`VEC_BYTES_PER_RUN`] = 4 bytes (a `(u16, u16)` pair); `Vec` may
    /// over-allocate by up to ~2x due to its growth strategy. Available only for tests
    /// and the `analysis` feature; not compiled into production builds.
    #[cfg(any(test, feature = "analysis"))]
    pub const fn byte_size(&self) -> usize {
        core::mem::size_of::<Self>() + self.runs.capacity() * VEC_BYTES_PER_RUN
    }
}

/// Bytes per run in the heap-allocated `Vec<(u16, u16)>` buffer. Each run is two `u16`s.
/// This is exact (unlike a `BTreeMap`-based store, which has opaque per-entry overhead),
/// but the actual heap usage is `capacity * VEC_BYTES_PER_RUN`, where `Vec` may
/// over-allocate.
#[cfg(any(test, feature = "analysis"))]
const VEC_BYTES_PER_RUN: usize = core::mem::size_of::<(u16, u16)>();

impl Write for Run {
    fn write(&self, buf: &mut impl BufMut) {
        // Slice encoding writes the length varint followed by each (start, end) pair.
        self.runs.as_slice().write(buf);
    }
}

impl EncodeSize for Run {
    fn encode_size(&self) -> usize {
        // Length varint + 4 bytes per run (two u16s). Must match slice encoding which uses
        // usize for the length prefix.
        self.runs.len().encode_size() + self.runs.len() * 4
    }
}

impl Read for Run {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        // Read as Vec of (start, end) pairs with bounded count to prevent OOM.
        let runs = Vec::<(u16, u16)>::read_cfg(buf, &(RangeCfg::new(..=MAX_RUNS), ((), ())))?;

        let mut prev_end: Option<u16> = None;
        for &(start, end) in &runs {
            if start > end {
                return Err(CodecError::Invalid("Run", "start must be <= end"));
            }
            if let Some(p) = prev_end {
                if start <= p.saturating_add(1) {
                    return Err(CodecError::Invalid(
                        "Run",
                        "runs must be sorted, non-overlapping, and non-adjacent",
                    ));
                }
            }
            prev_end = Some(end);
        }

        Ok(Self { runs })
    }
}

/// Iterator over values in a run container.
pub struct Iter<'a> {
    runs_iter: core::slice::Iter<'a, (u16, u16)>,
    current_run: Option<(u16, u16)>,
    current_value: Option<u16>,
    end: u32,
}

impl<'a> Iter<'a> {
    fn new(runs: &'a [(u16, u16)], start: u16, end: u32) -> Self {
        let end = end.min(bitmap::BITS);
        let mut runs_iter = runs.iter();
        let (current_run, current_value) = next_run(&mut runs_iter, start, end);
        Self {
            runs_iter,
            current_run,
            current_value,
            end,
        }
    }
}

impl Iterator for Iter<'_> {
    type Item = u16;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (_, end) = self.current_run?;
            let value = self.current_value?;

            if value <= end && (value as u32) < self.end {
                // Advance to next value in current run.
                if value == u16::MAX {
                    self.current_value = None;
                } else {
                    self.current_value = Some(value + 1);
                }
                return Some(value);
            }

            // Move to next run.
            (self.current_run, self.current_value) = next_run(&mut self.runs_iter, 0, self.end);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Values left in the current run, if any. Between `next()` calls, the
        // current run can already be exhausted (`value > end`) while `runs_iter`
        // still holds further runs; counting must continue from `runs_iter` in
        // that state.
        let in_current = match (self.current_run, self.current_value) {
            (Some((_, run_end)), Some(value)) if value <= run_end => {
                let end = self.end.min(run_end as u32 + 1);
                end.saturating_sub(value as u32) as usize
            }
            _ => 0,
        };
        let in_remaining: usize = self
            .runs_iter
            .clone()
            .take_while(|&&(s, _)| (s as u32) < self.end)
            .map(|&(s, e)| {
                let end = self.end.min(e as u32 + 1);
                end.saturating_sub(s as u32) as usize
            })
            .sum();
        let remaining = in_current + in_remaining;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Iter<'_> {}

fn next_run(
    runs_iter: &mut core::slice::Iter<'_, (u16, u16)>,
    start: u16,
    end: u32,
) -> (Option<(u16, u16)>, Option<u16>) {
    for &(run_start, run_end) in runs_iter {
        if run_end < start {
            continue;
        }
        if (run_start as u32) >= end {
            break;
        }
        return (Some((run_start, run_end)), Some(run_start.max(start)));
    }
    (None, None)
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Run {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let num_runs = u.int_in_range(0..=MAX_RUNS)?;
        let mut runs: Vec<(u16, u16)> = Vec::new();
        let mut prev_end: Option<u16> = None;

        for _ in 0..num_runs {
            let min_start = prev_end.map_or(0, |end| end as u32 + 2);
            if min_start > u16::MAX as u32 {
                break;
            }

            let start = u.int_in_range(min_start..=u16::MAX as u32)? as u16;
            let end = u.int_in_range(start..=u16::MAX)?;
            runs.push((start, end));
            prev_end = Some(end);
        }

        Ok(Self { runs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_empty() {
        let container = Run::new();
        assert!(container.is_empty());
        assert_eq!(container.len(), 0);
        assert_eq!(container.run_count(), 0);
    }

    #[test]
    fn test_full() {
        let container = Run::full();
        assert!(!container.is_empty());
        assert_eq!(container.len(), 65536);
        assert_eq!(container.run_count(), 1);
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
    fn test_iter_size_hint_between_runs() {
        let mut container = Run::new();
        container.insert(1);
        container.insert(3);
        container.insert(5);
        // Confirm the container holds three single-value runs.
        assert_eq!(
            container.runs().collect::<Vec<_>>(),
            vec![(1, 1), (3, 3), (5, 5)]
        );

        let mut iter = container.iter();
        assert_eq!(iter.len(), 3);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.len(), 2);

        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.len(), 1);

        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.len(), 0);

        assert_eq!(iter.next(), None);
        assert_eq!(iter.len(), 0);
    }

    #[test]
    fn test_iter_size_hint_within_run() {
        let mut container = Run::new();
        container.insert_range(10, 14); // run (10, 13)
        container.insert_range(20, 23); // run (20, 22)

        let mut iter = container.iter();
        assert_eq!(iter.len(), 4 + 3); // 7 total

        assert_eq!(iter.next(), Some(10));
        assert_eq!(iter.len(), 6);

        assert_eq!(iter.next(), Some(11));
        assert_eq!(iter.len(), 5);
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
        let bm = bitmap::Bitmap::from(words);
        let run = Run::from(&bm);

        assert_eq!(run.run_count(), 1);
        assert_eq!(run.len(), 65536);
    }

    #[test]
    fn test_byte_size_empty() {
        let r = Run::new();
        assert_eq!(r.byte_size(), core::mem::size_of::<Run>());
    }

    #[test]
    fn test_byte_size_grows_per_run() {
        let mut r = Run::new();
        let s0 = r.byte_size();
        // Insert 5 non-adjacent runs (gaps prevent merging).
        for i in 0..5 {
            let start = i * 100;
            r.insert_range(start, start + 50);
        }
        let s5 = r.byte_size();
        // With Vec storage, capacity may overshoot len due to doubling growth.
        // 5 entries × 4 bytes = 20 bytes minimum; capacity of 8 (next power of 2) × 4 = 32 max.
        let entry_bytes = 5 * super::VEC_BYTES_PER_RUN;
        assert!(s5 - s0 >= entry_bytes, "{} < {}", s5 - s0, entry_bytes);
        assert!(
            s5 - s0 <= 2 * entry_bytes,
            "{} > {}",
            s5 - s0,
            2 * entry_bytes
        );
    }

    #[test]
    fn test_byte_size_full_container() {
        // A fully-saturated Run is just one merged run [0, 65535] with capacity 1.
        let r = Run::full();
        assert_eq!(
            r.byte_size(),
            core::mem::size_of::<Run>() + super::VEC_BYTES_PER_RUN
        );
    }

    // -----------------------------------------------------------------------------
    // Codec validation: the Read impl must reject `(start, end)` sequences that
    // violate the sorted-and-disjoint invariant. The runtime API maintains this
    // invariant by construction, so these only fire for malformed peer-supplied
    // bytes — exactly the case fuzzing and these tests exist for.
    // -----------------------------------------------------------------------------

    #[test]
    fn test_codec_rejects_overlapping_runs() {
        // Second run starts (5) within the first's range (0..=10).
        use bytes::BytesMut;
        use commonware_codec::{Decode, Write};

        let runs: Vec<(u16, u16)> = vec![(0, 10), (5, 15)];
        let mut buf = BytesMut::new();
        runs.as_slice().write(&mut buf);

        let result = Run::decode_cfg(buf.freeze(), &());
        assert!(
            matches!(
                result,
                Err(CodecError::Invalid("Run", msg))
                    if msg.contains("non-overlapping")
            ),
            "expected Invalid(\"Run\", ...) error, got {result:?}"
        );
    }

    #[test]
    fn test_codec_rejects_adjacent_runs() {
        // Second run is adjacent (start == prev_end + 1). A correctly-encoded Run
        // would have merged these into a single run.
        use bytes::BytesMut;
        use commonware_codec::{Decode, Write};

        let runs: Vec<(u16, u16)> = vec![(0, 10), (11, 20)];
        let mut buf = BytesMut::new();
        runs.as_slice().write(&mut buf);

        let result = Run::decode_cfg(buf.freeze(), &());
        assert!(
            matches!(
                result,
                Err(CodecError::Invalid("Run", msg))
                    if msg.contains("non-adjacent")
            ),
            "expected Invalid(\"Run\", ...) error, got {result:?}"
        );
    }

    #[test]
    fn test_codec_rejects_out_of_order_runs() {
        // Second run starts strictly before the first ends — same code path as
        // the overlap check (`start <= prev_end + 1`), exercised via reverse order.
        use bytes::BytesMut;
        use commonware_codec::{Decode, Write};

        let runs: Vec<(u16, u16)> = vec![(20, 30), (0, 10)];
        let mut buf = BytesMut::new();
        runs.as_slice().write(&mut buf);

        let result = Run::decode_cfg(buf.freeze(), &());
        assert!(
            matches!(result, Err(CodecError::Invalid("Run", _))),
            "expected Invalid(\"Run\", ...) error, got {result:?}"
        );
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_arbitrary_can_generate_run_starting_at_zero() {
        let mut u = arbitrary::Unstructured::new(&[0, 1, 0, 0, 0, 5]);
        let run = <Run as arbitrary::Arbitrary>::arbitrary(&mut u).unwrap();

        assert_eq!(run.runs().collect::<Vec<_>>(), vec![(0, 5)]);
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_arbitrary_can_generate_trailing_max_singleton() {
        let mut u = arbitrary::Unstructured::new(&[0, 2, 0, 0, 0xff, 0xfd]);
        let run = <Run as arbitrary::Arbitrary>::arbitrary(&mut u).unwrap();

        assert_eq!(
            run.runs().collect::<Vec<_>>(),
            vec![(0, u16::MAX - 2), (u16::MAX, u16::MAX)]
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<super::Run>,
        }
    }
}
