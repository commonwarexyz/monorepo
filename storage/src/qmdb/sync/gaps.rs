//! Gap detection algorithm for sync operations.

use crate::merkle::{Family, Location};
use core::ops::Range;

mod step;

use step::{Step, scan_step};

/// Find the next gap in operations that needs to be fetched.
/// Returns a Range of operations to fetch, or None if no gaps.
/// Empty coverage ranges are ignored, and returned gaps are bounded by `range`.
///
/// Outstanding request ranges describe their maximum responses, but the source may return fewer
/// operations. In that case, we'll fetch the remaining operations in a subsequent request.
///
/// # Arguments
///
/// * `range` - The sync range
/// * `fetched_ranges` - Ranges of fetched batches, in ascending order of start location
/// * `outstanding_ranges` - Maximum ranges of outstanding requests, in ascending order of start location
pub fn find_next<F: Family>(
    range: Range<Location<F>>,
    fetched_ranges: impl IntoIterator<Item = Range<Location<F>>>,
    outstanding_ranges: impl IntoIterator<Item = Range<Location<F>>>,
) -> Option<Range<Location<F>>> {
    if range.is_empty() {
        return None;
    }

    // Track the next uncovered location (exclusive end of covered range)
    let mut next_uncovered: Location<F> = range.start;

    // Create iterators for both sets of ranges (already sorted)
    let mut fetched_ranges_iter = fetched_ranges.into_iter().peekable();
    let mut outstanding_ranges_iter = outstanding_ranges.into_iter().peekable();

    // Merge process both iterators in sorted order
    loop {
        let covered_range = match (fetched_ranges_iter.peek(), outstanding_ranges_iter.peek()) {
            (Some(f_range), Some(o_range)) => {
                if f_range.start <= o_range.start {
                    fetched_ranges_iter.next().unwrap()
                } else {
                    outstanding_ranges_iter.next().unwrap()
                }
            }
            (Some(_), None) => fetched_ranges_iter.next().unwrap(),
            (None, Some(_)) => outstanding_ranges_iter.next().unwrap(),
            (None, None) => break,
        };

        match scan_step(
            next_uncovered.as_u64(),
            range.end.as_u64(),
            covered_range.start.as_u64(),
            covered_range.end.as_u64(),
        ) {
            Step::Gap(end) => return Some(next_uncovered..Location::new(end)),
            Step::Advance(frontier) => next_uncovered = Location::new(frontier),
            Step::Complete => return None,
        }
    }

    // Check if there's a gap after all covered ranges
    if next_uncovered < range.end {
        // There's a gap from next_uncovered to the end of the range
        Some(next_uncovered..range.end)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr::Family as MmrFamily;
    use rstest::rstest;
    use std::num::NonZeroU64;

    /// Test case structure for find_next tests
    #[derive(Debug)]
    struct FindNextTestCase {
        lower_bound: u64,
        upper_bound: u64,
        fetched_ops: Vec<(u64, u64)>, // (start location, num_operations)
        requested_ops: Vec<u64>,
        fetch_batch_size: u64,
        expected: Option<std::ops::Range<u64>>,
    }

    #[rstest]
    #[case::empty_state_full_range(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(0..11),
    })]
    #[case::invalid_bounds(FindNextTestCase {
        lower_bound: 10,
        upper_bound: 6,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: None,
    })]
    #[case::zero_length_range(FindNextTestCase {
        lower_bound: 5,
        upper_bound: 6,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(5..6),
    })]
    #[case::overlapping_outstanding_requests(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![],
        requested_ops: vec![0, 3, 8],
        fetch_batch_size: 5,
        expected: None,
    })]
    #[case::outstanding_request_beyond_upper_bound(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![],
        requested_ops: vec![8],
        fetch_batch_size: 5,
        expected: Some(0..8),
    })]
    #[case::outstanding_requests_only(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![],
        requested_ops: vec![0, 7],
        fetch_batch_size: 4,
        expected: Some(4..7),
    })]
    #[case::fetched_range_starts_after_upper_bound(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 5,
        fetched_ops: vec![(7, 2)],
        requested_ops: vec![],
        fetch_batch_size: 2,
        expected: Some(0..5),
    })]
    #[case::outstanding_range_starts_after_upper_bound(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![7],
        fetch_batch_size: 2,
        expected: Some(0..5),
    })]
    #[case::empty_fetched_range(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 5,
        fetched_ops: vec![(2, 0), (4, 1)],
        requested_ops: vec![],
        fetch_batch_size: 2,
        expected: Some(0..4),
    })]
    #[case::empty_outstanding_range(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 5,
        fetched_ops: vec![(4, 1)],
        requested_ops: vec![2],
        fetch_batch_size: 0,
        expected: Some(0..4),
    })]
    #[case::single_ops_with_gaps(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![(0, 1), (2, 1), (4, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(1..2),
    })]
    #[case::multi_op_batch_gap_after(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![(0, 3)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(3..11),
    })]
    #[case::adjacent_single_ops(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![(0, 1), (1, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(2..11),
    })]
    #[case::no_gaps_all_covered_by_fetched_ops(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![(0, 1), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1), (8, 1), (9, 1), (10, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: None,
    })]
    #[case::fetch_batch_size_one(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![],
        requested_ops: vec![2, 5, 8],
        fetch_batch_size: 1,
        expected: Some(0..2),
    })]
    #[case::fetched_ops_starts_before_lower_bound(FindNextTestCase {
        lower_bound: 5,
        upper_bound: 11,
        fetched_ops: vec![(0, 8)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(8..11),
    })]
    #[case::fetched_ops_extends_beyond_upper_bound(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 7,
        fetched_ops: vec![(4, 5)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(0..4),
    })]
    #[case::fetch_batch_size_larger_than_range(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 6,
        fetched_ops: vec![],
        requested_ops: vec![2],
        fetch_batch_size: 100,
        expected: Some(0..2),
    })]
    #[case::coverage_exactly_reaches_upper_bound(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![(0, 5), (8, 3)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some(5..8),
    })]
    #[case::mixed_coverage_gap_at_start(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 16,
        fetched_ops: vec![(2, 3), (10, 2)],
        requested_ops: vec![6, 13],
        fetch_batch_size: 3,
        expected: Some(0..2),
    })]
    #[case::mixed_coverage_gap_in_middle(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 16,
        fetched_ops: vec![(0, 2), (8, 2)],
        requested_ops: vec![3, 12],
        fetch_batch_size: 4,
        expected: Some(2..3),
    })]
    #[case::mixed_coverage_interleaved_ranges(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 11,
        fetched_ops: vec![(1, 2), (6, 2)],
        requested_ops: vec![3, 8],
        fetch_batch_size: 2,
        expected: Some(0..1),
    })]
    fn test_find_next(#[case] test_case: FindNextTestCase) {
        let fetched_ranges = test_case
            .fetched_ops
            .iter()
            .map(|&(start, count)| Location::<MmrFamily>::new(start)..Location::new(start + count));
        let request_size = test_case.fetch_batch_size;
        let outstanding_ranges: Vec<Range<Location<MmrFamily>>> = test_case
            .requested_ops
            .into_iter()
            .map(|start| Location::new(start)..Location::new(start + request_size))
            .collect();
        let result = find_next(
            Location::new(test_case.lower_bound)..Location::new(test_case.upper_bound),
            fetched_ranges,
            outstanding_ranges,
        );
        assert_eq!(
            result,
            test_case
                .expected
                .map(|range| Location::new(range.start)..Location::new(range.end))
        );
    }

    fn covered_at(point: u64, ranges: &[Range<u64>]) -> bool {
        ranges
            .iter()
            .any(|range| range.start < range.end && range.contains(&point))
    }

    fn oracle(
        target: Range<u64>,
        fetched: &[Range<u64>],
        outstanding: &[Range<u64>],
    ) -> Option<Range<u64>> {
        if target.start >= target.end {
            return None;
        }

        let is_covered = |point| covered_at(point, fetched) || covered_at(point, outstanding);
        let gap_start = (target.start..target.end).find(|&point| !is_covered(point))?;
        let gap_end = (gap_start..target.end)
            .find(|&point| is_covered(point))
            .unwrap_or(target.end);
        Some(gap_start..gap_end)
    }

    fn assert_maximal_gap(
        target: Range<u64>,
        fetched: &[Range<u64>],
        outstanding: &[Range<u64>],
        actual: Option<Range<u64>>,
    ) {
        let is_covered = |point| covered_at(point, fetched) || covered_at(point, outstanding);
        assert_eq!(actual, oracle(target.clone(), fetched, outstanding));

        let Some(gap) = actual else {
            assert!((target.start..target.end).all(is_covered));
            return;
        };

        assert!(target.start <= gap.start);
        assert!(gap.start < gap.end);
        assert!(gap.end <= target.end);
        assert!((target.start..gap.start).all(&is_covered));
        assert!((gap.clone()).all(|point| !is_covered(point)));
        assert!(gap.end == target.end || is_covered(gap.end));

        let size = gap.end.checked_sub(gap.start).unwrap();
        assert!(NonZeroU64::try_from(size).is_ok());
    }

    fn sorted_range_lists() -> Vec<Vec<Range<u64>>> {
        let ranges: Vec<_> = (0..=5)
            .flat_map(|start| (0..=5).map(move |end| start..end))
            .collect();
        let mut lists = vec![Vec::new()];
        for first in &ranges {
            lists.push(vec![first.clone()]);
            for second in ranges.iter().filter(|second| second.start >= first.start) {
                lists.push(vec![first.clone(), second.clone()]);
            }
        }
        lists
    }

    fn assert_engine_accepts_gap<F: Family>(gap: &Range<Location<F>>) {
        let size = *gap.end.checked_sub(*gap.start).unwrap();
        assert!(NonZeroU64::try_from(size).is_ok());
    }

    #[test]
    fn exhaustive_sorted_range_pairs_match_oracle() {
        let target = 1..4;
        let lists = sorted_range_lists();
        assert_eq!(lists.len(), 793);
        for fetched in &lists {
            for outstanding in &lists {
                let actual = find_next(
                    Location::<MmrFamily>::new(target.start)..Location::new(target.end),
                    fetched
                        .iter()
                        .map(|range| Location::new(range.start)..Location::new(range.end)),
                    outstanding
                        .iter()
                        .map(|range| Location::new(range.start)..Location::new(range.end)),
                );
                if let Some(gap) = &actual {
                    assert_engine_accepts_gap(gap);
                }
                let actual = actual.map(|range| range.start.as_u64()..range.end.as_u64());
                assert_maximal_gap(target.clone(), fetched, outstanding, actual);
            }
        }

        assert_eq!(
            find_next::<MmrFamily>(
                Location::new(3)..Location::new(3),
                [Location::new(0)..Location::new(5)],
                [],
            ),
            None
        );
        assert_eq!(
            find_next::<MmrFamily>(
                Location::new(4)..Location::new(3),
                [],
                [Location::new(0)..Location::new(5)],
            ),
            None
        );
    }

    fn assert_family_maximum<F: Family>() {
        let end = F::MAX_LEAVES.as_u64();
        let target = end - 3..end;
        let fetched = end - 3..end - 2;
        let outstanding = end - 1..end;
        let actual = find_next(
            Location::<F>::new(target.start)..Location::new(target.end),
            core::iter::once(Location::new(fetched.start)..Location::new(fetched.end)),
            core::iter::once(Location::new(outstanding.start)..Location::new(outstanding.end)),
        );
        if let Some(gap) = &actual {
            assert_engine_accepts_gap(gap);
        }
        let actual = actual.map(|range| range.start.as_u64()..range.end.as_u64());
        assert_maximal_gap(
            target,
            core::slice::from_ref(&fetched),
            core::slice::from_ref(&outstanding),
            actual,
        );
    }

    #[test]
    fn family_maximum_locations() {
        assert_family_maximum::<crate::merkle::mmr::Family>();
        assert_family_maximum::<crate::merkle::mmb::Family>();
    }

    #[test]
    fn scalar_step_u64_maximum_boundaries() {
        assert_eq!(
            scan_step(u64::MAX - 2, u64::MAX, u64::MAX - 1, u64::MAX),
            Step::Gap(u64::MAX - 1)
        );
        assert_eq!(
            scan_step(u64::MAX - 2, u64::MAX, u64::MAX - 2, u64::MAX - 1),
            Step::Advance(u64::MAX - 1)
        );
        assert_eq!(
            scan_step(u64::MAX - 2, u64::MAX, u64::MAX - 2, u64::MAX),
            Step::Complete
        );
        assert_eq!(
            scan_step(u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX),
            Step::Advance(u64::MAX - 1)
        );
        assert_eq!(
            scan_step(u64::MAX - 1, u64::MAX, u64::MAX, 0),
            Step::Advance(u64::MAX - 1)
        );
    }
}
