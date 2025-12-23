//! Gap detection algorithm for sync operations.

use crate::mmr::Location;
use core::{num::NonZeroU64, ops::Range};
use std::collections::{BTreeMap, BTreeSet};

/// Find the next gap in operations that needs to be fetched.
/// Returns a Range of operations to fetch, or None if no gaps.
///
/// We assume that all outstanding requests will return `fetch_batch_size` operations,
/// but the resolver may return fewer. In that case, we'll fetch the remaining operations
/// in a subsequent request.
///
/// # Arguments
///
/// * `range` - The sync range
/// * `fetched_operations` - Map of start_loc -> operation count for fetched batches
/// * `outstanding_requests` - Set of start locations for outstanding requests
/// * `fetch_batch_size` - Expected size of each fetch batch
///
/// # Invariants
///
/// - All start locations in `fetched_operations` are in `range`
/// - All start locations in `outstanding_requests` are in `range`
/// - All operation counts in `fetched_operations` are > 0
pub fn find_next(
    range: Range<Location>,
    fetched_operations: &BTreeMap<Location, u64>, // start_loc -> operation_count
    outstanding_requests: &BTreeSet<Location>,
    fetch_batch_size: NonZeroU64,
) -> Option<Range<Location>> {
    if range.is_empty() {
        return None;
    }

    // Track the next uncovered location (exclusive end of covered range)
    let mut next_uncovered: Location = range.start;

    // Create iterators for both data structures (already sorted)
    let mut fetched_ops_iter = fetched_operations
        .iter()
        .map(|(&start_loc, &operation_count)| {
            let end_loc = start_loc.checked_add(operation_count).unwrap();
            start_loc..end_loc
        })
        .peekable();

    let mut outstanding_reqs_iter = outstanding_requests
        .iter()
        .map(|&start_loc| {
            let end_loc = start_loc.checked_add(fetch_batch_size.get()).unwrap();
            start_loc..end_loc
        })
        .peekable();

    // Merge process both iterators in sorted order
    loop {
        let covered_range = match (fetched_ops_iter.peek(), outstanding_reqs_iter.peek()) {
            (Some(f_range), Some(o_range)) => {
                if f_range.start <= o_range.start {
                    fetched_ops_iter.next().unwrap()
                } else {
                    outstanding_reqs_iter.next().unwrap()
                }
            }
            (Some(_), None) => fetched_ops_iter.next().unwrap(),
            (None, Some(_)) => outstanding_reqs_iter.next().unwrap(),
            (None, None) => break,
        };

        // Check if there's a gap before this covered range
        if next_uncovered < covered_range.start {
            // Found a gap between next_uncovered and the start of this range
            return Some(next_uncovered..covered_range.start);
        }

        // Update next_uncovered to the end of this covered range (or keep current if overlapping)
        next_uncovered = next_uncovered.max(covered_range.end);

        // Early exit if we've covered everything up to range.end
        if next_uncovered >= range.end {
            return None;
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
    use rstest::rstest;

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
        let fetched_ops: BTreeMap<Location, u64> = test_case
            .fetched_ops
            .into_iter()
            .map(|(k, v)| (Location::new_unchecked(k), v))
            .collect();
        let outstanding_requests: BTreeSet<Location> = test_case
            .requested_ops
            .into_iter()
            .map(Location::new_unchecked)
            .collect();
        let result = find_next(
            Location::new_unchecked(test_case.lower_bound)
                ..Location::new_unchecked(test_case.upper_bound),
            &fetched_ops,
            &outstanding_requests,
            NonZeroU64::new(test_case.fetch_batch_size).unwrap(),
        );
        assert_eq!(
            result,
            test_case
                .expected
                .map(|range| Location::new_unchecked(range.start)
                    ..Location::new_unchecked(range.end))
        );
    }
}
