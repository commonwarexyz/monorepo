//! Gap detection algorithm for sync operations.

use crate::mmr::Location;
use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet};

/// Find the next gap in operations that needs to be fetched.
/// Returns [start, end] inclusive range, or None if no gaps.
///
/// We assume that all outstanding requests will return `fetch_batch_size` operations,
/// but the resolver may return fewer. In that case, we'll fetch the remaining operations
/// in a subsequent request.
///
/// # Arguments
///
/// * `lower_bound` - The lower bound of the sync range (inclusive)
/// * `upper_bound` - The upper bound of the sync range (inclusive)
/// * `fetched_operations` - Map of start_loc -> operation count for fetched batches
/// * `outstanding_requests` - Set of start locations for outstanding requests
/// * `fetch_batch_size` - Expected size of each fetch batch
///
/// # Invariants
///
/// - All start locations in `fetched_operations` are in [lower_bound, upper_bound]
/// - All start locations in `outstanding_requests` are in [lower_bound, upper_bound]
/// - All operation counts in `fetched_operations` are > 0
pub fn find_next(
    lower_bound: Location,
    upper_bound: Location,
    fetched_operations: &BTreeMap<Location, u64>, // start_loc -> operation_count
    outstanding_requests: &BTreeSet<Location>,
    fetch_batch_size: NonZeroU64,
) -> Option<(Location, Location)> {
    if lower_bound > upper_bound {
        return None;
    }

    let mut current_covered_end: Option<Location> = None; // Nothing covered yet

    // Create iterators for both data structures (already sorted)
    let mut fetched_ops_iter = fetched_operations
        .iter()
        .map(|(&start_loc, &operation_count)| {
            let end_loc = start_loc.checked_add(operation_count - 1).unwrap();
            (start_loc, end_loc)
        })
        .peekable();

    let mut outstanding_reqs_iter = outstanding_requests
        .iter()
        .map(|&start_loc| {
            let end_loc = start_loc.checked_add(fetch_batch_size.get() - 1).unwrap();
            (start_loc, end_loc)
        })
        .peekable();

    // Merge process both iterators in sorted order
    loop {
        let (range_start, range_end) = match (fetched_ops_iter.peek(), outstanding_reqs_iter.peek())
        {
            (Some(&(f_start, _)), Some(&(o_start, _))) => {
                if f_start <= o_start {
                    fetched_ops_iter.next().unwrap()
                } else {
                    outstanding_reqs_iter.next().unwrap()
                }
            }
            (Some(_), None) => fetched_ops_iter.next().unwrap(),
            (None, Some(_)) => outstanding_reqs_iter.next().unwrap(),
            (None, None) => break,
        };

        // Check if there's a gap before this range
        match current_covered_end {
            None => {
                // This is the first range.
                if lower_bound < range_start {
                    // There's a gap between the lower bound and the start of the first range.
                    let gap_end = range_start - 1;
                    return Some((lower_bound, gap_end));
                }
            }
            Some(covered_end) => {
                // Check if there's a gap between current coverage and this range
                if covered_end + 1 < range_start {
                    let gap_start = covered_end + 1;
                    let gap_end = range_start - 1;
                    return Some((gap_start, gap_end));
                }
            }
        }

        // Update current covered end (merge overlapping ranges)
        current_covered_end = Some(match current_covered_end {
            None => range_end,
            Some(covered_end) => covered_end.max(range_end),
        });

        // Early exit if we've covered everything up to upper_bound
        if current_covered_end.unwrap() >= upper_bound {
            return None;
        }
    }

    // Check if there's a gap after all ranges
    match current_covered_end {
        None => {
            // No ranges at all - entire range is a gap
            Some((lower_bound, upper_bound))
        }
        Some(covered_end) => {
            // Check if there's a gap after the last covered location
            if covered_end < upper_bound {
                let gap_start = covered_end + 1;
                Some((gap_start, upper_bound))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Test case structure for find_next tests
    #[derive(Debug)]
    struct FindNextTestCase {
        lower_bound: u64,
        upper_bound: u64,
        fetched_ops: Vec<(u64, u64)>, // (start location, num_operations)
        requested_ops: Vec<u64>,
        fetch_batch_size: u64,
        expected: Option<(u64, u64)>,
    }

    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((0, 10)),
    }; "empty_state_full_range")]
    #[test_case(FindNextTestCase {
        lower_bound: 10,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: None,
    }; "invalid_bounds")]
    #[test_case(FindNextTestCase {
        lower_bound: 5,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((5, 5)),
    }; "zero_length_range")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![0, 3, 8],
        fetch_batch_size: 5,
        expected: None,
    }; "overlapping_outstanding_requests")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![8],
        fetch_batch_size: 5,
        expected: Some((0, 7)),
    }; "outstanding_request_beyond_upper_bound")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![0, 7],
        fetch_batch_size: 4,
        expected: Some((4, 6)),
    }; "outstanding_requests_only")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 1), (2, 1), (4, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((1, 1)),
    }; "single_ops_with_gaps")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 3)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((3, 10)),
    }; "multi_op_batch_gap_after")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 1), (1, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((2, 10)),
    }; "adjacent_single_ops")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 1), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1), (8, 1), (9, 1), (10, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: None,
    }; "no_gaps_all_covered_by_fetched_ops")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![2, 5, 8],
        fetch_batch_size: 1,
        expected: Some((0, 1)),
    }; "fetch_batch_size_one")]
    #[test_case(FindNextTestCase {
        lower_bound: 5,
        upper_bound: 10,
        fetched_ops: vec![(0, 8)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((8, 10)),
    }; "fetched_ops_starts_before_lower_bound")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 6,
        fetched_ops: vec![(4, 5)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((0, 3)),
    }; "fetched_ops_extends_beyond_upper_bound")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![2],
        fetch_batch_size: 100,
        expected: Some((0, 1)),
    }; "fetch_batch_size_larger_than_range")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 5), (8, 3)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((5, 7)),
    }; "coverage_exactly_reaches_upper_bound")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 15,
        fetched_ops: vec![(2, 3), (10, 2)],
        requested_ops: vec![6, 13],
        fetch_batch_size: 3,
        expected: Some((0, 1)),
    }; "mixed_coverage_gap_at_start")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 15,
        fetched_ops: vec![(0, 2), (8, 2)],
        requested_ops: vec![3, 12],
        fetch_batch_size: 4,
        expected: Some((2, 2)),
    }; "mixed_coverage_gap_in_middle")]
    #[test_case(FindNextTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(1, 2), (6, 2)],
        requested_ops: vec![3, 8],
        fetch_batch_size: 2,
        expected: Some((0, 0)),
    }; "mixed_coverage_interleaved_ranges")]
    fn test_find_next(test_case: FindNextTestCase) {
        let fetched_ops: BTreeMap<Location, u64> = test_case
            .fetched_ops
            .into_iter()
            .map(|(k, v)| (Location::new(k), v))
            .collect();
        let outstanding_requests: BTreeSet<Location> = test_case
            .requested_ops
            .into_iter()
            .map(Location::new)
            .collect();
        let result = find_next(
            Location::new(test_case.lower_bound),
            Location::new(test_case.upper_bound),
            &fetched_ops,
            &outstanding_requests,
            NonZeroU64::new(test_case.fetch_batch_size).unwrap(),
        );
        assert_eq!(
            result,
            test_case
                .expected
                .map(|(start, end)| (Location::new(start), Location::new(end)))
        );
    }
}
