//! A collection that manages disjoint, inclusive ranges `[start, end]`.
//!
//! # Design
//!
//! - Ranges are stored in ascending order of their start points.
//! - Ranges are disjoint; there are no overlapping ranges.
//! - Adjacent ranges are merged (e.g., inserting `5` into `[0,4]` and then inserting `4` results in `[0,5]`).
//! - Each key in the [BTreeMap] represents the inclusive start of a range, and its
//!   corresponding value represents the inclusive end of that range.

use std::collections::BTreeMap;

/// A collection that manages disjoint, inclusive ranges `[start, end]`.
#[derive(Debug, Default, PartialEq)]
pub struct RMap {
    ranges: BTreeMap<u64, u64>,
}

impl RMap {
    /// Creates a new, empty [RMap].
    pub fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    /// Inserts a value into the [RMap].
    ///
    /// # Behavior
    ///
    /// - Create a new range `[value, value]` if `value` is isolated.
    /// - Extend an existing range if `value` is adjacent to it (e.g., inserting `5` into `[1, 4]` results in `[1, 5]`).
    /// - Merge two ranges if `value` bridges them (e.g., inserting `3` into a map with `[1, 2]` and `[4, 5]` results in `[1, 5]`).
    /// - Do nothing if `value` is already covered by an existing range.
    ///
    /// # Complexity
    ///
    /// The time complexity is typically O(log N) due to `BTreeMap` lookups and insertions,
    /// where N is the number of disjoint ranges in the map. In scenarios involving merges,
    /// a few extra map operations (removals, insertions) might occur, but the overall
    /// complexity remains logarithmic.
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_storage::rmap::RMap;
    ///
    /// let mut map = RMap::new();
    /// map.insert(1); // Map: [1, 1]
    /// assert_eq!(map.next_gap(0), (None, Some(1)));
    /// map.insert(3); // Map: [1, 1], [3, 3]
    /// assert_eq!(map.next_gap(1), (Some(1), Some(3)));
    /// map.insert(2); // Map: [1, 3]
    /// map.insert(0); // Map: [0, 3]
    /// map.insert(5); // Map: [0, 3], [5, 5]
    /// map.insert(4); // Map: [0, 5]
    /// assert_eq!(map.get(&3), Some((0, 5)));
    /// ```
    pub fn insert(&mut self, value: u64) {
        let prev_opt = self
            .ranges
            .range(..=value)
            .next_back()
            .map(|(&s, &e)| (s, e));
        let next_opt = match value {
            u64::MAX => None,
            _ => self.ranges.range(value + 1..).next().map(|(&s, &e)| (s, e)),
        };

        match (prev_opt, next_opt) {
            (Some((p_start, p_end)), Some((n_start, n_end))) => {
                if value <= p_end {
                    // Value is within prev range
                    return;
                }
                if value == p_end + 1 && value + 1 == n_start {
                    // Value bridges prev and next
                    self.ranges.remove(&p_start);
                    self.ranges.remove(&n_start);
                    self.ranges.insert(p_start, n_end);
                } else if value == p_end + 1 {
                    // Value is adjacent to prev's end
                    self.ranges.remove(&p_start);
                    self.ranges.insert(p_start, value);
                } else if value + 1 == n_start {
                    // Value is adjacent to next's start
                    self.ranges.remove(&n_start);
                    self.ranges.insert(value, n_end);
                } else {
                    // New isolated range
                    self.ranges.insert(value, value);
                }
            }
            (Some((p_start, p_end)), None) => {
                if value <= p_end {
                    // Value is within prev range
                    return;
                }
                if value == p_end + 1 {
                    // Value is adjacent to prev's end
                    self.ranges.remove(&p_start);
                    self.ranges.insert(p_start, value);
                } else {
                    // New isolated range
                    self.ranges.insert(value, value);
                }
            }
            (None, Some((n_start, n_end))) => {
                if value + 1 == n_start {
                    // Value is adjacent to next's start
                    self.ranges.remove(&n_start);
                    self.ranges.insert(value, n_end);
                } else {
                    // New isolated range
                    self.ranges.insert(value, value);
                }
            }
            (None, None) => {
                // Map is empty or value is isolated
                self.ranges.insert(value, value);
            }
        }
    }

    /// Returns the range that contains the given value.
    pub fn get(&self, value: &u64) -> Option<(u64, u64)> {
        if let Some((&start, &end)) = self.ranges.range(..=value).next_back() {
            if *value <= end {
                return Some((start, end));
            }
        }
        None
    }

    /// Removes a range `[start, end]` (inclusive) from the [RMap].
    ///
    /// # Behavior
    ///
    /// - If the removal range completely covers an existing range, the existing range is removed.
    /// - If the removal range is a sub-range of an existing range, the existing range may be split
    ///   into two (e.g., removing `[3, 4]` from `[1, 6]` results in `[1, 2]` and `[5, 6]`).
    /// - If the removal range overlaps with the start or end of an existing range, the existing
    ///   range is truncated (e.g., removing `[1, 2]` from `[1, 5]` results in `[3, 5]`).
    /// - If the removal range covers multiple existing ranges, all such ranges are affected or removed.
    /// - If `start > end`, the method does nothing.
    /// - If the removal range does not overlap with any existing range, the map remains unchanged.
    ///
    /// # Complexity
    ///
    /// The time complexity is O(M + K log N), where N is the total number of ranges in the map,
    /// M is the number of ranges that overlap with the removal range (iterate part), and K is the number of
    /// new ranges created or ranges removed (at most 2 additions and M removals).
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_storage::rmap::RMap;
    ///
    /// let mut map = RMap::new();
    /// map.insert(1); map.insert(2); map.insert(3); // Map: [1, 3]
    /// map.insert(5); map.insert(6); map.insert(7); // Map: [1, 3], [5, 7]
    ///
    /// map.remove(2, 6); // Results in [1, 1], [7, 7]
    /// assert_eq!(map.get(&1), Some((1, 1)));
    /// assert_eq!(map.get(&2), None);
    /// assert_eq!(map.get(&6), None);
    /// assert_eq!(map.get(&7), Some((7, 7)));
    /// ```
    pub fn remove(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }

        // Iterate over ranges that could possibly overlap with the removal range `[start, end]`.
        // A range (r_start, r_end) overlaps if r_start <= end AND r_end >= start.
        //
        // We optimize the BTreeMap iteration by only looking at ranges whose start (r_start)
        // is less than or equal to the `end` of the removal range. If r_start > end,
        // then (r_start, r_end) cannot overlap with [start, end].
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();

        for (&r_start, &r_end) in self.ranges.iter() {
            // Case 1: No overlap
            if r_end < start || r_start > end {
                continue;
            }

            // Case 2: Removal range completely covers current range
            if start <= r_start && end >= r_end {
                to_remove.push(r_start);
                continue;
            }

            // Case 3: Current range completely covers removal range (split)
            if r_start < start && r_end > end {
                to_remove.push(r_start);
                to_add.push((r_start, start - 1));
                to_add.push((end + 1, r_end));
                continue;
            }

            // Case 4: Removal range overlaps start of current range
            if start <= r_start && end < r_end {
                // and end >= r_start implied by not Case 1
                to_remove.push(r_start);
                to_add.push((end + 1, r_end));
                continue;
            }

            // Case 5: Removal range overlaps end of current range
            if start > r_start && end >= r_end {
                // and start <= r_end implied by not Case 1
                to_remove.push(r_start);
                to_add.push((r_start, start - 1));
                continue;
            }
        }

        // Remove anything no longer needed.
        for r_start in to_remove {
            self.ranges.remove(&r_start);
        }

        // Add anything that is now needed.
        for (a_start, a_end) in to_add {
            if a_start <= a_end {
                // Ensure valid range before adding
                self.ranges.insert(a_start, a_end);
            }
        }
    }

    /// Returns an iterator over the ranges `(start, end)` in the [RMap].
    ///
    /// The ranges are yielded in ascending order of their start points.
    /// Each tuple represents an inclusive range `[start, end]`.
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_storage::rmap::RMap;
    ///
    /// let mut map = RMap::new();
    /// map.insert(0); map.insert(1); // Map: [0, 1]
    /// map.insert(3); map.insert(4); // Map: [0, 1], [3, 4]
    ///
    /// let mut iter = map.iter();
    /// assert_eq!(iter.next(), Some((&0, &1)));
    /// assert_eq!(iter.next(), Some((&3, &4)));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &u64)> {
        self.ranges.iter()
    }

    /// Finds the end of the range containing `value` and the start of the
    /// range succeeding `value`. This method is useful for identifying gaps around a given point.
    ///
    /// # Behavior
    ///
    /// - If `value` falls within an existing range `[r_start, r_end]`, `current_range_end` will be `Some(r_end)`.
    /// - If `value` falls in a gap between two ranges `[..., prev_end]` and `[next_start, ...]`,
    ///   `current_range_end` will be `None` and `next_range_start` will be `Some(next_start)`.
    /// - If `value` is before all ranges in the map, `current_range_end` will be `None`.
    /// - If `value` is after all ranges in the map (or within the last range), `next_range_start` will be `None`.
    /// - If the map is empty, both will be `None`.
    ///
    /// # Arguments
    ///
    /// * `value`: The `u64` value to query around.
    ///
    /// # Returns
    ///
    /// A tuple `(Option<u64>, Option<u64>)` where:
    /// - The first element (`current_range_end`) is `Some(end)` of the range that contains `value`. It's `None` if `value` is before all ranges, the map is empty, or `value` is not in any range.
    /// - The second element (`next_range_start`) is `Some(start)` of the first range that begins strictly after `value`. It's `None` if no range starts after `value` or the map is empty.
    ///
    /// # Complexity
    ///
    /// O(log N) due to `BTreeMap::range` lookups, where N is the number of ranges.
    ///
    /// # Example
    ///
    /// ```
    /// use commonware_storage::rmap::RMap;
    ///
    /// let mut map = RMap::new();
    /// map.insert(1); map.insert(2); // Map: [1, 2]
    /// map.insert(5); map.insert(6); // Map: [1, 2], [5, 6]
    ///
    /// assert_eq!(map.next_gap(0), (None, Some(1)));        // Before all ranges
    /// assert_eq!(map.next_gap(1), (Some(2), Some(5)));     // Value is at the start of a range
    /// assert_eq!(map.next_gap(2), (Some(2), Some(5)));     // Value is at the end of a range
    /// assert_eq!(map.next_gap(3), (None, Some(5)));     // Value is in a gap
    /// assert_eq!(map.next_gap(5), (Some(6), None));        // Value is at the start of the last range
    /// assert_eq!(map.next_gap(6), (Some(6), None));        // Value is at the end of the last range
    /// assert_eq!(map.next_gap(7), (None, None));        // After all ranges
    /// ```
    pub fn next_gap(&self, value: u64) -> (Option<u64>, Option<u64>) {
        let current_range_end = match self.ranges.range(..=value).next_back().map(|(_, &end)| end) {
            Some(end) if end >= value => Some(end),
            _ => None,
        };

        let next_range_start = match value {
            u64::MAX => None,
            _ => self
                .ranges
                .range(value + 1..)
                .next()
                .map(|(&start, _)| start),
        };

        (current_range_end, next_range_start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let map = RMap::new();
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_insert_empty() {
        let mut map = RMap::new();
        map.insert(5);
        assert_eq!(map.get(&5), Some((5, 5)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5, &5)]);
    }

    #[test]
    fn test_insert_isolated() {
        let mut map = RMap::new();
        map.insert(5);
        map.insert(10);
        assert_eq!(map.get(&5), Some((5, 5)));
        assert_eq!(map.get(&10), Some((10, 10)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5, &5), (&10, &10)]);
    }

    #[test]
    fn test_insert_covered() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3); // Range is 1-3
        map.insert(2); // Insert value already covered
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&2), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_insert_adjacent_end() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2); // Range is 1-2
        map.insert(3); // Adjacent to end
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_insert_adjacent_start() {
        let mut map = RMap::new();
        map.insert(2);
        map.insert(3); // Range is 2-3
        map.insert(1); // Adjacent to start
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_insert_bridge_ranges() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        assert_eq!(map.get(&1), Some((1, 2)));
        map.insert(5);
        map.insert(6);
        assert_eq!(map.get(&5), Some((5, 6)));
        // Current: (1,2), (5,6)
        map.insert(3); // Insert 3, should become (1,3), (5,6)
        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&2), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.get(&5), Some((5, 6)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1, &3), (&5, &6)]);

        map.insert(4); // Insert 4, should bridge to (1,6)
        assert_eq!(map.get(&1), Some((1, 6)));
        assert_eq!(map.get(&3), Some((1, 6)));
        assert_eq!(map.get(&4), Some((1, 6)));
        assert_eq!(map.get(&6), Some((1, 6)));
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.iter().next(), Some((&1, &6)));
    }

    #[test]
    fn test_insert_complex_merging_and_ordering() {
        let mut map = RMap::new();
        map.insert(10); // (10,10)
        map.insert(12); // (10,10), (12,12)
        map.insert(11); // (10,12)
        assert_eq!(map.get(&10), Some((10, 12)));
        assert_eq!(map.get(&11), Some((10, 12)));
        assert_eq!(map.get(&12), Some((10, 12)));

        map.insert(15); // (10,12), (15,15)
        map.insert(13); // (10,13), (15,15)
        assert_eq!(map.get(&13), Some((10, 13)));
        assert_eq!(map.get(&12), Some((10, 13)));
        assert_eq!(map.get(&15), Some((15, 15)));

        map.insert(14); // (10,15)
        assert_eq!(map.get(&10), Some((10, 15)));
        assert_eq!(map.get(&14), Some((10, 15)));
        assert_eq!(map.get(&15), Some((10, 15)));
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.iter().next(), Some((&10, &15)));

        map.insert(5); // (5,5), (10,15)
        map.insert(7); // (5,5), (7,7), (10,15)
        map.insert(6); // (5,7), (10,15)
        assert_eq!(map.get(&5), Some((5, 7)));
        assert_eq!(map.get(&6), Some((5, 7)));
        assert_eq!(map.get(&7), Some((5, 7)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5, &7), (&10, &15)]);

        map.insert(9); // (5,7), (9,9), (10,15) -> should become (5,7), (9,15)
        assert_eq!(map.get(&9), Some((9, 15)));
        assert_eq!(map.get(&10), Some((9, 15)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&5, &7), (&9, &15)]);

        map.insert(8); // (5,15)
        assert_eq!(map.get(&5), Some((5, 15)));
        assert_eq!(map.get(&8), Some((5, 15)));
        assert_eq!(map.get(&15), Some((5, 15)));
        assert_eq!(map.iter().next(), Some((&5, &15)));
    }

    #[test]
    fn test_insert_max_value() {
        let mut map = RMap::new();
        map.insert(u64::MAX);
        assert_eq!(map.get(&u64::MAX), Some((u64::MAX, u64::MAX)));
        map.insert(u64::MAX - 1);
        assert_eq!(map.get(&(u64::MAX - 1)), Some((u64::MAX - 1, u64::MAX)));
        assert_eq!(map.get(&u64::MAX), Some((u64::MAX - 1, u64::MAX)));
    }

    #[test]
    fn test_get() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3); // Range 1-3
        map.insert(5);
        map.insert(6); // Range 5-6

        assert_eq!(map.get(&1), Some((1, 3)));
        assert_eq!(map.get(&2), Some((1, 3)));
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.get(&4), None);
        assert_eq!(map.get(&5), Some((5, 6)));
        assert_eq!(map.get(&6), Some((5, 6)));
        assert_eq!(map.get(&0), None);
        assert_eq!(map.get(&7), None);
    }

    #[test]
    fn test_remove_empty() {
        let mut map = RMap::new();
        map.remove(1, 5);
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_invalid_range() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2); // 1-2
        map.remove(5, 1); // start > end, should do nothing
        assert_eq!(map.iter().next(), Some((&1, &2)));
    }

    #[test]
    fn test_remove_non_existent() {
        let mut map = RMap::new();
        map.insert(5);
        map.insert(6); // 5-6
        map.remove(1, 3); // Before existing
        assert_eq!(map.iter().next(), Some((&5, &6)));
        map.remove(8, 10); // After existing
        assert_eq!(map.iter().next(), Some((&5, &6)));
        map.remove(1, 10); // Covers existing
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_exact_match() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3); // 1-3
        map.insert(5);
        map.insert(6); // 5-6
        map.remove(1, 3);
        assert_eq!(map.get(&2), None);
        assert_eq!(map.iter().next(), Some((&5, &6)));
        map.remove(5, 6);
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_subset_split() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3);
        map.insert(4);
        map.insert(5); // 1-5
        map.remove(3, 3); // Remove 3 from 1-5 -> (1,2), (4,5)
        assert_eq!(map.get(&2), Some((1, 2)));
        assert_eq!(map.get(&3), None);
        assert_eq!(map.get(&4), Some((4, 5)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1, &2), (&4, &5)]);

        // Reset and test another split
        let mut map2 = RMap::new();
        map2.insert(1);
        map2.insert(2);
        map2.insert(3);
        map2.insert(4);
        map2.insert(5); // 1-5
        map2.remove(2, 4); // Remove 2-4 from 1-5 -> (1,1), (5,5)
        assert_eq!(map2.get(&1), Some((1, 1)));
        assert_eq!(map2.get(&2), None);
        assert_eq!(map2.get(&3), None);
        assert_eq!(map2.get(&4), None);
        assert_eq!(map2.get(&5), Some((5, 5)));
        assert_eq!(map2.iter().collect::<Vec<_>>(), vec![(&1, &1), (&5, &5)]);
    }

    #[test]
    fn test_remove_overlap_start() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3);
        map.insert(4);
        map.insert(5); // 1-5
        map.remove(0, 2); // Remove 0-2 from 1-5 -> (3,5)
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&2), None);
        assert_eq!(map.get(&3), Some((3, 5)));
        assert_eq!(map.iter().next(), Some((&3, &5)));
    }

    #[test]
    fn test_remove_overlap_end() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3);
        map.insert(4);
        map.insert(5); // 1-5
        map.remove(4, 6); // Remove 4-6 from 1-5 -> (1,3)
        assert_eq!(map.get(&3), Some((1, 3)));
        assert_eq!(map.get(&4), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.iter().next(), Some((&1, &3)));
    }

    #[test]
    fn test_remove_cover_multiple_ranges() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2); // 1-2
        map.insert(4);
        map.insert(5); // 4-5
        map.insert(7);
        map.insert(8); // 7-8

        map.remove(3, 6); // Removes 4-5, no truncation as 3 and 6 are in gaps. (1,2), (7,8)
        assert_eq!(map.get(&2), Some((1, 2)));
        assert_eq!(map.get(&4), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.get(&7), Some((7, 8)));
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&1, &2), (&7, &8)]);

        map.remove(0, 10); // Removes all remaining ranges
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_remove_partial_overlap_multiple_ranges() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2);
        map.insert(3); // 1-3
        map.insert(5);
        map.insert(6);
        map.insert(7); // 5-7
        map.insert(9);
        map.insert(10);
        map.insert(11); // 9-11

        map.remove(2, 6); // Affects 1-3 (becomes 1-1) and 5-7 (becomes 7-7)
        assert_eq!(map.get(&1), Some((1, 1)));
        assert_eq!(map.get(&2), None);
        assert_eq!(map.get(&3), None);
        assert_eq!(map.get(&5), None);
        assert_eq!(map.get(&6), None);
        assert_eq!(map.get(&7), Some((7, 7)));
        assert_eq!(map.get(&9), Some((9, 11)));
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            vec![(&1, &1), (&7, &7), (&9, &11)]
        );

        // Reset and test removing all
        let mut map2 = RMap::new();
        map2.insert(1);
        map2.insert(2);
        map2.insert(3);
        map2.insert(5);
        map2.insert(6);
        map2.insert(7);
        map2.insert(9);
        map2.insert(10);
        map2.insert(11);
        map2.remove(0, 20); // remove all
        assert_eq!(map2.iter().count(), 0);
    }

    #[test]
    fn test_remove_touching_boundaries_no_merge() {
        let mut map = RMap::new();
        map.insert(0);
        map.insert(1);
        map.insert(2); // 0-2
        map.insert(4);
        map.insert(5); // 4-5

        // Remove range that is exactly between two existing ranges
        map.remove(3, 3);
        assert_eq!(map.iter().collect::<Vec<_>>(), vec![(&0, &2), (&4, &5)]);
    }

    #[test]
    fn test_remove_max_value_ranges() {
        let mut map = RMap::new();
        map.insert(u64::MAX - 2);
        map.insert(u64::MAX - 1);
        map.insert(u64::MAX); // MAX-2 to MAX

        map.remove(u64::MAX, u64::MAX); // Remove MAX -> (MAX-2, MAX-1)
        assert_eq!(map.get(&(u64::MAX - 2)), Some((u64::MAX - 2, u64::MAX - 1)));
        assert_eq!(map.get(&u64::MAX), None);

        map.remove(u64::MAX - 2, u64::MAX - 2); // Remove MAX-2 -> (MAX-1, MAX-1)
        assert_eq!(map.get(&(u64::MAX - 2)), None);
        assert_eq!(map.get(&(u64::MAX - 1)), Some((u64::MAX - 1, u64::MAX - 1)));

        map.remove(u64::MAX - 1, u64::MAX - 1); // Remove MAX-1 -> empty
        assert_eq!(map.iter().count(), 0);

        map.insert(u64::MAX - 1);
        map.insert(u64::MAX); // MAX-1 to MAX
        map.remove(u64::MIN, u64::MAX); // Remove all
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn test_iter() {
        let mut map = RMap::new();
        assert_eq!(map.iter().next(), None);
        map.insert(5);
        map.insert(6); // 5-6
        map.insert(1);
        map.insert(2); // 1-2
        let mut iter = map.iter();
        assert_eq!(iter.next(), Some((&1, &2)));
        assert_eq!(iter.next(), Some((&5, &6)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_next_gap_empty() {
        let map = RMap::new();
        assert_eq!(map.next_gap(5), (None, None));
    }

    #[test]
    fn test_next_gap_single_range() {
        let mut map = RMap::new();
        map.insert(5);
        map.insert(6);
        map.insert(7); // 5-7
        assert_eq!(map.next_gap(4), (None, Some(5))); // Before range
        assert_eq!(map.next_gap(5), (Some(7), None)); // Start of range
        assert_eq!(map.next_gap(6), (Some(7), None)); // Middle of range
        assert_eq!(map.next_gap(7), (Some(7), None)); // End of range
        assert_eq!(map.next_gap(8), (None, None)); // After range
    }

    #[test]
    fn test_next_gap_multiple_ranges() {
        let mut map = RMap::new();
        map.insert(1);
        map.insert(2); // 1-2
        map.insert(5);
        map.insert(6); // 5-6
        map.insert(10); // 10-10

        assert_eq!(map.next_gap(0), (None, Some(1))); // Before all
        assert_eq!(map.next_gap(1), (Some(2), Some(5))); // Start of first range
        assert_eq!(map.next_gap(2), (Some(2), Some(5))); // End of first range
        assert_eq!(map.next_gap(3), (None, Some(5))); // Gap between 1st and 2nd
        assert_eq!(map.next_gap(4), (None, Some(5))); // Gap, closer to 2nd
        assert_eq!(map.next_gap(5), (Some(6), Some(10))); // Start of 2nd range
        assert_eq!(map.next_gap(6), (Some(6), Some(10))); // End of 2nd range
        assert_eq!(map.next_gap(7), (None, Some(10))); // Gap between 2nd and 3rd
        assert_eq!(map.next_gap(8), (None, Some(10))); // Gap
        assert_eq!(map.next_gap(9), (None, Some(10))); // Gap, closer to 3rd
        assert_eq!(map.next_gap(10), (Some(10), None)); // Start/End of 3rd range
        assert_eq!(map.next_gap(11), (None, None)); // After all
    }

    #[test]
    fn test_next_gap_value_is_max() {
        let mut map = RMap::new();
        map.insert(u64::MAX - 5);
        map.insert(u64::MAX - 4); // MAX-5 to MAX-4
        map.insert(u64::MAX - 1);
        map.insert(u64::MAX); // MAX-1 to MAX

        assert_eq!(map.next_gap(u64::MAX - 6), (None, Some(u64::MAX - 5)));
        assert_eq!(
            map.next_gap(u64::MAX - 5),
            (Some(u64::MAX - 4), Some(u64::MAX - 1))
        );
        assert_eq!(
            map.next_gap(u64::MAX - 4),
            (Some(u64::MAX - 4), Some(u64::MAX - 1))
        );
        assert_eq!(map.next_gap(u64::MAX - 3), (None, Some(u64::MAX - 1))); // In gap
        assert_eq!(map.next_gap(u64::MAX - 2), (None, Some(u64::MAX - 1))); // In gap
        assert_eq!(map.next_gap(u64::MAX - 1), (Some(u64::MAX), None));
        assert_eq!(map.next_gap(u64::MAX), (Some(u64::MAX), None));
    }

    #[test]
    fn test_odd_ranges() {
        // Insert values
        let mut map = RMap::new();
        map.insert(1);
        map.insert(10);
        map.insert(11);
        map.insert(14);

        // Sanity check next_gap
        assert_eq!(map.next_gap(0), (None, Some(1)));
        assert_eq!(map.next_gap(1), (Some(1), Some(10)));
        assert_eq!(map.next_gap(10), (Some(11), Some(14)));
        assert_eq!(map.next_gap(11), (Some(11), Some(14)));
        assert_eq!(map.next_gap(12), (None, Some(14)));
        assert_eq!(map.next_gap(14), (Some(14), None));
    }
}
