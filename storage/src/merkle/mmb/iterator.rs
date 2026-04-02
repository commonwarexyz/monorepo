//! Iterators for traversing MMBs of a given size, and functions for computing various MMB
//! properties from their output.

use crate::merkle::{
    mmb::{Family, Location, Position},
    Family as _,
};

/// A PeakIterator yields `(position, height)` for each peak in an MMB with the given size, in
/// order from **oldest** (leftmost) to **newest** (rightmost). Heights are always non-increasing.
///
/// The number of peaks after N leaves is always exactly `ilog2(N+1)`, and their heights are
/// non-increasing in this iteration order.
///
/// # Physical index ordering
///
/// The returned peaks are NOT monotonically ordered by position. This is due to the delayed
/// merging property of the MMB. A parent node at height `h` is not written immediately after its
/// leaves; instead, its creation is delayed by `2^(h-1) - 1` steps to maintain a constant rate of 1
/// merge per leaf.
///
/// As a result, older, taller peaks may be appended to the MMB *after* newer, shorter
/// peaks. For example, at `N=11` leaves, the Iterator yields peaks at positions `[18, 16, 17]`:
/// - `18`: The oldest height-3 peak (its merge was delayed by 3 steps).
/// - `16`: A height-1 peak (appended at step 9).
/// - `17`: The newest height-0 peak (a bare leaf added at step 10).
///
/// Code iterating through peaks must not assume their positions are sorted in any direction.
#[derive(Default)]
pub struct PeakIterator {
    n: Location,                 // The exact number of leaves in the MMB
    current_i: u32,              // Bit index, counting down from (num_peaks-1) to 0
    remaining: u32,              // Number of peaks left to yield
    start_leaf_cursor: Location, // First leaf of the next (rightward) peak
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of an MMB with the given number of nodes.
    ///
    /// # Panics
    ///
    /// Panics if size is not a valid MMB size.
    pub fn new(size: Position) -> Self {
        let n = Location::try_from(size).expect("size is not a valid MMB size");
        if n.as_u64() == 0 {
            return Self::default();
        }

        // Exactly `ilog2(N+1)` peaks total.
        let num_peaks = (n.as_u64() + 1).ilog2();

        Self {
            n,
            current_i: num_peaks - 1,
            remaining: num_peaks,
            start_leaf_cursor: Location::new(0),
        }
    }

    /// Return the number of leaves in the MMB.
    #[inline]
    pub const fn leaves(&self) -> Location {
        self.n
    }

    /// Returns the largest valid MMB size that is no greater than the given size.
    ///
    /// # Panics
    ///
    /// Panics if `size` exceeds [crate::merkle::Family::MAX_NODES].
    pub fn to_nearest_size(size: Position) -> Position {
        assert!(size <= Family::MAX_NODES, "size exceeds MAX_NODES");

        if size.as_u64() == 0 {
            return size;
        }

        // Use an O(1) estimate to find the baseline leaf count, then check if n+1
        // fits within the size boundary. location_to_position is monotonic, so one
        // refinement step from the estimate always suffices.
        let s = size.as_u64();
        let mut n = s / 2;
        n = (s + (n + 1).ilog2() as u64) / 2;

        let candidate = Family::location_to_position(Location::new(n + 1));
        if *candidate <= s {
            candidate
        } else {
            Family::location_to_position(Location::new(n))
        }
    }
}

impl Iterator for PeakIterator {
    type Item = (Position, u32); // (position, height)

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let i = self.current_i;
        let n_val = self.n.as_u64();

        // Height formula: h_i = i + b_i where b_i = ((n+1) >> i) & 1.
        // Index `i` corresponds to the original newest-to-oldest numbering; we iterate
        // from the highest `i` (oldest) down to 0 (newest).
        let height = (i as u64) + (((n_val + 1) >> i) & 1);
        let leaves_in_peak = 1u64 << height;

        // The last leaf in this peak's subtree.
        let last_leaf = Location::new(self.start_leaf_cursor.as_u64() + leaves_in_peak - 1);

        // Advance the cursor rightward for the next (newer) peak.
        self.start_leaf_cursor = Location::new(self.start_leaf_cursor.as_u64() + leaves_in_peak);
        self.current_i = self.current_i.wrapping_sub(1);
        self.remaining -= 1;

        let n_birth = peak_birth_leaf(last_leaf, height as u32);
        Some((birthed_node_pos(n_birth, height == 0), height as u32))
    }
}

impl ExactSizeIterator for PeakIterator {}

/// Compute the birth leaves of both children of a parent with the given birth leaf and height.
///
/// Returns `(left_leaf, right_leaf)`. The left child is always the older (lower leaf index) child.
pub(super) const fn child_leaves(parent_leaf: Location, height: u32) -> (Location, Location) {
    let parent_leaf = parent_leaf.as_u64();
    if height == 1 {
        (Location::new(parent_leaf - 1), Location::new(parent_leaf))
    } else {
        let base = 1u64 << (height - 2);
        (
            Location::new(parent_leaf - 3 * base),
            Location::new(parent_leaf - base),
        )
    }
}

/// Convert a leaf to the position of the birthed node. `is_leaf` specifies whether you want the
/// position of the leaf it births (its own position) or the position of the parent it births (if
/// any).
///
/// A leaf created alongside `birth_leaf` has position
/// `Family::location_to_position(birth_leaf)`. A parent created alongside `birth_leaf` has
/// position `Family::location_to_position(birth_leaf) + 1`.
///
/// # Warning
///
/// This calculates based solely on the structural math. If called with `is_leaf = false` on a
/// `birth_leaf` where no parent was actually birthed, it blindly returns the position of the next
/// appended leaf instead. It is the caller's responsibility to ensure a parent node functionally
/// exists at the provided `birth_leaf`.
pub(super) fn birthed_node_pos(birth_leaf: Location, is_leaf: bool) -> Position {
    if is_leaf {
        Family::location_to_position(birth_leaf)
    } else {
        Position::new(Family::location_to_position(birth_leaf).as_u64() + 1)
    }
}

/// Compute the birth leaf of a parent node from its position.
///
/// A parent created alongside `birth_leaf` has position
/// `Family::location_to_position(birth_leaf) + 1`. This function inverts that formula. Returns
/// `None` if `pos` is not a valid parent position (e.g., if it's a leaf).
fn parent_birth_leaf(pos: Position) -> Option<Location> {
    let p = pos.as_u64();

    // The first parent in an MMB is always at index 2 (merging leaves 0 and 1).
    if p < 2 {
        return None;
    }

    // Every position in an MMB is strictly either a leaf or a parent.
    // If a position coincides with an MMB footprint boundary
    // (meaning `Family::position_to_location(p).is_some()`), it is a leaf and we must reject it.
    if Family::position_to_location(pos).is_some() {
        return None;
    }

    // Since a parent's position is exactly location_to_position(s) + 1, we can simply invert
    // the formula by checking if `p - 1` corresponds to a valid tree size.
    Family::position_to_location(Position::new(p - 1))
}

/// Compute the positions of the left and right children of a parent node.
///
/// Uses the delay matrix: for a parent at height h created at `birth_leaf`, its children (both at
/// height h-1) were created at leaves determined by fixed delays that depend only on h.
///
/// # Panics
///
/// Panics if `height` is 0 or if `pos` is not a valid parent position.
pub(crate) fn children(pos: Position, height: u32) -> (Position, Position) {
    assert!(height > 0, "height-0 nodes are leaves and have no children");

    // Safely unwrap the birth leaf, or panic with a clear error if the caller passed a leaf.
    let s = parent_birth_leaf(pos).expect("pos is not a valid parent position");

    let (left_leaf, right_leaf) = child_leaves(s, height);
    let is_leaf = height == 1;
    let left = birthed_node_pos(left_leaf, is_leaf);
    let right = birthed_node_pos(right_leaf, is_leaf);

    (left, right)
}

/// Compute the birth leaf of a peak from its leaf range and height.
///
/// For a height-0 peak (bare leaf), the birth leaf equals the last leaf index. For a taller peak,
/// the birth leaf is `last_leaf + 2^(h-1) - 1`.
pub(super) const fn peak_birth_leaf(last_leaf: Location, height: u32) -> Location {
    let last_leaf = last_leaf.as_u64();
    if height == 0 {
        Location::new(last_leaf)
    } else {
        Location::new(last_leaf + (1u64 << (height - 1)) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_to_position() {
        assert_eq!(Family::location_to_position(Location::new(1)).as_u64(), 1);
        assert_eq!(Family::location_to_position(Location::new(2)).as_u64(), 3);
        assert_eq!(Family::location_to_position(Location::new(3)).as_u64(), 4);
        assert_eq!(Family::location_to_position(Location::new(4)).as_u64(), 6);
    }

    #[test]
    fn test_position_to_location_roundtrip() {
        for n in 1u64..=1000 {
            let size = Family::location_to_position(Location::new(n));
            assert_eq!(
                Family::position_to_location(size),
                Some(Location::new(n)),
                "N={n}"
            );
        }
    }

    #[test]
    fn test_max_position_and_max_location_consistent() {
        let max_pos = Family::MAX_NODES.as_u64();
        let max_loc = Family::MAX_LEAVES.as_u64();

        // MAX_NODES should correspond to MAX_LEAVES leaves.
        assert_eq!(
            Location::try_from(Position::new(max_pos)).ok(),
            Some(Location::new(max_loc)),
            "MAX_NODES should correspond to MAX_LEAVES leaves"
        );

        // The size formula should agree.
        assert_eq!(
            Position::try_from(Location::new(max_loc)).unwrap().as_u64(),
            max_pos,
            "location_to_position(MAX_LEAVES) should equal MAX_NODES"
        );

        // One more leaf should exceed MAX_NODES.
        let over_size = *Family::location_to_position(Location::new(max_loc + 1));
        assert!(over_size > max_pos, "one more leaf should exceed MAX_NODES");

        // Sizes above MAX_NODES should be rejected.
        assert!(!Position::new(max_pos + 1).is_valid());
    }

    #[test]
    fn test_child_leaves_matches_children() {
        for n in 1u64..=256 {
            let size = Position::try_from(Location::new(n)).unwrap();
            for (pos, height) in PeakIterator::new(size) {
                if height == 0 {
                    continue;
                }
                let leaf = parent_birth_leaf(pos).unwrap();
                let (left_leaf, right_leaf) = child_leaves(leaf, height);
                let is_leaf = height == 1;
                let left_pos = birthed_node_pos(left_leaf, is_leaf);
                let right_pos = birthed_node_pos(right_leaf, is_leaf);
                let (expected_left, expected_right) = children(pos, height);
                assert_eq!(
                    (left_pos, right_pos),
                    (expected_left, expected_right),
                    "n={n}, pos={pos}, height={height}"
                );
            }
        }
    }

    #[test]
    fn test_birthed_node_pos() {
        // Verify birthed_node_pos matches PeakIterator output for all peaks.
        for n in 1u64..=256 {
            let size = Position::try_from(Location::new(n)).unwrap();
            let mut first_leaf = 0u64;
            for (pos, height) in PeakIterator::new(size) {
                let leaves_in_peak = 1u64 << height;
                let last_leaf = first_leaf + leaves_in_peak - 1;
                let leaf = peak_birth_leaf(Location::new(last_leaf), height);
                let computed_pos = birthed_node_pos(leaf, height == 0);
                assert_eq!(computed_pos, pos, "n={n}, height={height}");
                first_leaf += leaves_in_peak;
            }
        }
    }

    #[test]
    fn test_invalid_sizes_rejected() {
        // Sizes between valid MMB sizes should fail conversion.
        for n in 1u64..=500 {
            let valid = *Position::try_from(Location::new(n)).unwrap();
            let next_valid = *Position::try_from(Location::new(n + 1)).unwrap();
            for gap in (valid + 1)..next_valid {
                assert!(
                    Location::try_from(Position::new(gap)).is_err(),
                    "size={gap} (between n={n} and n={}) should be invalid",
                    n + 1
                );
            }
        }
    }

    #[test]
    fn test_location_position_roundtrip() {
        use crate::merkle::mmb::{Location, Position};
        use core::convert::TryFrom;

        for n in 0u64..=1000 {
            let loc = Location::new(n);
            let pos = Position::try_from(loc).unwrap();

            // Roundtrip back to location.
            let loc2 = Location::try_from(pos).unwrap();
            assert_eq!(loc, loc2, "roundtrip failed for leaf {n}");

            // Non-leaf positions between consecutive leaves should fail.
            if n > 0 {
                let prev_loc = Location::new(n - 1);
                let prev_pos = Position::try_from(prev_loc).unwrap();
                for gap_pos in (*prev_pos + 1)..*pos {
                    assert!(
                        Location::try_from(Position::new(gap_pos)).is_err(),
                        "position {gap_pos} between leaves {prev_pos} and {pos} should not be a leaf"
                    );
                }
            }
        }
    }

    #[test]
    fn test_parent_birth_leaf_rejects_leaf_positions() {
        // These are valid leaf positions that previously slipped through the simplified
        // `parent_birth_leaf` check because `pos - 1` is also a valid MMB size.
        assert_eq!(parent_birth_leaf(Position::new(4)), None);
        assert_eq!(parent_birth_leaf(Position::new(11)), None);
    }

    #[test]
    #[should_panic(expected = "pos is not a valid parent position")]
    fn test_children_rejects_leaf_position() {
        children(Position::new(4), 1);
    }

    #[test]
    fn test_peak_birth_leaf() {
        // Verify peak_birth_leaf matches the inline computation used in test_birthed_node_pos.
        for n in 1u64..=256 {
            let size = Position::try_from(Location::new(n)).unwrap();
            let mut first_leaf = 0u64;
            for (pos, height) in PeakIterator::new(size) {
                let leaves_in_peak = 1u64 << height;
                let last_leaf = first_leaf + leaves_in_peak - 1;
                let leaf = peak_birth_leaf(Location::new(last_leaf), height);
                let computed_pos = birthed_node_pos(leaf, height == 0);
                assert_eq!(computed_pos, pos, "n={n}, height={height}");
                first_leaf += leaves_in_peak;
            }
        }
    }

    #[test]
    fn test_to_nearest_size() {
        // Zero maps to zero.
        assert_eq!(
            PeakIterator::to_nearest_size(Position::new(0)),
            Position::new(0)
        );

        // For every size 0..2000: result is valid, <= input, monotonic, and exact sizes
        // are unchanged while gaps round down.
        let mut prev = Position::new(0);
        for s in 0u64..=2000 {
            let nearest = PeakIterator::to_nearest_size(Position::new(s));
            assert!(
                nearest.is_valid_size(),
                "result {nearest} not valid for input {s}"
            );
            assert!(
                nearest <= Position::new(s),
                "result {nearest} exceeds input {s}"
            );
            assert!(nearest >= prev, "not monotonic at {s}");
            prev = nearest;
        }

        // Valid sizes map to themselves; gaps map to the previous valid size.
        for n in 1u64..=500 {
            let size = Position::try_from(Location::new(n)).unwrap();
            assert_eq!(PeakIterator::to_nearest_size(size), size, "n={n}");

            let next_size = Position::try_from(Location::new(n + 1)).unwrap();
            for s in *size + 1..*next_size {
                assert_eq!(
                    PeakIterator::to_nearest_size(Position::new(s)),
                    size,
                    "gap size {s} between n={n} and n={}",
                    n + 1
                );
            }
        }
    }
}
