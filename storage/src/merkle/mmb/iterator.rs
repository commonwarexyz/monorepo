//! Iterators for traversing MMBs of a given size, and functions for computing various MMB
//! properties from their output.

use crate::merkle::mmb::{Family, Location, Position};

/// Compute the MMB size required to hold `n` leaves.
const fn size_for_leaves(n: Location) -> Position {
    let n_val = n.as_u64();
    if n_val == 0 {
        return Position::new(0);
    }
    Position::new(2 * n_val - (n_val + 1).ilog2() as u64)
}

/// Use an O(1) estimation formula to find the baseline leaf count `N` for a given MMB size.
///
/// This provides a starting estimate that is accurate to within +/- 1 of the true leaf count.
const fn estimate_leaves(size: Position) -> Location {
    let size_val = size.as_u64();
    let n = size_val / 2;
    Location::new((size_val + (n + 1).ilog2() as u64) / 2)
}

/// Given an MMB size, return the number of leaves N such that `size_for_leaves(N) == size`.
///
/// Returns `None` if `size` is not a valid MMB size. Returns `Some(0)` for size 0.
pub(crate) fn leaves_for_size(size: Position) -> Option<Location> {
    if size.as_u64() == 0 {
        return Some(Location::new(0));
    }

    if size.as_u64() > <Family as crate::merkle::Family>::MAX_POSITION.as_u64() {
        return None;
    }

    let n = estimate_leaves(size);
    if size_for_leaves(n) == size {
        return Some(n);
    }
    if size_for_leaves(Location::new(n.as_u64() + 1)) == size {
        return Some(Location::new(n.as_u64() + 1));
    }

    None
}

/// A PeakIterator yields `(position, height)` for each peak in an MMB with the given size, in
/// order from **newest** (rightmost) to **oldest** (leftmost). Heights are always non-decreasing.
///
/// The number of peaks after N leaves is always exactly `ilog2(N+1)`, and their heights are
/// non-decreasing in this iteration order.
///
/// # Physical index ordering
///
/// The returned peaks are NOT monotonically ordered by position. This is due to the delayed
/// merging property of the MMB. A parent node at height `h` is not written immediately after its
/// leaves; instead, its creation is delayed by `2^(h-1) - 1` steps to maintain a constant rate of 1
/// merge per leaf.
///
/// As a result, older, taller peaks may be appended to the MMB *after* newer, shorter
/// peaks. For example, at `N=11` leaves, the Iterator yields peaks at positions `[17, 16, 18]`:
/// - `17`: The newest height-0 peak (a bare leaf added at step 10).
/// - `16`: An older height-1 peak (appended at step 9).
/// - `18`: The oldest height-3 peak (its merge was delayed by 3 steps and thus appended
///   *after* the leaf at position 17).
///
/// Code iterating through peaks must not assume their positions are sorted in any direction.
#[derive(Default)]
pub struct PeakIterator {
    n: Location,               // The exact number of leaves in the MMB
    current_i: u32,            // The bit index being evaluated, moving from 0 up to (L-1)
    num_peaks: u32,            // The total number of peaks (L-1)
    end_leaf_cursor: Location, // One past the last leaf covered by the next (rightward) peak
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of an MMB with the given number of nodes.
    ///
    /// # Panics
    ///
    /// Panics if size is not a valid MMB size.
    pub fn new(size: Position) -> Self {
        let n = leaves_for_size(size).expect("size is not a valid MMB size");
        if n.as_u64() == 0 {
            return Self::default();
        }

        // Exactly `ilog2(N+1)` peaks total.
        let num_peaks = (n.as_u64() + 1).ilog2();

        Self {
            n,
            current_i: 0,
            num_peaks,
            end_leaf_cursor: n,
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
    /// Panics if `size` exceeds [crate::merkle::Family::MAX_POSITION].
    pub fn to_nearest_size(size: Position) -> Position {
        assert!(
            size <= <Family as crate::merkle::Family>::MAX_POSITION,
            "size exceeds MAX_POSITION"
        );

        if size.as_u64() == 0 {
            return size;
        }

        let s = size.as_u64();

        // Use the O(1) estimation formula to find the baseline leaf count N.
        let n = estimate_leaves(size);

        // Check if n+1 fits within the size boundary. If it does, we use n+1.
        // If it overshoots, we safely fall back to n.
        let next_size = size_for_leaves(Location::new(n.as_u64() + 1));

        if next_size.as_u64() <= s {
            next_size
        } else {
            size_for_leaves(n)
        }
    }
}

impl Iterator for PeakIterator {
    type Item = (Position, u32); // (position, height)

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.num_peaks - self.current_i) as usize;
        (len, Some(len))
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_i >= self.num_peaks {
            return None;
        }

        let i = self.current_i;
        let n_val = self.n.as_u64();

        // Calculate the height of this peak: h_i = i + b_i
        let height = (i as u64) + (((n_val + 1) >> i) & 1);

        // The last leaf in this peak's tree (using the backward cursor)
        let leaves_in_peak = 1u64 << height;
        let last_leaf = Location::new(self.end_leaf_cursor.as_u64() - 1);

        // Step the cursor leftward for the next (older) peak
        self.end_leaf_cursor = Location::new(self.end_leaf_cursor.as_u64() - leaves_in_peak);
        self.current_i += 1;

        let n_birth = peak_birth_leaf(last_leaf, height as u32);
        Some((birthed_node_pos(n_birth, height == 0), height as u32))
    }
}

impl ExactSizeIterator for PeakIterator {}

/// Compute the birth leaves of both children of a parent with the given birth leaf and height.
///
/// Returns `(left_leaf, right_leaf)`. The left child is always the older (lower leaf index) child.
const fn child_leaves(parent_leaf: Location, height: u32) -> (Location, Location) {
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
/// A leaf created alongside `birth_leaf` has position `size_for_leaves(birth_leaf)`. A parent
/// created alongside `birth_leaf` has position `size_for_leaves(birth_leaf) + 1`.
///
/// # Warning
///
/// This calculates based solely on the structural math. If called with `is_leaf = false` on a
/// `birth_leaf` where no parent was actually birthed, it blindly returns the position of the next
/// appended leaf instead. It is the caller's responsibility to ensure a parent node functionally
/// exists at the provided `birth_leaf`.
const fn birthed_node_pos(birth_leaf: Location, is_leaf: bool) -> Position {
    if is_leaf {
        size_for_leaves(birth_leaf)
    } else {
        Position::new(size_for_leaves(birth_leaf).as_u64() + 1)
    }
}

/// Compute the birth leaf of a parent node from its position.
///
/// A parent created alongside `birth_leaf` has position `size_for_leaves(birth_leaf) + 1`. This
/// function inverts that formula. Returns `None` if `pos` is not a valid parent position
/// (e.g., if it's a leaf).
fn parent_birth_leaf(pos: Position) -> Option<Location> {
    let p = pos.as_u64();

    // The first parent in an MMB is always at index 2 (merging leaves 0 and 1).
    if p < 2 {
        return None;
    }

    // Every position in an MMB is strictly either a leaf or a parent.
    // If a position coincides with an MMB footprint boundary
    // (meaning `leaves_for_size(p).is_some()`), it is a leaf and we must reject it.
    if leaves_for_size(pos).is_some() {
        return None;
    }

    // Since a parent's position is exactly size_for_leaves(s) + 1, we can simply invert
    // the formula by checking if `p - 1` corresponds to a valid tree size.
    leaves_for_size(Position::new(p - 1))
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
const fn peak_birth_leaf(last_leaf: Location, height: u32) -> Location {
    let last_leaf = last_leaf.as_u64();
    if height == 0 {
        Location::new(last_leaf)
    } else {
        Location::new(last_leaf + (1u64 << (height - 1)) - 1)
    }
}

/// Compute the position of the `leaf_index`-th leaf.
#[inline]
pub(crate) const fn leaf_pos(leaf_index: Location) -> Position {
    size_for_leaves(leaf_index)
}

/// Return the set of pruned node positions (pos < `prune_pos`) that must be retained after
/// pruning.
///
/// The peaks of a sub-MMB at the prune boundary are sufficient for root computation and for
/// proving the boundary leaf (they are exactly the left-siblings needed to authenticate the
/// next leaf). However, updating an *arbitrary* retained leaf via `update_leaf` requires more:
/// each dirty ancestor needs both children during re-merkleization, and the off-path sibling
/// may lie in the pruned region without being a peak of the boundary sub-MMB.
///
/// This function therefore pins every pruned child of every retained parent, which covers all
/// possible update paths. It uses leaf-range checks to skip subtrees that are fully retained and
/// to pin roots of subtrees that are fully pruned. Each sliced peak contributes at most O(height)
/// pinned/traversed nodes, and there are O(log N) peaks, so worst-case total work is O(log^2 N).
///
/// If `update_leaf` after pruning is not needed (e.g., append-only with pruning but no
/// mutations), pinning only peaks would suffice and be cheaper.
pub(crate) fn nodes_to_pin(mmb_size: Position, prune_pos: Position) -> alloc::vec::Vec<Position> {
    let mut pinned = alloc::vec::Vec::new();
    let peaks = PeakIterator::new(mmb_size);
    let mut end_leaf_cursor = peaks.leaves().as_u64();

    for (peak_pos, height) in peaks {
        let leaves_in_peak = 1u64 << height;
        let leaf_start = end_leaf_cursor - leaves_in_peak;

        if peak_pos < prune_pos {
            pinned.push(peak_pos);
        } else if height > 0 {
            // If the oldest leaf is pruned, the peak spans the prune boundary, so we must traverse
            // its children.
            if leaf_pos(Location::new(leaf_start)) < prune_pos {
                collect_pruned_children(peak_pos, height, leaf_start, prune_pos, &mut pinned);
            }
        }

        end_leaf_cursor = leaf_start;
    }

    pinned
}

/// Walk a tree top-down, pinning any child whose position falls below `prune_pos`. Uses leaf-range
/// checks to skip fully retained subtrees.
fn collect_pruned_children(
    pos: Position,
    height: u32,
    leaf_start: u64,
    prune_pos: Position,
    pinned: &mut alloc::vec::Vec<Position>,
) {
    if height == 0 {
        return;
    }

    let (left, right) = children(pos, height);
    let mid_leaf = leaf_start + (1u64 << (height - 1));

    if left < prune_pos {
        pinned.push(left);
    } else if leaf_pos(Location::new(leaf_start)) < prune_pos {
        collect_pruned_children(left, height - 1, leaf_start, prune_pos, pinned);
    }

    if right < prune_pos {
        pinned.push(right);
    } else if leaf_pos(Location::new(mid_leaf)) < prune_pos {
        collect_pruned_children(right, height - 1, mid_leaf, prune_pos, pinned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_for_leaves() {
        assert_eq!(size_for_leaves(Location::new(1)).as_u64(), 1);
        assert_eq!(size_for_leaves(Location::new(2)).as_u64(), 3);
        assert_eq!(size_for_leaves(Location::new(3)).as_u64(), 4);
        assert_eq!(size_for_leaves(Location::new(4)).as_u64(), 6);
    }

    #[test]
    fn test_leaves_for_size_roundtrip() {
        for n in 1u64..=1000 {
            let size = size_for_leaves(Location::new(n));
            assert_eq!(leaves_for_size(size), Some(Location::new(n)), "N={n}");
        }
    }

    #[test]
    fn test_max_position_and_max_location_consistent() {
        // MAX_POSITION must be a valid MMB size whose leaf count is MAX_LOCATION.
        let max_pos = <Family as crate::merkle::Family>::MAX_POSITION.as_u64();
        let max_loc = <Family as crate::merkle::Family>::MAX_LOCATION.as_u64();
        assert_eq!(
            leaves_for_size(Position::new(max_pos)),
            Some(Location::new(max_loc)),
            "MAX_POSITION should correspond to MAX_LOCATION leaves"
        );

        // The size formula should agree.
        assert_eq!(
            size_for_leaves(Location::new(max_loc)).as_u64(),
            max_pos,
            "size_for_leaves(MAX_LOCATION) should equal MAX_POSITION"
        );

        // One more leaf should exceed MAX_POSITION.
        let over_size = size_for_leaves(Location::new(max_loc + 1)).as_u64();
        assert!(
            over_size > max_pos,
            "one more leaf should exceed MAX_POSITION"
        );

        // leaves_for_size must reject sizes above MAX_POSITION.
        assert_eq!(leaves_for_size(Position::new(max_pos + 1)), None);
    }

    /// Slow reference implementation for `nodes_to_pin` that recurses into every retained branch.
    fn nodes_to_pin_slow(mmb_size: Position, prune_pos: Position) -> alloc::vec::Vec<Position> {
        fn collect(
            pos: Position,
            height: u32,
            prune_pos: Position,
            pinned: &mut alloc::vec::Vec<Position>,
        ) {
            if height == 0 {
                return;
            }
            let (left, right) = children(pos, height);
            for child in [left, right] {
                if child < prune_pos {
                    pinned.push(child);
                } else {
                    collect(child, height - 1, prune_pos, pinned);
                }
            }
        }

        let mut pinned = alloc::vec::Vec::new();
        for (peak_pos, height) in PeakIterator::new(mmb_size) {
            if peak_pos < prune_pos {
                pinned.push(peak_pos);
            } else if height > 0 {
                collect(peak_pos, height, prune_pos, &mut pinned);
            }
        }
        pinned
    }

    #[test]
    fn test_child_leaves_matches_children() {
        for n in 1u64..=256 {
            let size = size_for_leaves(Location::new(n));
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
            let size = size_for_leaves(Location::new(n));
            let mut end_leaf_cursor = n;
            for (pos, height) in PeakIterator::new(size) {
                let leaves_in_peak = 1u64 << height;
                let last_leaf = end_leaf_cursor - 1;
                let leaf = peak_birth_leaf(Location::new(last_leaf), height);
                let computed_pos = birthed_node_pos(leaf, height == 0);
                assert_eq!(computed_pos, pos, "n={n}, height={height}");
                end_leaf_cursor -= leaves_in_peak;
            }
        }
    }

    #[test]
    fn test_nodes_to_pin_matches_reference() {
        for n in 0u64..=256 {
            let size = if n == 0 {
                Position::new(0)
            } else {
                size_for_leaves(Location::new(n))
            };
            for prune in 0..=size.as_u64() {
                let prune_pos = Position::new(prune);
                let fast = nodes_to_pin(size, prune_pos);
                let slow = nodes_to_pin_slow(size, prune_pos);
                assert_eq!(fast, slow, "n={n}, prune={prune}");
            }
        }
    }

    #[test]
    fn test_leaves_for_size_rejects_invalid() {
        // Sizes between valid MMB sizes should return None.
        for n in 1u64..=500 {
            let valid = size_for_leaves(Location::new(n)).as_u64();
            let next_valid = size_for_leaves(Location::new(n + 1)).as_u64();
            for gap in (valid + 1)..next_valid {
                assert_eq!(
                    leaves_for_size(Position::new(gap)),
                    None,
                    "size={gap} (between n={n} and n={}",
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
            let size = size_for_leaves(Location::new(n));
            let mut end_leaf_cursor = n;
            for (pos, height) in PeakIterator::new(size) {
                let leaves_in_peak = 1u64 << height;
                let last_leaf = end_leaf_cursor - 1;
                let leaf = peak_birth_leaf(Location::new(last_leaf), height);
                let computed_pos = birthed_node_pos(leaf, height == 0);
                assert_eq!(computed_pos, pos, "n={n}, height={height}");
                end_leaf_cursor -= leaves_in_peak;
            }
        }
    }
}
