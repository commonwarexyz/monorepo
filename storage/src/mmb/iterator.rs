//! Iterators for traversing MMBs of a given size, and functions for computing various MMB
//! properties from their output. These are lower levels methods that are useful for implementing
//! new MMB variants or extensions.

use super::{Position, MAX_POSITION};

/// Given an MMB size, return the number of leaves N such that `2*N - ilog2(N+1) == size`.
///
/// Returns `None` if `size` is not a valid MMB size. Returns `Some(0)` for size 0.
pub(crate) const fn leaves_for_size(size: u64) -> Option<u64> {
    if size == 0 {
        return Some(0);
    }

    // Max valid MMB size is MAX_POSITION + 1 (= 2^63 - 2).
    if size > MAX_POSITION.as_u64() + 1 {
        return None;
    }

    // N = (size + ilog2(N+1)) / 2. One refinement from size/2 is accurate to within +/-1,
    // so we only need to check n and n+1.
    let n = size / 2;
    let n = (size + (n + 1).ilog2() as u64) / 2;
    if 2 * n - (n + 1).ilog2() as u64 == size {
        return Some(n);
    }
    let n = n + 1;
    if 2 * n - (n + 1).ilog2() as u64 == size {
        return Some(n);
    }
    None
}

/// A PeakIterator yields `(physical_index, height)` for each peak in an MMB with the given size,
/// in order from **newest** (rightmost, lowest height) to **oldest** (leftmost, tallest). Heights
/// are therefore non-decreasing.
///
/// Because the MMB's 1-merge-per-leaf rule acts as a mathematical shock absorber, the number of
/// peaks after N leaves is always exactly `ilog2(N+1)`, and their heights are non-decreasing in
/// this iteration order.
///
/// # Physical index ordering
///
/// Peak positions are NOT necessarily in increasing or decreasing physical position order. When a
/// merge occurs, the parent node is appended after the leaf that triggered it, so a tall peak may
/// have a higher physical index than a shorter, newer peak. Code must not assume peak positions
/// are monotonically ordered.
pub struct PeakIterator {
    n: u64,               // The exact number of leaves in the MMB
    current_i: i32,       // The bit index being evaluated, moving from 0 up to (L-2)
    max_i: i32,           // The maximum bit index (L-2)
    end_leaf_cursor: u64, // One past the last leaf covered by the next (rightward) peak
}

impl Default for PeakIterator {
    fn default() -> Self {
        Self {
            n: 0,
            current_i: 0,
            max_i: -1,
            end_leaf_cursor: 0,
        }
    }
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of an MMB with the given number of nodes.
    ///
    /// # Panics
    ///
    /// Panics if size is not a valid MMB size.
    pub fn new(size: Position) -> Self {
        let n = leaves_for_size(*size).expect("size is not a valid MMB size");
        if n == 0 {
            return Self::default();
        }

        // L - 1 peaks total, where L is the bit length of (N + 1)
        let max_i = (n + 1).ilog2() as i32 - 1;

        Self {
            n,
            current_i: 0,
            max_i,
            end_leaf_cursor: n,
        }
    }

    /// Return the number of leaves in the MMB.
    #[inline]
    pub const fn leaves(&self) -> u64 {
        self.n
    }

    /// Return the position of the last leaf in an MMB of the given size.
    ///
    /// The last leaf is always the N-th leaf (0-indexed as N-1), whose physical index is
    /// `2*(N-1) - ilog2(N)`.
    pub fn last_leaf_pos(size: Position) -> Position {
        if size == 0 {
            return Position::new(0);
        }

        let n = leaves_for_size(*size).expect("size is not a valid MMB size");
        let last = n - 1;
        Position::new(2 * last - (last + 1).ilog2() as u64)
    }

    /// Returns the largest valid MMB size that is no greater than the given size.
    ///
    /// # Panics
    ///
    /// Panics if `size` exceeds [MAX_POSITION].
    pub fn to_nearest_size(size: Position) -> Position {
        assert!(size <= MAX_POSITION, "size exceeds MAX_POSITION");

        if size == 0 {
            return size;
        }

        let s = size.as_u64();

        // Use the O(1) estimation formula to find the baseline leaf count N.
        let mut n = s / 2;
        n = (s + (n + 1).ilog2() as u64) / 2;

        // Check if n+1 fits within the size boundary. If it does, we use n+1.
        // If it overshoots, we safely fall back to n.
        let next_size = 2 * (n + 1) - (n + 2).ilog2() as u64;

        if next_size <= s {
            Position::new(next_size)
        } else {
            Position::new(2 * n - (n + 1).ilog2() as u64)
        }
    }
}

impl Iterator for PeakIterator {
    type Item = (Position, u32); // (physical_index, height)

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_i > self.max_i {
            return None;
        }

        let i = self.current_i;

        // Calculate the height of this peak: h_i = i + b_i
        let b_i = ((self.n + 1) >> i) & 1;
        let height = (i as u64) + b_i;

        // The last leaf in this peak's tree (using the backward cursor)
        let leaves_in_peak = 1u64 << height;
        let last_leaf = self.end_leaf_cursor - 1;

        // Step the cursor leftward for the next (older) peak
        self.end_leaf_cursor -= leaves_in_peak;
        self.current_i += 1;

        // Compute the physical index using the birth-step formula.
        let physical_index = if height == 0 {
            // Height-0 peak is a bare leaf.
            let n_birth = last_leaf;
            2 * n_birth - (n_birth + 1).ilog2() as u64
        } else {
            // Height > 0 peak is a parent. delay = 2^(h-1) - 1.
            let delay = (1u64 << (height - 1)) - 1;
            let n_birth = last_leaf + delay;
            2 * n_birth + 1 - (n_birth + 1).ilog2() as u64
        };

        Some((Position::new(physical_index), height as u32))
    }
}

/// Compute the birth steps of both children of a parent with the given birth step and height.
///
/// Returns `(left_step, right_step)`. The left child is always the older (lower step) child.
pub(crate) const fn child_steps(parent_step: u64, height: u32) -> (u64, u64) {
    if height == 1 {
        (parent_step - 1, parent_step)
    } else {
        let base = 1u64 << (height - 2);
        (parent_step - 3 * base, parent_step - base)
    }
}

/// Convert a birth step to a physical position.
///
/// A leaf created at step S has position `2*S - ilog2(S+1)`.
/// A parent created at step S has position `2*S + 1 - ilog2(S+1)`.
pub(crate) const fn step_to_pos(step: u64, is_leaf: bool) -> Position {
    let log_val = (step + 1).ilog2() as u64;
    if is_leaf {
        Position::new(2 * step - log_val)
    } else {
        Position::new(2 * step + 1 - log_val)
    }
}

/// Compute the birth step of a parent node from its physical position.
///
/// A parent created at step S has position `2*S + 1 - ilog2(S+1)`. This function inverts that
/// formula. Returns `None` if `pos` is not a valid parent position (e.g., if it's a leaf).
pub(crate) const fn parent_birth_step(pos: Position) -> Option<u64> {
    let p = pos.as_u64();

    // The first parent in an MMB is always at index 2 (merging leaves 0 and 1).
    if p < 2 {
        return None;
    }

    // Starting estimate. One refinement gives accuracy within +/-1.
    // We use (p / 2 + 1) for the log estimate to avoid a double assignment.
    let mut s = (p - 1 + (p / 2 + 1).ilog2() as u64) / 2;
    loop {
        let computed = 2 * s + 1 - (s + 1).ilog2() as u64;

        if computed == p {
            return Some(s);
        }

        // If our formula overshoots the target, it means the target index
        // does not belong to a parent node (it is a leaf).
        if computed > p {
            return None;
        }

        s += 1;
    }
}

/// Compute the physical positions of the left and right children of a parent node.
///
/// Uses the delay matrix: for a parent at height h created at step S, its children (both at
/// height h-1) were created at steps determined by fixed delays that depend only on h.
///
/// # Panics
///
/// Panics if `height` is 0 or if `pos` is not a valid parent position.
pub(crate) fn children(pos: Position, height: u32) -> (Position, Position) {
    assert!(height > 0, "height-0 nodes are leaves and have no children");

    // Safely unwrap the birth step, or panic with a clear error if the caller passed a leaf.
    let s = parent_birth_step(pos).expect("pos is not a valid parent position");

    // Delay from the child's creation step to the parent's creation step.
    let (right_step, left_step) = if height == 1 {
        // h=1 parent (children are h=0 leaves): right delay = 0, left delay = 1
        (s, s - 1)
    } else {
        // h>1 parent (children are parents): right delay = 2^(h-2), left delay = 3*2^(h-2)
        let base = 1u64 << (height - 2);
        (s - base, s - 3 * base)
    };

    // Convert child step to physical position. Height-0 children use the leaf formula;
    // higher children use the parent formula.
    let child_pos = |step: u64, is_leaf: bool| -> Position {
        let log_val = (step + 1).ilog2() as u64;
        if is_leaf {
            Position::new(2 * step - log_val)
        } else {
            Position::new(2 * step + 1 - log_val)
        }
    };

    let is_leaf = height == 1;
    let left = child_pos(left_step, is_leaf);
    let right = child_pos(right_step, is_leaf);

    (left, right)
}

/// Compute the physical position of the `leaf_index`-th leaf.
#[inline]
const fn leaf_pos(leaf_index: u64) -> Position {
    Position::new(2 * leaf_index - (leaf_index + 1).ilog2() as u64)
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
    let n = leaves_for_size(*mmb_size).expect("size is not a valid MMB size");
    let mut end_leaf_cursor = n;

    for (peak_pos, height) in PeakIterator::new(mmb_size) {
        let leaves_in_peak = 1u64 << height;
        let leaf_start = end_leaf_cursor - leaves_in_peak;

        if peak_pos < prune_pos {
            pinned.push(peak_pos);
        } else if height > 0 {
            // If the oldest leaf in this peak is still retained, the entire peak is retained.
            if leaf_pos(leaf_start) < prune_pos {
                collect_pruned_children(peak_pos, height, leaf_start, prune_pos, &mut pinned);
            }
        }

        end_leaf_cursor = leaf_start;
    }
    pinned
}

/// Walk a tree top-down, pinning any child whose position falls below `prune_pos`.
/// Uses leaf-range checks to skip fully retained subtrees.
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
    } else if leaf_pos(leaf_start) < prune_pos {
        collect_pruned_children(left, height - 1, leaf_start, prune_pos, pinned);
    }

    if right < prune_pos {
        pinned.push(right);
    } else if leaf_pos(mid_leaf) < prune_pos {
        collect_pruned_children(right, height - 1, mid_leaf, prune_pos, pinned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Return the MMB size for the given number of leaves.
    const fn size_for_leaves(n: u64) -> u64 {
        assert!(n > 0, "n must be positive");
        n * 2 - (n + 1).ilog2() as u64
    }

    #[test]
    fn test_size_for_leaves() {
        assert_eq!(size_for_leaves(1), 1);
        assert_eq!(size_for_leaves(2), 3);
        assert_eq!(size_for_leaves(3), 4);
        assert_eq!(size_for_leaves(4), 6);
    }

    #[test]
    fn test_leaves_for_size_roundtrip() {
        for n in 1u64..=1000 {
            let size = size_for_leaves(n);
            assert_eq!(leaves_for_size(size), Some(n), "N={n}");
        }
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
    fn test_child_steps_matches_children() {
        for n in 1u64..=256 {
            let size = Position::new(size_for_leaves(n));
            for (pos, height) in PeakIterator::new(size) {
                if height == 0 {
                    continue;
                }
                let step = parent_birth_step(pos).unwrap();
                let (left_step, right_step) = child_steps(step, height);
                let is_leaf = height == 1;
                let left_pos = step_to_pos(left_step, is_leaf);
                let right_pos = step_to_pos(right_step, is_leaf);
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
    fn test_step_to_pos() {
        // Verify step_to_pos matches PeakIterator output for all peaks.
        for n in 1u64..=256 {
            let size = Position::new(size_for_leaves(n));
            let mut end_leaf_cursor = n;
            for (pos, height) in PeakIterator::new(size) {
                let leaves_in_peak = 1u64 << height;
                let last_leaf = end_leaf_cursor - 1;
                let step = if height == 0 {
                    last_leaf
                } else {
                    last_leaf + (1u64 << (height - 1)) - 1
                };
                let computed_pos = step_to_pos(step, height == 0);
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
                Position::new(size_for_leaves(n))
            };
            for prune in 0..=size.as_u64() {
                let prune_pos = Position::new(prune);
                let fast = nodes_to_pin(size, prune_pos);
                let slow = nodes_to_pin_slow(size, prune_pos);
                assert_eq!(fast, slow, "n={n}, prune={prune}");
            }
        }
    }
}
