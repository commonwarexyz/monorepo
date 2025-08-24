//! Iterators for traversing MMRs of a given size, and functions for computing various MMR
//! properties from their output.

/// A PeakIterator returns a (position, height) tuple for each peak in an MMR with the given size,
/// in decreasing order of height.
///
/// For the example MMR depicted at the top of this file, the PeakIterator would yield:
/// ```text
/// [(14, 3), (17, 1), (18, 0)]
/// ```
#[derive(Default)]
pub struct PeakIterator {
    size: u64,     // number of nodes in the MMR at the point the iterator was initialized
    node_pos: u64, // position of the current node
    two_h: u64,    // 2^(height+1) of the current node
}

impl PeakIterator {
    /// Return a new PeakIterator over the peaks of a MMR with the given number of nodes.
    pub fn new(size: u64) -> PeakIterator {
        if size == 0 {
            return PeakIterator::default();
        }
        // Compute the position at which to start the search for peaks. This starting position will
        // not be in the MMR unless it happens to be a single perfect binary tree, but that's OK as
        // we will descend leftward until we find the first peak.
        let start = u64::MAX >> size.leading_zeros();
        let two_h = 1 << start.trailing_ones();
        PeakIterator {
            size,
            node_pos: start - 1,
            two_h,
        }
    }

    /// Return the position of the last leaf in an MMR of the given size.
    ///
    /// This is an O(log2(n)) operation.
    pub fn last_leaf_pos(size: u64) -> u64 {
        if size == 0 {
            return 0;
        }

        let last_peak = PeakIterator::new(size).last().unwrap();
        last_peak.0 - last_peak.1 as u64
    }

    /// Return if an MMR of the given `size` has a valid structure.
    ///
    /// The implementation verifies that peaks in the MMR of the given size have strictly decreasing
    /// height, which is a necessary condition for MMR validity.
    pub const fn check_validity(size: u64) -> bool {
        if size == 0 {
            return true;
        }
        let start = u64::MAX >> size.leading_zeros();
        let mut two_h = 1 << start.trailing_ones();
        let mut node_pos = start - 1;
        while two_h > 1 {
            if node_pos < size {
                if two_h == 2 {
                    // If this peak is a leaf yet there are more nodes remaining, then this MMR is
                    // invalid.
                    return node_pos == size - 1;
                }
                // move to the right sibling
                node_pos += two_h - 1;
                if node_pos < size {
                    // If the right sibling is in the MMR, then it is invalid.
                    return false;
                }
                continue;
            }
            // descend to the left child
            two_h >>= 1;
            node_pos -= two_h;
        }
        true
    }

    // Returns the largest valid MMR size that is no greater than the given size.
    //
    // TODO(https://github.com/commonwarexyz/monorepo/issues/820): This is an O(log2(n)^2)
    // implementation but it's reasonably straightforward to make it O(log2(n)).
    pub fn to_nearest_size(mut size: u64) -> u64 {
        while !PeakIterator::check_validity(size) {
            // A size-0 MMR is always valid so this loop must terminate before underflow.
            size -= 1;
        }
        size
    }
}

impl Iterator for PeakIterator {
    type Item = (u64, u32); // (peak, height)

    fn next(&mut self) -> Option<Self::Item> {
        while self.two_h > 1 {
            if self.node_pos < self.size {
                // found a peak
                let peak_item = (self.node_pos, self.two_h.trailing_zeros() - 1);
                // move to the right sibling
                self.node_pos += self.two_h - 1;
                assert!(self.node_pos >= self.size); // sibling shouldn't be in the MMR if MMR is valid
                return Some(peak_item);
            }
            // descend to the left child
            self.two_h >>= 1;
            self.node_pos -= self.two_h;
        }
        None
    }
}

/// Returns the set of peaks that will require a new parent after adding the next leaf to an MMR
/// with the given peaks. This set is non-empty only if there is a height-0 (leaf) peak in the MMR.
/// The result will contain this leaf peak plus the other MMR peaks with contiguously increasing
/// height. Nodes in the result are ordered by decreasing height.
pub fn nodes_needing_parents(peak_iterator: PeakIterator) -> Vec<u64> {
    let mut peaks = Vec::new();
    let mut last_height = u32::MAX;

    for (peak_pos, height) in peak_iterator {
        assert!(last_height > 0);
        assert!(height < last_height);
        if height != last_height - 1 {
            peaks.clear();
        }
        peaks.push(peak_pos);
        last_height = height;
    }
    if last_height != 0 {
        // there is no peak that is a leaf
        peaks.clear();
    }
    peaks
}

/// Returns the leaf number of the leaf at position `pos` in an MMR, or None if this is not a
/// leaf. This is a constant-time implementation that is 4-5x faster than the naive tree traversal
/// approach (see `./mmr/benches/leaf_pos_to_num.rs`).
///
/// The algorithm returns the value `num` such that `2*num - num.count_ones() == pos`. It does this
/// by repeatedly applying the refinement function `g(n) = (pos + n.count_ones())/2`, starting with
/// input `n = pos/2`.
///
/// Only 3 applications of `g(n)` brings us within 1 of the true answer. At this point, we can
/// therefore identify the true answer by applying the inverse function on each of the 3 remaining
/// possibilities (num, num-1, num+1) and returning the one that matches.
///
/// Use of wrapping_sub in this implementation is both faster than regular subtraction and protects
/// against overflow.
#[inline]
pub const fn leaf_pos_to_num(pos: u64) -> Option<u64> {
    // Apply the refinement function three times to get within 1 of the true answer.
    let mut num = pos >> 1;
    num = (pos + (num.count_ones() as u64)) >> 1;
    num = (pos + (num.count_ones() as u64)) >> 1;
    num = (pos + (num.count_ones() as u64)) >> 1;

    // Check if `num` is the right answer.
    if pos == (num << 1).wrapping_sub(num.count_ones() as u64) {
        return Some(num);
    }

    // Check if `num - 1` is the right answer.
    if num > 0 {
        let check = num - 1;
        if pos == (check << 1).wrapping_sub(check.count_ones() as u64) {
            return Some(check);
        }
    }

    // Check if `num + 1` is the right answer.
    if num != u64::MAX {
        let check = num + 1;
        if pos == (check << 1).wrapping_sub(check.count_ones() as u64) {
            return Some(check);
        }
    }

    // The input is not a valid leaf position.
    None
}

/// Returns the position of the leaf with number `leaf_num` in an MMR.
#[inline]
pub const fn leaf_num_to_pos(leaf_num: u64) -> u64 {
    // This will never underflow since 2*n >= count_ones(n).
    leaf_num.checked_mul(2).expect("leaf_num overflow") - leaf_num.count_ones() as u64
}

/// Returns the height of the node at position `pos` in an MMR.
pub const fn pos_to_height(mut pos: u64) -> u32 {
    if pos == 0 {
        return 0;
    }

    let mut size = u64::MAX >> pos.leading_zeros();
    while size != 0 {
        if pos >= size {
            pos -= size;
        }
        size >>= 1;
    }

    pos as u32
}

/// A PathIterator returns a (parent_pos, sibling_pos) tuple for the sibling of each node along the
/// path from a given perfect binary tree peak to a designated leaf, not including the peak itself.
///
/// For example, consider the tree below and the path from the peak to leaf node 3. Nodes on the
/// path are [6, 5, 3] and tagged with '*' in the diagram):
///
/// ```text
///
///          6*
///        /   \
///       2     5*
///      / \   / \
///     0   1 3*  4
///
/// A PathIterator for this example yields:
///    [(6, 2), (5, 4)]
/// ```
#[derive(Debug)]
pub struct PathIterator {
    leaf_pos: u64, // position of the leaf node in the path
    node_pos: u64, // current node position in the path from peak to leaf
    two_h: u64,    // 2^height of the current node
}

impl PathIterator {
    /// Return a PathIterator over the siblings of nodes along the path from peak to leaf in the
    /// perfect binary tree with peak `peak_pos` and having height `height`, not including the peak
    /// itself.
    pub fn new(leaf_pos: u64, peak_pos: u64, height: u32) -> PathIterator {
        PathIterator {
            leaf_pos,
            node_pos: peak_pos,
            two_h: 1 << height,
        }
    }
}

impl Iterator for PathIterator {
    type Item = (u64, u64); // (parent_pos, sibling_pos)

    fn next(&mut self) -> Option<Self::Item> {
        if self.two_h <= 1 {
            return None;
        }

        let left_pos = self.node_pos - self.two_h;
        let right_pos = self.node_pos - 1;
        self.two_h >>= 1;

        if left_pos < self.leaf_pos {
            let r = Some((self.node_pos, left_pos));
            self.node_pos = right_pos;
            return r;
        }
        let r = Some((self.node_pos, right_pos));
        self.node_pos = left_pos;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{hasher::Standard, mem::Mmr};
    use commonware_cryptography::{sha256::hash, Sha256};
    use commonware_runtime::{deterministic, Runner};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_leaf_num_calculation_on_mmr() {
        let digest = hash(b"testing");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build MMR with 1000 leaves and make sure we can correctly convert each leaf position to
            // its number and back again.
            let mut mmr: Mmr<Sha256> = Mmr::new();
            let mut hasher = Standard::new();
            let mut num_to_pos = Vec::new();
            for _ in 0u64..1000 {
                num_to_pos.push(mmr.add(&mut hasher, &digest));
            }

            let mut last_leaf_pos = 0;
            for (leaf_num_expected, leaf_pos) in num_to_pos.iter().enumerate() {
                let leaf_num_got = leaf_pos_to_num(*leaf_pos).unwrap();
                assert_eq!(leaf_num_got, leaf_num_expected as u64);
                let leaf_pos_got = leaf_num_to_pos(leaf_num_got);
                assert_eq!(leaf_pos_got, *leaf_pos);
                for i in last_leaf_pos + 1..*leaf_pos {
                    assert!(leaf_pos_to_num(i).is_none());
                }
                last_leaf_pos = *leaf_pos;
            }
        });
    }

    #[test]
    fn test_leaf_num_calculation_on_random_large_inputs() {
        let mut rng = StdRng::seed_from_u64(0);
        for _ in 0..1_000_000 {
            // Test pos -> num -> pos
            let leaf_pos = rng.gen_range(1 << 62..1 << 63);
            let leaf_num = leaf_pos_to_num(leaf_pos);
            if let Some(leaf_num) = leaf_num {
                assert_eq!(leaf_num_to_pos(leaf_num), leaf_pos);
            }

            // Test num -> pos -> num
            let leaf_num = rng.gen_range(1 << 61..1 << 62);
            let leaf_pos = leaf_num_to_pos(leaf_num);
            assert_eq!(leaf_pos_to_num(leaf_pos), Some(leaf_num));
        }
    }
}
