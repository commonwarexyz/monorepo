//! A Merkle Mountain Belt (MMB) is an append-only data structure that allows for efficient
//! verification of the inclusion of an element in a list. Like the [MMR](crate::mmr), it stores
//! elements in a forest of perfect binary trees. Unlike the MMR, the trees are not required to have
//! strictly decreasing heights. (This module technically implements the _F-MMB_ from
//! <https://arxiv.org/abs/2511.13582>, which bags peaks using a left-deep merkle tree.)
//!
//! # Terminology
//!
//! An MMB is a forest of perfect binary trees (aka _mountains_) of non-increasing height. The roots
//! of these trees are called the _peaks_ of the MMB. Each _element_ stored in the MMB is
//! represented by some leaf node in one of these perfect trees, storing a positioned hash of the
//! element. Non-leaf nodes store a positioned hash of their children.
//!
//! The _size_ of an MMB is the total number of nodes summed over all trees.
//!
//! Each node in the MMB has a _position_: its 0-based index in the append-only array. Leaves and
//! internal nodes are appended strictly in insertion order, so positions are stable identifiers
//! that never change. An element's _location_ is its 0-based index among all leaves (i.e. its
//! insertion order). In the example below, the right-most element has position 11 and location 7.
//!
//! The _height_ of a node is 0 for a leaf, 1 for the parent of 2 leaves, and so on.
//!
//! The _birth leaf_ of a node is the `Location` of the leaf inserted when the node was physically
//! appended to the MMB. Because of the delayed merging property of the MMB, a parent node is not
//! necessarily appended at the same step as its rightmost leaf. At any given step `S` (where leaf
//! `S` is being added):
//! - Leaf `S` is born when leaf `S` is inserted.
//! - Exactly one parent node is born when leaf `S` is inserted, *unless* `S + 2` is a power of 2
//!   (in which case only the leaf is appended, and zero parents are born).
//!
//! For example, referencing the `N=8` diagram below:
//! - Node 10 (Leaf 6) has a birth leaf of 6 (it is appended at the same time as itself).
//! - Node 5 (a height-1 parent) has a birth leaf of 3 (it is appended immediately after Leaf 3).
//! - Node 7 (a height-2 parent) has a birth leaf of 4 (it is appended immediately after Leaf 4).
//!
//! The _root digest_ (or just _root_) is computed as `Hash(leaves || fold(peaks))`, where `fold`
//! left-folds peak digests from oldest to newest using `Hash(acc || peak)`.
//!
//! # Construction
//!
//! On each step, one leaf is appended at the next available position. If a unique pair of adjacent
//! same-height peaks exists, they are merged: one parent node is appended immediately after the
//! leaf. This "1-merge-per-leaf" budget ensures that after N leaves, the number of peaks is always
//! `ilog2(N+1)` and the total size is `2*N - ilog2(N+1)`.
//!
//! Because the leaf is always appended first and the merge parent (if any) follows, the physical
//! index of leaf N is `2*N - ilog2(N+1)` and the physical index of a parent created at step N is
//! `2*N + 1 - ilog2(N+1)`.
//!
//! # Physical layout
//!
//! Unlike the MMR (whose trees occupy contiguous, non-overlapping regions of the array), an MMB's
//! tree nodes may be interleaved in the array. A merge parent is appended after the leaf that
//! triggered the merge, so it may sit between nodes of different logical trees. Consequently, [peak
//! positions](iterator::PeakIterator) are yielded from newest to oldest (non-decreasing height),
//! NOT by physical position. Code must not assume peak positions are monotonically increasing. The
//! root fold (oldest to newest) therefore requires reversing the iterator.
//!
//! # Comparison with MMR
//!
//! An MMR with N leaves has `2*N - popcount(N)` nodes while an MMB has `2*N - ilog2(N+1)` nodes.
//! The MMB is always at least as compact as the MMR, and often more so. For example, with 8 leaves
//! the MMR has 15 nodes (one perfect tree) while the MMB has 13 nodes (three trees).
//!
//! The key structural difference is that an MMR requires strictly decreasing peak heights (at most
//! one tree per height), while an MMB allows up to two consecutive peaks of the same height. This
//! means appending a leaf to an MMB creates at most one new internal node, whereas an MMR may
//! create up to `O(log N)` internal nodes.
//!
//! # Examples
//!
//! After adding 8 elements to an MMB, it will have 13 nodes total with 3 peaks. The logical tree
//! structure (with nodes labeled by physical position) is:
//!
//! ```text
//!    Height
//!      2        7
//!             /   \
//!      1     2     5      9      12
//!           / \   / \    / \    /  \
//!      0   0   1 3   4  6   8  10  11
//!
//! Location 0   1 2   3  4   5  6   7
//! ```
//!
//! Note that the height-2 peak (position 7) has a higher physical index than leaf 4 (position 6).
//! This is because leaf 4 triggered the merge of the two height-1 peaks at positions 2 and 5, and
//! the resulting parent was appended after the leaf.
//!
//! The array layout is built incrementally:
//!
//! ```text
//! Step  Array contents (position 0..12)                Peaks after step
//!  0    L0                                             [(0,  h0)]
//!  1    L0  L1  P1                                     [(2,  h1)]
//!  2    L0  L1  P1  L2                                 [(2,  h1), (3,  h0)]
//!  3    L0  L1  P1  L2  L3  P3                         [(2,  h1), (5,  h1)]
//!  4    L0  L1  P1  L2  L3  P3  L4  P4                [(7,  h2), (6,  h0)]
//!  5    .. same prefix ..            L5  P5            [(7,  h2), (9,  h1)]
//!  6    .. same prefix ..                L6            [(7,  h2), (9,  h1), (10, h0)]
//!  7    .. same prefix ..                L6  L7  P7    [(7,  h2), (9,  h1), (12, h1)]
//! ```
//!
//! The root hash is computed as `Hash(8 || fold(peak1, peak2, peak3))`:
//!
//! ```text
//! peak1 = Hash(7,                                             // oldest peak (height 2)
//!           Hash(2, Hash(0, element_0), Hash(1, element_1)),
//!           Hash(5, Hash(3, element_2), Hash(4, element_3)))
//! peak2 = Hash(9, Hash(6, element_4), Hash(8, element_5))    // middle peak (height 1)
//! peak3 = Hash(12, Hash(10, element_6), Hash(11, element_7)) // newest peak (height 1)
//!
//! acc   = fold(peak1, peak2, peak3)
//!       = Hash(Hash(peak1 || peak2) || peak3)
//! root  = Hash(8 || acc)                                     // 8 = leaf count
//! ```

pub mod batch;
pub mod iterator;
pub mod mem;
pub mod proof;

use crate::merkle;
pub use crate::merkle::Readable;
pub use batch::{Changeset, MerkleizedBatch, UnmerkleizedBatch};

/// Marker type for the MMB family.
#[derive(Copy, Clone, Debug)]
pub struct Family;

impl merkle::Family for Family {
    /// Maximum valid position (node count): `2^63 - 2` (the size for `2^62 + 30` leaves).
    const MAX_POSITION: Position = Position::new(0x7FFF_FFFF_FFFF_FFFE);

    /// Maximum valid location (leaf count): `2^62 + 30`.
    const MAX_LOCATION: Location = Location::new(0x4000_0000_0000_001E);

    fn location_to_position(loc: Location) -> Position {
        let loc = loc.as_u64();
        // 2*N - ilog2(N+1) for MMB
        Position::new(2 * loc - (loc + 1).ilog2() as u64)
    }

    fn position_to_location(pos: Position) -> Option<Location> {
        let pos = pos.as_u64();
        // Solve 2*N - ilog2(N+1) = pos for N.
        // Starting estimate: N ~ (pos + ilog2(N+1)) / 2 ~ pos/2. One refinement gives accuracy
        // within +/-1, so the loop body runs at most a few times.
        let mut n = pos / 2;
        n = (pos + (n + 1).ilog2() as u64) / 2;
        loop {
            let leaf_pos = 2 * n - (n + 1).ilog2() as u64;
            if leaf_pos == pos {
                return Some(Location::new(n));
            }
            if leaf_pos > pos {
                // pos is not a leaf position (it falls between two leaf positions, so it's a
                // parent).
                return None;
            }
            n += 1;
        }
    }

    fn to_nearest_size(size: Position) -> Position {
        iterator::PeakIterator::to_nearest_size(size)
    }

    fn nodes_to_pin(size: Position, prune_pos: Position) -> alloc::vec::Vec<Position> {
        iterator::nodes_to_pin(size, prune_pos)
    }

    fn children(pos: Position, height: u32) -> (Position, Position) {
        iterator::children(pos, height)
    }

    type PeakIterator = iterator::PeakIterator;

    fn peak_iterator(size: Position) -> Self::PeakIterator {
        iterator::PeakIterator::new(size)
    }

    fn peaks_fold_order(size: Position) -> alloc::vec::Vec<(Position, u32)> {
        let mut peaks: alloc::vec::Vec<_> = iterator::PeakIterator::new(size).collect();
        peaks.reverse();
        peaks
    }

    fn merge_heights_on_append(size: Position) -> alloc::vec::Vec<u32> {
        // MMB merges at most one pair of same-height adjacent peaks per append.
        let mut prev_height = 0;
        for (_, height) in iterator::PeakIterator::new(size) {
            if height == prev_height {
                return alloc::vec![height + 1];
            }
            prev_height = height;
        }
        alloc::vec::Vec::new()
    }

    fn leaf_ancestors(loc: Location, size: Position) -> alloc::vec::Vec<(Position, u32)> {
        let peaks = iterator::PeakIterator::new(size);
        let mut end_leaf_cursor = peaks.leaves().as_u64();

        for (peak_pos, height) in peaks {
            let leaves_in_peak = 1u64 << height;
            let leaf_start = end_leaf_cursor - leaves_in_peak;
            end_leaf_cursor = leaf_start;

            if loc.as_u64() < leaf_start || loc.as_u64() >= leaf_start + leaves_in_peak {
                continue;
            }

            // Collect path from peak to leaf (top-down), then reverse for bottom-up.
            let path = batch::collect_path(peak_pos, height, leaf_start, loc);
            return path.into_iter().rev().collect();
        }
        alloc::vec::Vec::new()
    }

    fn proof_blueprint(
        leaves: Location,
        range: core::ops::Range<Location>,
    ) -> Result<crate::merkle::mem::Blueprint<Self>, crate::merkle::mem::Error<Self>> {
        use crate::merkle::mem::{Blueprint, Error};

        if range.is_empty() {
            return Err(Error::InvalidSize(0));
        }
        let end_minus_one = range
            .end
            .checked_sub(1)
            .expect("can't underflow because range is non-empty");
        if end_minus_one >= leaves {
            return Err(Error::LeafOutOfBounds(range.end));
        }

        let size = Position::try_from(leaves)?;
        let n = leaves;

        // Single-pass peak walk: classify each peak.
        // PeakIterator yields newest-to-oldest.
        let mut before = alloc::vec::Vec::new();
        let mut after = alloc::vec::Vec::new();
        let mut range_peaks = alloc::vec::Vec::new();
        let mut end_leaf_cursor = n;
        for (peak_pos, height) in iterator::PeakIterator::new(size) {
            let leaves_in_peak = 1u64 << height;
            let leaf_start = end_leaf_cursor - leaves_in_peak;

            if leaf_start >= range.end {
                after.push(peak_pos);
            } else if end_leaf_cursor <= range.start {
                before.push(peak_pos);
            } else {
                let birth_leaf = iterator::peak_birth_leaf(end_leaf_cursor - 1, height);
                range_peaks.push((birth_leaf, height, leaf_start));
            }
            end_leaf_cursor = leaf_start;
        }

        // Reverse all from newest-to-oldest to oldest-to-newest.
        before.reverse();
        after.reverse();
        range_peaks.reverse();

        // Build fetch_nodes: after-peaks first, then DFS siblings for each range peak.
        let mut fetch_nodes = after;
        for &(birth_leaf, height, leaf_start) in &range_peaks {
            proof::collect_siblings_dfs(birth_leaf, height, leaf_start, &range, &mut fetch_nodes);
        }

        Ok(Blueprint {
            fold_prefix: before,
            fetch_nodes,
        })
    }

    fn reconstruct_root<
        D: commonware_cryptography::Digest,
        H: crate::merkle::hasher::Hasher<Self, Digest = D>,
        E: AsRef<[u8]>,
    >(
        hasher: &mut H,
        proof_leaves: Location,
        proof_digests: &[D],
        elements: &[E],
        start_loc: Location,
    ) -> Result<D, crate::merkle::proof::ReconstructionError> {
        proof::reconstruct_root_standalone(hasher, proof_leaves, proof_digests, elements, start_loc)
    }

    fn is_valid_size(size: Position) -> bool {
        iterator::leaves_for_size(size).is_some()
    }
}

/// A node index or node count in an MMB.
pub type Position = merkle::Position<Family>;

/// A leaf index or leaf count in an MMB.
pub type Location = merkle::Location<Family>;

pub type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Errors that can occur during MMB operations.
#[derive(Debug)]
pub enum Error {
    /// Empty input where at least one element was required.
    Empty,
    /// The requested MMB size is invalid.
    InvalidSize(u64),
    /// A range end exceeds the number of leaves.
    RangeOutOfBounds(Location),
    /// A requested leaf location exceeds the current leaf count.
    LeafOutOfBounds(Location),
    /// A required node was not available (e.g. pruned).
    ElementPruned(Position),
    /// The provided pinned node list does not match the expected pruning boundary.
    InvalidPinnedNodes,
    /// Location exceeds the valid range.
    LocationOverflow(Location),
    /// A non-leaf position was used where a leaf position was required.
    NonLeaf(Position),
    /// Position exceeds the valid range for this MMB family.
    PositionOverflow(Position),
    /// Changeset was created against a different MMB state.
    StaleChangeset {
        /// The size the changeset was built against.
        expected: Position,
        /// The current MMB size.
        actual: Position,
    },
}

impl From<merkle::Error<Family>> for Error {
    fn from(e: merkle::Error<Family>) -> Self {
        match e {
            merkle::Error::LocationOverflow(loc) => Self::LocationOverflow(loc),
            merkle::Error::NonLeaf(pos) => Self::NonLeaf(pos),
            merkle::Error::PositionOverflow(pos) => Self::PositionOverflow(pos),
        }
    }
}

impl From<merkle::mem::Error<Family>> for Error {
    fn from(e: merkle::mem::Error<Family>) -> Self {
        match e {
            merkle::mem::Error::InvalidSize(s) => Self::InvalidSize(s),
            merkle::mem::Error::InvalidPinnedNodes => Self::InvalidPinnedNodes,
            merkle::mem::Error::ElementPruned(pos) => Self::ElementPruned(pos),
            merkle::mem::Error::LeafOutOfBounds(loc) => Self::LeafOutOfBounds(loc),
            merkle::mem::Error::LocationOverflow(loc) => Self::LocationOverflow(loc),
            merkle::mem::Error::NonLeaf(pos) => Self::NonLeaf(pos),
            merkle::mem::Error::PositionOverflow(pos) => Self::PositionOverflow(pos),
            merkle::mem::Error::StaleChangeset { expected, actual } => {
                Self::StaleChangeset { expected, actual }
            }
        }
    }
}
