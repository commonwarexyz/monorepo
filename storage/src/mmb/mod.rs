//! A Merkle Mountain Belt (MMB) is an append-only data structure that allows for efficient
//! verification of the inclusion of an element in a list. Like the [MMR](crate::mmr), it stores
//! elements in a forest of perfect binary trees. Unlike the MMR, the trees are not required to
//! have strictly decreasing heights.
//!
//! # Terminology
//!
//! An MMB is a forest of perfect binary trees (aka _mountains_) of non-increasing height. The
//! roots of these trees are called the _peaks_ of the MMB. Each _element_ stored in the MMB is
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
//! The _root digest_ (or just _root_) of an MMB is computed by left-folding the peak digests
//! from oldest to newest, starting from the hash of the leaf count.
//!
//! # Construction
//!
//! On each step, one leaf is appended at the next available position. If the two rightmost peaks
//! then have equal height, they are merged: one parent node is appended immediately after the
//! leaf. This "1-merge-per-leaf" budget ensures that after N leaves, the number of peaks is
//! always `ilog2(N+1)` and the total size is `2*N - ilog2(N+1)`.
//!
//! Because the leaf is always appended first and the merge parent (if any) follows, the physical
//! index of leaf N is `2*N - ilog2(N+1)` and the physical index of a parent created at step N is
//! `2*N + 1 - ilog2(N+1)`.
//!
//! # Physical layout
//!
//! Unlike the MMR (whose trees occupy contiguous, non-overlapping regions of the array), an MMB's
//! tree nodes may be interleaved in the array. A merge parent is appended after the leaf that
//! triggered the merge, so it may sit between nodes of different logical trees. Consequently,
//! [peak positions](iterator::PeakIterator) are ordered by tree age (non-increasing height), NOT
//! by physical position. Code must not assume peak positions are monotonically increasing.
//!
//! # Comparison with MMR
//!
//! An MMR with N leaves has `2*N - popcount(N)` nodes while an MMB has `2*N - ilog2(N+1)` nodes.
//! The MMB is always at least as compact as the MMR, and often more so. For example, with 8
//! leaves the MMR has 15 nodes (one perfect tree) while the MMB has 13 nodes (three trees).
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
//!      0   0   1 3   4  6   8 10  11
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
//! The root hash is computed by left-folding the peaks from oldest to newest:
//!
//! ```text
//! acc_0 = Hash(8)                                             // leaf count
//! acc_1 = Hash(acc_0,
//!   Hash(7,                                                   // oldest peak (height 2)
//!     Hash(2, Hash(0, element_0), Hash(1, element_1)),
//!     Hash(5, Hash(3, element_2), Hash(4, element_3))
//!   ))
//! acc_2 = Hash(acc_1,
//!   Hash(9, Hash(6, element_4), Hash(8, element_5)))          // middle peak (height 1)
//! root  = Hash(acc_2,
//!   Hash(12, Hash(10, element_6), Hash(11, element_7)))       // newest peak (height 1)
//! ```

pub mod hasher;
pub mod iterator;
pub mod location;
pub mod mem;
pub mod position;

pub use hasher::Standard as StandardHasher;
pub use location::{Location, LocationRangeExt, MAX_LOCATION};
pub use position::{Position, MAX_POSITION};
use thiserror::Error;

/// Errors that can occur during MMB operations.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum Error {
    #[error("{0} is not a leaf position")]
    NonLeaf(Position),

    #[error("location {0} out of bounds")]
    LocOutOfBounds(Location),

    #[error("position {0} out of bounds")]
    PosOutOfBounds(Position),

    #[error("missing node: {0}")]
    MissingNode(Position),

    #[error("element pruned: {0}")]
    ElementPruned(Position),

    #[error("position is not a leaf: {0}")]
    PositionNotLeaf(Position),

    #[error("invalid position: {0}")]
    InvalidPosition(Position),

    #[error("invalid size: {0}")]
    InvalidSize(u64),

    #[error("empty")]
    Empty,

    #[error("invalid pinned nodes")]
    InvalidPinnedNodes,

    #[error("leaf location out of bounds: {0}")]
    LeafOutOfBounds(Location),

    #[error("location {0} > MAX_LOCATION")]
    LocationOverflow(Location),
}
