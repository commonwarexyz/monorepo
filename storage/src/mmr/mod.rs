//! A Merkle Mountain Range (MMR) is an append-only data structure that allows for efficient
//! verification of the inclusion of an element, or some range of consecutive elements, in a list.
//!
//! # Terminology
//!
//! An MMR is a list of perfect binary trees (aka _mountains_) of strictly decreasing height. The
//! roots of these trees are called the _peaks_ of the MMR. Each _element_ stored in the MMR is
//! represented by some leaf node in one of these perfect trees, storing a positioned hash of the
//! element. Non-leaf nodes store a positioned hash of their children.
//!
//! The _size_ of an MMR is the total number of nodes summed over all trees.
//!
//! The nodes of the MMR are ordered by a post-order traversal of the MMR trees, starting from the
//! from tallest tree to shortest. The _position_ of a node in the MMR is defined as the 0-based
//! index of the node in this ordering. This implies the positions of elements, which are always
//! leaves, may not be contiguous even if they were consecutively added. An element's _location_ is
//! its 0-based index in the order of element insertion (aka its leaf index). In the example below,
//! the right-most element has position 18 and location 10.
//!
//! As the MMR is an append-only data structure, node positions never change and can be used as
//! stable identifiers.
//!
//! The _height_ of a node is 0 for a leaf, 1 for the parent of 2 leaves, and so on.
//!
//! The _root digest_ (or just _root_) of an MMR is the result of hashing together the size of the
//! MMR and the digests of every peak in decreasing order of height.
//!
//! # Examples
//!
//! (Borrowed from <https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/>): After adding 11
//! elements to an MMR, it will have 19 nodes total with 3 peaks corresponding to 3 perfect binary
//! trees as pictured below, with nodes identified by their positions:
//!
//! ```text
//!    Height
//!      3              14
//!                   /    \
//!                  /      \
//!                 /        \
//!                /          \
//!      2        6            13
//!             /   \        /    \
//!      1     2     5      9     12     17
//!           / \   / \    / \   /  \   /  \
//!      0   0   1 3   4  7   8 10  11 15  16 18
//!
//! Location 0   1 2   3  4   5  6   7  8   9 10
//! ```
//!
//! The root hash in this example is computed as:
//!
//! ```text
//!
//! Hash(19,
//!   Hash(14,                                                  // first peak
//!     Hash(6,
//!       Hash(2, Hash(0, element_0), Hash(1, element_1)),
//!       Hash(5, Hash(3, element_2), Hash(4, element_3))
//!     )
//!     Hash(13,
//!       Hash(9, Hash(7, element_4), Hash(8, element_5)),
//!       Hash(12, Hash(10, element_6), Hash(11, element_7))
//!     )
//!   )
//!   Hash(17, Hash(15, element_8), Hash(16, element_9))        // second peak
//!   Hash(18, element_10)                                      // third peak
//! )
//! ```

pub mod hasher;
pub mod iterator;
pub mod mem;
pub mod proof;

#[cfg(test)]
pub(crate) mod conformance;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod journaled;
        pub mod storage;
        pub mod verification;
    }
}

// --- Merkle family marker and type aliases ---
use crate::merkle::{self, MerkleFamily};
pub use hasher::Standard as StandardHasher;
pub use proof::{Proof, MAX_PROOF_DIGESTS_PER_ELEMENT};
use thiserror::Error;

/// Marker type for the MMR family.
#[derive(Copy, Clone, Debug)]
pub struct Mmr;

impl MerkleFamily for Mmr {
    /// Maximum valid position: the largest MMR size for 2^62 leaves is `2^63 - 1`.
    const MAX_POSITION: u64 = 0x7FFFFFFFFFFFFFFF; // (1 << 63) - 1

    /// Maximum valid location: the largest leaf count is `2^62`.
    const MAX_LOCATION: u64 = 0x4000_0000_0000_0000; // 2^62

    fn location_to_position(loc: u64) -> u64 {
        // 2*N - popcount(N) for MMR
        loc.checked_mul(2)
            .expect("should not overflow for valid leaf index")
            - loc.count_ones() as u64
    }

    fn position_to_location(pos: u64) -> Option<u64> {
        // Position 0 is always the first leaf at location 0.
        if pos == 0 {
            return Some(0);
        }

        // Find the height of the perfect binary tree containing this position.
        // Safe: pos + 1 cannot overflow since pos <= MAX_POSITION (checked by caller).
        let start = u64::MAX >> (pos + 1).leading_zeros();
        let height = start.trailing_ones();
        // Height 0 means this position is a peak (not a leaf in a tree).
        if height == 0 {
            return None;
        }
        let mut two_h = 1 << (height - 1);
        let mut cur_node = start - 1;
        let mut leaf_loc_floor = 0u64;

        while two_h > 1 {
            if cur_node == pos {
                return None;
            }
            let left_pos = cur_node - two_h;
            two_h >>= 1;
            if pos > left_pos {
                // The leaf is in the right subtree, so we must account for the leaves in the left
                // subtree all of which precede it.
                leaf_loc_floor += two_h;
                cur_node -= 1; // move to the right child
            } else {
                // The node is in the left subtree
                cur_node = left_pos;
            }
        }

        Some(leaf_loc_floor)
    }

    fn is_valid_size(size: u64) -> bool {
        if size == 0 {
            return true;
        }
        let leading_zeros = size.leading_zeros();
        if leading_zeros == 0 {
            // size overflow
            return false;
        }
        let start = u64::MAX >> leading_zeros;
        let mut two_h = 1 << start.trailing_ones();
        let mut node_pos = start.checked_sub(1).expect("start > 0 because size != 0");
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
}

/// A node index or node count in an MMR.
pub type Position = merkle::Position<Mmr>;

/// A leaf index or leaf count in an MMR.
pub type Location = merkle::Location<Mmr>;

/// Maximum valid [Position] value: the largest node count (size) an MMR can hold.
///
/// An MMR with `2^62` leaves has `2^63 - 1` nodes, so `MAX_POSITION = 2^63 - 1`.
pub const MAX_POSITION: Position = Position::MAX;

/// Maximum valid [Location] value: the largest leaf count an MMR can hold.
///
/// `MAX_LOCATION = 2^62`.
pub const MAX_LOCATION: Location = Location::MAX;

/// Error type for converting a [Position] to a [Location].
pub type LocationError = merkle::PositionConversionError<Mmr>;

pub use crate::merkle::LocationRangeExt;

/// Errors that can occur when interacting with an MMR.
#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "std")]
    #[error("metadata error: {0}")]
    MetadataError(#[from] crate::metadata::Error),
    #[cfg(feature = "std")]
    #[error("journal error: {0}")]
    JournalError(#[from] crate::journal::Error),
    #[cfg(feature = "std")]
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("missing node: {0}")]
    MissingNode(Position),
    #[error("invalid proof")]
    InvalidProof,
    #[error("root mismatch")]
    RootMismatch,
    #[error("element pruned: {0}")]
    ElementPruned(Position),
    #[error("position is not a leaf: {0}")]
    PositionNotLeaf(Position),
    #[error("invalid position: {0}")]
    InvalidPosition(Position),
    #[error("missing digest: {0}")]
    MissingDigest(Position),
    #[error("missing grafted leaf digest: {0}")]
    MissingGraftedLeaf(Position),
    #[error("invalid proof length")]
    InvalidProofLength,
    #[error("invalid size: {0}")]
    InvalidSize(u64),
    #[error("empty")]
    Empty,
    #[error("pruned chunks causes u64 overflow")]
    PrunedChunksOverflow,
    #[error("location {0} > MAX_LOCATION")]
    LocationOverflow(Location),
    #[error("range out of bounds: end location {0} exceeds MMR size")]
    RangeOutOfBounds(Location),
    #[error("mmr requires merkleization for requested size")]
    Unmerkleized,
    #[error("leaf location out of bounds: {0}")]
    LeafOutOfBounds(Location),
    #[error("bit offset {0} out of bounds (size: {1})")]
    BitOutOfBounds(u64, u64),
    #[error("invalid pinned nodes")]
    InvalidPinnedNodes,
    #[error("data corrupted: {0}")]
    DataCorrupted(&'static str),
}

impl From<LocationError> for Error {
    fn from(err: LocationError) -> Self {
        match err {
            LocationError::NonLeaf(pos) => Self::PositionNotLeaf(pos),
            LocationError::Overflow(pos) => Self::InvalidPosition(pos),
        }
    }
}

impl From<merkle::LocationConversionError<Mmr>> for Error {
    fn from(err: merkle::LocationConversionError<Mmr>) -> Self {
        match err {
            merkle::LocationConversionError::Overflow(loc) => Self::LocationOverflow(loc),
        }
    }
}
