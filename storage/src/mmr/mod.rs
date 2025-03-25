//! A Merkle Mountain Range (MMR) is an append-only data structure that allows for efficient
//! verification of the inclusion of an element, or some range of consecutive elements, in a list.
//!
//! # Terminology
//!
//! An MMR is a list of perfect binary trees (aka "mountains") of strictly decreasing height. The
//! roots of these trees are called the "peaks" of the MMR. Each "element" stored in the MMR is
//! represented by some leaf node in one of these perfect trees, storing a positioned hash of the
//! element. Non-leaf nodes store a positioned hash of their children.
//!
//! The "size" of an MMR is the total number of nodes summed over all trees.
//!
//! The nodes of the MMR are ordered by a post-order traversal of the MMR trees, starting from the
//! from tallest tree to shortest. The "position" of a node in the MMR is defined as the 0-based
//! index of the node in this ordering. This implies the positions of elements, which are always
//! leaves, may not be contiguous even if they were consecutively added. An element's "number" is
//! its 0-based index in the order of element insertion. In the example below, the right-most
//! element has position 18 and number 10.
//!
//! As the MMR is an append-only data structure, node positions never change and can be used as
//! stable identifiers.
//!
//! The "height" of a node is 0 for a leaf, 1 for the parent of 2 leaves, and so on.
//!
//! The "root hash" of an MMR is the result of hashing together the size of the MMR and the hashes
//! of every peak in decreasing order of height.
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
//! Number   0   1 2   3  4   5  6   7  8   9 10
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
//!       Hash(5, Hash(3, element_2), Hash(4, element_4))
//!     )
//!     Hash(13,
//!       Hash(9, Hash(7, element_0), Hash(8, element_8)),
//!       Hash(12, Hash(10, element_10), Hash(11, element_11))
//!     )
//!   )
//!   Hash(17, Hash(15, element_15), Hash(16, element_16))      // second peak
//!   Hash(18, element_18)                                      // third peak
//! )
//! ```

use commonware_utils::array::prefixed_u64::U64;
use thiserror::Error;

pub mod bitmap;
mod hasher;
mod iterator;
pub mod journaled;
pub mod mem;
pub mod mutable;
pub mod verification;

/// Errors that can occur when interacting with an MMR.
#[derive(Error, Debug)]
pub enum Error {
    #[error("an element required for this operation has been pruned: {0}")]
    ElementPruned(u64),
    #[error("metadata error: {0}")]
    MetadataError(#[from] crate::metadata::Error<U64>),
    #[error("journal error: {0}")]
    JournalError(#[from] crate::journal::Error),
    #[error("missing node: {0}")]
    MissingNode(u64),
    #[error("MMR is empty")]
    Empty,
    #[error("missing hashes in proof")]
    MissingHashes,
    #[error("extra hashes in proof")]
    ExtraHashes,
    #[error("invalid update")]
    InvalidUpdate,
}
