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
//! The _root digest_ (or just _root_) of an MMR is computed as `Hash(leaves || fold(peaks))`,
//! where `fold` left-folds peak digests in decreasing order of height using `Hash(acc || peak)`.
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
//! The root hash in this example is computed as `Hash(11 || fold(peak1, peak2, peak3))`:
//!
//! ```text
//! peak1 = Hash(14,                                            // tallest peak
//!           Hash(6,
//!             Hash(2, Hash(0, element_0), Hash(1, element_1)),
//!             Hash(5, Hash(3, element_2), Hash(4, element_3))),
//!           Hash(13,
//!             Hash(9, Hash(7, element_4), Hash(8, element_5)),
//!             Hash(12, Hash(10, element_6), Hash(11, element_7))))
//! peak2 = Hash(17, Hash(15, element_8), Hash(16, element_9))  // middle peak
//! peak3 = Hash(18, element_10)                                // shortest peak
//!
//! acc   = fold(peak1, peak2, peak3)
//!       = Hash(Hash(peak1 || peak2) || peak3)
//! root  = Hash(11 || acc)                                     // 11 = leaf count
//! ```

pub mod batch;
pub mod iterator;
pub mod mem;
pub mod proof;
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod journaled;
        pub mod verification;
    }
}

pub use super::proof::MAX_PROOF_DIGESTS_PER_ELEMENT;
use crate::merkle::{self, Family as _, Graftable};
pub use crate::merkle::{hasher, Readable};
pub use batch::{MerkleizedBatch, UnmerkleizedBatch};

/// MMR-specific type alias for `merkle::proof::Proof`.
pub type Proof<D> = merkle::proof::Proof<Family, D>;

/// A node index or node count in an MMR.
pub type Position = merkle::Position<Family>;

/// A leaf index or leaf count in an MMR.
pub type Location = merkle::Location<Family>;

pub type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Errors that can occur when interacting with an MMR.
pub type Error = merkle::Error<Family>;

/// Marker type for the MMR family.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Family;

impl merkle::Family for Family {
    /// Maximum valid position: the largest MMR size for 2^62 leaves is `2^63 - 1`.
    const MAX_NODES: Position = Position::new(0x7FFFFFFFFFFFFFFF); // (1 << 63) - 1

    /// Maximum valid location: the largest leaf count is `2^62`.
    const MAX_LEAVES: Location = Location::new(0x4000_0000_0000_0000); // 2^62

    fn location_to_position(loc: Location) -> Position {
        let loc = *loc;
        // 2*N - popcount(N)
        Position::new(
            loc.checked_mul(2)
                .expect("should not overflow for valid leaf index")
                - loc.count_ones() as u64,
        )
    }

    fn position_to_location(pos: Position) -> Option<Location> {
        let pos = *pos;
        // Position 0 is always the first leaf at location 0.
        if pos == 0 {
            return Some(Location::new(0));
        }

        // Find the height of the perfect binary tree containing this position.
        // Safe: pos + 1 cannot overflow since pos <= MAX_NODES (checked by caller).
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

        Some(Location::new(leaf_loc_floor))
    }

    fn to_nearest_size(size: Position) -> Position {
        iterator::PeakIterator::to_nearest_size(size)
    }

    fn peaks(size: Position) -> impl Iterator<Item = (Position, u32)> {
        iterator::PeakIterator::new(size)
    }

    fn children(pos: Position, height: u32) -> (Position, Position) {
        (pos - (1 << height), pos - 1)
    }

    fn parent_heights(leaves: Location) -> impl Iterator<Item = u32> {
        let count = (*leaves).trailing_ones();
        1..=count
    }

    fn pos_to_height(pos: Position) -> u32 {
        iterator::pos_to_height(pos)
    }

    fn is_valid_size(size: Position) -> bool {
        let size = *size;
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

impl Graftable for Family {
    fn chunk_peaks(
        size: Position,
        chunk_idx: u64,
        grafting_height: u32,
    ) -> impl Iterator<Item = (Position, u32)> {
        let chunk_end_loc = Location::new((chunk_idx + 1) << grafting_height);
        let chunk_end_pos = Position::try_from(chunk_end_loc).expect("chunk_peaks: chunk overflow");
        assert!(
            chunk_end_pos <= size,
            "chunk's leaf range exceeds the structure's leaf count"
        );

        // In an MMR, every aligned chunk of 2^h leaves has exactly one subtree root at height h.
        let first_leaf_loc = Location::new(chunk_idx << grafting_height);
        let first_leaf_pos =
            Position::try_from(first_leaf_loc).expect("chunk_peaks: chunk overflow");
        let root_pos = Position::new(*first_leaf_pos + (1u64 << (grafting_height + 1)) - 2);

        core::iter::once((root_pos, grafting_height))
    }

    fn subtree_root_position(leaf_start: Location, height: u32) -> Position {
        let leaf_pos = Self::location_to_position(leaf_start);
        let shift = 1u64
            .checked_shl(height + 1)
            .expect("height excessively large");

        leaf_pos
            .checked_add(shift)
            .and_then(|v| v.checked_sub(2))
            .expect("position overflow")
    }

    fn leftmost_leaf(pos: Position, height: u32) -> Location {
        let shift = 1u64
            .checked_shl(height + 1)
            .expect("height excessively large");
        let leftmost_pos = pos
            .checked_add(2)
            .and_then(|v| v.checked_sub(shift))
            .expect("position underflow or overflow");

        Self::position_to_location(leftmost_pos).expect("leftmost descendant must be a leaf")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;

    const MAX_NODES: Position = <Family as crate::merkle::Family>::MAX_NODES;
    const MAX_LEAVES: Location = <Family as crate::merkle::Family>::MAX_LEAVES;

    // --- Position tests ---

    #[test]
    fn test_from_location() {
        const CASES: &[(Location, Position)] = &[
            (Location::new(0), Position::new(0)),
            (Location::new(1), Position::new(1)),
            (Location::new(2), Position::new(3)),
            (Location::new(3), Position::new(4)),
            (Location::new(4), Position::new(7)),
            (Location::new(5), Position::new(8)),
            (Location::new(6), Position::new(10)),
            (Location::new(7), Position::new(11)),
            (Location::new(8), Position::new(15)),
            (Location::new(9), Position::new(16)),
            (Location::new(10), Position::new(18)),
            (Location::new(11), Position::new(19)),
            (Location::new(12), Position::new(22)),
            (Location::new(13), Position::new(23)),
            (Location::new(14), Position::new(25)),
            (Location::new(15), Position::new(26)),
        ];
        for (loc, expected_pos) in CASES {
            let pos = Position::try_from(*loc).unwrap();
            assert_eq!(pos, *expected_pos);
        }
    }

    #[test]
    fn test_position_checked_add() {
        let pos = Position::new(10);
        assert_eq!(pos.checked_add(5).unwrap(), 15);
        assert!(Position::new(u64::MAX).checked_add(1).is_none());
        assert!(MAX_NODES.checked_add(1).is_none());
        assert!(Position::new(*MAX_NODES - 5).checked_add(10).is_none());
        // MAX_NODES - 10 + 10 = MAX_NODES, which IS valid (inclusive bound)
        assert_eq!(
            Position::new(*MAX_NODES - 10).checked_add(10).unwrap(),
            *MAX_NODES
        );
        // MAX_NODES - 11 + 10 = MAX_NODES - 1, also valid
        assert_eq!(
            Position::new(*MAX_NODES - 11).checked_add(10).unwrap(),
            *MAX_NODES - 1
        );
    }

    #[test]
    fn test_position_checked_sub() {
        let pos = Position::new(10);
        assert_eq!(pos.checked_sub(5).unwrap(), 5);
        assert!(pos.checked_sub(11).is_none());
    }

    #[test]
    fn test_position_saturating_add() {
        let pos = Position::new(10);
        assert_eq!(pos.saturating_add(5), 15);
        // Saturates AT MAX_NODES (inclusive bound)
        assert_eq!(Position::new(u64::MAX).saturating_add(1), *MAX_NODES);
        assert_eq!(MAX_NODES.saturating_add(1), *MAX_NODES);
        assert_eq!(MAX_NODES.saturating_add(1000), *MAX_NODES);
        assert_eq!(Position::new(*MAX_NODES - 5).saturating_add(10), *MAX_NODES);
    }

    #[test]
    fn test_position_saturating_sub() {
        let pos = Position::new(10);
        assert_eq!(pos.saturating_sub(5), 5);
        assert_eq!(Position::new(0).saturating_sub(1), 0);
    }

    #[test]
    fn test_position_display() {
        assert_eq!(Position::new(42).to_string(), "Position(42)");
    }

    #[test]
    fn test_position_add() {
        assert_eq!(Position::new(10) + Position::new(5), 15);
    }

    #[test]
    fn test_position_sub() {
        assert_eq!(Position::new(10) - Position::new(3), 7);
    }

    #[test]
    fn test_position_comparison_with_u64() {
        let pos = Position::new(42);
        assert_eq!(pos, 42u64);
        assert_eq!(42u64, pos);
        assert_ne!(pos, 43u64);
        assert!(pos < 43u64);
        assert!(43u64 > pos);
        assert!(pos > 41u64);
        assert!(pos <= 42u64);
        assert!(42u64 >= pos);
    }

    #[test]
    fn test_position_assignment_with_u64() {
        let mut pos = Position::new(10);
        pos += 5;
        assert_eq!(pos, 15u64);
        pos -= 3;
        assert_eq!(pos, 12u64);
    }

    #[test]
    fn test_max_position() {
        let max_leaves = 1u64 << 62;
        let max_size = 2 * max_leaves - 1;
        assert_eq!(*MAX_NODES, max_size);
        assert_eq!(*MAX_NODES, (1u64 << 63) - 1);
        assert_eq!(max_size.leading_zeros(), 1);

        let overflow_size = 2 * (max_leaves + 1) - 1;
        assert_eq!(overflow_size.leading_zeros(), 0);

        // MAX_LEAVES is a valid location (inclusive bound), and converts to MAX_NODES.
        let pos = Position::try_from(MAX_LEAVES).unwrap();
        assert_eq!(pos, MAX_NODES);
    }

    #[test]
    fn test_is_valid_size() {
        let mut size_to_check = Position::new(0);
        let hasher = StandardHasher::<Sha256>::new();
        let mut mmr = mem::Mmr::new(&hasher);
        let digest = [1u8; 32];
        for _i in 0..10000 {
            while size_to_check != mmr.size() {
                assert!(
                    !size_to_check.is_valid_size(),
                    "size_to_check: {} {}",
                    size_to_check,
                    mmr.size()
                );
                size_to_check += 1;
            }
            assert!(size_to_check.is_valid_size());
            let batch = {
                let mut batch = mmr.new_batch();
                batch = batch.add(&hasher, &digest);
                batch.merkleize(&mmr, &hasher)
            };
            mmr.apply_batch(&batch).unwrap();
            size_to_check += 1;
        }
        assert!(!Position::new(u64::MAX).is_valid_size());
        assert!(Position::new(u64::MAX >> 1).is_valid_size());
        assert!(!Position::new((u64::MAX >> 1) + 1).is_valid_size());
        assert!(MAX_NODES.is_valid_size());
    }

    #[test]
    fn test_position_read_cfg_valid_values() {
        use commonware_codec::{Encode, ReadExt};

        let pos = Position::new(0);
        assert_eq!(Position::read(&mut pos.encode().as_ref()).unwrap(), pos);

        let pos = Position::new(12345);
        assert_eq!(Position::read(&mut pos.encode().as_ref()).unwrap(), pos);

        // MAX_NODES is a valid value (inclusive bound), so it should decode successfully
        assert_eq!(
            Position::read(&mut MAX_NODES.encode().as_ref()).unwrap(),
            MAX_NODES
        );

        let pos = MAX_NODES - 1;
        assert_eq!(Position::read(&mut pos.encode().as_ref()).unwrap(), pos);
    }

    #[test]
    fn test_position_read_cfg_invalid_values() {
        use commonware_codec::{varint::UInt, Encode, ReadExt};

        let encoded = UInt(*MAX_NODES + 1).encode();
        assert!(matches!(
            Position::read(&mut encoded.as_ref()),
            Err(commonware_codec::Error::Invalid("Position", _))
        ));

        let encoded = UInt(u64::MAX).encode();
        assert!(matches!(
            Position::read(&mut encoded.as_ref()),
            Err(commonware_codec::Error::Invalid("Position", _))
        ));
    }

    // --- Location tests ---

    #[test]
    fn test_try_from_position() {
        const CASES: &[(Position, Location)] = &[
            (Position::new(0), Location::new(0)),
            (Position::new(1), Location::new(1)),
            (Position::new(3), Location::new(2)),
            (Position::new(4), Location::new(3)),
            (Position::new(7), Location::new(4)),
            (Position::new(8), Location::new(5)),
            (Position::new(10), Location::new(6)),
            (Position::new(11), Location::new(7)),
            (Position::new(15), Location::new(8)),
            (Position::new(16), Location::new(9)),
            (Position::new(18), Location::new(10)),
            (Position::new(19), Location::new(11)),
            (Position::new(22), Location::new(12)),
            (Position::new(23), Location::new(13)),
            (Position::new(25), Location::new(14)),
            (Position::new(26), Location::new(15)),
        ];
        for (pos, expected_loc) in CASES {
            let loc = Location::try_from(*pos).expect("should map to a leaf location");
            assert_eq!(loc, *expected_loc);
        }
    }

    #[test]
    fn test_try_from_position_error() {
        const CASES: &[Position] = &[
            Position::new(2),
            Position::new(5),
            Position::new(6),
            Position::new(9),
            Position::new(12),
            Position::new(13),
            Position::new(14),
            Position::new(17),
            Position::new(20),
            Position::new(21),
            Position::new(24),
            Position::new(27),
            Position::new(28),
            Position::new(29),
            Position::new(30),
        ];
        for &pos in CASES {
            assert!(matches!(
                Location::try_from(pos).unwrap_err(),
                merkle::Error::NonLeaf(p) if p == pos
            ));
        }
    }

    #[test]
    fn test_try_from_position_error_overflow() {
        let overflow_pos = Position::new(u64::MAX);
        assert!(matches!(
            Location::try_from(overflow_pos).unwrap_err(),
            merkle::Error::PositionOverflow(p) if p == overflow_pos
        ));

        // MAX_NODES is a valid position (inclusive bound) and converts to MAX_LEAVES.
        let loc = Location::try_from(MAX_NODES).unwrap();
        assert_eq!(loc, MAX_LEAVES);

        let overflow_pos = MAX_NODES + 1;
        assert!(matches!(
            Location::try_from(overflow_pos).unwrap_err(),
            merkle::Error::PositionOverflow(p) if p == overflow_pos
        ));
    }

    #[test]
    fn test_location_checked_add() {
        let loc = Location::new(10);
        assert_eq!(loc.checked_add(5).unwrap(), 15);
        assert!(Location::new(u64::MAX).checked_add(1).is_none());
        assert!(MAX_LEAVES.checked_add(1).is_none());
        // MAX_LEAVES - 10 + 10 = MAX_LEAVES, which IS valid (inclusive bound)
        let loc = Location::new(*MAX_LEAVES - 10);
        assert_eq!(loc.checked_add(10).unwrap(), *MAX_LEAVES);
        // MAX_LEAVES - 11 + 10 = MAX_LEAVES - 1, also valid
        let loc = Location::new(*MAX_LEAVES - 11);
        assert_eq!(loc.checked_add(10).unwrap(), *MAX_LEAVES - 1);
    }

    #[test]
    fn test_location_checked_sub() {
        let loc = Location::new(10);
        assert_eq!(loc.checked_sub(5).unwrap(), 5);
        assert!(loc.checked_sub(11).is_none());
    }

    #[test]
    fn test_location_saturating_add() {
        let loc = Location::new(10);
        assert_eq!(loc.saturating_add(5), 15);
        // Saturates AT MAX_LEAVES (inclusive bound)
        assert_eq!(Location::new(u64::MAX).saturating_add(1), *MAX_LEAVES);
        assert_eq!(MAX_LEAVES.saturating_add(1), *MAX_LEAVES);
        assert_eq!(MAX_LEAVES.saturating_add(1000), *MAX_LEAVES);
    }

    #[test]
    fn test_location_saturating_sub() {
        let loc = Location::new(10);
        assert_eq!(loc.saturating_sub(5), 5);
        assert_eq!(Location::new(0).saturating_sub(1), 0);
    }

    #[test]
    fn test_location_display() {
        assert_eq!(Location::new(42).to_string(), "Location(42)");
    }

    #[test]
    fn test_location_add() {
        assert_eq!(Location::new(10) + Location::new(5), 15);
    }

    #[test]
    fn test_location_sub() {
        assert_eq!(Location::new(10) - Location::new(3), 7);
    }

    #[test]
    fn test_location_comparison_with_u64() {
        let loc = Location::new(42);
        assert_eq!(loc, 42u64);
        assert_eq!(42u64, loc);
        assert_ne!(loc, 43u64);
        assert!(loc < 43u64);
        assert!(43u64 > loc);
        assert!(loc > 41u64);
        assert!(loc <= 42u64);
        assert!(42u64 >= loc);
    }

    #[test]
    fn test_location_assignment_with_u64() {
        let mut loc = Location::new(10);
        loc += 5;
        assert_eq!(loc, 15u64);
        loc -= 3;
        assert_eq!(loc, 12u64);
    }

    #[test]
    fn test_location_is_valid() {
        assert!(Location::new(0).is_valid());
        assert!(Location::new(1000).is_valid());
        // MAX_LEAVES IS valid (inclusive bound)
        assert!(MAX_LEAVES.is_valid());
        assert!((MAX_LEAVES - 1).is_valid());
        assert!(!Location::new(*MAX_LEAVES + 1).is_valid());
        assert!(!Location::new(u64::MAX).is_valid());
    }

    #[test]
    fn test_max_location_boundary() {
        // MAX_LEAVES IS valid (inclusive bound) and round-trips through Position as MAX_NODES.
        assert!(MAX_LEAVES.is_valid());
        let pos = Position::try_from(MAX_LEAVES).unwrap();
        assert_eq!(pos, MAX_NODES);
        assert!(pos.is_valid());

        let loc = Location::try_from(pos).unwrap();
        assert_eq!(loc, MAX_LEAVES);
    }

    #[test]
    fn test_overflow_location_returns_error() {
        let over_loc = Location::new(*MAX_LEAVES + 1);
        assert!(!over_loc.is_valid());
        assert!(matches!(
            Position::try_from(over_loc).unwrap_err(),
            merkle::Error::LocationOverflow(l) if l == over_loc
        ));
    }

    #[test]
    fn test_location_read_cfg_valid_values() {
        use commonware_codec::{Encode, ReadExt};

        let loc = Location::new(0);
        assert_eq!(Location::read(&mut loc.encode().as_ref()).unwrap(), loc);

        let loc = Location::new(12345);
        assert_eq!(Location::read(&mut loc.encode().as_ref()).unwrap(), loc);

        // MAX_LEAVES is a valid value (inclusive bound), so it should decode successfully
        assert_eq!(
            Location::read(&mut MAX_LEAVES.encode().as_ref()).unwrap(),
            MAX_LEAVES
        );

        let loc = MAX_LEAVES - 1;
        assert_eq!(Location::read(&mut loc.encode().as_ref()).unwrap(), loc);
    }

    #[test]
    fn test_location_read_cfg_invalid_values() {
        use commonware_codec::{varint::UInt, Encode, ReadExt};

        let encoded = UInt(*MAX_LEAVES + 1).encode();
        assert!(matches!(
            Location::read(&mut encoded.as_ref()),
            Err(commonware_codec::Error::Invalid("Location", _))
        ));

        let encoded = UInt(u64::MAX).encode();
        assert!(matches!(
            Location::read(&mut encoded.as_ref()),
            Err(commonware_codec::Error::Invalid("Location", _))
        ));
    }

    #[test]
    fn test_pos_to_height() {
        // Verify pos_to_height for every node by tracking positions as they are appended. Each step
        // appends a leaf (height 0) then parents with heights from parent_heights.
        let mut next_pos = 0u64;
        for leaf_idx in 0u64..500 {
            let loc = Location::new(leaf_idx);
            // The leaf itself.
            assert_eq!(
                Family::pos_to_height(Position::new(next_pos)),
                0,
                "leaf at pos {next_pos} (loc {leaf_idx}) should be height 0"
            );
            next_pos += 1;

            // Parents created when this leaf is appended.
            for h in Family::parent_heights(loc) {
                assert_eq!(
                    Family::pos_to_height(Position::new(next_pos)),
                    h,
                    "parent at pos {next_pos} (born at loc {leaf_idx}) should be height {h}"
                );
                next_pos += 1;
            }
        }
    }

    #[test]
    fn test_chunk_peaks() {
        let hasher = StandardHasher::<Sha256>::new();
        let mut mmr = mem::Mmr::new(&hasher);
        let digest = [1u8; 32];

        // Build an MMR with 200 leaves.
        for _ in 0..200 {
            let merkleized = mmr
                .new_batch()
                .add(&hasher, &digest)
                .merkleize(&mmr, &hasher);
            mmr.apply_batch(&merkleized).unwrap();
        }
        let size = mmr.size();

        for grafting_height in 1..6 {
            let chunk_size = 1u64 << grafting_height;
            let num_chunks = 200 / chunk_size;

            for chunk_idx in 0..num_chunks {
                let peaks: Vec<_> = Family::chunk_peaks(size, chunk_idx, grafting_height).collect();

                // MMR always returns exactly one peak at the grafting height.
                assert_eq!(
                    peaks.len(),
                    1,
                    "MMR chunk_peaks should return 1 item (gh={grafting_height}, chunk={chunk_idx})"
                );
                assert_eq!(
                    peaks[0].1, grafting_height,
                    "peak should be at grafting height"
                );

                // The peak should be retrievable from the MMR.
                assert!(
                    mmr.get_node(peaks[0].0).is_some(),
                    "chunk peak not in MMR at pos {}",
                    peaks[0].0
                );
            }
        }
    }

    #[test]
    fn test_subtree_root_position() {
        // Verify subtree_root_position produces actual node positions by checking every node in a
        // growing MMR.
        let mut next_pos = 0u64;
        for leaf_idx in 0u64..500 {
            let leaf_pos = Family::subtree_root_position(Location::new(leaf_idx), 0);
            assert_eq!(
                *leaf_pos, next_pos,
                "height-0 subtree_root_position mismatch at leaf {leaf_idx}"
            );
            next_pos += 1;

            // For each parent created at this step, verify subtree_root_position matches the actual
            // position. In an MMR, a height-h parent covers 2^h leaves ending at leaf_idx, so its
            // leftmost leaf = leaf_idx + 1 - 2^h.
            for h in Family::parent_heights(Location::new(leaf_idx)) {
                let leftmost = leaf_idx + 1 - (1u64 << h);
                let pos = Family::subtree_root_position(Location::new(leftmost), h);
                assert_eq!(
                    *pos, next_pos,
                    "height-{h} subtree_root_position mismatch at leaf {leaf_idx}"
                );
                next_pos += 1;
            }
        }
    }

    #[test]
    fn test_leftmost_leaf() {
        // Verify leftmost_leaf is consistent with subtree_root_position:
        // `subtree_root_position(leftmost_leaf(pos, h), h) == pos`.
        let hasher = StandardHasher::<Sha256>::new();
        let mut mmr = mem::Mmr::new(&hasher);
        let digest = [1u8; 32];
        for _ in 0..200 {
            let merkleized = mmr
                .new_batch()
                .add(&hasher, &digest)
                .merkleize(&mmr, &hasher);
            mmr.apply_batch(&merkleized).unwrap();
        }
        for (peak_pos, peak_height) in Family::peaks(mmr.size()) {
            let ll = Family::leftmost_leaf(peak_pos, peak_height);
            let roundtrip = Family::subtree_root_position(ll, peak_height);
            assert_eq!(
                roundtrip, peak_pos,
                "roundtrip failed for pos={peak_pos} height={peak_height}"
            );
        }
    }
}
