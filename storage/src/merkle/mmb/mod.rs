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
//! positions](iterator::PeakIterator) are NOT monotonically ordered by physical position even
//! though they are yielded in oldest-to-newest order (non-increasing height).
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
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod journaled;
    }
}

pub use crate::merkle::Readable;
use crate::{
    merkle,
    merkle::{Family as _, Graftable},
};
pub use batch::{Changeset, MerkleizedBatch, UnmerkleizedBatch};

/// MMB-specific type alias for `merkle::proof::Proof`.
pub type Proof<D> = merkle::proof::Proof<Family, D>;

/// A node index or node count in an MMB.
pub type Position = merkle::Position<Family>;

/// A leaf index or leaf count in an MMB.
pub type Location = merkle::Location<Family>;

pub type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Errors that can occur during MMB operations.
pub type Error = merkle::Error<Family>;

/// Marker type for the MMB family.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Family;

impl merkle::Family for Family {
    /// Maximum valid position (node count): `2^63 - 2` (the size for `2^62 + 30` leaves).
    const MAX_NODES: Position = Position::new(0x7FFF_FFFF_FFFF_FFFE);

    /// Maximum valid location (leaf count): `2^62 + 30`.
    const MAX_LEAVES: Location = Location::new(0x4000_0000_0000_001E);

    fn location_to_position(loc: Location) -> Position {
        let loc = loc.as_u64();
        // 2*N - ilog2(N+1) for MMB
        Position::new(2 * loc - (loc + 1).ilog2() as u64)
    }

    fn position_to_location(pos: Position) -> Option<Location> {
        let pos = pos.as_u64();
        // Solve 2*N - ilog2(N+1) = pos for N.
        // Starting estimate: N ~ (pos + ilog2(N+1)) / 2 ~ pos/2. One refinement gives accuracy
        // within -1 if the input is a valid leaf position, so the loop body runs at most twice.
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

    fn peaks(size: Position) -> impl Iterator<Item = (Position, u32)> {
        iterator::PeakIterator::new(size)
    }

    fn children(pos: Position, height: u32) -> (Position, Position) {
        iterator::children(pos, height)
    }

    fn is_valid_size(size: Position) -> bool {
        Location::try_from(size).is_ok()
    }

    fn parent_heights(leaves: Location) -> impl Iterator<Item = u32> {
        let leaf = *leaves;
        let height = if (leaf + 2).is_power_of_two() {
            None
        } else {
            Some((leaf + 1).trailing_ones() + 1)
        };
        height.into_iter()
    }

    fn pos_to_height(pos: Position) -> u32 {
        // If position_to_location succeeds, it's a leaf (height 0).
        if Self::position_to_location(pos).is_some() {
            return 0;
        }

        // Parent node: its birth leaf is at position pos - 1.
        let birth = Self::position_to_location(Position::new(*pos - 1))
            .expect("position is neither leaf nor parent");

        // Height from the merge schedule: h = trailing_ones(birth + 1) + 1.
        (*birth + 1).trailing_ones() + 1
    }
}

impl Graftable for Family {
    fn leftmost_leaf(pos: Position, height: u32) -> Location {
        if height == 0 {
            return Self::position_to_location(pos).expect("height-0 node must be a leaf");
        }

        // Recover birth leaf from position, then compute leftmost via the closed-form: `leftmost =
        // birth - (3·2^(h-1) - 2)`.
        let prev_pos = pos.checked_sub(1).expect("position underflow");
        let birth =
            Self::position_to_location(prev_pos).expect("position is neither leaf nor parent");

        let term = 3u64
            .checked_shl(height - 1)
            .and_then(|v| v.checked_sub(2))
            .expect("height excessively large");

        birth.checked_sub(term).expect("location underflow")
    }

    fn subtree_root_position(leaf_start: Location, height: u32) -> Position {
        if height == 0 {
            return Self::location_to_position(leaf_start);
        }

        // birth_leaf = leaf_start + 3·2^(h-1) - 2 (derived by substituting last_leaf = leaf_start +
        // 2^h - 1 into birth_leaf = last_leaf + 2^(h-1) - 1)
        let offset = 3u64
            .checked_shl(height - 1)
            .and_then(|v| v.checked_sub(2))
            .expect("height excessively large");
        let birth_leaf = leaf_start.checked_add(offset).expect("location overflow");

        let birth_pos = Self::location_to_position(birth_leaf);
        birth_pos.checked_add(1).expect("position overflow")
    }

    fn chunk_peaks(
        size: Position,
        chunk_idx: u64,
        grafting_height: u32,
    ) -> impl Iterator<Item = (Position, u32)> {
        let chunk_size = 1u64 << grafting_height;
        let chunk_start = chunk_idx * chunk_size;
        let chunk_end = chunk_start + chunk_size;

        let n = *Location::try_from(size).expect("chunk_peaks: invalid size");
        assert!(
            chunk_end <= n,
            "chunk's leaf range exceeds the structure's leaf count"
        );

        // --- Find the first peak whose leaf range contains chunk_start ---
        //
        // An MMB with N leaves has p = ilog2(N+1) peaks. Let M = N+1. Peak k (0 = oldest) has
        // height h_k = (p-1-k) + bit(M, p-1-k) and covers 2^{h_k} leaves. The cumulative leaf count
        // after k peaks is:
        //
        //   S(k) = sum_{j=0}^{k-1} 2^{h_j}
        //
        // Substituting x = p - k (peaks remaining), this simplifies to:
        //
        //   S(k) = M - 2^x - (M mod 2^x)
        //
        // We want the first peak containing chunk_start, i.e. the largest k where S(k) <=
        // chunk_start. Rearranging:
        //
        //   M - chunk_start <= 2^x + (M mod 2^x)
        //
        // Since the RHS grows with x, we find the smallest qualifying x via ilog2 of the LHS, with
        // at most one correction step.
        let m = n + 1;
        let p = m.ilog2(); // number of peaks

        let diff = m - chunk_start;
        let maybe_x = diff.ilog2();
        let x_power = 1u64 << maybe_x;
        let x = if diff <= x_power + (m & (x_power - 1)) {
            maybe_x
        } else {
            maybe_x + 1
        };
        let lo = p - x;

        // --- Lazily iterate the covering peaks ---
        //
        // Starting from peak lo, walk peaks rightward until we pass the chunk. Each peak either
        // fits within the chunk (height <= gh) or entirely contains it (height > gh). Partial
        // overlaps are impossible because both peak starts and chunk boundaries are multiples of
        // their respective sizes (powers of two in non-increasing order).
        //
        // Node positions are computed using the birth-leaf formula: any MMB node at height h
        // covering leaves [s, s + 2^h) was born at leaf (s + 2^h - 1) + (2^(h-1) - 1), giving:
        // `position = location_to_position(birth_leaf) + 1`. For h = 0, the node is a bare leaf at
        // `location_to_position(s)`.
        let initial_cursor = m - (1u64 << x) - (m & ((1u64 << x) - 1));
        let mut leaf_cursor = initial_cursor;

        (lo..p).map_while(move |k| {
            let i = p - 1 - k;
            let height = i as u64 + ((m >> i) & 1);
            let peak_leaves = 1u64 << height;
            let peak_start = leaf_cursor;
            let peak_end = peak_start + peak_leaves;
            leaf_cursor = peak_end;

            if peak_start >= chunk_end {
                return None;
            }

            let (pos, h) = if height <= grafting_height as u64 {
                // Peak fits entirely within the chunk.
                let last_leaf = peak_end - 1;
                if height == 0 {
                    (Self::location_to_position(Location::new(last_leaf)), 0)
                } else {
                    let birth = last_leaf + (1u64 << (height - 1)) - 1;
                    let pos = Position::new(
                        Self::location_to_position(Location::new(birth)).as_u64() + 1,
                    );
                    (pos, height as u32)
                }
            } else if grafting_height == 0 {
                // Chunk is a single leaf.
                (Self::location_to_position(Location::new(chunk_start)), 0)
            } else {
                // Peak entirely contains the chunk. Compute the height-gh sub-node via the
                // birth-leaf formula.
                let chunk_last_leaf = chunk_end - 1;
                let birth = chunk_last_leaf + (1u64 << (grafting_height - 1)) - 1;
                let pos =
                    Position::new(Self::location_to_position(Location::new(birth)).as_u64() + 1);
                (pos, grafting_height)
            };

            Some((pos, h))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmb::mem::Mmb;
    use commonware_cryptography::Sha256;

    /// Verify the MMB merge schedule via `Family::parent_heights`.
    #[test]
    fn test_parent_heights_schedule() {
        let expected: [Option<u32>; 16] = [
            None,    // loc=0:  0+2=2=2^1
            Some(1), // loc=1
            None,    // loc=2:  2+2=4=2^2
            Some(1), // loc=3
            Some(2), // loc=4
            Some(1), // loc=5
            None,    // loc=6:  6+2=8=2^3
            Some(1), // loc=7
            Some(2), // loc=8
            Some(1), // loc=9
            Some(3), // loc=10
            Some(1), // loc=11
            Some(2), // loc=12
            Some(1), // loc=13
            None,    // loc=14: 14+2=16=2^4
            Some(1), // loc=15
        ];

        for (i, expected) in expected.iter().enumerate() {
            let loc = Location::new(i as u64);
            let height: Option<u32> = crate::merkle::Family::parent_heights(loc).next();
            assert_eq!(height, *expected, "mismatch at loc={i}");
        }
    }

    #[test]
    fn test_pos_to_height() {
        // Verify pos_to_height for every node by tracking positions as they are appended. Each step
        // appends a leaf (height 0) and optionally a parent (height from parent_heights).
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

            // Optional parent (MMB creates at most one parent per leaf).
            if let Some(h) = Family::parent_heights(loc).next() {
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
    fn test_leftmost_leaf() {
        // Verify leftmost_leaf is consistent with subtree_root_position:
        // subtree_root_position(leftmost_leaf(pos, h), h) == pos.
        let hasher = StandardHasher::<Sha256>::new();
        let mut mmb = Mmb::new(&hasher);
        let digest = [1u8; 32];
        for _ in 0..200 {
            let changeset = mmb
                .new_batch()
                .add(&hasher, &digest)
                .merkleize(&hasher)
                .finalize();
            mmb.apply(changeset).unwrap();
        }
        for (peak_pos, peak_height) in Family::peaks(mmb.size()) {
            let ll = Family::leftmost_leaf(peak_pos, peak_height);
            let roundtrip = Family::subtree_root_position(ll, peak_height);
            assert_eq!(
                roundtrip, peak_pos,
                "roundtrip failed for pos={peak_pos} height={peak_height}"
            );
        }
    }

    #[test]
    fn test_subtree_root_position_virtual_roundtrip() {
        // Verify the round-trip for subtree positions that may not correspond to any physical node
        // in the MMB. For example, in the 8-leaf MMB with grafting height 2, chunk 1 (leaves [4,8))
        // has no single height-2 node, but subtree_root_position still produces a deterministic
        // position that round-trips through leftmost_leaf.
        for height in 0u32..10 {
            let chunk_size = 1u64 << height;
            for chunk_idx in 0u64..200 {
                let leaf_start = Location::new(chunk_idx * chunk_size);
                let pos = Family::subtree_root_position(leaf_start, height);
                let roundtrip = Family::leftmost_leaf(pos, height);
                assert_eq!(
                    roundtrip, leaf_start,
                    "virtual roundtrip failed: leaf_start={leaf_start}, height={height}, pos={pos}"
                );
            }
        }
    }

    #[test]
    fn test_chunk_peaks() {
        let hasher = StandardHasher::<Sha256>::new();
        let mut mmb = Mmb::new(&hasher);
        let digest = [1u8; 32];

        // Build an MMB with 200 leaves.
        for _ in 0..200 {
            let changeset = mmb
                .new_batch()
                .add(&hasher, &digest)
                .merkleize(&hasher)
                .finalize();
            mmb.apply(changeset).unwrap();
        }
        let size = mmb.size();

        for grafting_height in 1..6 {
            let chunk_size = 1u64 << grafting_height;
            let num_chunks = 200 / chunk_size;

            for chunk_idx in 0..num_chunks {
                let chunk_start = chunk_idx * chunk_size;
                let peaks: Vec<_> = Family::chunk_peaks(size, chunk_idx, grafting_height).collect();

                // Verify the peaks partition the chunk's leaf range.
                assert!(
                    !peaks.is_empty(),
                    "chunk must have at least one covering peak"
                );

                let mut covered = 0u64;
                for &(pos, h) in &peaks {
                    // Each peak should be retrievable from the MMB.
                    assert!(
                        mmb.get_node(pos).is_some(),
                        "chunk peak not in MMB at pos {pos} (gh={grafting_height}, chunk={chunk_idx})"
                    );

                    // Height should be at most grafting_height.
                    assert!(
                        h <= grafting_height,
                        "peak height {h} > grafting_height {grafting_height}"
                    );

                    // Verify this peak covers the expected leaf range.
                    let peak_leaves = 1u64 << h;
                    let expected_start = chunk_start + covered;
                    let leaf_loc = Location::new(expected_start);
                    let leaf_pos = Family::location_to_position(leaf_loc);

                    // The peak should be an ancestor of its first leaf. We can verify
                    // by checking that descending from the peak reaches this leaf.
                    if h > 0 {
                        let mut p = pos;
                        let mut ph = h;
                        while ph > 0 {
                            let (left, _) = Family::children(p, ph);
                            p = left;
                            ph -= 1;
                        }
                        assert_eq!(
                            p, leaf_pos,
                            "peak's leftmost leaf mismatch (gh={grafting_height}, chunk={chunk_idx})"
                        );
                    } else {
                        assert_eq!(pos, leaf_pos, "height-0 peak should be the leaf itself");
                    }

                    covered += peak_leaves;
                }

                assert_eq!(
                    covered, chunk_size,
                    "peaks don't partition chunk (gh={grafting_height}, chunk={chunk_idx})"
                );
            }
        }
    }

    #[test]
    fn test_subtree_root_position() {
        // Verify subtree_root_position matches actual node positions by walking
        // through a growing MMB.
        let mut next_pos = 0u64;
        for leaf_idx in 0u64..500 {
            let loc = Location::new(leaf_idx);

            // Height 0: the leaf itself.
            let pos = Family::subtree_root_position(loc, 0);
            assert_eq!(
                *pos, next_pos,
                "height-0 subtree_root_position mismatch at leaf {leaf_idx}"
            );
            next_pos += 1;

            // Optional parent at this step.
            if let Some(h) = Family::parent_heights(loc).next() {
                // The parent covers 2^h leaves. Its leftmost leaf is
                // birth_leaf - (3*2^(h-1) - 2) = leaf_idx - (3*2^(h-1) - 2).
                let leftmost = leaf_idx + 2 - 3 * (1u64 << (h - 1));
                let pos = Family::subtree_root_position(Location::new(leftmost), h);
                assert_eq!(
                    *pos, next_pos,
                    "height-{h} subtree_root_position mismatch at leaf {leaf_idx}"
                );
                next_pos += 1;
            }
        }
    }
}
