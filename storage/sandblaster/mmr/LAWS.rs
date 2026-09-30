//! What commonware-storage's MMR position arithmetic guarantees, for
//! `position.rs`, `location.rs`, `mmr/mod.rs` and `mmr/iterator.rs` exactly
//! as written, at the MMR family. Claims and preconditions only; PROOF.rs
//! proves them.
//!
//! An MMR with `n` leaves is a row of perfect binary trees (mountains): one
//! of height `h` for each set bit `h` of `n`, tallest first. Its nodes are
//! numbered in post-order, tree after tree (their positions); the position
//! of leaf `n` is the number of nodes before it, `mmr_size(n)`.

use sandblaster::prelude::*;
use crate::merkle::{Location, Position};
use crate::merkle::mmr::Family;
use crate::merkle::mmr::iterator::PeakIterator;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// The number of nodes of an MMR with `n` leaves: `2n - popcount(n)` (each
/// mountain of `2^h` leaves has `2^(h+1) - 1` nodes).
#[spec]
#[example(mmr_size(0) == 0 && mmr_size(1) == 1 && mmr_size(2) == 3 && mmr_size(3) == 4)]
#[example(mmr_size(4) == 7 && mmr_size(11) == 19 && mmr_size(pow2(62)) == pow2(63) - 1)]
pub fn mmr_size(n: Int) -> Int {
    2 * n - popcount(n)
}

/// Whether `r` nodes make perfect binary trees (of `2^(k+1) - 1` nodes
/// each) of pairwise different heights `k` at most `h`, the tallest that fits
/// taken first.
#[spec]
#[decreases(h + 1)]
#[example(fits(0, -1) && !fits(1, -1) && fits(1, 0) && fits(3, 1) && fits(4, 1) && !fits(2, 1) && !fits(5, 1))]
pub fn fits(r: Int, h: Int) -> bool {
    if h < 0 {
        r == 0
    } else if r + 1 >= pow2(h + 1) {
        fits(r + 1 - pow2(h + 1), h - 1)
    } else {
        fits(r, h - 1)
    }
}

/// Whether `s` is the size of an MMR: perfect binary trees of pairwise
/// different heights (at most 63).
#[spec]
#[example(valid_size(0) && valid_size(1) && !valid_size(2) && valid_size(3) && valid_size(4))]
#[example(!valid_size(5) && !valid_size(6) && valid_size(7) && valid_size(19))]
pub fn valid_size(s: Int) -> bool {
    fits(s, 63)
}

/// The peaks — (position, height) of each mountain's root, tallest first —
/// of the mountains of `n` leaves (`n < 2^(h+1)`) laid out from position
/// `at`: one mountain of height `k` for each set bit `k` of `n`.
#[spec]
#[decreases(h + 1)]
pub fn mountains(at: Int, n: Int, h: Int) -> Seq<(Int, Int)> {
    if h < 0 {
        seq![]
    } else if n >= pow2(h) {
        seq![(at + pow2(h + 1) - 2, h), ..mountains(at + pow2(h + 1) - 1, n - pow2(h), h - 1)]
    } else {
        mountains(at, n, h - 1)
    }
}

/// The peaks of the MMR with `n` leaves (`n < 2^64`), tallest first.
#[spec]
#[example(peaks(11) == seq![(14 as Int, 3 as Int), (17 as Int, 1 as Int), (18 as Int, 0 as Int)])]
#[example(peaks(0) == seq![] && peaks(1) == seq![(0 as Int, 0 as Int)])]
pub fn peaks(n: Int) -> Seq<(Int, Int)> {
    mountains(0, n, 63)
}

/// The items `PeakIterator::next` yields from `it` — (position, height)
/// as numbers —, until it returns `None` (at most `k` of them).
#[spec]
#[decreases(k)]
pub fn items(it: PeakIterator, k: Int) -> Seq<(Int, Int)> {
    if k <= 0 {
        seq![]
    } else {
        let mut i = it;
        match i.next() {
            None => seq![],
            Some(x) => seq![(x.0.0 as Int, x.1 as Int), ..items(i, k - 1)],
        }
    }
}

/// The height of the node at position `p` of the perfect binary tree of
/// height `h` numbered from 0 in post-order (`p < 2^(h+1) - 1`): its root
/// is the last node, its left subtree the first `2^h - 1`, its right
/// subtree the next `2^h - 1`.
#[spec]
#[decreases(h)]
#[example(height_in(0, 1) == 0 && height_in(1, 1) == 0 && height_in(2, 1) == 1)]
pub fn height_in(p: Int, h: Int) -> Int {
    if h <= 0 || p + 2 >= pow2(h + 1) {
        h
    } else if p + 1 < pow2(h) {
        height_in(p, h - 1)
    } else {
        height_in(p + 1 - pow2(h), h - 1)
    }
}

/// The height of the node at position `p` in any MMR that has it (every
/// position below `2^65 - 1` is a node of the tree of height 64, the MMR
/// of `2^64` leaves, and positions never change as leaves are added).
#[spec]
#[example(node_height(0) == 0 && node_height(2) == 1 && node_height(6) == 2 && node_height(14) == 3)]
#[example(node_height(15) == 0 && node_height(17) == 1 && node_height(18) == 0)]
pub fn node_height(p: Int) -> Int {
    height_in(p, 64)
}

// ---------------------------------------------------------------------------
// Preconditions: the panics the code documents, stated where the host
// calls it (each is proven at every call inside the verified files and is
// an obligation of host callers; the record lists them)
// ---------------------------------------------------------------------------

/// `PeakIterator::new` needs the size of an MMR below `2^63` ("iteration
/// will panic if size is not a valid MMR size").
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::new)]
fn peak_iterator_new_pre() {
    requires((size.0 as Int) < pow2(63) && crate::laws::valid_size(size.0 as Nat));
}

/// `PeakIterator::to_nearest_size` needs a size of at most `MAX_NODES`.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::to_nearest_size)]
fn to_nearest_size_pre() {
    requires((size.0 as Int) < pow2(63));
}

/// `Family::to_nearest_size`: the same.
#[lift_attach(crate::merkle::mmr::Family::to_nearest_size)]
fn family_to_nearest_size_pre() {
    requires((size.0 as Int) < pow2(63));
}

/// `Family::peaks`: a size as for `PeakIterator::new`.
#[lift_attach(crate::merkle::mmr::Family::peaks)]
fn family_peaks_pre() {
    requires((size.0 as Int) < pow2(63) && crate::laws::valid_size(size.0 as Nat));
}

/// `location_to_position` is for locations up to `MAX_LEAVES` (`2^62`).
#[lift_attach(crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_pre() {
    requires((loc.0 as Int) <= pow2(62));
}

/// `position_to_location` is for positions up to `MAX_NODES`.
#[lift_attach(crate::merkle::mmr::Family::position_to_location)]
fn position_to_location_pre() {
    requires((pos.0 as Int) < pow2(63));
}

/// `children` is for a node of height `1 ≤ height < 64` (its left child
/// `pos - 2^height` exists).
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_pre() {
    requires(height < 64u32 && pow2(height as Int) <= (pos.0 as Int));
}

/// `chunk_peaks` needs the chunk's leaves within `MAX_LEAVES` and within
/// the structure of size `size`.
#[lift_attach(crate::merkle::mmr::Family::chunk_peaks)]
fn chunk_peaks_pre() {
    requires(grafting_height <= 62u32 && ((chunk_idx as Int) + 1) * pow2(grafting_height as Int) <= pow2(62)
        && crate::laws::mmr_size(((chunk_idx as Nat) + 1) * pow2(grafting_height as Int)) <= size.0 as Nat);
}

/// `Position + Position` must not overflow (the code documents the panic).
#[lift_attach(crate::merkle::position::Position::add)]
fn position_add_pre() {
    requires((self.0 as Int) + (rhs.0 as Int) < pow2(64));
}

/// `Position + u64` must not overflow.
#[lift_attach(crate::merkle::position::Position::add__u64)]
fn position_add_u64_pre() {
    requires((self.0 as Int) + (rhs as Int) < pow2(64));
}

/// `Position += u64` must not overflow.
#[lift_attach(crate::merkle::position::Position::add_assign__u64)]
fn position_add_assign_pre() {
    requires((self.0 as Int) + (rhs as Int) < pow2(64));
}

/// `Position - Position` must not underflow.
#[lift_attach(crate::merkle::position::Position::sub)]
fn position_sub_pre() {
    requires(rhs.0 <= self.0);
}

/// `Position - u64` must not underflow.
#[lift_attach(crate::merkle::position::Position::sub__u64)]
fn position_sub_u64_pre() {
    requires(rhs <= self.0);
}

/// `Position -= u64` must not underflow.
#[lift_attach(crate::merkle::position::Position::sub_assign__u64)]
fn position_sub_assign_pre() {
    requires(rhs <= self.0);
}

/// `Location + Location` must not overflow.
#[lift_attach(crate::merkle::location::Location::add)]
fn location_add_pre() {
    requires((self.0 as Int) + (rhs.0 as Int) < pow2(64));
}

/// `Location + u64` must not overflow.
#[lift_attach(crate::merkle::location::Location::add__u64)]
fn location_add_u64_pre() {
    requires((self.0 as Int) + (rhs as Int) < pow2(64));
}

/// `Location += u64` must not overflow.
#[lift_attach(crate::merkle::location::Location::add_assign__u64)]
fn location_add_assign_pre() {
    requires((self.0 as Int) + (rhs as Int) < pow2(64));
}

/// `Location - Location` must not underflow.
#[lift_attach(crate::merkle::location::Location::sub)]
fn location_sub_pre() {
    requires(rhs.0 <= self.0);
}

/// `Location - u64` must not underflow.
#[lift_attach(crate::merkle::location::Location::sub__u64)]
fn location_sub_u64_pre() {
    requires(rhs <= self.0);
}

/// `Location -= u64` must not underflow.
#[lift_attach(crate::merkle::location::Location::sub_assign__u64)]
fn location_sub_assign_pre() {
    requires(rhs <= self.0);
}

// ---------------------------------------------------------------------------
// Laws
// ---------------------------------------------------------------------------

/// A leaf's position is the number of nodes before it: `location_to_position`
/// of location `n` is `mmr_size(n)`, which is also the size of the MMR with
/// `n` leaves.
#[law]
fn location_to_position_counts_nodes(loc: Location) {
    requires((loc.0 as Int) <= pow2(62));
    ensures(Family::location_to_position(loc).0 as Int == mmr_size(loc.0 as Int));
}

/// `position_to_location` returns a location only for the position of
/// that leaf, and `location_to_position` maps it back: the conversions are
/// inverse where `position_to_location` answers. (That it answers for
/// every leaf position is the code's own claim, checked by its exhaustive
/// behavior-class test and the differential harness, not proven here.)
#[law]
fn position_to_location_is_sound(pos: Position, loc: Location) {
    requires((pos.0 as Int) < pow2(63));
    requires(Family::position_to_location(pos) == Some(loc));
    ensures(mmr_size(loc.0 as Int) == pos.0 as Int && (loc.0 as Int) <= pow2(62)
        && Family::location_to_position(loc).0 == pos.0);
}

/// The MMR sizes are exactly the sizes of MMRs of some number of leaves:
/// every `mmr_size(n)` is one.
#[law]
fn mmr_sizes_are_valid(n: Nat) {
    requires(n < pow2(64));
    ensures(valid_size(mmr_size(n)));
}

/// Every MMR size is `mmr_size(n)` for some number of leaves `n`.
#[law]
fn valid_sizes_have_leaves(s: Nat) {
    requires(valid_size(s));
    ensures(exists(|n: Nat| mmr_size(n) == s));
}

/// `is_valid_size` holds exactly for the MMR sizes up to `MAX_NODES`.
#[law]
fn is_valid_size_characterizes_mmr_sizes(size: Position) {
    ensures(Family::is_valid_size(size) == ((size.0 as Int) < pow2(63) && valid_size(size.0 as Nat)));
}

/// `to_nearest_size` rounds down to the largest MMR size at most `size`.
#[law]
fn to_nearest_size_rounds_down(size: Position, s: Nat) {
    requires((size.0 as Int) < pow2(63));
    ensures(valid_size(PeakIterator::to_nearest_size(size).0 as Nat)
        && PeakIterator::to_nearest_size(size).0 <= size.0
        && implies(valid_size(s) && s <= size.0 as Nat, s <= PeakIterator::to_nearest_size(size).0 as Nat));
}

/// The peak iterator of the MMR with `n` leaves yields exactly its peaks,
/// tallest first, and then ends. (`valid_size(mmr_size(n))` always holds,
/// by `mmr_sizes_are_valid`; it is repeated so that `PeakIterator::new`'s
/// precondition can be read off the statement.)
#[law]
fn peak_iterator_yields_the_peaks(n: Nat) {
    requires(mmr_size(n) < pow2(63) && valid_size(mmr_size(n)));
    ensures(items(PeakIterator::new(Position::new(mmr_size(n) as u64)), 64) == peaks(n));
}

/// `pos_to_height` is the height of the node at that position.
#[law]
fn pos_to_height_is_the_node_height(pos: Position) {
    ensures(Family::pos_to_height(pos) as Int == node_height(pos.0 as Int));
}
