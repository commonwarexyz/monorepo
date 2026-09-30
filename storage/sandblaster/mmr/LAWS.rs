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
use crate::merkle::{Error, Location, Position};
use crate::merkle::mmr::Family;
use crate::merkle::mmr::iterator::PeakIterator;
use crate::__lift::{Once, Ordering, RangeInclusiveU32};

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

/// The ordering of two numbers (`core::cmp::Ordering`; opaque: proofs read
/// it through the comparisons it answers).
#[spec]
#[opaque]
#[example(order(1, 2) == Ordering::Less && order(2, 2) == Ordering::Equal && order(3, 2) == Ordering::Greater)]
pub fn order(a: Int, b: Int) -> Ordering {
    if a < b { Ordering::Less } else if a == b { Ordering::Equal } else { Ordering::Greater }
}

/// One step of the peak search on an MMR of size `s`, at the node `p` with
/// `t = 2^(k+1)` for its height `k` (`t <= 1`: finished): a node not in
/// the MMR (`p >= s`) is left for its left child (`p - t/2`, half the
/// height); a node in it is the next peak (position, height), and the
/// search moves on to its right sibling (`p + t - 1`). The new node, the
/// new `t` and the peak found, if any.
#[spec]
#[opaque]
#[decreases(t)]
#[example(search_step(19, 30, 32) == (29 as Int, 16 as Int, Some((14 as Int, 3 as Int))))]
#[example(search_step(19, 29, 16) == (20 as Int, 4 as Int, Some((17 as Int, 1 as Int))))]
#[example(search_step(19, 19, 2) == (18 as Int, 1 as Int, None) && search_step(0, 0, 0) == (0 as Int, 0 as Int, None))]
pub fn search_step(s: Int, p: Int, t: Int) -> (Int, Int, Option<(Int, Int)>) {
    if t <= 1 {
        (p, t, None)
    } else if p < s {
        (p + t - 1, t, Some((p, (log2(t as Nat) as Int) - 1)))
    } else {
        search_step(s, p - t / 2, t / 2)
    }
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
// Contracts: what each function host code can call returns (DESIGN.md
// §15.5: every one must be determined). A position or location is its
// value `.0`; `MAX_NODES = 2^63 - 1`, `MAX_LEAVES = 2^62`.
// ---------------------------------------------------------------------------

/// `Position::new(x)` is the position with value `x`.
#[lift_attach(crate::merkle::position::Position::new)]
fn position_new() {
    ensures(|ret: Position| ret == Position(pos, crate::__lift::PhantomData));
}

/// `as_u64` is the value.
#[lift_attach(crate::merkle::position::Position::as_u64)]
fn position_as_u64() {
    ensures(|ret: u64| ret == self.0);
}

/// `is_valid`: at most the maximum.
#[lift_attach(crate::merkle::position::Position::is_valid)]
fn position_is_valid() {
    ensures(|ret: bool| ret == ((self.0 as Int) <= pow2(63) - 1));
}

/// `is_valid_index`: below the maximum.
#[lift_attach(crate::merkle::position::Position::is_valid_index)]
fn position_is_valid_index() {
    ensures(|ret: bool| ret == ((self.0 as Int) < pow2(63) - 1));
}

/// `checked_add`: the sum up to the maximum, else `None`.
#[lift_attach(crate::merkle::position::Position::checked_add)]
fn position_checked_add() {
    ensures(|ret: Option<Position>| ret == (if (self.0 as Int) + (rhs as Int) <= pow2(63) - 1 { Some(Position::new(self.0 + rhs)) } else { None }));
}

/// `checked_sub`: the difference, else `None`.
#[lift_attach(crate::merkle::position::Position::checked_sub)]
fn position_checked_sub() {
    ensures(|ret: Option<Position>| ret == (if rhs <= self.0 { Some(Position::new(self.0 - rhs)) } else { None }));
}

/// `saturating_add`: the sum, at most the maximum.
#[lift_attach(crate::merkle::position::Position::saturating_add)]
fn position_saturating_add() {
    ensures(|ret: Position| ret == (if (self.0 as Int) + (rhs as Int) <= pow2(63) - 1 { Position::new(self.0 + rhs) } else { Position::new(0x7FFF_FFFF_FFFF_FFFFu64) }));
}

/// `saturating_sub`: the difference, at least 0.
#[lift_attach(crate::merkle::position::Position::saturating_sub)]
fn position_saturating_sub() {
    ensures(|ret: Position| ret == (if rhs <= self.0 { Position::new(self.0 - rhs) } else { Position::new(0u64) }));
}

/// `is_valid_size`: an MMR size up to `MAX_NODES`.
#[lift_attach(crate::merkle::position::Position::is_valid_size)]
fn position_is_valid_size() {
    ensures(|ret: bool| ret == ((self.0 as Int) < pow2(63) && crate::laws::valid_size(self.0 as Nat)));
}

/// `==` compares the values.
#[lift_attach(crate::merkle::position::Position::eq)]
fn position_eq() {
    ensures(|ret: bool| ret == (self.0 == other.0));
}

/// `<`, `<=`, `>`, `>=` compare the values.
#[lift_attach(crate::merkle::position::Position::partial_cmp)]
fn position_partial_cmp() {
    ensures(|ret: Option<crate::__lift::Ordering>| crate::__lift::ord_lt(ret) == (self.0 < other.0) && crate::__lift::ord_le(ret) == (self.0 <= other.0)
        && crate::__lift::ord_gt(ret) == (self.0 > other.0) && crate::__lift::ord_ge(ret) == (self.0 >= other.0));
}

/// `cmp` orders the values.
#[lift_attach(crate::merkle::position::Position::cmp)]
fn position_cmp() {
    ensures(|ret: crate::__lift::Ordering| ret == crate::laws::order(self.0 as Int, other.0 as Int));
}

/// `default` is 0.
#[lift_attach(crate::merkle::position::Position::default)]
fn position_default() {
    ensures(|ret: Position| ret == Position::new(0u64));
}

/// `*x` is the value.
#[lift_attach(crate::merkle::position::Position::deref)]
fn position_deref() {
    ensures(|ret: &u64| *ret == self.0);
}

/// `as_ref` is the value.
#[lift_attach(crate::merkle::position::Position::as_ref)]
fn position_as_ref() {
    ensures(|ret: &u64| *ret == self.0);
}

/// `From<u64>` wraps the value.
#[lift_attach(crate::merkle::position::Position::from__u64)]
fn position_from_u64() {
    ensures(|ret: Position| ret == Position::new(value));
}

/// `From<usize>` wraps the value.
#[lift_attach(crate::merkle::position::Position::from__usize)]
fn position_from_usize() {
    ensures(|ret: Position| ret == Position::new(value as u64));
}

/// `+` adds the values.
#[lift_attach(crate::merkle::position::Position::add)]
fn position_add() {
    ensures(|ret: Position| ret == Position::new(self.0 + rhs.0));
}

/// `+ u64` adds to the value.
#[lift_attach(crate::merkle::position::Position::add__u64)]
fn position_add_u64() {
    ensures(|ret: Position| ret == Position::new(self.0 + rhs));
}

/// `-` subtracts the values.
#[lift_attach(crate::merkle::position::Position::sub)]
fn position_sub() {
    ensures(|ret: Position| ret == Position::new(self.0 - rhs.0));
}

/// `- u64` subtracts from the value.
#[lift_attach(crate::merkle::position::Position::sub__u64)]
fn position_sub_u64() {
    ensures(|ret: Position| ret == Position::new(self.0 - rhs));
}

/// `== u64` compares the value.
#[lift_attach(crate::merkle::position::Position::eq__u64)]
fn position_eq_u64() {
    ensures(|ret: bool| ret == (self.0 == *other));
}

/// `<`, `<=`, `>`, `>=` with a `u64` compare the value.
#[lift_attach(crate::merkle::position::Position::partial_cmp__u64)]
fn position_partial_cmp_u64() {
    ensures(|ret: Option<crate::__lift::Ordering>| crate::__lift::ord_lt(ret) == (self.0 < *other) && crate::__lift::ord_le(ret) == (self.0 <= *other)
        && crate::__lift::ord_gt(ret) == (self.0 > *other) && crate::__lift::ord_ge(ret) == (self.0 >= *other));
}

/// `+= u64` adds to the value.
#[lift_attach(crate::merkle::position::Position::add_assign__u64)]
fn position_add_assign() {
    ensures(|ret: Position| ret == Position::new(((self.0 as Int) + (rhs as Int)) as u64));
}

/// `-= u64` subtracts from the value.
#[lift_attach(crate::merkle::position::Position::sub_assign__u64)]
fn position_sub_assign() {
    ensures(|ret: Position| ret == Position::new(((self.0 as Int) - (rhs as Int)) as u64));
}

/// `Location::new(x)` is the location with value `x`.
#[lift_attach(crate::merkle::location::Location::new)]
fn location_new() {
    ensures(|ret: Location| ret == Location(loc, crate::__lift::PhantomData));
}

/// `as_u64` is the value.
#[lift_attach(crate::merkle::location::Location::as_u64)]
fn location_as_u64() {
    ensures(|ret: u64| ret == self.0);
}

/// `is_valid`: at most the maximum.
#[lift_attach(crate::merkle::location::Location::is_valid)]
fn location_is_valid() {
    ensures(|ret: bool| ret == ((self.0 as Int) <= pow2(62)));
}

/// `is_valid_index`: below the maximum.
#[lift_attach(crate::merkle::location::Location::is_valid_index)]
fn location_is_valid_index() {
    ensures(|ret: bool| ret == ((self.0 as Int) < pow2(62)));
}

/// `checked_add`: the sum up to the maximum, else `None`.
#[lift_attach(crate::merkle::location::Location::checked_add)]
fn location_checked_add() {
    ensures(|ret: Option<Location>| ret == (if (self.0 as Int) + (rhs as Int) <= pow2(62) { Some(Location::new(self.0 + rhs)) } else { None }));
}

/// `checked_sub`: the difference, else `None`.
#[lift_attach(crate::merkle::location::Location::checked_sub)]
fn location_checked_sub() {
    ensures(|ret: Option<Location>| ret == (if rhs <= self.0 { Some(Location::new(self.0 - rhs)) } else { None }));
}

/// `saturating_add`: the sum, at most the maximum.
#[lift_attach(crate::merkle::location::Location::saturating_add)]
fn location_saturating_add() {
    ensures(|ret: Location| ret == (if (self.0 as Int) + (rhs as Int) <= pow2(62) { Location::new(self.0 + rhs) } else { Location::new(0x4000_0000_0000_0000u64) }));
}

/// `saturating_sub`: the difference, at least 0.
#[lift_attach(crate::merkle::location::Location::saturating_sub)]
fn location_saturating_sub() {
    ensures(|ret: Location| ret == (if rhs <= self.0 { Location::new(self.0 - rhs) } else { Location::new(0u64) }));
}

/// `==` compares the values.
#[lift_attach(crate::merkle::location::Location::eq)]
fn location_eq() {
    ensures(|ret: bool| ret == (self.0 == other.0));
}

/// `<`, `<=`, `>`, `>=` compare the values.
#[lift_attach(crate::merkle::location::Location::partial_cmp)]
fn location_partial_cmp() {
    ensures(|ret: Option<crate::__lift::Ordering>| crate::__lift::ord_lt(ret) == (self.0 < other.0) && crate::__lift::ord_le(ret) == (self.0 <= other.0)
        && crate::__lift::ord_gt(ret) == (self.0 > other.0) && crate::__lift::ord_ge(ret) == (self.0 >= other.0));
}

/// `cmp` orders the values.
#[lift_attach(crate::merkle::location::Location::cmp)]
fn location_cmp() {
    ensures(|ret: crate::__lift::Ordering| ret == crate::laws::order(self.0 as Int, other.0 as Int));
}

/// `default` is 0.
#[lift_attach(crate::merkle::location::Location::default)]
fn location_default() {
    ensures(|ret: Location| ret == Location::new(0u64));
}

/// `*x` is the value.
#[lift_attach(crate::merkle::location::Location::deref)]
fn location_deref() {
    ensures(|ret: &u64| *ret == self.0);
}

/// `From<u64>` wraps the value.
#[lift_attach(crate::merkle::location::Location::from__u64)]
fn location_from_u64() {
    ensures(|ret: Location| ret == Location::new(value));
}

/// `From<usize>` wraps the value.
#[lift_attach(crate::merkle::location::Location::from__usize)]
fn location_from_usize() {
    ensures(|ret: Location| ret == Location::new(value as u64));
}

/// `+` adds the values.
#[lift_attach(crate::merkle::location::Location::add)]
fn location_add() {
    ensures(|ret: Location| ret == Location::new(self.0 + rhs.0));
}

/// `+ u64` adds to the value.
#[lift_attach(crate::merkle::location::Location::add__u64)]
fn location_add_u64() {
    ensures(|ret: Location| ret == Location::new(self.0 + rhs));
}

/// `-` subtracts the values.
#[lift_attach(crate::merkle::location::Location::sub)]
fn location_sub() {
    ensures(|ret: Location| ret == Location::new(self.0 - rhs.0));
}

/// `- u64` subtracts from the value.
#[lift_attach(crate::merkle::location::Location::sub__u64)]
fn location_sub_u64() {
    ensures(|ret: Location| ret == Location::new(self.0 - rhs));
}

/// `== u64` compares the value.
#[lift_attach(crate::merkle::location::Location::eq__u64)]
fn location_eq_u64() {
    ensures(|ret: bool| ret == (self.0 == *other));
}

/// `<`, `<=`, `>`, `>=` with a `u64` compare the value.
#[lift_attach(crate::merkle::location::Location::partial_cmp__u64)]
fn location_partial_cmp_u64() {
    ensures(|ret: Option<crate::__lift::Ordering>| crate::__lift::ord_lt(ret) == (self.0 < *other) && crate::__lift::ord_le(ret) == (self.0 <= *other)
        && crate::__lift::ord_gt(ret) == (self.0 > *other) && crate::__lift::ord_ge(ret) == (self.0 >= *other));
}

/// `+= u64` adds to the value.
#[lift_attach(crate::merkle::location::Location::add_assign__u64)]
fn location_add_assign() {
    ensures(|ret: Location| ret == Location::new(((self.0 as Int) + (rhs as Int)) as u64));
}

/// `-= u64` subtracts from the value.
#[lift_attach(crate::merkle::location::Location::sub_assign__u64)]
fn location_sub_assign() {
    ensures(|ret: Location| ret == Location::new(((self.0 as Int) - (rhs as Int)) as u64));
}

/// `Position::try_from(loc)`: the position of leaf `loc` (the number of
/// nodes before it) for a location up to `MAX_LEAVES`, else
/// `LocationOverflow`.
#[lift_attach(crate::merkle::position::Position::try_from__Location)]
fn position_try_from() {
    ensures(|ret: crate::__lift::Result<Position, crate::merkle::Error>| ret == (if (loc.0 as Int) <= pow2(62) { crate::__lift::Result::Ok(Position::new((crate::laws::mmr_size(loc.0 as Int)) as u64)) } else { crate::__lift::Result::Err(crate::merkle::Error::LocationOverflow(loc)) }));
}

/// `Location::try_from(pos)`: the location of the leaf at `pos`; `NonLeaf`
/// for any other position up to `MAX_NODES`, `PositionOverflow` above it.
#[lift_attach(crate::merkle::location::Location::try_from__Position)]
fn location_try_from() {
    ensures(|ret: crate::__lift::Result<Location, crate::merkle::Error>| ret == (if (pos.0 as Int) <= pow2(63) - 1 {
        match crate::merkle::mmr::Family::position_to_location(pos) { Some(l) => crate::__lift::Result::Ok(l), None => crate::__lift::Result::Err(crate::merkle::Error::NonLeaf(pos)) }
    } else { crate::__lift::Result::Err(crate::merkle::Error::PositionOverflow(pos)) }));
}

/// `Family::default` is the (only) value of the marker type.
#[lift_attach(crate::merkle::mmr::Family::default)]
fn family_default() {
    ensures(|ret: crate::merkle::mmr::Family| ret == crate::merkle::mmr::Family);
}

/// `Family::to_nearest_size` is `PeakIterator::to_nearest_size`.
#[lift_attach(crate::merkle::mmr::Family::to_nearest_size)]
fn family_to_nearest_size() {
    ensures(|ret: Position| ret == crate::merkle::mmr::iterator::PeakIterator::to_nearest_size(size));
}

/// `Family::peaks` is the peak iterator of the size.
#[lift_attach(crate::merkle::mmr::Family::peaks)]
fn family_peaks() {
    ensures(|ret: crate::merkle::mmr::iterator::PeakIterator| ret == crate::merkle::mmr::iterator::PeakIterator::new(size));
}

/// `children` of the node at `pos` of height `height`: its left child
/// `pos - 2^height` and its right child `pos - 1`.
#[lift_attach(crate::merkle::mmr::Family::children)]
fn family_children() {
    ensures(|ret: (Position, Position)| ret == (Position::new(((pos.0 as Int) - pow2(height as Int)) as u64), Position::new(((pos.0 as Int) - 1) as u64)));
}

/// `parent_heights(n)`: appending leaf `n` creates parents of heights
/// `1..=t`, `t` the number of trailing ones of `n`.
#[lift_attach(crate::merkle::mmr::Family::parent_heights)]
fn family_parent_heights() {
    ensures(|ret: crate::__lift::RangeInclusiveU32| ret == crate::__lift::range_inclusive_u32(1u32, (!leaves.0).trailing_zeros()));
}

/// `chunk_peaks`: the one subtree root of height `g` over the chunk's
/// `2^g` leaves, at its first leaf's position plus `2^(g+1) - 2`.
#[lift_attach(crate::merkle::mmr::Family::chunk_peaks)]
fn family_chunk_peaks() {
    ensures(|ret: crate::__lift::Once<(Position, u32)>| ret.v.is_some()
        && (ret.v.unwrap_or((Position::new(0u64), 0u32)).0.0 as Int) == crate::laws::mmr_size((chunk_idx as Int) * pow2(grafting_height as Int)) + pow2((grafting_height as Int) + 1) - 2
        && ret.v.unwrap_or((Position::new(0u64), 0u32)).1 == grafting_height);
}

/// `PeakIterator::default`: the finished iterator of the empty MMR.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::default)]
fn peak_iterator_default() {
    ensures(|ret: PeakIterator| ret.size == Position::new(0u64) && ret.node_pos == Position::new(0u64) && ret.two_h == 0u64);
}

/// `PeakIterator::new(size)` of an MMR size `size > 0` starts the search at
/// the root of the smallest perfect tree with at least `size` nodes:
/// `2^b - 1` nodes for the bit length `b` of `size` (`log2(size) + 1`), so
/// its root is at `2^b - 2` and `two_h` is `2^b`.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::new)]
fn peak_iterator_new() {
    ensures(|ret: PeakIterator| if size.0 == 0u64 {
        ret.size == Position::new(0u64) && ret.node_pos == Position::new(0u64) && ret.two_h == 0u64
    } else {
        ret.size == size && (ret.node_pos.0 as Int) == (pow2(log2(size.0 as Nat) + 1) as Int) - 2 && (ret.two_h as Int) == pow2(log2(size.0 as Nat) + 1)
    });
}

/// `next` takes one step of the search (`search_step`) and yields the peak
/// it finds.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::next)]
fn peak_iterator_next() {
    ensures(|ret: (PeakIterator, Option<(Position, u32)>)| ret.0.size == self.size
        && crate::laws::search_step(self.size.0 as Int, self.node_pos.0 as Int, self.two_h as Int)
            == ((ret.0.node_pos.0 as Int), (ret.0.two_h as Int), match ret.1 { None => None, Some(x) => Some((x.0.0 as Int, x.1 as Int)) }));
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
/// inverse where `position_to_location` answers.
#[law]
fn position_to_location_is_sound(pos: Position, loc: Location) {
    requires((pos.0 as Int) < pow2(63));
    requires(Family::position_to_location(pos) == Some(loc));
    ensures(mmr_size(loc.0 as Int) == pos.0 as Int && (loc.0 as Int) <= pow2(62)
        && Family::location_to_position(loc).0 == pos.0);
}

/// Every leaf position has a location: `position_to_location` of the
/// position of leaf `n` (`n <= MAX_LEAVES`) is `n`, so with
/// `position_to_location_is_sound` it answers exactly on leaf positions.
#[law]
fn position_to_location_is_complete(pos: Position, loc: Location) {
    requires((loc.0 as Int) <= pow2(62) && (pos.0 as Int) == mmr_size(loc.0 as Int) && (pos.0 as Int) < pow2(63));
    ensures(Family::position_to_location(pos) == Some(loc));
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

/// `to_nearest_size` rounds down to an MMR size at most `size`.
#[law]
fn to_nearest_size_rounds_down(size: Position) {
    requires((size.0 as Int) < pow2(63));
    ensures(valid_size(PeakIterator::to_nearest_size(size).0 as Nat) && PeakIterator::to_nearest_size(size).0 <= size.0);
}

/// `to_nearest_size` is the largest MMR size at most `size`: every MMR
/// size `s` up to `size` is at most it.
#[law]
fn to_nearest_size_is_largest(size: Position, s: Nat) {
    requires((size.0 as Int) < pow2(63) && valid_size(s) && s <= size.0 as Nat);
    ensures(s <= PeakIterator::to_nearest_size(size).0 as Nat);
}

/// The peak iterator of the MMR with `n` leaves yields exactly its peaks
/// (as numbers), tallest first, and then ends. (`valid_size(mmr_size(n))`
/// always holds, by `mmr_sizes_are_valid`; it is repeated so that
/// `PeakIterator::new`'s precondition can be read off the statement.)
#[law]
fn peak_iterator_yields_the_peaks(n: Nat, size: Position) {
    requires((size.0 as Int) == mmr_size(n) && mmr_size(n) < pow2(63) && valid_size(mmr_size(n)));
    ensures(crate::iter::yields(PeakIterator::new(size), 64, |it: PeakIterator| {
        let r = PeakIterator::next(it);
        (r.0, match r.1 { None => None, Some(p) => Some((p.0.0 as Int, p.1 as Int)) })
    }) == peaks(n));
}

/// `pos_to_height` is the height of the node at that position.
#[law]
fn pos_to_height_is_the_node_height(pos: Position) {
    ensures(Family::pos_to_height(pos) as Int == node_height(pos.0 as Int));
}
