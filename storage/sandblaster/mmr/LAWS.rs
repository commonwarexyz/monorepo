//! What commonware-storage's MMR position arithmetic guarantees, for
//! `position.rs`, `location.rs`, `mmr/mod.rs` and `mmr/iterator.rs` exactly
//! as written, at the MMR family, except what stays unchecked host code
//! (listed in the record): `Graftable::subtree_root_position` and
//! `Graftable::leftmost_leaf`, the formatting and hashing impls, the codec
//! impls (`Write`, `EncodeSize`, `Read`), `LocationRangeExt`, the `Clone`,
//! `Copy` and `Eq` impls (read as value semantics: the model copies a value
//! and compares with `PartialEq::eq`) and the `arbitrary::Arbitrary` impls
//! behind the `arbitrary` cargo feature. Claims and preconditions only;
//! PROOF.rs proves them.
//!
//! An MMR with `n` leaves is a row of perfect binary trees (mountains): one
//! of height `h` for each set bit `h` of `n`, tallest first. Its nodes are
//! numbered in post-order, tree after tree (their positions); the position
//! of leaf `n` is the number of nodes before it, `mmr_size(n)`.
//!
//! Reading the statements: a position or location is its value `.0` (a
//! `u64`); `x as Int` / `x as Nat` read a word as an unbounded integer, so
//! `+`, `-` and `<` on them never wrap; `pow2(k)` is `2^k`, `log2(x)` the
//! position of the highest set bit, `popcount(n)` the number of set bits. In
//! a contract `ensures(|ret: T| ..)`, `ret` is the result; for a method on
//! `&mut self` (`+=`, `-=`, `next`) it is the new `self` (for `next`, the
//! pair of the new iterator and the item). `ord_lt(o)` is `o == Some(Less)`,
//! `ord_le(o)` is `Some(Less)` or `Some(Equal)`, and so on: how Rust's `<`,
//! `<=`, `>`, `>=` read `partial_cmp`. `Once.v` is the item
//! `core::iter::once` has not yet yielded; `range_inclusive_u32(a, b)` is
//! `a..=b`, and `.end` is its bound `b`: its last value when `a <= b`; of
//! an empty range (`1..=0`), which has no values, `.end` is only the bound.
//! In an impl on `u64` (`u64 == Position`), the `u64` receiver is `self_`.
//! Paths are written in full (`crate::laws::..`, `crate::__lift::..`)
//! because each precondition and contract is checked inside the host file
//! it attaches to.

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

/// `MAX_NODES`: the size of the MMR of `MAX_LEAVES` leaves, the largest
/// valid position or size.
#[spec]
#[example(max_nodes() == pow2(63) - 1 && max_nodes() == mmr_size(max_leaves()))]
pub fn max_nodes() -> Int {
    pow2(63) - 1
}

/// `MAX_LEAVES`: the largest valid location or leaf count.
#[spec]
#[example(max_leaves() == pow2(62))]
pub fn max_leaves() -> Int {
    pow2(62)
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
// one tree of height 63 (2^64 - 1 nodes) is a size; 2^65 - 1 nodes are not:
// the trees of heights 0 to 63 together have only 2^65 - 66
#[example(valid_size(pow2(64) - 1) && !valid_size(pow2(65) - 1))]
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
// 2^63 leaves: one tree of height 63, its root the last of its 2^64 - 1 nodes
#[example(peaks(pow2(63)) == seq![(pow2(64) - 2, 63 as Int)])]
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

/// The height of the node at position `p` in any MMR that has it, for
/// `0 <= p < 2^65 - 1` — every `u64` position, the only positions it is
/// applied to, among them: each such `p` is a node of the tree of height 64
/// (the MMR of `2^64` leaves), and positions never change as leaves are
/// added. Outside that range the value is no node's height (64 from
/// `2^65 - 1` on).
#[spec]
#[example(node_height(0) == 0 && node_height(2) == 1 && node_height(6) == 2 && node_height(14) == 3)]
#[example(node_height(15) == 0 && node_height(17) == 1 && node_height(18) == 0)]
// `u64::MAX` is the first node after the tree of height 63: leaf 2^63
// (`pos_to_height(u64::MAX)` is 0)
#[example(node_height(pow2(64) - 1) == 0)]
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

/// One call of `next` on an MMR of size `s`, from the node `p` with
/// `t = 2^(k+1)` for its height `k` (`t <= 1`: finished): a node not in
/// the MMR (`p >= s`) is left for its left child (`p - t/2`, one level
/// lower: `t` halves), and the search goes on from there; a node in it is
/// the next peak (position, height), and the search moves on to its right
/// sibling (`p + t - 1`). The new node, the new `t` and the peak found, if
/// any.
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
// Preconditions: what the code's documentation makes callers guarantee (a
// documented panic, or a documented domain), stated where the host calls
// it (each is proven at every call inside the verified files and is an
// obligation of host callers; the record lists them)
// ---------------------------------------------------------------------------

/// `PeakIterator::new` needs an MMR size of at most `MAX_NODES`. `new` itself
/// panics only from `2^63` ("size overflow"); the documented panic for any
/// other invalid size ("iteration will panic if size is not a valid MMR
/// size") comes from `next`, and is required here, where the size is given:
/// before panicking, iteration of an invalid size can yield a wrong peak
/// (size 5 yields `(2, 1)` first).
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::new)]
fn peak_iterator_new_pre() {
    requires((size.0 as Int) <= crate::laws::max_nodes() && crate::laws::valid_size(size.0 as Nat));
}

/// `PeakIterator::to_nearest_size` needs a size of at most `MAX_NODES`.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::to_nearest_size)]
fn to_nearest_size_pre() {
    requires((size.0 as Int) <= crate::laws::max_nodes());
}

/// `Family::to_nearest_size`: the same.
#[lift_attach(crate::merkle::mmr::Family::to_nearest_size)]
fn family_to_nearest_size_pre() {
    requires((size.0 as Int) <= crate::laws::max_nodes());
}

/// `Family::peaks`: a size as for `PeakIterator::new`.
#[lift_attach(crate::merkle::mmr::Family::peaks)]
fn family_peaks_pre() {
    requires((size.0 as Int) <= crate::laws::max_nodes() && crate::laws::valid_size(size.0 as Nat));
}

/// `location_to_position` is for locations up to `MAX_LEAVES` (`2^62`), the
/// trait's guaranteed domain (the code itself panics only from `2^63`).
#[lift_attach(crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_pre() {
    requires((loc.0 as Int) <= crate::laws::max_leaves());
}

/// `position_to_location` is for positions up to `MAX_NODES` (the trait:
/// "the caller guarantees `pos <= MAX_NODES`").
#[lift_attach(crate::merkle::mmr::Family::position_to_location)]
fn position_to_location_pre() {
    requires((pos.0 as Int) <= crate::laws::max_nodes());
}

/// `children` needs `height < 64` and `2^height <= pos` (the shift
/// `1 << height` and the subtraction `pos - 2^height` must not overflow).
/// The trait's caller guarantee `height > 0` is not needed by the code: at
/// height 0 it returns `(pos - 1, pos - 1)`.
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_pre() {
    requires(height < 64u32 && pow2(height as Int) <= (pos.0 as Int));
}

/// `chunk_peaks` needs the chunk's leaves `[c·2^g, (c+1)·2^g)` (`c` is
/// `chunk_idx`, `g` is `grafting_height`) within the structure of size
/// `size` — the trait's documented panic ("the chunk's leaf range exceeds
/// the structure's leaf count") — and within `MAX_LEAVES`. The trait
/// documents no panic for the second bound: it is the code's own
/// `expect("chunk_peaks: chunk overflow")` on `Position::try_from` of the
/// chunk's end. Outside it the code does not always panic: `(c + 1) << g`
/// drops high bits, and it returns another chunk's root (`c = 2^62, g = 2,
/// size = 7` gives `(6, 2)`, the root of chunk 0). The trait's other
/// documented panic, `size` not a valid size, is not raised by the MMR's
/// code and is not required.
#[lift_attach(crate::merkle::mmr::Family::chunk_peaks)]
fn chunk_peaks_pre() {
    requires(((chunk_idx as Int) + 1) * pow2(grafting_height as Int) <= crate::laws::max_leaves()
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
// value `.0`; `max_nodes()` and `max_leaves()` are `MAX_NODES` and
// `MAX_LEAVES`.
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

/// `is_valid`: at most `MAX_NODES`.
#[lift_attach(crate::merkle::position::Position::is_valid)]
fn position_is_valid() {
    ensures(|ret: bool| ret == ((self.0 as Int) <= crate::laws::max_nodes()));
}

/// `is_valid_index`: below `MAX_NODES`.
#[lift_attach(crate::merkle::position::Position::is_valid_index)]
fn position_is_valid_index() {
    ensures(|ret: bool| ret == ((self.0 as Int) < crate::laws::max_nodes()));
}

/// `checked_add`: the sum if it is at most `MAX_NODES`, else `None`.
#[lift_attach(crate::merkle::position::Position::checked_add)]
fn position_checked_add() {
    ensures(|ret: Option<Position>| ret == (if (self.0 as Int) + (rhs as Int) <= crate::laws::max_nodes() { Some(Position::new(self.0 + rhs)) } else { None }));
}

/// `checked_sub`: the difference, else `None`.
#[lift_attach(crate::merkle::position::Position::checked_sub)]
fn position_checked_sub() {
    ensures(|ret: Option<Position>| ret == (if rhs <= self.0 { Some(Position::new(self.0 - rhs)) } else { None }));
}

/// `saturating_add`: the sum, capped at `MAX_NODES`.
#[lift_attach(crate::merkle::position::Position::saturating_add)]
fn position_saturating_add() {
    ensures(|ret: Position| ret == (if (self.0 as Int) + (rhs as Int) <= crate::laws::max_nodes() { Position::new(self.0 + rhs) } else { Position::new(crate::laws::max_nodes() as u64) }));
}

/// `saturating_sub`: the difference, at least 0.
#[lift_attach(crate::merkle::position::Position::saturating_sub)]
fn position_saturating_sub() {
    ensures(|ret: Position| ret == (if rhs <= self.0 { Position::new(self.0 - rhs) } else { Position::new(0u64) }));
}

/// `is_valid_size`: an MMR size up to `MAX_NODES`.
#[lift_attach(crate::merkle::position::Position::is_valid_size)]
fn position_is_valid_size() {
    ensures(|ret: bool| ret == ((self.0 as Int) <= crate::laws::max_nodes() && crate::laws::valid_size(self.0 as Nat)));
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

/// `u64 == Position` compares the value. (An impl on `u64` is named
/// `u64__<method>__<argument type>`; its receiver is `self_`.)
#[lift_attach(crate::merkle::position::u64__eq__Position)]
fn u64_eq_position() {
    ensures(|ret: bool| ret == (self_ == other.0));
}

/// `<`, `<=`, `>`, `>=` of a `u64` with a position compare the value.
#[lift_attach(crate::merkle::position::u64__partial_cmp__Position)]
fn u64_partial_cmp_position() {
    ensures(|ret: Option<crate::__lift::Ordering>| crate::__lift::ord_lt(ret) == (self_ < other.0) && crate::__lift::ord_le(ret) == (self_ <= other.0)
        && crate::__lift::ord_gt(ret) == (self_ > other.0) && crate::__lift::ord_ge(ret) == (self_ >= other.0));
}

/// `u64::from(pos)` is the value.
#[lift_attach(crate::merkle::position::u64__from__Position)]
fn u64_from_position() {
    ensures(|ret: u64| ret == position.0);
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

/// `is_valid`: at most `MAX_LEAVES`.
#[lift_attach(crate::merkle::location::Location::is_valid)]
fn location_is_valid() {
    ensures(|ret: bool| ret == ((self.0 as Int) <= crate::laws::max_leaves()));
}

/// `is_valid_index`: below `MAX_LEAVES`.
#[lift_attach(crate::merkle::location::Location::is_valid_index)]
fn location_is_valid_index() {
    ensures(|ret: bool| ret == ((self.0 as Int) < crate::laws::max_leaves()));
}

/// `checked_add`: the sum if it is at most `MAX_LEAVES`, else `None`.
#[lift_attach(crate::merkle::location::Location::checked_add)]
fn location_checked_add() {
    ensures(|ret: Option<Location>| ret == (if (self.0 as Int) + (rhs as Int) <= crate::laws::max_leaves() { Some(Location::new(self.0 + rhs)) } else { None }));
}

/// `checked_sub`: the difference, else `None`.
#[lift_attach(crate::merkle::location::Location::checked_sub)]
fn location_checked_sub() {
    ensures(|ret: Option<Location>| ret == (if rhs <= self.0 { Some(Location::new(self.0 - rhs)) } else { None }));
}

/// `saturating_add`: the sum, capped at `MAX_LEAVES`.
#[lift_attach(crate::merkle::location::Location::saturating_add)]
fn location_saturating_add() {
    ensures(|ret: Location| ret == (if (self.0 as Int) + (rhs as Int) <= crate::laws::max_leaves() { Location::new(self.0 + rhs) } else { Location::new(crate::laws::max_leaves() as u64) }));
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

/// `u64 == Location` compares the value.
#[lift_attach(crate::merkle::location::u64__eq__Location)]
fn u64_eq_location() {
    ensures(|ret: bool| ret == (self_ == other.0));
}

/// `<`, `<=`, `>`, `>=` of a `u64` with a location compare the value.
#[lift_attach(crate::merkle::location::u64__partial_cmp__Location)]
fn u64_partial_cmp_location() {
    ensures(|ret: Option<crate::__lift::Ordering>| crate::__lift::ord_lt(ret) == (self_ < other.0) && crate::__lift::ord_le(ret) == (self_ <= other.0)
        && crate::__lift::ord_gt(ret) == (self_ > other.0) && crate::__lift::ord_ge(ret) == (self_ >= other.0));
}

/// `u64::from(loc)` is the value.
#[lift_attach(crate::merkle::location::u64__from__Location)]
fn u64_from_location() {
    ensures(|ret: u64| ret == loc.0);
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
    ensures(|ret: crate::__lift::Result<Position, crate::merkle::Error>| ret == (if (loc.0 as Int) <= crate::laws::max_leaves() { crate::__lift::Result::Ok(Position::new((crate::laws::mmr_size(loc.0 as Int)) as u64)) } else { crate::__lift::Result::Err(crate::merkle::Error::LocationOverflow(loc)) }));
}

/// `Location::try_from(pos)`: the location of the leaf at `pos`; `NonLeaf`
/// for any other position up to `MAX_NODES`, `PositionOverflow` above it.
#[lift_attach(crate::merkle::location::Location::try_from__Position)]
fn location_try_from() {
    ensures(|ret: crate::__lift::Result<Location, crate::merkle::Error>| ret == (if (pos.0 as Int) <= crate::laws::max_nodes() {
        match crate::merkle::mmr::Family::position_to_location(pos) { Some(l) => crate::__lift::Result::Ok(l), None => crate::__lift::Result::Err(crate::merkle::Error::NonLeaf(pos)) }
    } else { crate::__lift::Result::Err(crate::merkle::Error::PositionOverflow(pos)) }));
}

/// `Family::MAX_NODES` is `max_nodes()`. (An associated constant is read
/// as the function `Family__MAX_NODES()`.)
#[lift_attach(crate::merkle::mmr::Family__MAX_NODES)]
fn family_max_nodes() {
    ensures(|ret: Position| ret == Position::new(crate::laws::max_nodes() as u64));
}

/// `Family::MAX_LEAVES` is `max_leaves()`.
#[lift_attach(crate::merkle::mmr::Family__MAX_LEAVES)]
fn family_max_leaves() {
    ensures(|ret: Location| ret == Location::new(crate::laws::max_leaves() as u64));
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

/// `children` of the node at `pos` of height `height`: its subtree is the
/// `2^(height+1) - 1` positions ending at `pos` (post-order), so its right
/// child, the root of the right half, is just before it (`pos - 1`), and
/// its left child, the root of the left half, is `2^height - 1` positions
/// (the right half) before that (`pos - 2^height`).
#[lift_attach(crate::merkle::mmr::Family::children)]
fn family_children() {
    ensures(|ret: (Position, Position)| ret == (Position::new(((pos.0 as Int) - pow2(height as Int)) as u64), Position::new(((pos.0 as Int) - 1) as u64)));
}

/// `parent_heights(n)`: `1..=t`, `t` the number of trailing ones of `n`
/// (`(!n).trailing_zeros()`); `parent_heights_are_the_appended_parents`
/// says these are the heights of the parents appending leaf `n` creates.
#[lift_attach(crate::merkle::mmr::Family::parent_heights)]
fn family_parent_heights() {
    ensures(|ret: crate::__lift::RangeInclusiveU32| ret == crate::__lift::range_inclusive_u32(1u32, (!leaves.0).trailing_zeros()));
}

/// `chunk_peaks(size, c, g)` yields one item: the subtree root of height
/// `g` over the chunk's `2^g` leaves `[c·2^g, (c+1)·2^g)`, at its first
/// leaf's position `mmr_size(c·2^g)` plus `2^(g+1) - 2`, with its height
/// `g`.
#[lift_attach(crate::merkle::mmr::Family::chunk_peaks)]
fn family_chunk_peaks() {
    ensures(|ret: crate::__lift::Once<(Position, u32)>| ret.v == Some((Position::new((crate::laws::mmr_size((chunk_idx as Int) * pow2(grafting_height as Int)) + pow2((grafting_height as Int) + 1) - 2) as u64), grafting_height)));
}

/// `PeakIterator::default`: the finished iterator of the empty MMR.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::default)]
fn peak_iterator_default() {
    ensures(|ret: PeakIterator| ret.size == Position::new(0u64) && ret.node_pos == Position::new(0u64) && ret.two_h == 0u64);
}

/// `PeakIterator::new(size)`: of size 0, the finished iterator (as
/// `default`); of an MMR size `size > 0`, the search starts at the root of
/// the smallest perfect tree with at least `size` nodes: `2^b - 1` nodes for
/// the bit length `b` of `size` (`log2(size) + 1`), so its root is at
/// `2^b - 2` and `two_h` is `2^b`.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::new)]
fn peak_iterator_new() {
    ensures(|ret: PeakIterator| if size.0 == 0u64 {
        ret.size == Position::new(0u64) && ret.node_pos == Position::new(0u64) && ret.two_h == 0u64
    } else {
        ret.size == size && (ret.node_pos.0 as Int) == (pow2(log2(size.0 as Nat) + 1) as Int) - 2 && (ret.two_h as Int) == pow2(log2(size.0 as Nat) + 1)
    });
}

/// `next` takes one step of the search (`search_step`), keeps `size`, and
/// yields the peak it finds.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::next)]
fn peak_iterator_next() {
    ensures(|ret: (PeakIterator, Option<(Position, u32)>)| ret.0.size == self.size
        && crate::laws::search_step(self.size.0 as Int, self.node_pos.0 as Int, self.two_h as Int)
            == ((ret.0.node_pos.0 as Int), (ret.0.two_h as Int), match ret.1 { None => None, Some(x) => Some((x.0.0 as Int, x.1 as Int)) }));
}

/// `pos_to_height(pos)` (a `pub(crate)` function of `mmr/iterator.rs`, which
/// the rest of the crate calls) is the height of the node at `pos`.
#[lift_attach(crate::merkle::mmr::iterator::pos_to_height)]
fn pos_to_height_value() {
    ensures(|ret: u32| (ret as Int) == crate::laws::node_height(pos.0 as Int));
}

// ---------------------------------------------------------------------------
// Type invariant (locked with its type, DESIGN.md §15.6)
// ---------------------------------------------------------------------------

/// A `PeakIterator` is finished (`two_h <= 1`) or partway through the peak
/// search of an MMR of size `1 <= size < 2^63`: `two_h` is a power of two
/// `2^(k+1)` (`k >= 0`), and `node_pos` is the root of a perfect tree of
/// height `k = log2(two_h) - 1` whose first node is at most
/// `size`, with the nodes from that first node to the end of the MMR making
/// mountains of distinct heights no taller than that tree. Its fields are
/// private, and `new` (of a valid size), `default` and `next` are the only
/// ways to get one, so host code never holds another state; `next`'s
/// contract speaks of these states, and its `assert!` never fires.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator)]
fn peak_iterator_state() {
    invariant(crate::laws::iter_ok(self.size.0, self.node_pos.0, self.two_h));
}

/// The invariant of `peak_iterator_state`, of the fields `(size, node_pos, two_h)`.
#[spec]
#[opaque]
#[example(iter_ok(0u64, 0u64, 0u64) && iter_ok(19u64, 30u64, 32u64) && !iter_ok(1u64, 0u64, 4u64) && !iter_ok(2u64, 30u64, 32u64))]
// states the host's iterator passes through: of size 1 after its peak and
// finished, and `new(MAX_NODES)`
#[example(iter_ok(1u64, 1u64, 2u64) && iter_ok(1u64, 0u64, 1u64) && iter_ok((pow2(63) - 1) as u64, (pow2(63) - 2) as u64, pow2(63) as u64))]
// states it never holds: size 0 mid-search, `two_h` not a power of two, leaf
// 0 of the 3-node MMR (whose first mountain is taller), a tree starting
// before position 0, size 2^63
#[example(!iter_ok(0u64, 0u64, 2u64) && !iter_ok(1u64, 1u64, 3u64) && !iter_ok(3u64, 0u64, 2u64) && !iter_ok(2u64, 1u64, 4u64) && !iter_ok(pow2(63) as u64, pow2(63) as u64, 2u64))]
pub fn iter_ok(s: u64, p: u64, t: u64) -> bool {
    t <= 1u64 || (2 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int)
        && 1 <= (s as Int) && (s as Int) < pow2(63) && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int)
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1))
}

// ---------------------------------------------------------------------------
// Laws
// ---------------------------------------------------------------------------

/// A leaf's position is the number of nodes before it: `location_to_position`
/// of location `n` is `mmr_size(n)`, which is also the size of the MMR with
/// `n` leaves.
#[law]
fn location_to_position_counts_nodes(loc: Location) {
    requires((loc.0 as Int) <= max_leaves());
    ensures(Family::location_to_position(loc).0 as Int == mmr_size(loc.0 as Int));
}

/// `position_to_location` returns a location only for the position of
/// that leaf, and `location_to_position` maps it back: the conversions are
/// inverse where `position_to_location` answers.
#[law]
fn position_to_location_is_sound(pos: Position, loc: Location) {
    requires((pos.0 as Int) <= max_nodes());
    requires(Family::position_to_location(pos) == Some(loc));
    ensures(mmr_size(loc.0 as Int) == pos.0 as Int && (loc.0 as Int) <= max_leaves()
        && Family::location_to_position(loc).0 == pos.0);
}

/// Every leaf position has a location: `position_to_location` of the
/// position of leaf `n` (`n <= MAX_LEAVES`) is `n`, so with
/// `position_to_location_is_sound` it answers exactly on leaf positions.
/// (`pos <= MAX_NODES` follows from the rest; it is repeated so that
/// `position_to_location`'s precondition can be read off the statement.)
#[law]
fn position_to_location_is_complete(pos: Position, loc: Location) {
    requires((loc.0 as Int) <= max_leaves() && (pos.0 as Int) == mmr_size(loc.0 as Int) && (pos.0 as Int) <= max_nodes());
    ensures(Family::position_to_location(pos) == Some(loc));
}

/// Every `mmr_size(n)` with `n < 2^64` is an MMR size
/// (`valid_sizes_have_leaves` is the converse: every MMR size is some
/// `mmr_size(n)`).
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
    ensures(Family::is_valid_size(size) == ((size.0 as Int) <= max_nodes() && valid_size(size.0 as Nat)));
}

/// `to_nearest_size` rounds down to an MMR size at most `size`.
#[law]
fn to_nearest_size_rounds_down(size: Position) {
    requires((size.0 as Int) <= max_nodes());
    ensures(valid_size(PeakIterator::to_nearest_size(size).0 as Nat) && PeakIterator::to_nearest_size(size).0 <= size.0);
}

/// `to_nearest_size` is the largest MMR size at most `size`: every MMR
/// size `s` up to `size` is at most it.
#[law]
fn to_nearest_size_is_largest(size: Position, s: Nat) {
    requires((size.0 as Int) <= max_nodes() && valid_size(s) && s <= size.0 as Nat);
    ensures(s <= PeakIterator::to_nearest_size(size).0 as Nat);
}

/// The peak iterator of the MMR with `n` leaves yields exactly its peaks
/// (as numbers), tallest first, and then ends. (`valid_size(mmr_size(n))`
/// always holds, by `mmr_sizes_are_valid`; it is repeated so that
/// `PeakIterator::new`'s precondition can be read off the statement.)
/// (An MMR of at most `MAX_LEAVES` leaves has at most 62 peaks, fewer than
/// `yields`' bound 64, so the equality also says that the call after the
/// last peak returns `None`.)
#[law]
fn peak_iterator_yields_the_peaks(n: Nat, size: Position) {
    requires((size.0 as Int) == mmr_size(n) && mmr_size(n) <= max_nodes() && valid_size(mmr_size(n)));
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

/// Appending leaf `n` (location `leaves`, below `MAX_LEAVES`) puts the
/// leaf at position `mmr_size(n)` and then one parent of each height
/// `parent_heights(n)` yields (`1..=t`, `t` its `.end`), in that order: the
/// node at `mmr_size(n) + i` has height `i` for each `i <= t`, and the MMR
/// grows to `mmr_size(n + 1) = mmr_size(n) + 1 + t` nodes.
#[law]
fn parent_heights_are_the_appended_parents(leaves: Location, i: Nat) {
    requires((leaves.0 as Int) < max_leaves() && i <= (Family::parent_heights(leaves).end as Nat));
    ensures(node_height(mmr_size(leaves.0 as Int) + (i as Int)) == (i as Int)
        && mmr_size((leaves.0 as Int) + 1) == mmr_size(leaves.0 as Int) + 1 + (Family::parent_heights(leaves).end as Int));
}
