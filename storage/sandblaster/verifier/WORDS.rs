//! Word facts the prover uses on its own (a `#[bridges]` module: each
//! checked lemma is a rule of `auto`; an unconditional equation rewrites,
//! an unconditional inequality joins the linear problems whose atoms match
//! it). Here: the set bits of a word, and the comparisons of positions and
//! locations (their `PartialOrd`/`PartialEq` impls, as Rust desugars `<`)
//! against the comparisons of their values.

use sandblaster::prelude::*;
use crate::merkle::{Location, Position};

/// A word's set bits are at most its value.
#[lemma]
pub fn count_ones_le_self(x: u64) {
    ensures((x.count_ones() as u64) <= x);
    crate::stdlib::bits::count_ones_u64(x);
    by_arithmetic();
}

/// A word's set bits are at most its value (as integers).
#[lemma]
pub fn count_ones_le_self_int(x: u64) {
    ensures((x.count_ones() as Int) <= (x as Int));
    crate::stdlib::bits::count_ones_u64(x);
    by_arithmetic();
}

/// A word's set bits are its `popcount` (from above).
#[lemma]
pub fn count_ones_le_popcount(x: u64) {
    ensures((x.count_ones() as Int) <= popcount(x as Int));
    crate::stdlib::bits::count_ones_u64(x);
    follows();
}

/// A word's set bits are its `popcount` (from below).
#[lemma]
pub fn count_ones_ge_popcount(x: u64) {
    ensures((x.count_ones() as Int) >= popcount(x as Int));
    crate::stdlib::bits::count_ones_u64(x);
    follows();
}

/// `a < b` on positions: `<` on their values.
#[lemma]
pub fn position_lt(a: Position, b: Position) {
    ensures(crate::__lift::ord_lt(a.partial_cmp(&b)) == (a.0 < b.0));
    unfold(crate::merkle::position::Position::partial_cmp);
    unfold(crate::merkle::position::Position::cmp);
    if a.0 < b.0 { follows(); } else if a.0 == b.0 { follows(); } else { follows(); }
}

/// `a <= b` on positions: `<=` on their values.
#[lemma]
pub fn position_le(a: Position, b: Position) {
    ensures(crate::__lift::ord_le(a.partial_cmp(&b)) == (a.0 <= b.0));
    unfold(crate::merkle::position::Position::partial_cmp);
    unfold(crate::merkle::position::Position::cmp);
    if a.0 < b.0 { follows(); } else if a.0 == b.0 { follows(); } else { follows(); }
}

/// `a > b` on positions: `>` on their values.
#[lemma]
pub fn position_gt(a: Position, b: Position) {
    ensures(crate::__lift::ord_gt(a.partial_cmp(&b)) == (a.0 > b.0));
    unfold(crate::merkle::position::Position::partial_cmp);
    unfold(crate::merkle::position::Position::cmp);
    if a.0 < b.0 { follows(); } else if a.0 == b.0 { follows(); } else { follows(); }
}

/// `a >= b` on positions: `>=` on their values.
#[lemma]
pub fn position_ge(a: Position, b: Position) {
    ensures(crate::__lift::ord_ge(a.partial_cmp(&b)) == (a.0 >= b.0));
    unfold(crate::merkle::position::Position::partial_cmp);
    unfold(crate::merkle::position::Position::cmp);
    if a.0 < b.0 { follows(); } else if a.0 == b.0 { follows(); } else { follows(); }
}

/// `a == n` of a position and a word: `==` on the value.
#[lemma]
pub fn position_eq_u64(a: Position, n: u64) {
    ensures(a.eq__u64(&n) == (a.0 == n));
    unfold(crate::merkle::position::Position::eq__u64);
    follows();
}

/// `a == b` on positions: `==` on their values.
#[lemma]
pub fn position_eq(a: Position, b: Position) {
    ensures(a.eq(&b) == (a.0 == b.0));
    unfold(crate::merkle::position::Position::eq);
    follows();
}

/// `a <= b` on locations: `<=` on their values.
#[lemma]
pub fn location_le(a: Location, b: Location) {
    ensures(crate::__lift::ord_le(a.partial_cmp(&b)) == (a.0 <= b.0));
    unfold(crate::merkle::location::Location::partial_cmp);
    unfold(crate::merkle::location::Location::cmp);
    if a.0 < b.0 { follows(); } else if a.0 == b.0 { follows(); } else { follows(); }
}

/// `a >= b` on locations: `>=` on their values.
#[lemma]
pub fn location_ge(a: Location, b: Location) {
    ensures(crate::__lift::ord_ge(a.partial_cmp(&b)) == (a.0 >= b.0));
    unfold(crate::merkle::location::Location::partial_cmp);
    unfold(crate::merkle::location::Location::cmp);
    if a.0 < b.0 { follows(); } else if a.0 == b.0 { follows(); } else { follows(); }
}

/// A `a < b` test on positions: the values pass `<` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_lt_true(a: Position, b: Position) {
    requires(crate::__lift::ord_lt(a.partial_cmp(&b)) == true);
    ensures((a.0 < b.0) == true);
    position_lt(a, b);
    follows();
}

/// A failed `a < b` test on positions: the values fail `<` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_lt_false(a: Position, b: Position) {
    requires(crate::__lift::ord_lt(a.partial_cmp(&b)) == false);
    ensures((a.0 < b.0) == false);
    position_lt(a, b);
    follows();
}

/// A `a <= b` test on positions: the values pass `<=` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_le_true(a: Position, b: Position) {
    requires(crate::__lift::ord_le(a.partial_cmp(&b)) == true);
    ensures((a.0 <= b.0) == true);
    position_le(a, b);
    follows();
}

/// A failed `a <= b` test on positions: the values fail `<=` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_le_false(a: Position, b: Position) {
    requires(crate::__lift::ord_le(a.partial_cmp(&b)) == false);
    ensures((a.0 <= b.0) == false);
    position_le(a, b);
    follows();
}

/// A `a > b` test on positions: the values pass `>` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_gt_true(a: Position, b: Position) {
    requires(crate::__lift::ord_gt(a.partial_cmp(&b)) == true);
    ensures((a.0 > b.0) == true);
    position_gt(a, b);
    follows();
}

/// A failed `a > b` test on positions: the values fail `>` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_gt_false(a: Position, b: Position) {
    requires(crate::__lift::ord_gt(a.partial_cmp(&b)) == false);
    ensures((a.0 > b.0) == false);
    position_gt(a, b);
    follows();
}

/// A `a >= b` test on positions: the values pass `>=` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_ge_true(a: Position, b: Position) {
    requires(crate::__lift::ord_ge(a.partial_cmp(&b)) == true);
    ensures((a.0 >= b.0) == true);
    position_ge(a, b);
    follows();
}

/// A failed `a >= b` test on positions: the values fail `>=` (a
/// forward rule on the fact the test leaves).
#[lemma]
pub fn pos_ge_false(a: Position, b: Position) {
    requires(crate::__lift::ord_ge(a.partial_cmp(&b)) == false);
    ensures((a.0 >= b.0) == false);
    position_ge(a, b);
    follows();
}

/// A well-shaped subtree, as arithmetic (`well_shaped` is opaque; this
/// equation opens it the same way in goals and facts).
#[lemma]
pub fn well_shaped_is(s: crate::merkle::proof::Subtree) {
    ensures(crate::laws::well_shaped(s) == ((s.leaf_start.0 as Int) + pow2(s.height as Int) <= pow2(62) && (s.pos.0 as Int) + 2 >= pow2((s.height as Int) + 1)));
    by_unfolding(crate::laws::well_shaped, crate::laws::max_leaves);
}

/// The left half of a subtree is one level down (`left_half` is opaque;
/// its fields as equations).
#[lemma]
pub fn left_half_height(s: crate::merkle::proof::Subtree) {
    ensures(crate::laws::left_half(s).height == ((s.height as Int) - 1) as u32);
    by_unfolding(crate::laws::left_half);
}

/// The right half of a subtree is one level down.
#[lemma]
pub fn right_half_height(s: crate::merkle::proof::Subtree) {
    ensures(crate::laws::right_half(s).height == ((s.height as Int) - 1) as u32);
    by_unfolding(crate::laws::right_half);
}

/// The left half of a subtree starts at its first leaf.
#[lemma]
pub fn left_half_start(s: crate::merkle::proof::Subtree) {
    ensures(crate::laws::left_half(s).leaf_start == s.leaf_start);
    by_unfolding(crate::laws::left_half);
}

/// A subtree disjoint from a range, as arithmetic (`disjoint` is opaque;
/// this equation opens it the same way in goals and facts).
#[lemma]
pub fn disjoint_is(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<crate::merkle::Location>) {
    ensures(crate::laws::disjoint(s, range) == ((s.leaf_start.0 as Int) + pow2(s.height as Int) <= (range.start.0 as Int) || s.leaf_start.0 >= range.end.0));
    by_unfolding(crate::laws::disjoint);
}

/// `max_leaves()` is `2^62` (the laws' name for `MAX_LEAVES`).
#[lemma]
pub fn max_leaves_value() {
    ensures(crate::laws::max_leaves() == pow2(62));
    by_unfolding(crate::laws::max_leaves);
}
