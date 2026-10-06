//! What the lifted verifier guarantees (first set), for `hasher.rs` and
//! `proof.rs` as written at QMDB's instance (the MMR family, SHA-256), and
//! what each function host code can call returns. Claims, preconditions
//! and panic contracts only; PROOF.rs proves them.
//!
//! Reading the statements: a position or location is its value `.0` (a
//! `u64`); `x as Int` reads a word as an unbounded integer, so `+`, `-` and
//! `<` on it never wrap; `pow2(k)` is `2^k`. A function's `requires(p)` is
//! its domain: what callers guarantee (outside it nothing is promised); its
//! `panics_when(p)` says that on its domain it panics exactly when `p`
//! holds, and otherwise returns what its contract says. A function with
//! neither returns on every input. A `Subtree` is the perfect
//! binary subtree of an MMR whose root is at position `pos`, of height
//! `height`, whose first leaf is at location `leaf_start`. In a contract
//! `ensures(|ret: T| ..)`, `ret` is the result; for a method that takes
//! `&mut` arguments it is the tuple of their new values and the result
//! (`reconstruct_digest`: the elements not yet taken, the cursor, the
//! collected digests and the result). `ord_lt(o)` is `o == Some(Less)`,
//! `ord_le(o)` is `Some(Less)` or `Some(Equal)`, and so on: how Rust's `<`,
//! `<=`, `>`, `>=` read `partial_cmp`. In an impl on `u64` (`u64 ==
//! Position`), the `u64` receiver is `self_`. `collision(Some((a, b)))` says
//! that `a` and `b` are two different messages with one SHA-256 digest; a
//! law tagged `#[reduces_to(collision_resistance)]` holds unless the
//! collision it names is one. Paths are written in full because each
//! precondition and contract is checked inside the host file it attaches to.
//!
//! The known answers (`#[example]`) come from `known_answers.py`, a model
//! of commonware's MMR and of `reconstruct_digest` written in Python from
//! commonware's code and documentation, not from these definitions; each
//! example names the line of its output it states.

use sandblaster::prelude::*;
use crate::merkle::{Digest, Location, Position};
use crate::merkle::hasher::Standard;
use crate::merkle::proof::{ReconstructionError, Subtree};
use crate::sha256::{collision, collision_resistance, sha256};

// ---------------------------------------------------------------------------
// Vocabulary: the bounds and the node count (as in `sandblaster/mmr/LAWS.rs`)
// ---------------------------------------------------------------------------

/// `MAX_LEAVES`: the largest valid location or leaf count.
#[spec]
// known_answers.py: `max_leaves`
#[example(max_leaves() == pow2(62))]
pub fn max_leaves() -> Int {
    pow2(62)
}

/// `MAX_NODES`: the size of the MMR of `MAX_LEAVES` leaves, the largest
/// valid position or size.
#[spec]
// known_answers.py: `mmr_size(2^62)`
#[example(max_nodes() == 9223372036854775807)]
pub fn max_nodes() -> Int {
    pow2(63) - 1
}

/// The number of nodes of an MMR with `n` leaves: `2n - popcount(n)` (each
/// mountain of `2^h` leaves has `2^(h+1) - 1` nodes). It is also the
/// position of leaf `n`: the number of nodes before it.
#[spec]
// known_answers.py: `mmr_size(..)`
#[example(mmr_size(0) == 0 && mmr_size(1) == 1 && mmr_size(2) == 3 && mmr_size(3) == 4)]
#[example(mmr_size(4) == 7 && mmr_size(11) == 19 && mmr_size(pow2(62)) == 9223372036854775807)]
pub fn mmr_size(n: Int) -> Int {
    2 * n - popcount(n)
}

/// The ordering of two numbers (`core::cmp::Ordering`; opaque: proofs read
/// it through the comparisons it answers).
#[spec]
#[opaque]
// known_answers.py: `order(..)`
#[example(order(1, 2) == crate::__lift::Ordering::Less && order(2, 2) == crate::__lift::Ordering::Equal && order(3, 2) == crate::__lift::Ordering::Greater)]
pub fn order(a: Int, b: Int) -> crate::__lift::Ordering {
    if a < b { crate::__lift::Ordering::Less } else if a == b { crate::__lift::Ordering::Equal } else { crate::__lift::Ordering::Greater }
}

// ---------------------------------------------------------------------------
// Where the position arithmetic the verifier calls panics, and what callers
// guarantee (the same statements as `sandblaster/mmr/LAWS.rs`). A documented
// panic is a panic contract: `panics_when(p)` says that where the function's
// `requires` hold it panics exactly when `p` holds (proven of rustc's MIR;
// the record lists it). A `requires` is what the documentation makes
// callers guarantee where the code would not simply panic: it is proven at
// every call inside the verified files and is an obligation of host
// callers (the record lists it); outside it nothing is promised.
//
// Every panic here is rustc's overflow check: it holds in a build with
// overflow checks on, as every profile of this workspace sets them; a
// build without them (a downstream crate's default release profile) wraps
// instead of panicking (DESIGN.md §16.5).
// ---------------------------------------------------------------------------

/// `location_to_position` is for locations up to `MAX_LEAVES` (`2^62`), the
/// trait's guaranteed domain ("callers must not rely on" larger ones).
/// Above it the code does not simply panic: it returns `2·loc -
/// popcount(loc)`, which is no position of a valid MMR, up to `2^63`, and
/// panics only from `2^63` on (`checked_mul(2)`'s `expect`).
#[lift_attach(crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_pre() {
    requires((loc.0 as Int) <= crate::laws::max_leaves());
}

/// `children` panics where its arithmetic overflows: at a height of 64 or
/// more (the shift `1 << height`), or when the left child would come
/// before position 0 (`pos < 2^height`: the subtraction `pos - 2^height`).
/// The trait's caller guarantee `height > 0` is not needed by the code: at
/// height 0 it returns `(pos - 1, pos - 1)`.
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_panics() {
    panics_when(height >= 64u32 || (pos.0 as Int) < pow2(height as Int));
}

/// `Position + Position` panics when the sum overflows a `u64` (as
/// documented).
#[lift_attach(crate::merkle::position::Position::add)]
fn position_add_panics() {
    panics_when((self.0 as Int) + (rhs.0 as Int) >= pow2(64));
}

/// `Position + u64` panics when the sum overflows.
#[lift_attach(crate::merkle::position::Position::add__u64)]
fn position_add_u64_panics() {
    panics_when((self.0 as Int) + (rhs as Int) >= pow2(64));
}

/// `Position += u64` panics when the sum overflows.
#[lift_attach(crate::merkle::position::Position::add_assign__u64)]
fn position_add_assign_panics() {
    panics_when((self.0 as Int) + (rhs as Int) >= pow2(64));
}

/// `Position - Position` panics when the difference underflows (`rhs`
/// above `self`).
#[lift_attach(crate::merkle::position::Position::sub)]
fn position_sub_panics() {
    panics_when(rhs.0 > self.0);
}

/// `Position - u64` panics when the difference underflows.
#[lift_attach(crate::merkle::position::Position::sub__u64)]
fn position_sub_u64_panics() {
    panics_when(rhs > self.0);
}

/// `Position -= u64` panics when the difference underflows.
#[lift_attach(crate::merkle::position::Position::sub_assign__u64)]
fn position_sub_assign_panics() {
    panics_when(rhs > self.0);
}

/// `Location + Location` panics when the sum overflows a `u64` (as
/// documented).
#[lift_attach(crate::merkle::location::Location::add)]
fn location_add_panics() {
    panics_when((self.0 as Int) + (rhs.0 as Int) >= pow2(64));
}

/// `Location + u64` panics when the sum overflows.
#[lift_attach(crate::merkle::location::Location::add__u64)]
fn location_add_u64_panics() {
    panics_when((self.0 as Int) + (rhs as Int) >= pow2(64));
}

/// `Location += u64` panics when the sum overflows.
#[lift_attach(crate::merkle::location::Location::add_assign__u64)]
fn location_add_assign_panics() {
    panics_when((self.0 as Int) + (rhs as Int) >= pow2(64));
}

/// `Location - Location` panics when the difference underflows (`rhs`
/// above `self`).
#[lift_attach(crate::merkle::location::Location::sub)]
fn location_sub_panics() {
    panics_when(rhs.0 > self.0);
}

/// `Location - u64` panics when the difference underflows.
#[lift_attach(crate::merkle::location::Location::sub__u64)]
fn location_sub_u64_panics() {
    panics_when(rhs > self.0);
}

/// `Location -= u64` panics when the difference underflows.
#[lift_attach(crate::merkle::location::Location::sub_assign__u64)]
fn location_sub_assign_panics() {
    panics_when(rhs > self.0);
}

// ---------------------------------------------------------------------------
// The shape of a subtree (`proof.rs`): what every `Subtree` the verifier
// is given satisfies. Host code builds them (`Blueprint::new`, from the
// peaks of a structure of at most `MAX_LEAVES` leaves), so this is a
// precondition of the subtree methods, an obligation of host code listed
// in the record, until that code is lifted. (A type invariant would need
// private fields: `Subtree`'s are `pub`.) The methods document no panic:
// on another subtree their arithmetic can overflow and panic (a height of
// 64 or more, leaves past `2^64`, a root position below `2^height`) or
// they answer for a subtree no MMR has, so the shape stays a
// precondition, not a panic contract.
// ---------------------------------------------------------------------------

/// A subtree the verifier can be given: it is at most 62 high, has its
/// `2^height` leaves within `MAX_LEAVES`, and its root's position is at
/// least that of the first node of its height (`2^(height+1) - 2`, the root
/// of the leftmost tree of that height). (The height bound follows from the
/// leaf bound; it comes first so that a height far out of range is
/// rejected without computing `2^height`.)
#[spec]
#[opaque]
// known_answers.py: `well_shaped(..)` (the subtrees at 6 and 5 of an MMR;
// the one tree of `MAX_LEAVES` leaves; position 1 is a leaf; a subtree of
// height 63; leaves past `MAX_LEAVES`)
#[example(well_shaped(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }))]
#[example(well_shaped(Subtree { pos: Position::new(9223372036854775806u64), height: 62u32, leaf_start: Location::new(0u64) }))]
#[example(well_shaped(Subtree { pos: Position::new(5u64), height: 1u32, leaf_start: Location::new(2u64) }))]
#[example(!well_shaped(Subtree { pos: Position::new(1u64), height: 1u32, leaf_start: Location::new(0u64) }))]
#[example(!well_shaped(Subtree { pos: Position::new(0u64), height: 63u32, leaf_start: Location::new(0u64) }))]
#[example(!well_shaped(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(4611686018427387903u64) }))]
pub fn well_shaped(s: Subtree) -> bool {
    s.height <= 62u32 && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= max_leaves() && (s.pos.0 as Int) + 2 >= pow2((s.height as Int) + 1)
}

/// `is_before` needs a well-shaped subtree.
#[lift_attach(crate::merkle::proof::Subtree::is_before)]
fn is_before_pre() {
    requires(crate::laws::well_shaped(self));
}

/// `is_outside` needs a well-shaped subtree.
#[lift_attach(crate::merkle::proof::Subtree::is_outside)]
fn is_outside_pre() {
    requires(crate::laws::well_shaped(self));
}

/// `is_inside` needs a well-shaped subtree.
#[lift_attach(crate::merkle::proof::Subtree::is_inside)]
fn is_inside_pre() {
    requires(crate::laws::well_shaped(self));
}

/// `children` needs a well-shaped subtree above the leaves.
#[lift_attach(crate::merkle::proof::Subtree::children)]
fn children_of_subtree_pre() {
    requires(crate::laws::well_shaped(self) && self.height >= 1u32);
}

/// `reconstruct_digest` needs a well-shaped subtree. It recurses once per
/// level of the subtree, so it is at most `height` (at most 62) calls deep:
/// its depth bound `height <= 64` is a host obligation like its
/// precondition (a stack-safety statement: host code calls it with a
/// well-shaped subtree, which meets the bound), stated here, where the
/// reviewer reads it.
#[lift_attach(crate::merkle::proof::Subtree::reconstruct_digest)]
fn reconstruct_digest_pre() {
    requires(crate::laws::well_shaped(self));
    decreases(self.height, max = 64);
}

// ---------------------------------------------------------------------------
// Vocabulary: what the MMR hashes
// ---------------------------------------------------------------------------

/// The bytes hashed for the leaf at position `pos` holding `element`: the
/// position as 8 big-endian bytes, then the element.
#[spec]
// known_answers.py: `leaf_message(..)`
#[example(leaf_message(1u64, &[9u8]) == seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 9u8])]
#[example(leaf_message(258u64, &[]) == seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 2u8])]
pub fn leaf_message(pos: u64, element: &[u8]) -> Seq<u8> {
    seq![..pos.to_be_bytes(), ..element]
}

/// The bytes hashed for the internal node at position `pos` whose children
/// have the digests `left` and `right`: the position as 8 big-endian bytes,
/// then the two digests.
#[spec]
// known_answers.py: `len(node_message(..))`, `node_message(..)[:9]`
#[example(node_message(2u64, [1u8; 32], [2u8; 32]).len() == 72)]
#[example(node_message(2u64, [1u8; 32], [2u8; 32]).take(9) == seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 1u8])]
pub fn node_message(pos: u64, left: Digest, right: Digest) -> Seq<u8> {
    seq![..pos.to_be_bytes(), ..left, ..right]
}

// ---------------------------------------------------------------------------
// Vocabulary: the subtree of an MMR and what a proof carries for it. The
// known answers are on the MMR of the four leaves `[1]`, `[2]`, `[3]`,
// `[4]` (positions 0 to 6: leaves at 0, 1, 3, 4, their parents at 2 and 5,
// the root at 6), and on the MMR of eight leaves for the geometry.
// ---------------------------------------------------------------------------

/// The left half of the subtree `s` (its root's left child): `2^height`
/// positions before its root, over the first half of its leaves.
#[spec]
#[opaque]
// known_answers.py: `halves of ..`
#[example(left_half(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }) == Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) })]
#[example(left_half(Subtree { pos: Position::new(14u64), height: 3u32, leaf_start: Location::new(0u64) }) == Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) })]
#[example(left_half(Subtree { pos: Position::new(13u64), height: 2u32, leaf_start: Location::new(4u64) }) == Subtree { pos: Position::new(9u64), height: 1u32, leaf_start: Location::new(4u64) })]
#[example(left_half(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) }) == Subtree { pos: Position::new(0u64), height: 0u32, leaf_start: Location::new(0u64) })]
pub fn left_half(s: Subtree) -> Subtree {
    Subtree { pos: Position::new(((s.pos.0 as Int) - pow2(s.height as Int)) as u64), height: ((s.height as Int) - 1) as u32, leaf_start: s.leaf_start }
}

/// The right half of the subtree `s` (its root's right child): the position
/// just before its root, over the second half of its leaves.
#[spec]
#[opaque]
// known_answers.py: `halves of ..`
#[example(right_half(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }) == Subtree { pos: Position::new(5u64), height: 1u32, leaf_start: Location::new(2u64) })]
#[example(right_half(Subtree { pos: Position::new(14u64), height: 3u32, leaf_start: Location::new(0u64) }) == Subtree { pos: Position::new(13u64), height: 2u32, leaf_start: Location::new(4u64) })]
#[example(right_half(Subtree { pos: Position::new(13u64), height: 2u32, leaf_start: Location::new(4u64) }) == Subtree { pos: Position::new(12u64), height: 1u32, leaf_start: Location::new(6u64) })]
#[example(right_half(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) }) == Subtree { pos: Position::new(1u64), height: 0u32, leaf_start: Location::new(1u64) })]
pub fn right_half(s: Subtree) -> Subtree {
    Subtree { pos: Position::new(((s.pos.0 as Int) - 1) as u64), height: ((s.height as Int) - 1) as u32, leaf_start: Location::new(((s.leaf_start.0 as Int) + pow2((s.height as Int) - 1)) as u64) }
}

/// The digest of the subtree `s` of the MMR whose elements, in location
/// order, are `leaves`: a leaf's digest, or an internal node's over the
/// digests of its two halves. (A leaf past the end of `leaves` gets 32 zero
/// bytes, a placeholder: the laws apply it only to subtrees within
/// `leaves`.)
#[spec]
#[decreases(s.height)]
// known_answers.py: `m4 digest at ..`; the last example pins the placeholder
// of a leaf `leaves` lacks (the convention above, not an answer of the model)
#[example(subtree_root(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == hex!("760de5f6 3faa89b2 66b490d3 4dcf1e04 3fbac001 eb1843fb 072a8d12 512f87cd"))]
#[example(subtree_root(Subtree { pos: Position::new(5u64), height: 1u32, leaf_start: Location::new(2u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == hex!("b1953f2b 9097b569 585499cd f72de918 fb7d6e4c 076bda3a 62f463f6 8423493f"))]
#[example(subtree_root(Subtree { pos: Position::new(0u64), height: 0u32, leaf_start: Location::new(0u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"))]
#[example(subtree_root(Subtree { pos: Position::new(0u64), height: 0u32, leaf_start: Location::new(0u64) }, &[]) == [0u8; 32])]
pub fn subtree_root(s: Subtree, leaves: &[&[u8]]) -> Digest {
    if s.height == 0u32 {
        match leaves.get(s.leaf_start.0 as usize) {
            Some(e) => sha256(leaf_message(s.pos.0, e)),
            None => [0u8; 32],
        }
    } else {
        sha256(node_message(s.pos.0, subtree_root(left_half(s), leaves), subtree_root(right_half(s), leaves)))
    }
}

/// Whether the leaves of the subtree `s` all come before `range.start` or
/// all at or after `range.end` (for a range that is not empty: none of
/// them is in `range`).
#[spec]
#[opaque]
// known_answers.py: `outside(..)` (the last: the empty range 2..2)
#[example(disjoint(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(2u64), end: Location::new(4u64) }) && disjoint(Subtree { pos: Position::new(5u64), height: 1u32, leaf_start: Location::new(2u64) }, crate::__lift::Range { start: Location::new(0u64), end: Location::new(2u64) }))]
#[example(!disjoint(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(2u64) }) && !disjoint(Subtree { pos: Position::new(5u64), height: 1u32, leaf_start: Location::new(2u64) }, crate::__lift::Range { start: Location::new(3u64), end: Location::new(9u64) }))]
#[example(disjoint(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(2u64), end: Location::new(2u64) }) && !disjoint(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(2u64), end: Location::new(2u64) }))]
pub fn disjoint(s: Subtree, range: core::ops::Range<Location>) -> bool {
    (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (range.start.0 as Int) || s.leaf_start.0 >= range.end.0
}

/// The elements a proof of the leaves in `range` supplies for the subtree
/// `s`: its leaves in `range`, left to right (a leaf past the end of
/// `leaves` supplies none).
#[spec]
#[decreases(s.height)]
// known_answers.py: `m4 root, range ..: elements`
#[example(leaves_in(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == seq![&[2u8], &[3u8]])]
#[example(leaves_in(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(0u64), end: Location::new(4u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == seq![&[1u8], &[2u8], &[3u8], &[4u8]])]
#[example(leaves_in(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(4u64), end: Location::new(5u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]).len() == 0)]
pub fn leaves_in(s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]]) -> Seq<&[u8]> {
    if disjoint(s, range) {
        seq![]
    } else if s.height == 0u32 {
        match leaves.get(s.leaf_start.0 as usize) {
            Some(e) => seq![e],
            None => seq![],
        }
    } else {
        seq![..leaves_in(left_half(s), range, leaves), ..leaves_in(right_half(s), range, leaves)]
    }
}

/// The digests a proof of the leaves in `range` gives for the subtree `s`:
/// the digest of each largest part of `s` with no leaf in `range`, left to
/// right.
#[spec]
#[decreases(s.height)]
// known_answers.py: `m4 .., range ..: sibling digests (positions)`
#[example(sibling_digests(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == seq![hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")])]
#[example(sibling_digests(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(4u64), end: Location::new(5u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == seq![hex!("760de5f6 3faa89b2 66b490d3 4dcf1e04 3fbac001 eb1843fb 072a8d12 512f87cd")])]
#[example(sibling_digests(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(2u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]) == seq![hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21")])]
#[example(sibling_digests(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(0u64), end: Location::new(4u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]]).len() == 0)]
pub fn sibling_digests(s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]]) -> Seq<Digest> {
    if disjoint(s, range) {
        seq![subtree_root(s, leaves)]
    } else if s.height == 0u32 {
        seq![]
    } else {
        seq![..sibling_digests(left_half(s), range, leaves), ..sibling_digests(right_half(s), range, leaves)]
    }
}

/// Rebuilding the digest of the subtree `s` from a proof of the leaves in
/// `range` (what `reconstruct_digest` returns): `elements` are the proven
/// elements not yet used, in location order, `siblings` the proof's
/// digests, `cursor` the index of the next one not yet used, and
/// `collected`, when given, the (position, digest) pairs recorded so far.
/// A part of `s` outside `range` (`disjoint`) takes the next digest
/// (`MissingDigests` when there is none); a leaf in `range` takes the next
/// element and hashes it as the leaf at its position (`MissingElements`
/// when there is none); any other subtree rebuilds its left half, then its
/// right half, records the two halves' (position, digest) pairs (left
/// first), and hashes their digests as the node at its position. An error
/// stops the walk; what was used stays used. The result is the elements
/// not used, the cursor, the pairs recorded and the digest (or the error).
#[spec]
#[decreases(s.height)]
// known_answers.py: `rebuild ..`: an honest proof of leaves 1 and 2 (also
// recording), no digests, no elements, a part outside the range at cursor
// 1, a leaf given two elements, a leaf given a wrong element, the right half
// failing after it took an element (also recording) or a digest
#[example(match rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[2u8], &[3u8]], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize, None) { (e, c, col, r) => e.len() == 0usize && c == 2usize && col == None && r == crate::__lift::Result::Ok(hex!("760de5f6 3faa89b2 66b490d3 4dcf1e04 3fbac001 eb1843fb 072a8d12 512f87cd")) })]
#[example(rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[2u8], &[3u8]], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize, Some(seq![])).2 == Some(seq![(Position::new(0u64), hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21")), (Position::new(1u64), hex!("57371aca 58aaf804 a0eb0fad 7039c80a 1cd53f85 d29bf276 a21388ec 1be58fce")), (Position::new(3u64), hex!("cfdb2575 dd8ffadb e5371e2b d13a2eef d739836d fb174e4f d29ace2e 0a5aceb3")), (Position::new(4u64), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")), (Position::new(2u64), hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71")), (Position::new(5u64), hex!("b1953f2b 9097b569 585499cd f72de918 fb7d6e4c 076bda3a 62f463f6 8423493f"))]))]
#[example(match rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[2u8], &[3u8]], &[], 0usize, None) { (e, c, _, r) => e.len() == 2usize && c == 0usize && r == crate::__lift::Result::Err(ReconstructionError::MissingDigests) })]
#[example(match rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize, None) { (_, c, _, r) => c == 1usize && r == crate::__lift::Result::Err(ReconstructionError::MissingElements) })]
#[example(match rebuild(Subtree { pos: Position::new(2u64), height: 1u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(2u64), end: Location::new(4u64) }, &[], &[hex!("760de5f6 3faa89b2 66b490d3 4dcf1e04 3fbac001 eb1843fb 072a8d12 512f87cd"), hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71")], 1usize, None) { (_, c, _, r) => c == 2usize && r == crate::__lift::Result::Ok(hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71")) })]
#[example(match rebuild(Subtree { pos: Position::new(1u64), height: 0u32, leaf_start: Location::new(1u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(2u64) }, &[&[2u8], &[7u8]], &[], 0usize, None) { (e, _, _, r) => e.len() == 1usize && r == crate::__lift::Result::Ok(hex!("57371aca 58aaf804 a0eb0fad 7039c80a 1cd53f85 d29bf276 a21388ec 1be58fce")) })]
#[example(rebuild(Subtree { pos: Position::new(1u64), height: 0u32, leaf_start: Location::new(1u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(2u64) }, &[&[5u8]], &[], 0usize, None).3 == crate::__lift::Result::Ok(hex!("3314dcb1 2687aeca 2ac27bab eef74705 23d9d36f daa2d216 9ecbede5 f94abd53")))]
#[example(match rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[2u8], &[3u8]], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21")], 0usize, None) { (e, c, _, r) => e.len() == 0usize && c == 1usize && r == crate::__lift::Result::Err(ReconstructionError::MissingDigests) })]
#[example(match rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[2u8]], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize, Some(seq![])) { (e, c, col, r) => e.len() == 0usize && c == 1usize && col == Some(seq![(Position::new(0u64), hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21")), (Position::new(1u64), hex!("57371aca 58aaf804 a0eb0fad 7039c80a 1cd53f85 d29bf276 a21388ec 1be58fce"))]) && r == crate::__lift::Result::Err(ReconstructionError::MissingElements) })]
#[example(match rebuild(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(3u64), end: Location::new(4u64) }, &[], &[hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71"), hex!("cfdb2575 dd8ffadb e5371e2b d13a2eef d739836d fb174e4f d29ace2e 0a5aceb3")], 0usize, None) { (e, c, _, r) => e.len() == 0usize && c == 2usize && r == crate::__lift::Result::Err(ReconstructionError::MissingElements) })]
pub fn rebuild(s: Subtree, range: core::ops::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>)
    -> (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, ReconstructionError>) {
    if disjoint(s, range) {
        match siblings.get(cursor) {
            Some(d) => (elements, ((cursor as Int) + 1) as usize, collected, crate::__lift::Result::Ok(*d)),
            None => (elements, cursor, collected, crate::__lift::Result::Err(ReconstructionError::MissingDigests)),
        }
    } else if s.height == 0u32 {
        match elements.split_first() {
            Some(p) => (p.1, cursor, collected, crate::__lift::Result::Ok(sha256(leaf_message(s.pos.0, *p.0)))),
            None => (elements, cursor, collected, crate::__lift::Result::Err(ReconstructionError::MissingElements)),
        }
    } else {
        let l = rebuild(left_half(s), range, elements, siblings, cursor, collected);
        match l.3 {
            crate::__lift::Result::Err(e) => (l.0, l.1, l.2, crate::__lift::Result::Err(e)),
            crate::__lift::Result::Ok(dl) => {
                let r = rebuild(right_half(s), range, l.0, siblings, l.1, l.2);
                match r.3 {
                    crate::__lift::Result::Err(e) => (r.0, r.1, r.2, crate::__lift::Result::Err(e)),
                    crate::__lift::Result::Ok(dr) => (
                        r.0,
                        r.1,
                        match r.2 {
                            Some(c) => Some(seq![..c, (left_half(s).pos, dl), (right_half(s).pos, dr)]),
                            None => None,
                        },
                        crate::__lift::Result::Ok(sha256(node_message(s.pos.0, dl, dr))),
                    ),
                }
            }
        }
    }
}

/// The collision a forged proof meets (the witness of
/// `rebuilding_binds_the_elements`): walking the subtree `s` from its root
/// as `rebuild` does (from `elements`, `siblings` and `cursor`) and as the
/// MMR of `leaves` has it, the two messages hashed at the first node where
/// they differ (a leaf of `range` given another element than its own, or a
/// node one of whose halves rebuilt to another digest than its own). `None`
/// when rebuilding fails or no node differs. (Only the proof depends on how
/// it finds the pair: whatever it names, `collision` holds only for two
/// different messages with one SHA-256 digest.)
#[spec]
#[decreases(s.height)]
// known_answers.py: `clash: ..`: an honest proof, a leaf given [5], the
// root when its second element is [5] or its first digest is position 1's,
// no elements
#[example(rebuild_clash(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]], &[&[2u8], &[3u8]], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize) == None)]
#[example(rebuild_clash(Subtree { pos: Position::new(3u64), height: 0u32, leaf_start: Location::new(2u64) }, crate::__lift::Range { start: Location::new(2u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]], &[&[5u8]], &[], 0usize) == Some((leaf_message(3u64, &[5u8]), leaf_message(3u64, &[3u8]))))]
#[example(rebuild_clash(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]], &[&[2u8], &[5u8]], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize) == Some((node_message(6u64, hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71"), hex!("9dc026b9 01c940ac 7483a134 4ac2e2e1 ce1eda4b eb9ca0d0 344a4f73 c487d772")), node_message(6u64, hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71"), hex!("b1953f2b 9097b569 585499cd f72de918 fb7d6e4c 076bda3a 62f463f6 8423493f")))))]
#[example(rebuild_clash(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]], &[&[2u8], &[3u8]], &[hex!("57371aca 58aaf804 a0eb0fad 7039c80a 1cd53f85 d29bf276 a21388ec 1be58fce"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize) == Some((node_message(6u64, hex!("5b6c5e85 2ef3b1aa 456644a4 3440c130 00ac6672 2fb227a4 022c2f10 088a158a"), hex!("b1953f2b 9097b569 585499cd f72de918 fb7d6e4c 076bda3a 62f463f6 8423493f")), node_message(6u64, hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71"), hex!("b1953f2b 9097b569 585499cd f72de918 fb7d6e4c 076bda3a 62f463f6 8423493f")))))]
#[example(rebuild_clash(Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[&[1u8], &[2u8], &[3u8], &[4u8]], &[], &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], 0usize) == None)]
pub fn rebuild_clash(s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]], elements: &[&[u8]], siblings: &[Digest], cursor: usize) -> Option<(Seq<u8>, Seq<u8>)> {
    if disjoint(s, range) {
        None
    } else if s.height == 0u32 {
        match elements.split_first() {
            Some(p) => match leaves.get(s.leaf_start.0 as usize) {
                Some(e) => if leaf_message(s.pos.0, *p.0) == leaf_message(s.pos.0, e) { None } else { Some((leaf_message(s.pos.0, *p.0), leaf_message(s.pos.0, e))) },
                None => None,
            },
            None => None,
        }
    } else {
        let l = rebuild(left_half(s), range, elements, siblings, cursor, None);
        let cl = rebuild_clash(left_half(s), range, leaves, elements, siblings, cursor);
        let cr = rebuild_clash(right_half(s), range, leaves, l.0, siblings, l.1);
        match l.3 {
            crate::__lift::Result::Err(_) => None,
            crate::__lift::Result::Ok(dl) => {
                let r = rebuild(right_half(s), range, l.0, siblings, l.1, None);
                match r.3 {
                    crate::__lift::Result::Err(_) => None,
                    crate::__lift::Result::Ok(dr) => {
                        if node_message(s.pos.0, dl, dr) == node_message(s.pos.0, subtree_root(left_half(s), leaves), subtree_root(right_half(s), leaves)) {
                            match cl {
                                Some(c) => Some(c),
                                None => cr,
                            }
                        } else {
                            Some((node_message(s.pos.0, dl, dr), node_message(s.pos.0, subtree_root(left_half(s), leaves), subtree_root(right_half(s), leaves))))
                        }
                    }
                }
            }
        }
    }
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

/// `children` of the node at `pos` of height `height`: its subtree is the
/// `2^(height+1) - 1` positions ending at `pos` (post-order), so its right
/// child, the root of the right half, is just before it (`pos - 1`), and
/// its left child, the root of the left half, is `2^height - 1` positions
/// (the right half) before that (`pos - 2^height`).
#[lift_attach(crate::merkle::mmr::Family::children)]
fn family_children() {
    ensures(|ret: (Position, Position)| ret == (Position::new(((pos.0 as Int) - pow2(height as Int)) as u64), Position::new(((pos.0 as Int) - 1) as u64)));
}

/// `Standard::new(bagging)` is the hasher with that bagging policy.
#[lift_attach(crate::merkle::hasher::Standard::new)]
fn standard_new() {
    ensures(|ret: Standard| ret == Standard { _hasher: crate::__lift::PhantomData, bagging: bagging });
}

/// `root_bagging` is the hasher's bagging policy.
#[lift_attach(crate::merkle::hasher::Standard::root_bagging)]
fn standard_root_bagging() {
    ensures(|ret: crate::merkle::Bagging| ret == self.bagging);
}

/// `hash(parts)` is the SHA-256 of the concatenation of `parts`.
#[lift_attach(crate::merkle::hasher::Standard::hash)]
fn standard_hash() {
    ensures(|ret: [u8; 32]| ret == crate::sha256::sha256_parts(parts));
}

/// `digest(data)` is the SHA-256 of `data`.
#[lift_attach(crate::merkle::hasher::Standard::digest)]
fn standard_digest() {
    ensures(|ret: [u8; 32]| ret == crate::sha256::sha256(seq![..data]));
}

/// `fold(acc, peak)` is the SHA-256 of the accumulator, then the peak.
#[lift_attach(crate::merkle::hasher::Standard::fold)]
fn standard_fold() {
    ensures(|ret: [u8; 32]| ret == crate::sha256::sha256(seq![..*acc, ..*peak]));
}

/// `is_before(range)`: the subtree's leaves all come before the range
/// (its last leaf is before `range.start`).
#[lift_attach(crate::merkle::proof::Subtree::is_before)]
fn subtree_is_before() {
    ensures(|ret: bool| ret == ((self.leaf_start.0 as Int) + pow2(self.height as Int) <= (range.start.0 as Int)));
}

/// `is_outside(range)`: none of the subtree's leaves is in the range.
#[lift_attach(crate::merkle::proof::Subtree::is_outside)]
fn subtree_is_outside() {
    ensures(|ret: bool| ret == crate::laws::disjoint(self, *range));
}

/// `is_inside(range)`: all of the subtree's leaves are in the range.
#[lift_attach(crate::merkle::proof::Subtree::is_inside)]
fn subtree_is_inside() {
    ensures(|ret: bool| ret == (range.start.0 <= self.leaf_start.0 && (self.leaf_start.0 as Int) + pow2(self.height as Int) <= (range.end.0 as Int)));
}

/// `children()` are the subtree's two halves: its left half first, then
/// its right half.
#[lift_attach(crate::merkle::proof::Subtree::children)]
fn subtree_children() {
    ensures(|ret: (Subtree, Subtree)| ret.0 == crate::laws::left_half(self) && ret.1 == crate::laws::right_half(self));
}

/// `reconstruct_digest` rebuilds the subtree's digest from the proof
/// (`rebuild`): from the elements `elements` not yet taken, the sibling
/// digests `siblings` from index `cursor` on, and the pairs collected so
/// far, it returns what `rebuild` says (the hasher is SHA-256's: its digests
/// are `leaf_message`'s and `node_message`'s SHA-256).
#[lift_attach(crate::merkle::proof::Subtree::reconstruct_digest)]
fn subtree_reconstruct_digest() {
    ensures(|ret: (&[&[u8]], usize, Option<Seq<(Position, [u8; 32])>>, crate::__lift::Result<[u8; 32], ReconstructionError>)| ret == crate::laws::rebuild(self, *range, elements, siblings, cursor, collected));
}

// ---------------------------------------------------------------------------
// Laws: position arithmetic (as in `sandblaster/mmr/LAWS.rs`)
// ---------------------------------------------------------------------------

/// A leaf's position is the number of nodes before it: `location_to_position`
/// of location `n` is `mmr_size(n)`, which is also the size of the MMR with
/// `n` leaves.
#[law]
fn location_to_position_counts_nodes(loc: Location) {
    requires((loc.0 as Int) <= max_leaves());
    ensures(crate::merkle::mmr::Family::location_to_position(loc).0 as Int == mmr_size(loc.0 as Int));
}

// ---------------------------------------------------------------------------
// Laws: hashing (`hasher.rs` at `Standard<Sha256>`)
// ---------------------------------------------------------------------------

/// A leaf's digest is the SHA-256 of its message.
#[law]
fn leaf_digest_is_sha256_of_its_message(h: Standard, pos: Position, element: &[u8]) {
    ensures(h.leaf_digest(pos, element) == sha256(leaf_message(pos.0, element)));
}

/// An internal node's digest is the SHA-256 of its message.
#[law]
fn node_digest_is_sha256_of_its_message(h: Standard, pos: Position, left: Digest, right: Digest) {
    ensures(h.node_digest(pos, &left, &right) == sha256(node_message(pos.0, left, right)));
}

/// A node digest binds the node's position and its children's digests:
/// two equal node digests have the same position and children, unless
/// their two messages are a SHA-256 collision.
#[law]
#[reduces_to(collision_resistance)]
fn node_digests_bind(h: Standard, p: Position, l: Digest, r: Digest, q: Position, l2: Digest, r2: Digest) {
    requires(h.node_digest(p, &l, &r) == h.node_digest(q, &l2, &r2));
    ensures((p == q && l == l2 && r == r2) || collision(Some((node_message(p.0, l, r), node_message(q.0, l2, r2)))));
}

/// A leaf digest binds the leaf's position and element: two equal leaf
/// digests have the same position and element, unless their two messages
/// are a SHA-256 collision.
#[law]
#[reduces_to(collision_resistance)]
fn leaf_digests_bind(h: Standard, p: Position, e: &[u8], q: Position, e2: &[u8]) {
    requires(h.leaf_digest(p, e) == h.leaf_digest(q, e2));
    ensures((p == q && e == e2) || collision(Some((leaf_message(p.0, e), leaf_message(q.0, e2)))));
}

/// A leaf digest equals an internal node's digest only at the same
/// position, unless their two messages are a SHA-256 collision. (In one
/// MMR a position is a leaf or an internal node, never both, so a proof
/// cannot pass a node off as a leaf or a leaf as a node.)
#[law]
#[reduces_to(collision_resistance)]
fn leaves_and_nodes_differ_by_position(h: Standard, p: Position, e: &[u8], q: Position, l: Digest, r: Digest) {
    requires(h.leaf_digest(p, e) == h.node_digest(q, &l, &r));
    ensures(p == q || collision(Some((leaf_message(p.0, e), node_message(q.0, l, r)))));
}

// ---------------------------------------------------------------------------
// Laws: rebuilding a subtree's digest from a proof (`proof.rs`)
// ---------------------------------------------------------------------------

/// Honest proofs are accepted: rebuilding the subtree `s` from elements
/// that begin with its leaves in `range` and from digests that, from
/// `cursor` on, begin with the digests of its parts outside `range` (left
/// to right) gives the digest of `s` in the MMR of `leaves` and uses
/// exactly those, leaving the elements `rest` and the digests `more` for
/// the next subtree (a range proof rebuilds its peaks one after another
/// from one iterator and one cursor). Collecting pairs or not changes none
/// of this.
#[law]
fn honest_proofs_rebuild_the_subtree(s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]], elements: &[&[u8]], rest: Seq<&[u8]>, siblings: &[Digest], cursor: usize, more: Seq<Digest>, collected: Option<Seq<(Position, Digest)>>) {
    requires(well_shaped(s) && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(seq![..elements] == seq![..leaves_in(s, range, leaves), ..rest]);
    requires(seq![..siblings].skip(cursor as Nat) == seq![..sibling_digests(s, range, leaves), ..more]);
    ensures(rebuild(s, range, elements, siblings, cursor, collected).3 == crate::__lift::Result::Ok(subtree_root(s, leaves))
        && seq![..rebuild(s, range, elements, siblings, cursor, collected).0] == rest
        && (rebuild(s, range, elements, siblings, cursor, collected).1 as Int) == (cursor as Int) + sibling_digests(s, range, leaves).len());
}

/// Rebuilding binds the elements: if rebuilding the subtree `s` (collecting
/// pairs or not) gives its digest in the MMR of `leaves`, the elements it
/// used are the leaves of `s` in `range`, in order, unless two different
/// messages it hashed have one SHA-256 digest (`rebuild_clash` names them).
#[law]
#[reduces_to(collision_resistance)]
fn rebuilding_binds_the_elements(s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]], elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(well_shaped(s) && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(rebuild(s, range, elements, siblings, cursor, collected).3 == crate::__lift::Result::Ok(subtree_root(s, leaves)));
    ensures(seq![..elements] == seq![..leaves_in(s, range, leaves), ..rebuild(s, range, elements, siblings, cursor, collected).0]
        || collision(rebuild_clash(s, range, leaves, elements, siblings, cursor)));
}
