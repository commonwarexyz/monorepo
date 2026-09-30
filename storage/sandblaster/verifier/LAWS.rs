//! What the lifted verifier guarantees (first set), for `hasher.rs` and
//! `proof.rs` as written at QMDB's instance (the MMR family, SHA-256).
//! Claims and preconditions only; PROOF.rs proves them.

use sandblaster::prelude::*;
use crate::merkle::{Digest, Location, Position};
use crate::merkle::hasher::Standard;
use crate::merkle::proof::Subtree;
use crate::sha256::{collision, collision_resistance, sha256};

// ---------------------------------------------------------------------------
// Preconditions of the position arithmetic the verifier calls (the panics
// the code documents; the same statements as `sandblaster/mmr/LAWS.rs`)
// ---------------------------------------------------------------------------

/// `location_to_position` is for locations up to `MAX_LEAVES` (`2^62`).
#[lift_attach(crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_pre() {
    requires((loc.0 as Int) <= pow2(62));
}

/// `children` is for a node of height `1 ≤ height < 64` (its left child
/// `pos - 2^height` exists).
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_pre() {
    requires(height < 64u32 && pow2(height as Int) <= (pos.0 as Int));
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
// The shape of a subtree (`proof.rs`): what every `Subtree` the verifier
// is given satisfies. Host code builds them (`Blueprint::new`, from the
// peaks of a structure of at most `MAX_LEAVES` leaves), so this is a
// precondition of the subtree methods, an obligation of host code listed
// in the record, until that code is lifted. (A type invariant would need
// private fields: `Subtree`'s are `pub`.)
// ---------------------------------------------------------------------------

/// A subtree of height `height` whose root is at position `pos` and whose
/// first leaf is at location `leaf_start` is at most 62 high, its leaves lie
/// within `MAX_LEAVES` (`2^62`), and its root's position is at least that of
/// the first node of its height (`2^(h+1) - 2`, the root of the leftmost tree
/// of that height).
#[spec]
#[example(shaped(2u64, 1u32, 0u64) && shaped(6u64, 2u32, 0u64) && shaped(5u64, 1u32, 2u64))]
#[example(!shaped(1u64, 1u32, 0u64) && !shaped(0u64, 63u32, 0u64) && !shaped(2u64, 1u32, 4611686018427387903u64))]
pub fn shaped(pos: u64, height: u32, leaf_start: u64) -> bool {
    height <= 62u32 && (leaf_start as Int) + pow2(height as Int) <= pow2(62) && (pos as Int) + 2 >= pow2((height as Int) + 1)
}

/// A subtree the verifier can be given (`shaped`, of its fields).
#[spec]
#[opaque]
pub fn well_shaped(s: Subtree) -> bool {
    s.height <= 62u32 && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= pow2(62) && (s.pos.0 as Int) + 2 >= pow2((s.height as Int) + 1)
}

/// `leaf_end` needs a well-shaped subtree.
#[lift_attach(crate::merkle::proof::Subtree::leaf_end)]
fn leaf_end_pre() {
    requires(crate::laws::well_shaped(self));
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

/// `reconstruct_digest` needs a well-shaped subtree.
#[lift_attach(crate::merkle::proof::Subtree::reconstruct_digest)]
fn reconstruct_digest_pre() {
    requires(crate::laws::well_shaped(self));
}

// ---------------------------------------------------------------------------
// Vocabulary: what the MMR hashes
// ---------------------------------------------------------------------------

/// The bytes hashed for the leaf at position `pos` holding `element`: the
/// position as 8 big-endian bytes, then the element.
#[spec]
#[example(leaf_message(1u64, &[9u8]) == seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 9u8])]
#[example(leaf_message(258u64, &[]) == seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 2u8])]
pub fn leaf_message(pos: u64, element: &[u8]) -> Seq<u8> {
    seq![..pos.to_be_bytes(), ..element]
}

/// The bytes hashed for the internal node at position `pos` whose children
/// have the digests `left` and `right`: the position as 8 big-endian bytes,
/// then the two digests.
#[spec]
#[example(node_message(2u64, [1u8; 32], [2u8; 32]).len() == 72)]
#[example(node_message(2u64, [1u8; 32], [2u8; 32]).take(9) == seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 1u8])]
pub fn node_message(pos: u64, left: Digest, right: Digest) -> Seq<u8> {
    seq![..pos.to_be_bytes(), ..left, ..right]
}

// ---------------------------------------------------------------------------
// Vocabulary: the subtree of an MMR and what a proof carries for it
// ---------------------------------------------------------------------------

/// The left half of the subtree `s` (its root's left child): `2^height`
/// positions before its root, over the first half of its leaves.
#[spec]
#[opaque]
pub fn left_half(s: Subtree) -> Subtree {
    Subtree { pos: Position::new(((s.pos.0 as Int) - pow2(s.height as Int)) as u64), height: ((s.height as Int) - 1) as u32, leaf_start: s.leaf_start }
}

/// The right half of the subtree `s` (its root's right child): the position
/// just before its root, over the second half of its leaves.
#[spec]
#[opaque]
pub fn right_half(s: Subtree) -> Subtree {
    Subtree { pos: Position::new(((s.pos.0 as Int) - 1) as u64), height: ((s.height as Int) - 1) as u32, leaf_start: Location::new(((s.leaf_start.0 as Int) + pow2((s.height as Int) - 1)) as u64) }
}

/// The digest of the subtree `s` of the MMR whose elements, in location
/// order, are `leaves`: a leaf's digest, or an internal node's over the
/// digests of its two halves.
#[spec]
#[decreases(s.height)]
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

/// Whether none of the leaves of the subtree `s` is in `range`.
#[spec]
#[opaque]
pub fn disjoint(s: Subtree, range: core::ops::Range<Location>) -> bool {
    (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (range.start.0 as Int) || s.leaf_start.0 >= range.end.0
}

/// The elements a proof of the leaves in `range` supplies for the subtree
/// `s`: its leaves in `range`, left to right.
#[spec]
#[decreases(s.height)]
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
pub fn sibling_digests(s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]]) -> Seq<Digest> {
    if disjoint(s, range) {
        seq![subtree_root(s, leaves)]
    } else if s.height == 0u32 {
        seq![]
    } else {
        seq![..sibling_digests(left_half(s), range, leaves), ..sibling_digests(right_half(s), range, leaves)]
    }
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
