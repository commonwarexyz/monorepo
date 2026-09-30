//! Proofs of LAWS.rs and of the safety of the lifted files as written.
//! Machine artifacts: attachments (`#[lift_attach]`) give the lifted code
//! its measures, invariants and function summaries without touching the
//! host files.

use sandblaster::prelude::*;
use crate::merkle::{Digest, Position};
use crate::merkle::hasher::Standard;

// ---------------------------------------------------------------------------
// Powers of two (as in `sandblaster/mmr/PROOF.rs`)
// ---------------------------------------------------------------------------

/// Equal exponents, equal powers.
#[lemma]
fn pow2_eq(a: Int, b: Int) {
    requires(a == b);
    ensures(pow2(a) == pow2(b));
    rewrite(a == b);
    follows();
}

/// Congruence: equal shift amounts, equal powers.
#[lemma]
fn shl_cong(b: u32, j: u32) {
    requires(b < 64u32 && b == j);
    ensures(1u64 << b == 1u64 << j);
    follows();
}

/// `1 << b` is `2^b` (one case per amount).
#[lemma]
fn shl_one(b: u32) {
    requires(b < 64u32);
    ensures((1u64 << b) as Int == pow2(b as Int));
    if b <= 0u32 { assert(b == 0u32); shl_cong(b, 0u32); pow2_eq(b as Int, 0); follows(); }
    else if b <= 1u32 { assert(b == 1u32); shl_cong(b, 1u32); pow2_eq(b as Int, 1); follows(); }
    else if b <= 2u32 { assert(b == 2u32); shl_cong(b, 2u32); pow2_eq(b as Int, 2); follows(); }
    else if b <= 3u32 { assert(b == 3u32); shl_cong(b, 3u32); pow2_eq(b as Int, 3); follows(); }
    else if b <= 4u32 { assert(b == 4u32); shl_cong(b, 4u32); pow2_eq(b as Int, 4); follows(); }
    else if b <= 5u32 { assert(b == 5u32); shl_cong(b, 5u32); pow2_eq(b as Int, 5); follows(); }
    else if b <= 6u32 { assert(b == 6u32); shl_cong(b, 6u32); pow2_eq(b as Int, 6); follows(); }
    else if b <= 7u32 { assert(b == 7u32); shl_cong(b, 7u32); pow2_eq(b as Int, 7); follows(); }
    else if b <= 8u32 { assert(b == 8u32); shl_cong(b, 8u32); pow2_eq(b as Int, 8); follows(); }
    else if b <= 9u32 { assert(b == 9u32); shl_cong(b, 9u32); pow2_eq(b as Int, 9); follows(); }
    else if b <= 10u32 { assert(b == 10u32); shl_cong(b, 10u32); pow2_eq(b as Int, 10); follows(); }
    else if b <= 11u32 { assert(b == 11u32); shl_cong(b, 11u32); pow2_eq(b as Int, 11); follows(); }
    else if b <= 12u32 { assert(b == 12u32); shl_cong(b, 12u32); pow2_eq(b as Int, 12); follows(); }
    else if b <= 13u32 { assert(b == 13u32); shl_cong(b, 13u32); pow2_eq(b as Int, 13); follows(); }
    else if b <= 14u32 { assert(b == 14u32); shl_cong(b, 14u32); pow2_eq(b as Int, 14); follows(); }
    else if b <= 15u32 { assert(b == 15u32); shl_cong(b, 15u32); pow2_eq(b as Int, 15); follows(); }
    else if b <= 16u32 { assert(b == 16u32); shl_cong(b, 16u32); pow2_eq(b as Int, 16); follows(); }
    else if b <= 17u32 { assert(b == 17u32); shl_cong(b, 17u32); pow2_eq(b as Int, 17); follows(); }
    else if b <= 18u32 { assert(b == 18u32); shl_cong(b, 18u32); pow2_eq(b as Int, 18); follows(); }
    else if b <= 19u32 { assert(b == 19u32); shl_cong(b, 19u32); pow2_eq(b as Int, 19); follows(); }
    else if b <= 20u32 { assert(b == 20u32); shl_cong(b, 20u32); pow2_eq(b as Int, 20); follows(); }
    else if b <= 21u32 { assert(b == 21u32); shl_cong(b, 21u32); pow2_eq(b as Int, 21); follows(); }
    else if b <= 22u32 { assert(b == 22u32); shl_cong(b, 22u32); pow2_eq(b as Int, 22); follows(); }
    else if b <= 23u32 { assert(b == 23u32); shl_cong(b, 23u32); pow2_eq(b as Int, 23); follows(); }
    else if b <= 24u32 { assert(b == 24u32); shl_cong(b, 24u32); pow2_eq(b as Int, 24); follows(); }
    else if b <= 25u32 { assert(b == 25u32); shl_cong(b, 25u32); pow2_eq(b as Int, 25); follows(); }
    else if b <= 26u32 { assert(b == 26u32); shl_cong(b, 26u32); pow2_eq(b as Int, 26); follows(); }
    else if b <= 27u32 { assert(b == 27u32); shl_cong(b, 27u32); pow2_eq(b as Int, 27); follows(); }
    else if b <= 28u32 { assert(b == 28u32); shl_cong(b, 28u32); pow2_eq(b as Int, 28); follows(); }
    else if b <= 29u32 { assert(b == 29u32); shl_cong(b, 29u32); pow2_eq(b as Int, 29); follows(); }
    else if b <= 30u32 { assert(b == 30u32); shl_cong(b, 30u32); pow2_eq(b as Int, 30); follows(); }
    else if b <= 31u32 { assert(b == 31u32); shl_cong(b, 31u32); pow2_eq(b as Int, 31); follows(); }
    else if b <= 32u32 { assert(b == 32u32); shl_cong(b, 32u32); pow2_eq(b as Int, 32); follows(); }
    else if b <= 33u32 { assert(b == 33u32); shl_cong(b, 33u32); pow2_eq(b as Int, 33); follows(); }
    else if b <= 34u32 { assert(b == 34u32); shl_cong(b, 34u32); pow2_eq(b as Int, 34); follows(); }
    else if b <= 35u32 { assert(b == 35u32); shl_cong(b, 35u32); pow2_eq(b as Int, 35); follows(); }
    else if b <= 36u32 { assert(b == 36u32); shl_cong(b, 36u32); pow2_eq(b as Int, 36); follows(); }
    else if b <= 37u32 { assert(b == 37u32); shl_cong(b, 37u32); pow2_eq(b as Int, 37); follows(); }
    else if b <= 38u32 { assert(b == 38u32); shl_cong(b, 38u32); pow2_eq(b as Int, 38); follows(); }
    else if b <= 39u32 { assert(b == 39u32); shl_cong(b, 39u32); pow2_eq(b as Int, 39); follows(); }
    else if b <= 40u32 { assert(b == 40u32); shl_cong(b, 40u32); pow2_eq(b as Int, 40); follows(); }
    else if b <= 41u32 { assert(b == 41u32); shl_cong(b, 41u32); pow2_eq(b as Int, 41); follows(); }
    else if b <= 42u32 { assert(b == 42u32); shl_cong(b, 42u32); pow2_eq(b as Int, 42); follows(); }
    else if b <= 43u32 { assert(b == 43u32); shl_cong(b, 43u32); pow2_eq(b as Int, 43); follows(); }
    else if b <= 44u32 { assert(b == 44u32); shl_cong(b, 44u32); pow2_eq(b as Int, 44); follows(); }
    else if b <= 45u32 { assert(b == 45u32); shl_cong(b, 45u32); pow2_eq(b as Int, 45); follows(); }
    else if b <= 46u32 { assert(b == 46u32); shl_cong(b, 46u32); pow2_eq(b as Int, 46); follows(); }
    else if b <= 47u32 { assert(b == 47u32); shl_cong(b, 47u32); pow2_eq(b as Int, 47); follows(); }
    else if b <= 48u32 { assert(b == 48u32); shl_cong(b, 48u32); pow2_eq(b as Int, 48); follows(); }
    else if b <= 49u32 { assert(b == 49u32); shl_cong(b, 49u32); pow2_eq(b as Int, 49); follows(); }
    else if b <= 50u32 { assert(b == 50u32); shl_cong(b, 50u32); pow2_eq(b as Int, 50); follows(); }
    else if b <= 51u32 { assert(b == 51u32); shl_cong(b, 51u32); pow2_eq(b as Int, 51); follows(); }
    else if b <= 52u32 { assert(b == 52u32); shl_cong(b, 52u32); pow2_eq(b as Int, 52); follows(); }
    else if b <= 53u32 { assert(b == 53u32); shl_cong(b, 53u32); pow2_eq(b as Int, 53); follows(); }
    else if b <= 54u32 { assert(b == 54u32); shl_cong(b, 54u32); pow2_eq(b as Int, 54); follows(); }
    else if b <= 55u32 { assert(b == 55u32); shl_cong(b, 55u32); pow2_eq(b as Int, 55); follows(); }
    else if b <= 56u32 { assert(b == 56u32); shl_cong(b, 56u32); pow2_eq(b as Int, 56); follows(); }
    else if b <= 57u32 { assert(b == 57u32); shl_cong(b, 57u32); pow2_eq(b as Int, 57); follows(); }
    else if b <= 58u32 { assert(b == 58u32); shl_cong(b, 58u32); pow2_eq(b as Int, 58); follows(); }
    else if b <= 59u32 { assert(b == 59u32); shl_cong(b, 59u32); pow2_eq(b as Int, 59); follows(); }
    else if b <= 60u32 { assert(b == 60u32); shl_cong(b, 60u32); pow2_eq(b as Int, 60); follows(); }
    else if b <= 61u32 { assert(b == 61u32); shl_cong(b, 61u32); pow2_eq(b as Int, 61); follows(); }
    else if b <= 62u32 { assert(b == 62u32); shl_cong(b, 62u32); pow2_eq(b as Int, 62); follows(); }
    else if b <= 63u32 { assert(b == 63u32); shl_cong(b, 63u32); pow2_eq(b as Int, 63); follows(); }
    else { by_contradiction(); }
}

/// `children`: `1 << height` is `2^height`.
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_facts() {
    at_start! {
        crate::proofs::shl_one(height);
    }
}

// ---------------------------------------------------------------------------
// The subtree reconstruction (`proof.rs`)
// ---------------------------------------------------------------------------

/// `reconstruct_digest` recurses once per level of the subtree: its height
/// is below 64 (a `u64` leaf count), so the recursion is at most 64 deep.
#[lift_attach(crate::merkle::proof::Subtree::reconstruct_digest)]
fn reconstruct_digest_measure() {
    decreases(self.height, max = 64);
}

/// A well-shaped subtree is at most 62 high (its `2^height` leaves fit in
/// `2^62`), with its bounds as integers.
#[lemma]
fn shape_bounds(s: crate::merkle::proof::Subtree) {
    requires(crate::laws::well_shaped(s));
    ensures(s.height <= 62u32 && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= pow2(62)
        && (s.pos.0 as Int) + 2 >= pow2((s.height as Int) + 1));
    crate::words::well_shaped_is(s);
    follows();
}

/// `children`: the halves of a well-shaped subtree are well shaped, one
/// level down: the left child at `pos - 2^height`, the right one at
/// `pos - 1`, the right one's leaves after the left one's.
#[lift_attach(crate::merkle::proof::Subtree::children)]
fn children_of_subtree_facts() {
    opaque();
    at_start! {
        crate::proofs::shape_bounds(self);
        crate::proofs::shl_one(self.height);
        crate::proofs::shl_one(self.height - 1u32);
        crate::stdlib::bits::pow2_step(self.height as Int);
        crate::stdlib::bits::pow2_step((self.height as Int) + 1);
    }
    ensures(|r: (crate::merkle::proof::Subtree, crate::merkle::proof::Subtree)| crate::laws::well_shaped(r.0) && crate::laws::well_shaped(r.1)
        && r.0.height == self.height - 1u32 && r.1.height == self.height - 1u32
        && (r.0.pos.0 as Int) == (self.pos.0 as Int) - pow2(self.height as Int)
        && (r.1.pos.0 as Int) == (self.pos.0 as Int) - 1
        && r.0.leaf_start.0 == self.leaf_start.0
        && (r.1.leaf_start.0 as Int) == (self.leaf_start.0 as Int) + pow2((self.height as Int) - 1));
}

/// `leaf_end`: `1 << height` is `2^height`.
#[lift_attach(crate::merkle::proof::Subtree::leaf_end)]
fn leaf_end_facts() {
    opaque();
    at_start! {
        crate::proofs::shape_bounds(self);
        crate::proofs::shl_one(self.height);
    }
    ensures(|r: crate::merkle::Location| (r.0 as Int) == (self.leaf_start.0 as Int) + pow2(self.height as Int));
}

// ---------------------------------------------------------------------------
// Hashing (`hasher.rs` at `Standard<Sha256>`)
// ---------------------------------------------------------------------------

/// Two parts hash as their concatenation.
#[lemma]
fn concat_two(a: &[u8], b: &[u8]) {
    ensures(crate::sha256::concat(&[a, b]) == seq![..a, ..b]);
    by_unfolding(crate::sha256::concat);
}

/// Three parts hash as their concatenation.
#[lemma]
fn concat_three(a: &[u8], b: &[u8], c: &[u8]) {
    ensures(crate::sha256::concat(&[a, b, c]) == seq![..a, ..b, ..c]);
    by_unfolding(crate::sha256::concat);
}

/// `leaf_digest`: the SHA-256 of the leaf's message; callers see only that
/// (it is opaque in proofs).
#[lift_attach(crate::merkle::hasher::Standard::leaf_digest)]
fn leaf_digest_summary() {
    opaque();
    at_start! {
        crate::proofs::concat_two(&(pos.0).to_be_bytes(), element);
    }
    ensures(|r: [u8; 32]| r == crate::sha256::sha256(crate::laws::leaf_message(pos.0, element)));
}

/// `node_digest`: the SHA-256 of the node's message; opaque in proofs.
#[lift_attach(crate::merkle::hasher::Standard::node_digest)]
fn node_digest_summary() {
    opaque();
    at_start! {
        crate::proofs::concat_three(&(pos.0).to_be_bytes(), left, right);
    }
    ensures(|r: [u8; 32]| r == crate::sha256::sha256(crate::laws::node_message(pos.0, *left, *right)));
}

#[proof]
fn leaf_digest_is_sha256_of_its_message(h: Standard, pos: Position, element: &[u8]) {
    let d = h.leaf_digest(pos, element);
    follows();
}

#[proof]
fn node_digest_is_sha256_of_its_message(h: Standard, pos: Position, left: Digest, right: Digest) {
    let d = h.node_digest(pos, &left, &right);
    follows();
}

/// Two digests with the same bytes are the same digest.
#[lemma]
fn digest_bytes_inj(a: Digest, b: Digest) {
    requires(seq![..a] == seq![..b]);
    ensures(a == b);
    follows();
}

/// Two byte strings with the same bytes are the same byte string.
#[lemma]
fn bytes_inj(a: &[u8], b: &[u8]) {
    requires(seq![..a] == seq![..b]);
    ensures(a == b);
    follows();
}

/// Positions with the same value are the same position.
#[lemma]
fn position_inj(p: Position, q: Position) {
    requires(p.0 == q.0);
    ensures(p == q);
    follows();
}

#[proof]
fn node_digests_bind(h: Standard, p: Position, l: Digest, r: Digest, q: Position, l2: Digest, r2: Digest) {
    node_digest_is_sha256_of_its_message(h, p, l, r);
    node_digest_is_sha256_of_its_message(h, q, l2, r2);
    if crate::laws::node_message(p.0, l, r) == crate::laws::node_message(q.0, l2, r2) {
        unfold(crate::laws::node_message);
        crate::stdlib::seqs::append_inj::<u8>(seq![..(p.0).to_be_bytes()], seq![..l, ..r], seq![..(q.0).to_be_bytes()], seq![..l2, ..r2]);
        crate::stdlib::seqs::append_inj::<u8>(seq![..l], seq![..r], seq![..l2], seq![..r2]);
        crate::stdlib::bits::u64_bytes_inj(p.0, q.0);
        position_inj(p, q);
        digest_bytes_inj(l, l2);
        digest_bytes_inj(r, r2);
        follows();
    } else {
        by_unfolding(crate::sha256::collision);
    }
}

#[proof]
fn leaf_digests_bind(h: Standard, p: Position, e: &[u8], q: Position, e2: &[u8]) {
    leaf_digest_is_sha256_of_its_message(h, p, e);
    leaf_digest_is_sha256_of_its_message(h, q, e2);
    if crate::laws::leaf_message(p.0, e) == crate::laws::leaf_message(q.0, e2) {
        unfold(crate::laws::leaf_message);
        crate::stdlib::seqs::append_inj::<u8>(seq![..(p.0).to_be_bytes()], seq![..e], seq![..(q.0).to_be_bytes()], seq![..e2]);
        crate::stdlib::bits::u64_bytes_inj(p.0, q.0);
        position_inj(p, q);
        bytes_inj(e, e2);
        follows();
    } else {
        by_unfolding(crate::sha256::collision);
    }
}

#[proof]
fn leaves_and_nodes_differ_by_position(h: Standard, p: Position, e: &[u8], q: Position, l: Digest, r: Digest) {
    leaf_digest_is_sha256_of_its_message(h, p, e);
    node_digest_is_sha256_of_its_message(h, q, l, r);
    if crate::laws::leaf_message(p.0, e) == crate::laws::node_message(q.0, l, r) {
        unfold(crate::laws::leaf_message);
        unfold(crate::laws::node_message);
        crate::stdlib::seqs::append_inj::<u8>(seq![..(p.0).to_be_bytes()], seq![..e], seq![..(q.0).to_be_bytes()], seq![..l, ..r]);
        crate::stdlib::bits::u64_bytes_inj(p.0, q.0);
        position_inj(p, q);
        follows();
    } else {
        by_unfolding(crate::sha256::collision);
    }
}

// ---------------------------------------------------------------------------
// Rebuilding a subtree (`reconstruct_digest`)
// ---------------------------------------------------------------------------

/// `is_outside`: `disjoint`; opaque in proofs.
#[lift_attach(crate::merkle::proof::Subtree::is_outside)]
fn is_outside_summary() {
    opaque();
    at_start! {
        crate::proofs::shape_bounds(self);
        crate::words::location_ge(self.leaf_start, range.end);
        crate::words::location_le(self.leaf_end(), range.start);
    }
    ensures(|r: bool| r == crate::laws::disjoint(self, *range));
}

/// `is_outside` is `disjoint`.
#[lemma]
fn is_outside_is_disjoint(s: crate::merkle::proof::Subtree, range: core::ops::Range<crate::merkle::Location>) {
    requires(crate::laws::well_shaped(s));
    ensures(s.is_outside(&range) == crate::laws::disjoint(s, range));
    let o = s.is_outside(&range);
    follows();
}

/// A word whose value is `i` is `i as u64`.
#[lemma]
fn u64_of_int(x: u64, i: Int) {
    requires((x as Int) == i);
    ensures(x == i as u64);
    by_arithmetic();
}

/// Locations with the same value are the same location.
#[lemma]
fn location_inj(p: crate::merkle::Location, q: crate::merkle::Location) {
    requires(p.0 == q.0);
    ensures(p == q);
    follows();
}

/// The children of a well-shaped subtree above the leaves are its halves.
#[lemma]
fn children_are_halves(s: crate::merkle::proof::Subtree) {
    requires(crate::laws::well_shaped(s) && s.height >= 1u32);
    ensures(s.children() == (crate::laws::left_half(s), crate::laws::right_half(s)));
    crate::proofs::shape_bounds(s);
    let c = s.children();
    let lp = ((s.pos.0 as Int) - pow2(s.height as Int)) as u64;
    let rp = ((s.pos.0 as Int) - 1) as u64;
    let rs = ((s.leaf_start.0 as Int) + pow2((s.height as Int) - 1)) as u64;
    let ch = ((s.height as Int) - 1) as u32;
    u64_of_int(c.0.pos.0, (s.pos.0 as Int) - pow2(s.height as Int));
    u64_of_int(c.1.pos.0, (s.pos.0 as Int) - 1);
    u64_of_int(c.1.leaf_start.0, (s.leaf_start.0 as Int) + pow2((s.height as Int) - 1));
    assert(c.0.height == ch && c.1.height == ch, { by_arithmetic(); });
    position_inj(c.0.pos, Position::new(lp));
    position_inj(c.1.pos, Position::new(rp));
    location_inj(c.0.leaf_start, s.leaf_start);
    location_inj(c.1.leaf_start, crate::merkle::Location::new(rs));
    assert(c.0 == crate::laws::left_half(s), { unfold(crate::laws::left_half); follows(); });
    assert(c.1 == crate::laws::right_half(s), { unfold(crate::laws::right_half); follows(); });
    follows();
}

/// Digests whose part from `c` on is `x ++ y`: from `c + |x|` on, `y`.
#[lemma]
fn skip_after(a: &[Digest], c: Nat, x: Seq<Digest>, y: Seq<Digest>) {
    requires(seq![..a].skip(c) == seq![..x, ..y]);
    ensures(seq![..a].skip(c + x.len()) == y);
    crate::stdlib::seqs::skip_skip::<Digest>(seq![..a], c, x.len());
    crate::stdlib::seqs::take_skip_append::<Digest>(x, y);
    follows();
}

/// Digests whose part from `c` on starts with `d`: the one at `c` is `d`.
#[lemma]
fn skip_at(a: &[Digest], c: usize, d: Digest, y: Seq<Digest>) {
    requires(seq![..a].skip(c as Nat) == seq![d, ..y]);
    ensures(a.get(c) == Some(&d));
    crate::stdlib::seqs::skip_get0::<Digest>(seq![..a], c as Nat);
    assert(seq![..a].skip(c as Nat).get(0) == Some(d), {
        rewrite(seq![..a].skip(c as Nat) == seq![d, ..y]);
        by_computation();
    });
    crate::stdlib::bridges::slice_get::<Digest>(a, seq![..a], c);
    follows();
}

/// Digests whose part from `c` on is `x ++ y`: there are at least `c + |x|`.
#[lemma]
fn skip_len_after(a: &[Digest], c: Nat, x: Seq<Digest>, y: Seq<Digest>) {
    requires(c <= (a.len() as Nat) && seq![..a].skip(c) == seq![..x, ..y]);
    ensures(c + x.len() <= (a.len() as Nat));
    crate::stdlib::seqs::skip_len::<Digest>(seq![..a], c);
    crate::stdlib::seqs::len_app::<Digest>(x, y);
    assert(seq![..a].len() == (a.len() as Nat), { follows(); });
    by_arithmetic();
}

/// Byte strings that are `e ++ rest`: the first item is `e`, the rest `rest`.
#[lemma]
fn items_first(elems: &[&[u8]], e: &[u8], rest: Seq<&[u8]>) {
    requires(seq![..elems] == seq![e, ..rest]);
    ensures(0usize < elems.len() && crate::__lift::bytes_iter_next(elems).1 == Some(e) && seq![..crate::__lift::bytes_iter_next(elems).0] == rest);
    unfold(crate::__lift::bytes_iter_next);
    match elems.split_first() {
        Some(v) => {
            sandblaster::lemmas::slice::split_first_some::<&[u8]>(elems, v.0, v.1);
            assert(seq![..elems] == seq![v.0, ..v.1], { follows(); });
            assert(*v.0 == e && seq![..v.1] == rest, { follows(); });
            follows();
        }
        None => {
            sandblaster::lemmas::slice::split_first_none::<&[u8]>(elems);
            assert(elems.is_empty(), { follows(); });
            sandblaster::lemmas::slice::is_empty_nil::<&[u8]>(elems);
            assert(seq![..elems] == seq![], { follows(); });
            by_contradiction();
        }
    }
}

/// Concatenations of byte strings regroup.
#[lemma]
fn assoc_items(a: Seq<&[u8]>, b: Seq<&[u8]>, c: Seq<&[u8]>) {
    ensures(seq![..seq![..a, ..b], ..c] == seq![..a, ..seq![..b, ..c]]);
    sandblaster::lemmas::seq::append_assoc::<&[u8]>(a, b, c);
    follows();
}

/// Concatenations of digests regroup.
#[lemma]
fn assoc_digests(a: Seq<Digest>, b: Seq<Digest>, c: Seq<Digest>) {
    ensures(seq![..seq![..a, ..b], ..c] == seq![..a, ..seq![..b, ..c]]);
    sandblaster::lemmas::seq::append_assoc::<Digest>(a, b, c);
    follows();
}

/// The halves of a well-shaped subtree above the leaves: well shaped, one
/// level down, the left one over the first half of the leaves, the right
/// one over the second.
#[lemma]
fn halves_facts(s: crate::merkle::proof::Subtree) {
    requires(crate::laws::well_shaped(s) && s.height >= 1u32);
    ensures(crate::laws::well_shaped(crate::laws::left_half(s)) && crate::laws::well_shaped(crate::laws::right_half(s))
        && crate::laws::left_half(s).height == s.height - 1u32 && crate::laws::right_half(s).height == s.height - 1u32
        && crate::laws::left_half(s).leaf_start.0 == s.leaf_start.0
        && (crate::laws::right_half(s).leaf_start.0 as Int) == (s.leaf_start.0 as Int) + pow2((s.height as Int) - 1));
    let c = s.children();
    children_are_halves(s);
    follows();
}
