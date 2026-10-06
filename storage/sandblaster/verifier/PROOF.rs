//! Proofs of LAWS.rs and of the safety of the lifted files as written.
//! Machine artifacts: attachments (`#[lift_attach]`) give the lifted code
//! its measures, invariants and function summaries without touching the
//! host files.

use sandblaster::prelude::*;
use crate::merkle::{Digest, Location, Position};
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

/// `children`: `1 << height` is `2^height`; its panic theorem's walk
/// uses `children_panics`.
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_facts() {
    at_start! {
        crate::proofs::shl_one(height);
    }
    panic_lemma(crate::proofs::children_panics);
}

/// Congruence: equal amounts, equal wrapping shifts.
#[lemma]
fn wshlx_cong(x: u64, b: u32, j: u32) {
    requires(b == j);
    ensures(x.wrapping_shl(b) == x.wrapping_shl(j));
    follows();
}

/// `1.wrapping_shl(b)` is `2^b` below 64: the literal reading's `1 << b`
/// (MIR's `Shl` masks its amount; one case per amount, as `shl_one`).
#[lemma]
fn wshl_one(b: u32) {
    requires(b < 64u32);
    ensures((1u64.wrapping_shl(b) as Int) == pow2(b as Int));
    if b <= 0u32 { assert(b == 0u32); wshlx_cong(1u64, b, 0u32); pow2_eq(b as Int, 0); follows(); }
    else if b <= 1u32 { assert(b == 1u32); wshlx_cong(1u64, b, 1u32); pow2_eq(b as Int, 1); follows(); }
    else if b <= 2u32 { assert(b == 2u32); wshlx_cong(1u64, b, 2u32); pow2_eq(b as Int, 2); follows(); }
    else if b <= 3u32 { assert(b == 3u32); wshlx_cong(1u64, b, 3u32); pow2_eq(b as Int, 3); follows(); }
    else if b <= 4u32 { assert(b == 4u32); wshlx_cong(1u64, b, 4u32); pow2_eq(b as Int, 4); follows(); }
    else if b <= 5u32 { assert(b == 5u32); wshlx_cong(1u64, b, 5u32); pow2_eq(b as Int, 5); follows(); }
    else if b <= 6u32 { assert(b == 6u32); wshlx_cong(1u64, b, 6u32); pow2_eq(b as Int, 6); follows(); }
    else if b <= 7u32 { assert(b == 7u32); wshlx_cong(1u64, b, 7u32); pow2_eq(b as Int, 7); follows(); }
    else if b <= 8u32 { assert(b == 8u32); wshlx_cong(1u64, b, 8u32); pow2_eq(b as Int, 8); follows(); }
    else if b <= 9u32 { assert(b == 9u32); wshlx_cong(1u64, b, 9u32); pow2_eq(b as Int, 9); follows(); }
    else if b <= 10u32 { assert(b == 10u32); wshlx_cong(1u64, b, 10u32); pow2_eq(b as Int, 10); follows(); }
    else if b <= 11u32 { assert(b == 11u32); wshlx_cong(1u64, b, 11u32); pow2_eq(b as Int, 11); follows(); }
    else if b <= 12u32 { assert(b == 12u32); wshlx_cong(1u64, b, 12u32); pow2_eq(b as Int, 12); follows(); }
    else if b <= 13u32 { assert(b == 13u32); wshlx_cong(1u64, b, 13u32); pow2_eq(b as Int, 13); follows(); }
    else if b <= 14u32 { assert(b == 14u32); wshlx_cong(1u64, b, 14u32); pow2_eq(b as Int, 14); follows(); }
    else if b <= 15u32 { assert(b == 15u32); wshlx_cong(1u64, b, 15u32); pow2_eq(b as Int, 15); follows(); }
    else if b <= 16u32 { assert(b == 16u32); wshlx_cong(1u64, b, 16u32); pow2_eq(b as Int, 16); follows(); }
    else if b <= 17u32 { assert(b == 17u32); wshlx_cong(1u64, b, 17u32); pow2_eq(b as Int, 17); follows(); }
    else if b <= 18u32 { assert(b == 18u32); wshlx_cong(1u64, b, 18u32); pow2_eq(b as Int, 18); follows(); }
    else if b <= 19u32 { assert(b == 19u32); wshlx_cong(1u64, b, 19u32); pow2_eq(b as Int, 19); follows(); }
    else if b <= 20u32 { assert(b == 20u32); wshlx_cong(1u64, b, 20u32); pow2_eq(b as Int, 20); follows(); }
    else if b <= 21u32 { assert(b == 21u32); wshlx_cong(1u64, b, 21u32); pow2_eq(b as Int, 21); follows(); }
    else if b <= 22u32 { assert(b == 22u32); wshlx_cong(1u64, b, 22u32); pow2_eq(b as Int, 22); follows(); }
    else if b <= 23u32 { assert(b == 23u32); wshlx_cong(1u64, b, 23u32); pow2_eq(b as Int, 23); follows(); }
    else if b <= 24u32 { assert(b == 24u32); wshlx_cong(1u64, b, 24u32); pow2_eq(b as Int, 24); follows(); }
    else if b <= 25u32 { assert(b == 25u32); wshlx_cong(1u64, b, 25u32); pow2_eq(b as Int, 25); follows(); }
    else if b <= 26u32 { assert(b == 26u32); wshlx_cong(1u64, b, 26u32); pow2_eq(b as Int, 26); follows(); }
    else if b <= 27u32 { assert(b == 27u32); wshlx_cong(1u64, b, 27u32); pow2_eq(b as Int, 27); follows(); }
    else if b <= 28u32 { assert(b == 28u32); wshlx_cong(1u64, b, 28u32); pow2_eq(b as Int, 28); follows(); }
    else if b <= 29u32 { assert(b == 29u32); wshlx_cong(1u64, b, 29u32); pow2_eq(b as Int, 29); follows(); }
    else if b <= 30u32 { assert(b == 30u32); wshlx_cong(1u64, b, 30u32); pow2_eq(b as Int, 30); follows(); }
    else if b <= 31u32 { assert(b == 31u32); wshlx_cong(1u64, b, 31u32); pow2_eq(b as Int, 31); follows(); }
    else if b <= 32u32 { assert(b == 32u32); wshlx_cong(1u64, b, 32u32); pow2_eq(b as Int, 32); follows(); }
    else if b <= 33u32 { assert(b == 33u32); wshlx_cong(1u64, b, 33u32); pow2_eq(b as Int, 33); follows(); }
    else if b <= 34u32 { assert(b == 34u32); wshlx_cong(1u64, b, 34u32); pow2_eq(b as Int, 34); follows(); }
    else if b <= 35u32 { assert(b == 35u32); wshlx_cong(1u64, b, 35u32); pow2_eq(b as Int, 35); follows(); }
    else if b <= 36u32 { assert(b == 36u32); wshlx_cong(1u64, b, 36u32); pow2_eq(b as Int, 36); follows(); }
    else if b <= 37u32 { assert(b == 37u32); wshlx_cong(1u64, b, 37u32); pow2_eq(b as Int, 37); follows(); }
    else if b <= 38u32 { assert(b == 38u32); wshlx_cong(1u64, b, 38u32); pow2_eq(b as Int, 38); follows(); }
    else if b <= 39u32 { assert(b == 39u32); wshlx_cong(1u64, b, 39u32); pow2_eq(b as Int, 39); follows(); }
    else if b <= 40u32 { assert(b == 40u32); wshlx_cong(1u64, b, 40u32); pow2_eq(b as Int, 40); follows(); }
    else if b <= 41u32 { assert(b == 41u32); wshlx_cong(1u64, b, 41u32); pow2_eq(b as Int, 41); follows(); }
    else if b <= 42u32 { assert(b == 42u32); wshlx_cong(1u64, b, 42u32); pow2_eq(b as Int, 42); follows(); }
    else if b <= 43u32 { assert(b == 43u32); wshlx_cong(1u64, b, 43u32); pow2_eq(b as Int, 43); follows(); }
    else if b <= 44u32 { assert(b == 44u32); wshlx_cong(1u64, b, 44u32); pow2_eq(b as Int, 44); follows(); }
    else if b <= 45u32 { assert(b == 45u32); wshlx_cong(1u64, b, 45u32); pow2_eq(b as Int, 45); follows(); }
    else if b <= 46u32 { assert(b == 46u32); wshlx_cong(1u64, b, 46u32); pow2_eq(b as Int, 46); follows(); }
    else if b <= 47u32 { assert(b == 47u32); wshlx_cong(1u64, b, 47u32); pow2_eq(b as Int, 47); follows(); }
    else if b <= 48u32 { assert(b == 48u32); wshlx_cong(1u64, b, 48u32); pow2_eq(b as Int, 48); follows(); }
    else if b <= 49u32 { assert(b == 49u32); wshlx_cong(1u64, b, 49u32); pow2_eq(b as Int, 49); follows(); }
    else if b <= 50u32 { assert(b == 50u32); wshlx_cong(1u64, b, 50u32); pow2_eq(b as Int, 50); follows(); }
    else if b <= 51u32 { assert(b == 51u32); wshlx_cong(1u64, b, 51u32); pow2_eq(b as Int, 51); follows(); }
    else if b <= 52u32 { assert(b == 52u32); wshlx_cong(1u64, b, 52u32); pow2_eq(b as Int, 52); follows(); }
    else if b <= 53u32 { assert(b == 53u32); wshlx_cong(1u64, b, 53u32); pow2_eq(b as Int, 53); follows(); }
    else if b <= 54u32 { assert(b == 54u32); wshlx_cong(1u64, b, 54u32); pow2_eq(b as Int, 54); follows(); }
    else if b <= 55u32 { assert(b == 55u32); wshlx_cong(1u64, b, 55u32); pow2_eq(b as Int, 55); follows(); }
    else if b <= 56u32 { assert(b == 56u32); wshlx_cong(1u64, b, 56u32); pow2_eq(b as Int, 56); follows(); }
    else if b <= 57u32 { assert(b == 57u32); wshlx_cong(1u64, b, 57u32); pow2_eq(b as Int, 57); follows(); }
    else if b <= 58u32 { assert(b == 58u32); wshlx_cong(1u64, b, 58u32); pow2_eq(b as Int, 58); follows(); }
    else if b <= 59u32 { assert(b == 59u32); wshlx_cong(1u64, b, 59u32); pow2_eq(b as Int, 59); follows(); }
    else if b <= 60u32 { assert(b == 60u32); wshlx_cong(1u64, b, 60u32); pow2_eq(b as Int, 60); follows(); }
    else if b <= 61u32 { assert(b == 61u32); wshlx_cong(1u64, b, 61u32); pow2_eq(b as Int, 61); follows(); }
    else if b <= 62u32 { assert(b == 62u32); wshlx_cong(1u64, b, 62u32); pow2_eq(b as Int, 62); follows(); }
    else if b <= 63u32 { assert(b == 63u32); wshlx_cong(1u64, b, 63u32); pow2_eq(b as Int, 63); follows(); }
    else { by_contradiction(); }
}

/// `children`'s panic condition as its code tests it: a height of 64 or
/// more (the shift's check), or `pos` below `1 << height` (the
/// subtraction's).
#[lemma]
fn children_panics(pos: Position, height: u32) {
    requires(height >= 64u32 || (pos.0 as Int) < pow2(height as Int));
    ensures(height >= 64u32 || pos.0 < 1u64.wrapping_shl(height));
    if height >= 64u32 {
        follows();
    } else {
        wshl_one(height);
        follows();
    }
}

// ---------------------------------------------------------------------------
// The subtree reconstruction (`proof.rs`)
// ---------------------------------------------------------------------------

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

/// `children`: its contract (the halves) in the words it computes them
/// (`1 << (height - 1)` is `2^(height - 1)`, and so is the right half's
/// offset); the halves are well shaped, one level down.
#[lift_attach(crate::merkle::proof::Subtree::children)]
fn children_of_subtree_facts() {
    opaque();
    at_start! {
        crate::proofs::shape_bounds(self);
        crate::proofs::shl_one(self.height);
        crate::proofs::shl_one(self.height - 1u32);
        crate::stdlib::bits::pow2_step(self.height as Int);
        crate::stdlib::bits::pow2_step((self.height as Int) + 1);
        crate::proofs::right_start(self);
        crate::proofs::halves_are(self);
        crate::proofs::halves_facts(self);
        crate::proofs::children_in_range(self);
    }
    ensures(|ret: (Subtree, Subtree)| crate::laws::well_shaped(ret.0) && crate::laws::well_shaped(ret.1)
        && ret.0.height == self.height - 1u32 && ret.1.height == self.height - 1u32);
}

/// A well-shaped subtree above the leaves is in `Family::children`'s
/// range: the no-panic clause of its panic contract.
#[lemma]
fn children_in_range(s: crate::merkle::proof::Subtree) {
    requires(crate::laws::well_shaped(s) && s.height >= 1u32);
    ensures(!(s.height >= 64u32 || (s.pos.0 as Int) < pow2(s.height as Int)));
    shape_bounds(s);
    crate::stdlib::bits::pow2_step(s.height as Int);
    crate::stdlib::bits::pow2_step((s.height as Int) + 1);
    follows();
}

/// The first leaf of the right half as `children` computes it
/// (`leaf_start + (1 << (height - 1))`) and as `right_half` states it.
#[lemma]
fn right_start(s: crate::merkle::proof::Subtree) {
    requires(s.height >= 1u32 && s.height <= 62u32 && ((1u64 << (s.height - 1u32)) as Int) == pow2((s.height as Int) - 1)
        && (s.leaf_start.0 as Int) + pow2((s.height as Int) - 1) < pow2(64));
    ensures(Location::new(s.leaf_start.0 + (1u64 << (s.height - 1u32))) == Location::new(((s.leaf_start.0 as Int) + pow2((s.height as Int) - 1)) as u64));
    assert(s.leaf_start.0 + (1u64 << (s.height - 1u32)) == ((s.leaf_start.0 as Int) + pow2((s.height as Int) - 1)) as u64, { by_arithmetic(); });
    follows();
}

/// The halves of a well-shaped subtree above the leaves, with the height
/// as `children` computes it (`height - 1`): the left one at
/// `pos - 2^height`, the right one at `pos - 1` over the leaves from
/// `leaf_start + 2^(height - 1)`.
#[lemma]
fn halves_are(s: crate::merkle::proof::Subtree) {
    requires(crate::laws::well_shaped(s) && s.height >= 1u32);
    ensures(crate::laws::left_half(s) == crate::merkle::proof::Subtree { pos: Position::new(((s.pos.0 as Int) - pow2(s.height as Int)) as u64), height: s.height - 1u32, leaf_start: s.leaf_start }
        && crate::laws::right_half(s) == crate::merkle::proof::Subtree { pos: Position::new(((s.pos.0 as Int) - 1) as u64), height: s.height - 1u32, leaf_start: Location::new(((s.leaf_start.0 as Int) + pow2((s.height as Int) - 1)) as u64) });
    assert(((s.height as Int) - 1) as u32 == s.height - 1u32, { by_arithmetic(); });
    unfold(crate::laws::left_half);
    unfold(crate::laws::right_half);
    follows();
}

/// `leaf_end` (internal: only `is_before` and `is_inside` call it) needs a
/// well-shaped subtree; `1 << height` is `2^height`.
#[lift_attach(crate::merkle::proof::Subtree::leaf_end)]
fn leaf_end_facts() {
    requires(crate::laws::well_shaped(self));
    opaque();
    at_start! {
        crate::proofs::shape_bounds(self);
        crate::proofs::shl_one(self.height);
    }
    ensures(|ret: crate::merkle::Location| (ret.0 as Int) == (self.leaf_start.0 as Int) + pow2(self.height as Int));
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
    ensures(|ret: bool| ret == crate::laws::disjoint(self, *range));
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
    let c = s.children();
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
    crate::proofs::shape_bounds(s);
    crate::proofs::halves_are(s);
    crate::stdlib::bits::pow2_step(s.height as Int);
    crate::stdlib::bits::pow2_step((s.height as Int) + 1);
    crate::words::well_shaped_is(crate::laws::left_half(s));
    crate::words::well_shaped_is(crate::laws::right_half(s));
    follows();
}

// ---------------------------------------------------------------------------
// The position arithmetic's contracts (as in `sandblaster/mmr/PROOF.rs`)
// ---------------------------------------------------------------------------

/// `location_to_position`: the node count before the leaf (opaque to its
/// callers: they use this summary, not its body's `expect`).
#[lift_attach(crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_summary() {
    opaque();
    at_start! {
        crate::stdlib::bits::count_ones_u64(loc.0);
        crate::proofs::double_fits(loc.0);
    }
    ensures(|ret: Position| (ret.0 as Int) == crate::laws::mmr_size(loc.0 as Int));
}

/// `checked_mul(2)` of a location up to `2^62` does not overflow (the
/// test in the form `checked_mul` makes it).
#[lemma]
fn double_fits(x: u64) {
    requires((x as Int) <= pow2(62));
    ensures(((x as Int) * 2 <= 18446744073709551615) == true);
    follows();
}

/// `Position::try_from(Location)` (opaque to its callers).
#[lift_attach(crate::merkle::position::Position::try_from__Location)]
fn try_from_summary() {
    opaque();
    ensures(|ret: crate::__lift::Result<Position, crate::merkle::Error>| match ret {
        crate::__lift::Result::Ok(q) => (loc.0 as Int) <= pow2(62) && (q.0 as Int) == crate::laws::mmr_size(loc.0 as Int),
        crate::__lift::Result::Err(_) => (loc.0 as Int) > pow2(62),
    });
}

/// From the summary (the call in a proof step brings it in).
#[proof]
fn location_to_position_counts_nodes(loc: Location) {
    let r = crate::merkle::mmr::Family::location_to_position(loc);
    follows();
}

/// Positions with equal values are equal (the marker carries nothing).
#[lemma]
fn position_ext(a: Position, b: Position) {
    requires(a.0 == b.0);
    ensures(a == b);
    match a {
        Position(x, p) => match b {
            Position(y, q) => match p {
                crate::__lift::PhantomData => match q {
                    crate::__lift::PhantomData => follows(),
                },
            },
        },
    }
}

/// `location_to_position` is pinned by its law.
#[proof(complete = crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_determined(loc: Location) {
    use_hyp(0, loc);
    use_real(0, loc);
    apply(position_ext);
}

/// `order` by cases (its definition).
#[lemma]
fn order_def(a: Int, b: Int) {
    ensures(crate::laws::order(a, b) == (if a < b { crate::__lift::Ordering::Less } else if a == b { crate::__lift::Ordering::Equal } else { crate::__lift::Ordering::Greater }));
    by_unfolding(crate::laws::order);
}

/// `Position::cmp` compares the values.
#[lift_attach(crate::merkle::position::Position::cmp)]
fn position_cmp_facts() {
    at_start! {
        crate::proofs::order_def(self.0 as Int, other.0 as Int);
    }
}

/// `Position::partial_cmp` with a `u64` compares the value.
#[lift_attach(crate::merkle::position::Position::partial_cmp__u64)]
fn position_partial_cmp_u64_facts() {
    at_start! {
        crate::proofs::order_def(self.0 as Int, *other as Int);
    }
}

/// `Location::cmp` compares the values.
#[lift_attach(crate::merkle::location::Location::cmp)]
fn location_cmp_facts() {
    at_start! {
        crate::proofs::order_def(self.0 as Int, other.0 as Int);
    }
}

/// `Location::partial_cmp` with a `u64` compares the value.
#[lift_attach(crate::merkle::location::Location::partial_cmp__u64)]
fn location_partial_cmp_u64_facts() {
    at_start! {
        crate::proofs::order_def(self.0 as Int, *other as Int);
    }
}

/// `Position::partial_cmp` compares the values (through `cmp`).
#[lift_attach(crate::merkle::position::Position::partial_cmp)]
fn position_partial_cmp_facts() {
    at_start! {
        crate::proofs::order_def(self.0 as Int, other.0 as Int);
    }
}

/// `Location::partial_cmp` compares the values (through `cmp`).
#[lift_attach(crate::merkle::location::Location::partial_cmp)]
fn location_partial_cmp_facts() {
    at_start! {
        crate::proofs::order_def(self.0 as Int, other.0 as Int);
    }
}

/// `u64`'s `partial_cmp` with a position compares the value.
#[lift_attach(crate::merkle::position::u64__partial_cmp__Position)]
fn u64_partial_cmp_position_facts() {
    at_start! {
        crate::proofs::order_def(self_ as Int, other.0 as Int);
    }
}

/// `u64`'s `partial_cmp` with a location compares the value.
#[lift_attach(crate::merkle::location::u64__partial_cmp__Location)]
fn u64_partial_cmp_location_facts() {
    at_start! {
        crate::proofs::order_def(self_ as Int, other.0 as Int);
    }
}

// ---------------------------------------------------------------------------
// The hasher's contracts
// ---------------------------------------------------------------------------

/// One part hashes as itself.
#[lemma]
fn concat_one(a: &[u8]) {
    ensures(crate::sha256::concat(&[a]) == seq![..a]);
    by_unfolding(crate::sha256::concat);
}

/// `digest`: the one part it hashes.
#[lift_attach(crate::merkle::hasher::Standard::digest)]
fn digest_facts() {
    at_start! {
        crate::proofs::concat_one(data);
    }
}

/// `fold`: the two parts it hashes.
#[lift_attach(crate::merkle::hasher::Standard::fold)]
fn fold_facts() {
    at_start! {
        crate::proofs::concat_two(acc, peak);
    }
}

// ---------------------------------------------------------------------------
// `reconstruct_digest`'s contract (`rebuild`)
// ---------------------------------------------------------------------------

/// One step of `rebuild` on a subtree outside the range: the next digest.
#[lemma]
fn rebuild_outside(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::disjoint(s, range));
    ensures(crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (match siblings.get(cursor) {
        Some(d) => (elements, ((cursor as Int) + 1) as usize, collected, crate::__lift::Result::Ok(*d)),
        None => (elements, cursor, collected, crate::__lift::Result::Err(crate::merkle::proof::ReconstructionError::MissingDigests)),
    }));
    unfold(crate::laws::rebuild);
    follows();
}


/// `rebuild`'s node case after its left half returned `dl`: the right half,
/// then the node.
#[spec]
// known_answers.py: `rebuild subtree at 2, range 1..3`, `rebuild subtree at 5 after it, then the root`
#[example(after_left(crate::merkle::proof::Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], (&[&[3u8]], 1usize, None, crate::__lift::Result::Ok(hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71"))), hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71")).1 == 2usize)]
#[example(after_left(crate::merkle::proof::Subtree { pos: Position::new(6u64), height: 2u32, leaf_start: Location::new(0u64) }, crate::__lift::Range { start: Location::new(1u64), end: Location::new(3u64) }, &[hex!("2ae1c19c 0cbd378e 46c927a9 f3611923 ec07cc1a e357502a 09536d45 5275cf21"), hex!("13ab0e82 105ce64b d07ff85d 4e8b8b66 245bae76 a1a4ccf9 344da003 051f6537")], (&[&[3u8]], 1usize, None, crate::__lift::Result::Ok(hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71"))), hex!("bf7c6368 0c5908e6 5cc9aa23 85bf7cfc 24e5c78a 3a28babb 28ce2670 0e479b71")).3 == crate::__lift::Result::Ok(hex!("760de5f6 3faa89b2 66b490d3 4dcf1e04 3fbac001 eb1843fb 072a8d12 512f87cd")))]
fn after_left(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, siblings: &[Digest], l: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>), dl: Digest) -> (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>) {
    match crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).3 {
        crate::__lift::Result::Err(e) => (crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).0, crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).1, crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).2, crate::__lift::Result::Err(e)),
        crate::__lift::Result::Ok(dr) => (
            crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).0,
            crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).1,
            crate::proofs::record(crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2).2, (crate::laws::left_half(s).pos, dl), (crate::laws::right_half(s).pos, dr)),
            crate::__lift::Result::Ok(crate::sha256::sha256(crate::laws::node_message(s.pos.0, dl, dr))),
        ),
    }
}

/// Two pairs pushed to the collected digests, when they are collected (as
/// `reconstruct_digest` pushes them).
#[spec]
#[example(record(None, (Position::new(1u64), [1u8; 32]), (Position::new(2u64), [2u8; 32])) == None)]
#[example(record(Some(seq![]), (Position::new(1u64), [1u8; 32]), (Position::new(2u64), [2u8; 32])) == Some(seq![(Position::new(1u64), [1u8; 32]), (Position::new(2u64), [2u8; 32])]))]
fn record(col: Option<Seq<(Position, Digest)>>, a: (Position, Digest), b: (Position, Digest)) -> Option<Seq<(Position, Digest)>> {
    match col {
        Some(c) => Some(crate::__lift_model::vec_push(crate::__lift_model::vec_push(c, a), b)),
        None => None,
    }
}

/// `record` as `rebuild` states it: the two pairs appended.
#[lemma]
fn record_spec(col: Option<Seq<(Position, Digest)>>, a: (Position, Digest), b: (Position, Digest)) {
    ensures(crate::proofs::record(col, a, b) == (match col { Some(c) => Some(seq![..c, a, b]), None => None }));
    match col {
        Some(c) => {
            unfold(crate::proofs::record);
            unfold(crate::__lift_model::vec_push);
            sandblaster::lemmas::seq::append_assoc::<(Position, Digest)>(c, seq![a], seq![b]);
            follows();
        }
        None => {
            unfold(crate::proofs::record);
            follows();
        }
    }
}

/// `record_spec` for every argument.
#[lemma]
fn record_spec_all() {
    ensures(forall(|col: Option<Seq<(Position, Digest)>>, a: (Position, Digest), b: (Position, Digest)| crate::proofs::record(col, a, b) == (match col { Some(c) => Some(seq![..c, a, b]), None => None })));
    follows();
}

/// `rebuild` one step: its definition at these arguments.
#[lemma]
fn rebuild_step(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    ensures(crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (if crate::laws::disjoint(s, range) {
        match siblings.get(cursor) {
            Some(d) => (elements, ((cursor as Int) + 1) as usize, collected, crate::__lift::Result::Ok(*d)),
            None => (elements, cursor, collected, crate::__lift::Result::Err(crate::merkle::proof::ReconstructionError::MissingDigests)),
        }
    } else if s.height == 0u32 {
        match elements.split_first() {
            Some(p) => (p.1, cursor, collected, crate::__lift::Result::Ok(crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, *p.0)))),
            None => (elements, cursor, collected, crate::__lift::Result::Err(crate::merkle::proof::ReconstructionError::MissingElements)),
        }
    } else {
        let l = crate::laws::rebuild(crate::laws::left_half(s), range, elements, siblings, cursor, collected);
        match l.3 {
            crate::__lift::Result::Err(e) => (l.0, l.1, l.2, crate::__lift::Result::Err(e)),
            crate::__lift::Result::Ok(dl) => {
                let r = crate::laws::rebuild(crate::laws::right_half(s), range, l.0, siblings, l.1, l.2);
                match r.3 {
                    crate::__lift::Result::Err(e) => (r.0, r.1, r.2, crate::__lift::Result::Err(e)),
                    crate::__lift::Result::Ok(dr) => (
                        r.0,
                        r.1,
                        match r.2 {
                            Some(c) => Some(seq![..c, (crate::laws::left_half(s).pos, dl), (crate::laws::right_half(s).pos, dr)]),
                            None => None,
                        },
                        crate::__lift::Result::Ok(crate::sha256::sha256(crate::laws::node_message(s.pos.0, dl, dr))),
                    ),
                }
            }
        }
    }));
    by_unfolding(crate::laws::rebuild);
}

/// `rebuild` one step on a node, as `reconstruct_digest`'s tests find it
/// (the conclusion is a fact of its node branch, whose path facts are the
/// hypotheses).
#[lemma]
fn rebuild_case_node(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s));
    ensures(implies(s.is_outside(&range) == false, implies((s.height == 0u32) == false, crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (match crate::laws::rebuild(crate::laws::left_half(s), range, elements, siblings, cursor, collected).3 {
        crate::__lift::Result::Err(e) => (crate::laws::rebuild(crate::laws::left_half(s), range, elements, siblings, cursor, collected).0, crate::laws::rebuild(crate::laws::left_half(s), range, elements, siblings, cursor, collected).1, crate::laws::rebuild(crate::laws::left_half(s), range, elements, siblings, cursor, collected).2, crate::__lift::Result::Err(e)),
        crate::__lift::Result::Ok(dl) => crate::proofs::after_left(s, range, siblings, crate::laws::rebuild(crate::laws::left_half(s), range, elements, siblings, cursor, collected), dl),
    }))));
    is_outside_is_disjoint(s, range);
    if crate::laws::disjoint(s, range) {
        assert(s.is_outside(&range) == true, { follows(); });
        follows();
    } else if s.height == 0u32 {
        assert((s.height == 0u32) == true, { follows(); });
        follows();
    } else {
        rebuild_node(s, range, elements, siblings, cursor, collected);
        follows();
    }
}

/// A node whose left half fails: the left half's state and error (a
/// forward rule: its hypotheses are the left half's induction hypothesis
/// and the code's path facts, its conclusion the node's value).
#[lemma]
fn node_left_fails(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s));
    ensures(implies(s.is_outside(&range) == false, implies((s.height == 0u32) == false, forall(|t: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|x: crate::merkle::proof::ReconstructionError| implies(t == crate::laws::rebuild(s.children().0, range, elements, siblings, cursor, collected), implies(t.3 == crate::__lift::Result::Err(x), crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (t.0, t.1, t.2, crate::__lift::Result::Err(x)))))))));
    rebuild_case_node(s, range, elements, siblings, cursor, collected);
    if s.height >= 1u32 {
        children_are_halves(s);
        follows();
    } else {
        follows();
    }
}

/// A node whose right half fails: the right half's state and error.
#[lemma]
fn node_right_fails(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s));
    ensures(implies(s.is_outside(&range) == false, implies((s.height == 0u32) == false, forall(|t: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|dl: Digest| forall(|u: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|x: crate::merkle::proof::ReconstructionError| implies(t == crate::laws::rebuild(s.children().0, range, elements, siblings, cursor, collected), implies(t.3 == crate::__lift::Result::Ok(dl), implies(u == crate::laws::rebuild(s.children().1, range, t.0, siblings, t.1, t.2), implies(u.3 == crate::__lift::Result::Err(x), crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (u.0, u.1, u.2, crate::__lift::Result::Err(x)))))))))))));
    rebuild_case_node(s, range, elements, siblings, cursor, collected);
    if s.height >= 1u32 {
        children_are_halves(s);
        follows();
    } else {
        follows();
    }
}

/// A node whose halves both rebuild, collecting: the right half's elements
/// and cursor, the two halves' pairs pushed, and the node digest (in the
/// words `reconstruct_digest` computes them; the last hypothesis is
/// `node_digest`'s summary at its call).
#[lemma]
fn node_rebuilds_collecting(h: Standard, s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s));
    ensures(implies(s.is_outside(&range) == false, implies((s.height == 0u32) == false, forall(|t: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|dl: Digest| forall(|u: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|dr: Digest| forall(|c: Seq<(Position, Digest)>| implies(t == crate::laws::rebuild(s.children().0, range, elements, siblings, cursor, collected), implies(t.3 == crate::__lift::Result::Ok(dl), implies(u == crate::laws::rebuild(s.children().1, range, t.0, siblings, t.1, t.2), implies(u.3 == crate::__lift::Result::Ok(dr), implies(h.node_digest(s.pos, &dl, &dr) == crate::sha256::sha256(crate::laws::node_message(s.pos.0, dl, dr)), implies(u.2 == Some(c), crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (u.0, u.1, Some(crate::__lift_model::vec_push(crate::__lift_model::vec_push(c, (s.children().0.pos, dl)), (s.children().1.pos, dr))), crate::__lift::Result::Ok(h.node_digest(s.pos, &dl, &dr)))))))))))))))));
    rebuild_case_node(s, range, elements, siblings, cursor, collected);
    if s.height >= 1u32 {
        children_are_halves(s);
        follows();
    } else {
        follows();
    }
}

/// A node whose halves both rebuild, not collecting.
#[lemma]
fn node_rebuilds_quietly(h: Standard, s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s));
    ensures(implies(s.is_outside(&range) == false, implies((s.height == 0u32) == false, forall(|t: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|dl: Digest| forall(|u: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, crate::__lift::Result<Digest, crate::merkle::proof::ReconstructionError>)| forall(|dr: Digest| implies(t == crate::laws::rebuild(s.children().0, range, elements, siblings, cursor, collected), implies(t.3 == crate::__lift::Result::Ok(dl), implies(u == crate::laws::rebuild(s.children().1, range, t.0, siblings, t.1, t.2), implies(u.3 == crate::__lift::Result::Ok(dr), implies(h.node_digest(s.pos, &dl, &dr) == crate::sha256::sha256(crate::laws::node_message(s.pos.0, dl, dr)), implies(u.2 == None, crate::laws::rebuild(s, range, elements, siblings, cursor, collected) == (u.0, u.1, None, crate::__lift::Result::Ok(h.node_digest(s.pos, &dl, &dr))))))))))))))));
    rebuild_case_node(s, range, elements, siblings, cursor, collected);
    if s.height >= 1u32 {
        children_are_halves(s);
        follows();
    } else {
        follows();
    }
}

/// `reconstruct_digest`: `rebuild`'s step at its arguments, and at a node
/// its step in the words the code computes it (`children`, `vec_push`).
#[lift_attach(crate::merkle::proof::Subtree::reconstruct_digest)]
fn reconstruct_digest_facts() {
    at_start! {
        crate::proofs::rebuild_step(self, *range, elements, siblings, cursor, collected);
        crate::proofs::node_left_fails(self, *range, elements, siblings, cursor, collected);
        crate::proofs::node_right_fails(self, *range, elements, siblings, cursor, collected);
        crate::proofs::node_rebuilds_collecting(*hasher, self, *range, elements, siblings, cursor, collected);
        crate::proofs::node_rebuilds_quietly(*hasher, self, *range, elements, siblings, cursor, collected);
    }
}

// ---------------------------------------------------------------------------
// Honest proofs (`honest_proofs_rebuild_the_subtree`)
// ---------------------------------------------------------------------------

/// An index below a slice's length has an item.
#[lemma]
fn get_in_bounds(xs: &[&[u8]], i: usize) {
    requires((i as Int) < (xs.len() as Int));
    ensures(xs.get(i).is_some());
    follows();
}

/// `rebuild` on a leaf in the range: the first element, hashed.
#[lemma]
fn rebuild_leaf(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elems: &[&[u8]], e: &[u8], rest: Seq<&[u8]>, sibs: &[Digest], c: usize, col: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s) && crate::laws::disjoint(s, range) == false && (s.height == 0u32) == true && seq![..elems] == seq![e, ..rest]);
    ensures(seq![..crate::laws::rebuild(s, range, elems, sibs, c, col).0] == rest && crate::laws::rebuild(s, range, elems, sibs, c, col).1 == c
        && crate::laws::rebuild(s, range, elems, sibs, c, col).3 == crate::__lift::Result::Ok(crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, e))));
    unfold(crate::laws::rebuild);
    match elems.split_first() {
        Some(v) => {
            sandblaster::lemmas::slice::split_first_some::<&[u8]>(elems, v.0, v.1);
            assert(seq![..elems] == seq![v.0, ..v.1], { follows(); });
            assert(*v.0 == e && seq![..v.1] == rest, { follows(); });
            assert(crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, *v.0)) == crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, e)), {
                rewrite(*v.0 == e);
                follows();
            });
            rewrite(crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, *v.0)) == crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, e)));
            follows();
        }
        None => {
            items_first(elems, e, rest);
            sandblaster::lemmas::slice::split_first_none::<&[u8]>(elems);
            assert(elems.is_empty(), { follows(); });
            by_contradiction();
        }
    }
}

/// `rebuild` on a node: its left half, then (`after_left`) the rest.
#[lemma]
fn rebuild_node(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elems: &[&[u8]], sibs: &[Digest], c: usize, col: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s) && crate::laws::disjoint(s, range) == false && (s.height == 0u32) == false);
    ensures(crate::laws::rebuild(s, range, elems, sibs, c, col) == (match crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).3 {
        crate::__lift::Result::Err(e) => (crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).0, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).1, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).2, crate::__lift::Result::Err(e)),
        crate::__lift::Result::Ok(dl) => crate::proofs::after_left(s, range, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col), dl),
    }));
    unfold(crate::laws::rebuild);
    unfold(crate::proofs::after_left);
    follows();
}

/// The induction behind `honest_proofs_rebuild_the_subtree` (its
/// statement, by induction on the height).
#[lemma]
#[decreases(s.height)]
fn rebuilds(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elems: &[&[u8]], rest: Seq<&[u8]>, sibs: &[Digest], c: usize, more: Seq<Digest>, col: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s) && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(seq![..elems] == seq![..crate::laws::leaves_in(s, range, leaves), ..rest]);
    requires(seq![..sibs].skip(c as Nat) == seq![..crate::laws::sibling_digests(s, range, leaves), ..more]);
    ensures(seq![..crate::laws::rebuild(s, range, elems, sibs, c, col).0] == rest && (crate::laws::rebuild(s, range, elems, sibs, c, col).1 as Int) == (c as Int) + crate::laws::sibling_digests(s, range, leaves).len()
        && crate::laws::rebuild(s, range, elems, sibs, c, col).3 == crate::__lift::Result::Ok(crate::laws::subtree_root(s, leaves)));
    crate::proofs::shape_bounds(s);
    if crate::laws::disjoint(s, range) {
        // the whole subtree is one sibling digest
        assert(crate::laws::sibling_digests(s, range, leaves) == seq![crate::laws::subtree_root(s, leaves)], { by_unfolding(crate::laws::sibling_digests); });
        assert(crate::laws::leaves_in(s, range, leaves) == seq![], { by_unfolding(crate::laws::leaves_in); });
        skip_at(sibs, c, crate::laws::subtree_root(s, leaves), more);
        rebuild_outside(s, range, elems, sibs, c, col);
        follows();
    } else if s.height == 0u32 {
        // a leaf in the range: one element
        crate::stdlib::bits::pow2_same(s.height as Int, 0);
        get_in_bounds(leaves, s.leaf_start.0 as usize);
        match leaves.get(s.leaf_start.0 as usize) {
            Some(e) => {
                assert(crate::laws::leaves_in(s, range, leaves) == seq![*e], { by_unfolding(crate::laws::leaves_in); });
                assert(crate::laws::sibling_digests(s, range, leaves) == seq![], { by_unfolding(crate::laws::sibling_digests); });
                assert(crate::laws::subtree_root(s, leaves) == crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, *e)), { by_unfolding(crate::laws::subtree_root); });
                rebuild_leaf(s, range, elems, *e, rest, sibs, c, col);
                follows();
            }
            None => by_contradiction(),
        }
    } else {
        // an internal node: the left half, then the right half
        halves_facts(s);
        crate::stdlib::bits::pow2_step(s.height as Int);
        crate::proofs::shape_bounds(crate::laws::left_half(s));
        crate::proofs::shape_bounds(crate::laws::right_half(s));
        assert(crate::laws::leaves_in(s, range, leaves) == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)], { by_unfolding(crate::laws::leaves_in); });
        assert(crate::laws::sibling_digests(s, range, leaves) == seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves)], { by_unfolding(crate::laws::sibling_digests); });
        crate::stdlib::bits::pow2_same((crate::laws::left_half(s).height as Int), (s.height as Int) - 1);
        crate::stdlib::bits::pow2_same((crate::laws::right_half(s).height as Int), (s.height as Int) - 1);
        sandblaster::lemmas::nat::pow2_pos((s.height as Int) - 1);
        assert((crate::laws::left_half(s).leaf_start.0 as Int) + pow2(crate::laws::left_half(s).height as Int) <= (leaves.len() as Int), { by_arithmetic(); });
        assert((crate::laws::right_half(s).leaf_start.0 as Int) + pow2(crate::laws::right_half(s).height as Int) <= (leaves.len() as Int), { by_arithmetic(); });
        calc! {
            seq![..elems]
                == seq![..crate::laws::leaves_in(s, range, leaves), ..rest] by { follows(); };
                == seq![..seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)], ..rest] by {
                    rewrite(crate::laws::leaves_in(s, range, leaves) == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)]);
                    follows();
                };
                == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..seq![..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), ..rest]] by { assoc_items(crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), rest); follows(); };
        }
        calc! {
            seq![..sibs].skip(c as Nat)
                == seq![..crate::laws::sibling_digests(s, range, leaves), ..more] by { follows(); };
                == seq![..seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves)], ..more] by {
                    rewrite(crate::laws::sibling_digests(s, range, leaves) == seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves)]);
                    follows();
                };
                == seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more]] by { assoc_digests(crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), more); follows(); };
        }
        // the left half (induction), from where the node starts
        rebuilds(crate::laws::left_half(s), range, leaves, elems, seq![..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), ..rest], sibs, c, seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more], col);
        skip_after(sibs, c as Nat, crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more]);
        assert((crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).1 as Nat) == (c as Nat) + crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves).len(), { by_arithmetic(); });
        assert(seq![..sibs].skip(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).1 as Nat) == seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more], {
            rewrite((crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).1 as Nat) == (c as Nat) + crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves).len());
            follows();
        });
        // the right half (induction), from where the left half stopped
        rebuilds(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).0, rest, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).1, more, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).2);
        // the node: the halves' digests hashed
        assert(crate::laws::subtree_root(s, leaves) == crate::sha256::sha256(crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves))), { by_unfolding(crate::laws::subtree_root); });
        crate::stdlib::seqs::len_app::<Digest>(crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves));
        rewrite(rebuild_node(s, range, elems, sibs, c, col));
        rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col).3 == crate::__lift::Result::Ok(crate::laws::subtree_root(crate::laws::left_half(s), leaves)));
        unfold(crate::proofs::after_left);
        follows();
    }
}

#[proof]
fn honest_proofs_rebuild_the_subtree(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elements: &[&[u8]], rest: Seq<&[u8]>, siblings: &[Digest], cursor: usize, more: Seq<Digest>, collected: Option<Seq<(Position, Digest)>>) {
    rebuilds(s, range, leaves, elements, rest, siblings, cursor, more, collected);
    follows();
}

// ---------------------------------------------------------------------------
// Forged proofs (`rebuilding_binds_the_elements`)
// ---------------------------------------------------------------------------

/// Two leaf messages at one position are equal only for equal elements.
#[lemma]
fn leaf_message_inj(p: u64, a: &[u8], b: &[u8]) {
    requires(crate::laws::leaf_message(p, a) == crate::laws::leaf_message(p, b));
    ensures(a == b);
    crate::stdlib::seqs::append_inj::<u8>(seq![..p.to_be_bytes()], seq![..a], seq![..p.to_be_bytes()], seq![..b]);
    bytes_inj(a, b);
    follows();
}

/// Two node messages at one position are equal only for equal children.
#[lemma]
fn node_message_inj(p: u64, l: Digest, r: Digest, l2: Digest, r2: Digest) {
    requires(crate::laws::node_message(p, l, r) == crate::laws::node_message(p, l2, r2));
    ensures(l == l2 && r == r2);
    crate::stdlib::seqs::append_inj::<u8>(seq![..p.to_be_bytes()], seq![..l, ..r], seq![..p.to_be_bytes()], seq![..l2, ..r2]);
    crate::stdlib::seqs::append_inj::<u8>(seq![..l], seq![..r], seq![..l2], seq![..r2]);
    digest_bytes_inj(l, l2);
    digest_bytes_inj(r, r2);
    follows();
}

/// Two walks that start alike are one walk.
#[lemma]
fn rebuild_same_start(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, e1: &[&[u8]], e2: &[&[u8]], sibs: &[Digest], c1: usize, c2: usize, col1: Option<Seq<(Position, Digest)>>, col2: Option<Seq<(Position, Digest)>>) {
    requires(e1 == e2 && c1 == c2 && col1 == col2);
    ensures(crate::laws::rebuild(s, range, e1, sibs, c1, col1).0 == crate::laws::rebuild(s, range, e2, sibs, c2, col2).0
        && crate::laws::rebuild(s, range, e1, sibs, c1, col1).1 == crate::laws::rebuild(s, range, e2, sibs, c2, col2).1
        && crate::laws::rebuild(s, range, e1, sibs, c1, col1).2 == crate::laws::rebuild(s, range, e2, sibs, c2, col2).2
        && crate::laws::rebuild(s, range, e1, sibs, c1, col1).3 == crate::laws::rebuild(s, range, e2, sibs, c2, col2).3);
    rewrite(e1 == e2);
    rewrite(c1 == c2);
    rewrite(col1 == col2);
    follows();
}

/// A walk that collects nothing returns nothing collected.
#[lemma]
#[decreases(s.height)]
fn rebuild_stays_quiet(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elems: &[&[u8]], sibs: &[Digest], c: usize) {
    requires(crate::laws::well_shaped(s));
    ensures(crate::laws::rebuild(s, range, elems, sibs, c, None).2 == None);
    crate::proofs::shape_bounds(s);
    if crate::laws::disjoint(s, range) {
        rebuild_outside(s, range, elems, sibs, c, None);
        follows();
    } else if s.height == 0u32 {
        unfold(crate::laws::rebuild);
        follows();
    } else {
        halves_facts(s);
        rebuild_stays_quiet(crate::laws::left_half(s), range, elems, sibs, c);
        // the right half starts with what the left half collected: nothing
        rebuild_same_start(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).2, None);
        rebuild_stays_quiet(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1);
        rewrite(rebuild_node(s, range, elems, sibs, c, None));
        match crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 {
            crate::__lift::Result::Err(ex) => {
                rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 == crate::__lift::Result::Err(ex));
                follows();
            }
            crate::__lift::Result::Ok(dl) => {
                rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(dl));
                record_spec_all();
                follows();
            }
        }
    }
}

/// Collecting pairs or not, a walk takes the same elements and digests and
/// gives the same result (only what it records differs).
#[lemma]
#[decreases(s.height)]
fn rebuild_ignores_collected(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, elems: &[&[u8]], sibs: &[Digest], c: usize, col: Option<Seq<(Position, Digest)>>) {
    requires(crate::laws::well_shaped(s));
    ensures(crate::laws::rebuild(s, range, elems, sibs, c, col).0 == crate::laws::rebuild(s, range, elems, sibs, c, None).0
        && crate::laws::rebuild(s, range, elems, sibs, c, col).1 == crate::laws::rebuild(s, range, elems, sibs, c, None).1
        && crate::laws::rebuild(s, range, elems, sibs, c, col).3 == crate::laws::rebuild(s, range, elems, sibs, c, None).3);
    crate::proofs::shape_bounds(s);
    if crate::laws::disjoint(s, range) {
        rebuild_outside(s, range, elems, sibs, c, col);
        rebuild_outside(s, range, elems, sibs, c, None);
        follows();
    } else if s.height == 0u32 {
        rebuild_step(s, range, elems, sibs, c, col);
        rebuild_step(s, range, elems, sibs, c, None);
        follows();
    } else {
        halves_facts(s);
        let l = crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, col);
        let lq = crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None);
        // the left halves: one walk (induction), the quiet one recording nothing
        rebuild_ignores_collected(crate::laws::left_half(s), range, elems, sibs, c, col);
        rebuild_stays_quiet(crate::laws::left_half(s), range, elems, sibs, c);
        // the right halves start alike: one walk (induction)
        rebuild_ignores_collected(crate::laws::right_half(s), range, l.0, sibs, l.1, l.2);
        rebuild_same_start(crate::laws::right_half(s), range, l.0, lq.0, sibs, l.1, lq.1, None, lq.2);
        let r = crate::laws::rebuild(crate::laws::right_half(s), range, l.0, sibs, l.1, l.2);
        let rq = crate::laws::rebuild(crate::laws::right_half(s), range, lq.0, sibs, lq.1, lq.2);
        rewrite(rebuild_node(s, range, elems, sibs, c, col));
        rewrite(rebuild_node(s, range, elems, sibs, c, None));
        // by the quiet walk's results (the collecting walk's are the same)
        match lq.3 {
            crate::__lift::Result::Err(e) => {
                rewrite(l.3 == crate::__lift::Result::Err(e));
                follows();
            }
            crate::__lift::Result::Ok(dl) => {
                rewrite(l.3 == crate::__lift::Result::Ok(dl));
                match rq.3 {
                    crate::__lift::Result::Err(e) => {
                        rewrite(r.3 == crate::__lift::Result::Err(e));
                        follows();
                    }
                    crate::__lift::Result::Ok(dr) => {
                        rewrite(r.3 == crate::__lift::Result::Ok(dr));
                        follows();
                    }
                }
            }
        }
    }
}

/// Two different messages with one digest are a collision.
#[lemma]
fn differ_collide(m: Seq<u8>, t: Seq<u8>) {
    requires((m == t) == false && crate::sha256::sha256(m) == crate::sha256::sha256(t));
    ensures(crate::sha256::collision(Some((m, t))));
    by_unfolding(crate::sha256::collision);
}

/// `rebuild_clash` one step on a leaf in the range.
#[lemma]
fn clash_leaf_eq(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elems: &[&[u8]], sibs: &[Digest], c: usize) {
    requires(crate::laws::disjoint(s, range) == false && (s.height == 0u32) == true);
    ensures(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == (match elems.split_first() {
        Some(p) => match leaves.get(s.leaf_start.0 as usize) {
            Some(e) => if crate::laws::leaf_message(s.pos.0, *p.0) == crate::laws::leaf_message(s.pos.0, e) { None } else { Some((crate::laws::leaf_message(s.pos.0, *p.0), crate::laws::leaf_message(s.pos.0, e))) },
            None => None,
        },
        None => None,
    }));
    if crate::laws::disjoint(s, range) {
        by_contradiction();
    } else if s.height == 0u32 {
        unfold(crate::laws::rebuild_clash);
        follows();
    } else {
        by_contradiction();
    }
}

/// Byte strings split as their first and the rest, as sequences.
#[lemma]
fn items_split(elems: &[&[u8]]) {
    ensures(match elems.split_first() { Some(p) => seq![..elems] == seq![*p.0, ..p.1], None => seq![..elems] == seq![] });
    match elems.split_first() {
        Some(v) => {
            sandblaster::lemmas::slice::split_first_some::<&[u8]>(elems, v.0, v.1);
            follows();
        }
        None => {
            sandblaster::lemmas::slice::split_first_none::<&[u8]>(elems);
            assert(elems.is_empty(), { follows(); });
            sandblaster::lemmas::slice::is_empty_nil::<&[u8]>(elems);
            follows();
        }
    }
}

/// `rebuild_clash` on a leaf of the range whose first element is `x` and
/// whose own element is `e`: the two leaf messages, when they differ.
#[lemma]
fn clash_leaf_at(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elems: &[&[u8]], sibs: &[Digest], c: usize, x: &[u8], rest: &[&[u8]], e: &[u8]) {
    requires(crate::laws::disjoint(s, range) == false && (s.height == 0u32) == true);
    requires(elems.split_first() == Some((&x, rest)) && leaves.get(s.leaf_start.0 as usize) == Some(&e));
    ensures(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == (if crate::laws::leaf_message(s.pos.0, x) == crate::laws::leaf_message(s.pos.0, e) { None } else { Some((crate::laws::leaf_message(s.pos.0, x), crate::laws::leaf_message(s.pos.0, e))) }));
    clash_leaf_eq(s, range, leaves, elems, sibs, c);
    rewrite(clash_leaf_eq(s, range, leaves, elems, sibs, c));
    rewrite(elems.split_first() == Some((&x, rest)));
    rewrite(leaves.get(s.leaf_start.0 as usize) == Some(&e));
    follows();
}

/// `binds` on a leaf of the range: its element, or two leaf messages with
/// one digest.
#[lemma]
fn binds_leaf(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elems: &[&[u8]], sibs: &[Digest], c: usize) {
    requires(crate::laws::well_shaped(s) && crate::laws::disjoint(s, range) == false && (s.height == 0u32) == true && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(crate::laws::rebuild(s, range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(crate::laws::subtree_root(s, leaves)));
    ensures(implies(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == None, seq![..elems] == seq![..crate::laws::leaves_in(s, range, leaves), ..crate::laws::rebuild(s, range, elems, sibs, c, None).0])
        && implies(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) != None, crate::sha256::collision(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c))));
    crate::stdlib::bits::pow2_same(s.height as Int, 0);
    get_in_bounds(leaves, s.leaf_start.0 as usize);
    rebuild_step(s, range, elems, sibs, c, None);
    clash_leaf_eq(s, range, leaves, elems, sibs, c);
    items_split(elems);
    match leaves.get(s.leaf_start.0 as usize) {
        Some(e) => {
            assert(crate::laws::leaves_in(s, range, leaves) == seq![*e], { by_unfolding(crate::laws::leaves_in); });
            assert(crate::laws::subtree_root(s, leaves) == crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, e)), { by_unfolding(crate::laws::subtree_root); });
            match elems.split_first() {
                Some(v) => {
                    assert(seq![..elems] == seq![*v.0, ..v.1], { follows(); });
                    rebuild_leaf(s, range, elems, *v.0, seq![..v.1], sibs, c, None);
                    clash_leaf_at(s, range, leaves, elems, sibs, c, *v.0, v.1, *e);
                    assert(crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, *v.0)) == crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, e)), { follows(); });
                    if crate::laws::leaf_message(s.pos.0, *v.0) == crate::laws::leaf_message(s.pos.0, e) {
                        leaf_message_inj(s.pos.0, *v.0, e);
                        assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == None, { follows(); });
                        rewrite(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == None);
                        // the elements are the leaf's, then what is left
                        rewrite(crate::laws::leaves_in(s, range, leaves) == seq![*e]);
                        rewrite(seq![..elems] == seq![*v.0, ..v.1]);
                        rewrite(seq![..crate::laws::rebuild(s, range, elems, sibs, c, None).0] == seq![..v.1]);
                        follows();
                    } else {
                        differ_collide(crate::laws::leaf_message(s.pos.0, *v.0), crate::laws::leaf_message(s.pos.0, e));
                        assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == Some((crate::laws::leaf_message(s.pos.0, *v.0), crate::laws::leaf_message(s.pos.0, e))), { follows(); });
                        rewrite(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == Some((crate::laws::leaf_message(s.pos.0, *v.0), crate::laws::leaf_message(s.pos.0, e))));
                        follows();
                    }
                }
                None => {
                    // no element: the leaf's step fails
                    assert(crate::laws::rebuild(s, range, elems, sibs, c, None).3 == crate::__lift::Result::Err(crate::merkle::proof::ReconstructionError::MissingElements), { follows(); });
                    by_contradiction();
                }
            }
        }
        None => by_contradiction(),
    }
}

/// The induction behind `rebuilding_binds_the_elements` (a walk that
/// collects nothing): when no pair is named, the elements were the leaves'
/// (then what is left), and a named pair is a collision.
#[lemma]
#[decreases(s.height)]
fn binds(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elems: &[&[u8]], sibs: &[Digest], c: usize) {
    requires(crate::laws::well_shaped(s) && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(crate::laws::rebuild(s, range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(crate::laws::subtree_root(s, leaves)));
    ensures(implies(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == None, seq![..elems] == seq![..crate::laws::leaves_in(s, range, leaves), ..crate::laws::rebuild(s, range, elems, sibs, c, None).0])
        && implies(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) != None, crate::sha256::collision(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c))));
    crate::proofs::shape_bounds(s);
    if crate::laws::disjoint(s, range) {
        // nothing used, nothing named
        assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == None, { by_unfolding(crate::laws::rebuild_clash); });
        assert(crate::laws::leaves_in(s, range, leaves) == seq![], { by_unfolding(crate::laws::leaves_in); });
        rebuild_outside(s, range, elems, sibs, c, None);
        follows();
    } else if s.height == 0u32 {
        binds_leaf(s, range, leaves, elems, sibs, c);
        follows();
    } else {
        // a node: two node messages with one digest, or its halves' digests
        // are their own and each half binds its elements
        halves_facts(s);
        crate::stdlib::bits::pow2_step(s.height as Int);
        crate::proofs::shape_bounds(crate::laws::left_half(s));
        crate::proofs::shape_bounds(crate::laws::right_half(s));
        crate::stdlib::bits::pow2_same((crate::laws::left_half(s).height as Int), (s.height as Int) - 1);
        crate::stdlib::bits::pow2_same((crate::laws::right_half(s).height as Int), (s.height as Int) - 1);
        sandblaster::lemmas::nat::pow2_pos((s.height as Int) - 1);
        assert((crate::laws::left_half(s).leaf_start.0 as Int) + pow2(crate::laws::left_half(s).height as Int) <= (leaves.len() as Int), { by_arithmetic(); });
        assert((crate::laws::right_half(s).leaf_start.0 as Int) + pow2(crate::laws::right_half(s).height as Int) <= (leaves.len() as Int), { by_arithmetic(); });
        assert(crate::laws::leaves_in(s, range, leaves) == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)], { by_unfolding(crate::laws::leaves_in); });
        assert(crate::laws::subtree_root(s, leaves) == crate::sha256::sha256(crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves))), { by_unfolding(crate::laws::subtree_root); });
        match crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 {
            crate::__lift::Result::Err(ex) => {
                assert(crate::laws::rebuild(s, range, elems, sibs, c, None).3 == crate::__lift::Result::Err(ex), {
                    rewrite(rebuild_node(s, range, elems, sibs, c, None));
                    rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 == crate::__lift::Result::Err(ex));
                    follows();
                });
                by_contradiction();
            }
            crate::__lift::Result::Ok(dl) => {
                // the right half starts with what the left half collected: nothing
                rebuild_stays_quiet(crate::laws::left_half(s), range, elems, sibs, c);
                rebuild_same_start(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).2, None);
                match crate::laws::rebuild(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, None).3 {
                    crate::__lift::Result::Err(ex) => {
                        assert(crate::laws::rebuild(s, range, elems, sibs, c, None).3 == crate::__lift::Result::Err(ex), {
                            rewrite(rebuild_node(s, range, elems, sibs, c, None));
                            rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(dl));
                            unfold(crate::proofs::after_left);
                            follows();
                        });
                        by_contradiction();
                    }
                    crate::__lift::Result::Ok(dr) => {
                        assert(crate::laws::rebuild(s, range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(crate::sha256::sha256(crate::laws::node_message(s.pos.0, dl, dr))), {
                            rewrite(rebuild_node(s, range, elems, sibs, c, None));
                            rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(dl));
                            unfold(crate::proofs::after_left);
                            follows();
                        });
                        assert(crate::laws::rebuild(s, range, elems, sibs, c, None).0 == crate::laws::rebuild(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, None).0, {
                            rewrite(rebuild_node(s, range, elems, sibs, c, None));
                            rewrite(crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).3 == crate::__lift::Result::Ok(dl));
                            unfold(crate::proofs::after_left);
                            follows();
                        });
                        assert(crate::sha256::sha256(crate::laws::node_message(s.pos.0, dl, dr)) == crate::sha256::sha256(crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves))), { follows(); });
                        assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == (if crate::laws::node_message(s.pos.0, dl, dr) == crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves)) { match crate::laws::rebuild_clash(crate::laws::left_half(s), range, leaves, elems, sibs, c) { Some(x) => Some(x), None => crate::laws::rebuild_clash(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1) } } else { Some((crate::laws::node_message(s.pos.0, dl, dr), crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves)))) }), { unfold(crate::laws::rebuild_clash); follows(); });
                        if crate::laws::node_message(s.pos.0, dl, dr) == crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves)) {
                            // each half rebuilt its own digest: each binds its elements, or names a collision
                            node_message_inj(s.pos.0, dl, dr, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves));
                            binds(crate::laws::left_half(s), range, leaves, elems, sibs, c);
                            binds(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1);
                            match crate::laws::rebuild_clash(crate::laws::left_half(s), range, leaves, elems, sibs, c) {
                                Some(x) => {
                                    assert(crate::laws::rebuild_clash(crate::laws::left_half(s), range, leaves, elems, sibs, c) != None, { follows(); });
                                    assert(crate::sha256::collision(crate::laws::rebuild_clash(crate::laws::left_half(s), range, leaves, elems, sibs, c)), { follows(); });
                                    assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == crate::laws::rebuild_clash(crate::laws::left_half(s), range, leaves, elems, sibs, c), { follows(); });
                                    rewrite(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == crate::laws::rebuild_clash(crate::laws::left_half(s), range, leaves, elems, sibs, c));
                                    follows();
                                }
                                None => {
                                    assert(seq![..elems] == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0], { follows(); });
                                    assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == crate::laws::rebuild_clash(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1), { follows(); });
                                    rewrite(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == crate::laws::rebuild_clash(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1));
                                    match crate::laws::rebuild_clash(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1) {
                                        Some(y) => {
                                            assert(crate::laws::rebuild_clash(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1) != None, { follows(); });
                                            assert(crate::sha256::collision(crate::laws::rebuild_clash(crate::laws::right_half(s), range, leaves, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1)), { follows(); });
                                            follows();
                                        }
                                        None => {
                                            assert(seq![..crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0] == seq![..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), ..crate::laws::rebuild(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, None).0], { follows(); });
                                            assoc_items(crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), seq![..crate::laws::rebuild(crate::laws::right_half(s), range, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).0, sibs, crate::laws::rebuild(crate::laws::left_half(s), range, elems, sibs, c, None).1, None).0]);
                                            follows();
                                        }
                                    }
                                }
                            }
                        } else {
                            differ_collide(crate::laws::node_message(s.pos.0, dl, dr), crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves)));
                            assert(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == Some((crate::laws::node_message(s.pos.0, dl, dr), crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves)))), { follows(); });
                            rewrite(crate::laws::rebuild_clash(s, range, leaves, elems, sibs, c) == Some((crate::laws::node_message(s.pos.0, dl, dr), crate::laws::node_message(s.pos.0, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves)))));
                            follows();
                        }
                    }
                }
            }
        }
    }
}

#[proof]
fn rebuilding_binds_the_elements(s: crate::merkle::proof::Subtree, range: crate::__lift::Range<Location>, leaves: &[&[u8]], elements: &[&[u8]], siblings: &[Digest], cursor: usize, collected: Option<Seq<(Position, Digest)>>) {
    rebuild_ignores_collected(s, range, elements, siblings, cursor, collected);
    binds(s, range, leaves, elements, siblings, cursor);
    if crate::laws::rebuild_clash(s, range, leaves, elements, siblings, cursor) == None { follows(); } else { follows(); }
}
