//! Proofs of LAWS.rs and of the safety of the lifted files as written.
//! Machine artifacts: attachments (`#[lift_attach]`) give the lifted code
//! its loop measures, invariants and function summaries without touching
//! the host files.

use sandblaster::prelude::*;
use crate::laws::{fits, height_in, items, mmr_size, mountains, node_height, peaks, valid_size};
use crate::merkle::{Location, Position};
use crate::merkle::mmr::Family;
use crate::merkle::mmr::iterator::PeakIterator;

// ---------------------------------------------------------------------------
// Powers of two and word masks
// ---------------------------------------------------------------------------

/// Equal exponents, equal powers.
#[lemma]
fn pow2_eq(a: Int, b: Int) {
    requires(a == b);
    ensures(pow2(a) == pow2(b));
    rewrite(a == b);
    follows();
}

/// Congruence: equal shift amounts, equal masks.
#[lemma]
fn shr_cong(k: u32, j: u32) {
    requires(k < 64u32 && k == j);
    ensures(u64::MAX >> k == u64::MAX >> j);
    follows();
}

/// Congruence: equal shift amounts, equal powers.
#[lemma]
fn shl_cong(b: u32, j: u32) {
    requires(b < 64u32 && b == j);
    ensures(1u64 << b == 1u64 << j);
    follows();
}

/// Congruence: equal words, equal trailing zeros.
#[lemma]
fn tz_cong(t: u64, c: u64) {
    requires(t == c);
    ensures(t.trailing_zeros() == c.trailing_zeros());
    follows();
}

/// `u64::MAX >> k` is `64 - k` ones; its complement has `64 - k` trailing
/// zeros (one case per amount).
#[lemma]
fn mask_facts(k: u32) {
    requires(k < 64u32);
    ensures((u64::MAX >> k) as Int == pow2(64 - (k as Int)) - 1 && ((!(u64::MAX >> k)).trailing_zeros() as Int) == 64 - (k as Int));
    if k <= 0u32 { assert(k == 0u32); shr_cong(k, 0u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 0u32)); pow2_eq(64 - (k as Int), 64); follows(); }
    else if k <= 1u32 { assert(k == 1u32); shr_cong(k, 1u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 1u32)); pow2_eq(64 - (k as Int), 63); follows(); }
    else if k <= 2u32 { assert(k == 2u32); shr_cong(k, 2u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 2u32)); pow2_eq(64 - (k as Int), 62); follows(); }
    else if k <= 3u32 { assert(k == 3u32); shr_cong(k, 3u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 3u32)); pow2_eq(64 - (k as Int), 61); follows(); }
    else if k <= 4u32 { assert(k == 4u32); shr_cong(k, 4u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 4u32)); pow2_eq(64 - (k as Int), 60); follows(); }
    else if k <= 5u32 { assert(k == 5u32); shr_cong(k, 5u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 5u32)); pow2_eq(64 - (k as Int), 59); follows(); }
    else if k <= 6u32 { assert(k == 6u32); shr_cong(k, 6u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 6u32)); pow2_eq(64 - (k as Int), 58); follows(); }
    else if k <= 7u32 { assert(k == 7u32); shr_cong(k, 7u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 7u32)); pow2_eq(64 - (k as Int), 57); follows(); }
    else if k <= 8u32 { assert(k == 8u32); shr_cong(k, 8u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 8u32)); pow2_eq(64 - (k as Int), 56); follows(); }
    else if k <= 9u32 { assert(k == 9u32); shr_cong(k, 9u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 9u32)); pow2_eq(64 - (k as Int), 55); follows(); }
    else if k <= 10u32 { assert(k == 10u32); shr_cong(k, 10u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 10u32)); pow2_eq(64 - (k as Int), 54); follows(); }
    else if k <= 11u32 { assert(k == 11u32); shr_cong(k, 11u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 11u32)); pow2_eq(64 - (k as Int), 53); follows(); }
    else if k <= 12u32 { assert(k == 12u32); shr_cong(k, 12u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 12u32)); pow2_eq(64 - (k as Int), 52); follows(); }
    else if k <= 13u32 { assert(k == 13u32); shr_cong(k, 13u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 13u32)); pow2_eq(64 - (k as Int), 51); follows(); }
    else if k <= 14u32 { assert(k == 14u32); shr_cong(k, 14u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 14u32)); pow2_eq(64 - (k as Int), 50); follows(); }
    else if k <= 15u32 { assert(k == 15u32); shr_cong(k, 15u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 15u32)); pow2_eq(64 - (k as Int), 49); follows(); }
    else if k <= 16u32 { assert(k == 16u32); shr_cong(k, 16u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 16u32)); pow2_eq(64 - (k as Int), 48); follows(); }
    else if k <= 17u32 { assert(k == 17u32); shr_cong(k, 17u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 17u32)); pow2_eq(64 - (k as Int), 47); follows(); }
    else if k <= 18u32 { assert(k == 18u32); shr_cong(k, 18u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 18u32)); pow2_eq(64 - (k as Int), 46); follows(); }
    else if k <= 19u32 { assert(k == 19u32); shr_cong(k, 19u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 19u32)); pow2_eq(64 - (k as Int), 45); follows(); }
    else if k <= 20u32 { assert(k == 20u32); shr_cong(k, 20u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 20u32)); pow2_eq(64 - (k as Int), 44); follows(); }
    else if k <= 21u32 { assert(k == 21u32); shr_cong(k, 21u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 21u32)); pow2_eq(64 - (k as Int), 43); follows(); }
    else if k <= 22u32 { assert(k == 22u32); shr_cong(k, 22u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 22u32)); pow2_eq(64 - (k as Int), 42); follows(); }
    else if k <= 23u32 { assert(k == 23u32); shr_cong(k, 23u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 23u32)); pow2_eq(64 - (k as Int), 41); follows(); }
    else if k <= 24u32 { assert(k == 24u32); shr_cong(k, 24u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 24u32)); pow2_eq(64 - (k as Int), 40); follows(); }
    else if k <= 25u32 { assert(k == 25u32); shr_cong(k, 25u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 25u32)); pow2_eq(64 - (k as Int), 39); follows(); }
    else if k <= 26u32 { assert(k == 26u32); shr_cong(k, 26u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 26u32)); pow2_eq(64 - (k as Int), 38); follows(); }
    else if k <= 27u32 { assert(k == 27u32); shr_cong(k, 27u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 27u32)); pow2_eq(64 - (k as Int), 37); follows(); }
    else if k <= 28u32 { assert(k == 28u32); shr_cong(k, 28u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 28u32)); pow2_eq(64 - (k as Int), 36); follows(); }
    else if k <= 29u32 { assert(k == 29u32); shr_cong(k, 29u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 29u32)); pow2_eq(64 - (k as Int), 35); follows(); }
    else if k <= 30u32 { assert(k == 30u32); shr_cong(k, 30u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 30u32)); pow2_eq(64 - (k as Int), 34); follows(); }
    else if k <= 31u32 { assert(k == 31u32); shr_cong(k, 31u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 31u32)); pow2_eq(64 - (k as Int), 33); follows(); }
    else if k <= 32u32 { assert(k == 32u32); shr_cong(k, 32u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 32u32)); pow2_eq(64 - (k as Int), 32); follows(); }
    else if k <= 33u32 { assert(k == 33u32); shr_cong(k, 33u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 33u32)); pow2_eq(64 - (k as Int), 31); follows(); }
    else if k <= 34u32 { assert(k == 34u32); shr_cong(k, 34u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 34u32)); pow2_eq(64 - (k as Int), 30); follows(); }
    else if k <= 35u32 { assert(k == 35u32); shr_cong(k, 35u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 35u32)); pow2_eq(64 - (k as Int), 29); follows(); }
    else if k <= 36u32 { assert(k == 36u32); shr_cong(k, 36u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 36u32)); pow2_eq(64 - (k as Int), 28); follows(); }
    else if k <= 37u32 { assert(k == 37u32); shr_cong(k, 37u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 37u32)); pow2_eq(64 - (k as Int), 27); follows(); }
    else if k <= 38u32 { assert(k == 38u32); shr_cong(k, 38u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 38u32)); pow2_eq(64 - (k as Int), 26); follows(); }
    else if k <= 39u32 { assert(k == 39u32); shr_cong(k, 39u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 39u32)); pow2_eq(64 - (k as Int), 25); follows(); }
    else if k <= 40u32 { assert(k == 40u32); shr_cong(k, 40u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 40u32)); pow2_eq(64 - (k as Int), 24); follows(); }
    else if k <= 41u32 { assert(k == 41u32); shr_cong(k, 41u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 41u32)); pow2_eq(64 - (k as Int), 23); follows(); }
    else if k <= 42u32 { assert(k == 42u32); shr_cong(k, 42u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 42u32)); pow2_eq(64 - (k as Int), 22); follows(); }
    else if k <= 43u32 { assert(k == 43u32); shr_cong(k, 43u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 43u32)); pow2_eq(64 - (k as Int), 21); follows(); }
    else if k <= 44u32 { assert(k == 44u32); shr_cong(k, 44u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 44u32)); pow2_eq(64 - (k as Int), 20); follows(); }
    else if k <= 45u32 { assert(k == 45u32); shr_cong(k, 45u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 45u32)); pow2_eq(64 - (k as Int), 19); follows(); }
    else if k <= 46u32 { assert(k == 46u32); shr_cong(k, 46u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 46u32)); pow2_eq(64 - (k as Int), 18); follows(); }
    else if k <= 47u32 { assert(k == 47u32); shr_cong(k, 47u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 47u32)); pow2_eq(64 - (k as Int), 17); follows(); }
    else if k <= 48u32 { assert(k == 48u32); shr_cong(k, 48u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 48u32)); pow2_eq(64 - (k as Int), 16); follows(); }
    else if k <= 49u32 { assert(k == 49u32); shr_cong(k, 49u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 49u32)); pow2_eq(64 - (k as Int), 15); follows(); }
    else if k <= 50u32 { assert(k == 50u32); shr_cong(k, 50u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 50u32)); pow2_eq(64 - (k as Int), 14); follows(); }
    else if k <= 51u32 { assert(k == 51u32); shr_cong(k, 51u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 51u32)); pow2_eq(64 - (k as Int), 13); follows(); }
    else if k <= 52u32 { assert(k == 52u32); shr_cong(k, 52u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 52u32)); pow2_eq(64 - (k as Int), 12); follows(); }
    else if k <= 53u32 { assert(k == 53u32); shr_cong(k, 53u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 53u32)); pow2_eq(64 - (k as Int), 11); follows(); }
    else if k <= 54u32 { assert(k == 54u32); shr_cong(k, 54u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 54u32)); pow2_eq(64 - (k as Int), 10); follows(); }
    else if k <= 55u32 { assert(k == 55u32); shr_cong(k, 55u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 55u32)); pow2_eq(64 - (k as Int), 9); follows(); }
    else if k <= 56u32 { assert(k == 56u32); shr_cong(k, 56u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 56u32)); pow2_eq(64 - (k as Int), 8); follows(); }
    else if k <= 57u32 { assert(k == 57u32); shr_cong(k, 57u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 57u32)); pow2_eq(64 - (k as Int), 7); follows(); }
    else if k <= 58u32 { assert(k == 58u32); shr_cong(k, 58u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 58u32)); pow2_eq(64 - (k as Int), 6); follows(); }
    else if k <= 59u32 { assert(k == 59u32); shr_cong(k, 59u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 59u32)); pow2_eq(64 - (k as Int), 5); follows(); }
    else if k <= 60u32 { assert(k == 60u32); shr_cong(k, 60u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 60u32)); pow2_eq(64 - (k as Int), 4); follows(); }
    else if k <= 61u32 { assert(k == 61u32); shr_cong(k, 61u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 61u32)); pow2_eq(64 - (k as Int), 3); follows(); }
    else if k <= 62u32 { assert(k == 62u32); shr_cong(k, 62u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 62u32)); pow2_eq(64 - (k as Int), 2); follows(); }
    else if k <= 63u32 { assert(k == 63u32); shr_cong(k, 63u32); tz_cong(!(u64::MAX >> k), !(u64::MAX >> 63u32)); pow2_eq(64 - (k as Int), 1); follows(); }
    else { by_contradiction(); }
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

/// A power of two's trailing zeros are its exponent (one case per exponent).
#[lemma]
fn tz_pow2(t: u64, e: Int) {
    requires(0 <= e && e < 64 && (t as Int) == pow2(e));
    ensures((t.trailing_zeros() as Int) == e);
    if e <= 0 { assert(e == 0); pow2_eq(e, 0); tz_cong(t, 1u64); follows(); }
    else if e <= 1 { assert(e == 1); pow2_eq(e, 1); tz_cong(t, 2u64); follows(); }
    else if e <= 2 { assert(e == 2); pow2_eq(e, 2); tz_cong(t, 4u64); follows(); }
    else if e <= 3 { assert(e == 3); pow2_eq(e, 3); tz_cong(t, 8u64); follows(); }
    else if e <= 4 { assert(e == 4); pow2_eq(e, 4); tz_cong(t, 16u64); follows(); }
    else if e <= 5 { assert(e == 5); pow2_eq(e, 5); tz_cong(t, 32u64); follows(); }
    else if e <= 6 { assert(e == 6); pow2_eq(e, 6); tz_cong(t, 64u64); follows(); }
    else if e <= 7 { assert(e == 7); pow2_eq(e, 7); tz_cong(t, 128u64); follows(); }
    else if e <= 8 { assert(e == 8); pow2_eq(e, 8); tz_cong(t, 256u64); follows(); }
    else if e <= 9 { assert(e == 9); pow2_eq(e, 9); tz_cong(t, 512u64); follows(); }
    else if e <= 10 { assert(e == 10); pow2_eq(e, 10); tz_cong(t, 1024u64); follows(); }
    else if e <= 11 { assert(e == 11); pow2_eq(e, 11); tz_cong(t, 2048u64); follows(); }
    else if e <= 12 { assert(e == 12); pow2_eq(e, 12); tz_cong(t, 4096u64); follows(); }
    else if e <= 13 { assert(e == 13); pow2_eq(e, 13); tz_cong(t, 8192u64); follows(); }
    else if e <= 14 { assert(e == 14); pow2_eq(e, 14); tz_cong(t, 16384u64); follows(); }
    else if e <= 15 { assert(e == 15); pow2_eq(e, 15); tz_cong(t, 32768u64); follows(); }
    else if e <= 16 { assert(e == 16); pow2_eq(e, 16); tz_cong(t, 65536u64); follows(); }
    else if e <= 17 { assert(e == 17); pow2_eq(e, 17); tz_cong(t, 131072u64); follows(); }
    else if e <= 18 { assert(e == 18); pow2_eq(e, 18); tz_cong(t, 262144u64); follows(); }
    else if e <= 19 { assert(e == 19); pow2_eq(e, 19); tz_cong(t, 524288u64); follows(); }
    else if e <= 20 { assert(e == 20); pow2_eq(e, 20); tz_cong(t, 1048576u64); follows(); }
    else if e <= 21 { assert(e == 21); pow2_eq(e, 21); tz_cong(t, 2097152u64); follows(); }
    else if e <= 22 { assert(e == 22); pow2_eq(e, 22); tz_cong(t, 4194304u64); follows(); }
    else if e <= 23 { assert(e == 23); pow2_eq(e, 23); tz_cong(t, 8388608u64); follows(); }
    else if e <= 24 { assert(e == 24); pow2_eq(e, 24); tz_cong(t, 16777216u64); follows(); }
    else if e <= 25 { assert(e == 25); pow2_eq(e, 25); tz_cong(t, 33554432u64); follows(); }
    else if e <= 26 { assert(e == 26); pow2_eq(e, 26); tz_cong(t, 67108864u64); follows(); }
    else if e <= 27 { assert(e == 27); pow2_eq(e, 27); tz_cong(t, 134217728u64); follows(); }
    else if e <= 28 { assert(e == 28); pow2_eq(e, 28); tz_cong(t, 268435456u64); follows(); }
    else if e <= 29 { assert(e == 29); pow2_eq(e, 29); tz_cong(t, 536870912u64); follows(); }
    else if e <= 30 { assert(e == 30); pow2_eq(e, 30); tz_cong(t, 1073741824u64); follows(); }
    else if e <= 31 { assert(e == 31); pow2_eq(e, 31); tz_cong(t, 2147483648u64); follows(); }
    else if e <= 32 { assert(e == 32); pow2_eq(e, 32); tz_cong(t, 4294967296u64); follows(); }
    else if e <= 33 { assert(e == 33); pow2_eq(e, 33); tz_cong(t, 8589934592u64); follows(); }
    else if e <= 34 { assert(e == 34); pow2_eq(e, 34); tz_cong(t, 17179869184u64); follows(); }
    else if e <= 35 { assert(e == 35); pow2_eq(e, 35); tz_cong(t, 34359738368u64); follows(); }
    else if e <= 36 { assert(e == 36); pow2_eq(e, 36); tz_cong(t, 68719476736u64); follows(); }
    else if e <= 37 { assert(e == 37); pow2_eq(e, 37); tz_cong(t, 137438953472u64); follows(); }
    else if e <= 38 { assert(e == 38); pow2_eq(e, 38); tz_cong(t, 274877906944u64); follows(); }
    else if e <= 39 { assert(e == 39); pow2_eq(e, 39); tz_cong(t, 549755813888u64); follows(); }
    else if e <= 40 { assert(e == 40); pow2_eq(e, 40); tz_cong(t, 1099511627776u64); follows(); }
    else if e <= 41 { assert(e == 41); pow2_eq(e, 41); tz_cong(t, 2199023255552u64); follows(); }
    else if e <= 42 { assert(e == 42); pow2_eq(e, 42); tz_cong(t, 4398046511104u64); follows(); }
    else if e <= 43 { assert(e == 43); pow2_eq(e, 43); tz_cong(t, 8796093022208u64); follows(); }
    else if e <= 44 { assert(e == 44); pow2_eq(e, 44); tz_cong(t, 17592186044416u64); follows(); }
    else if e <= 45 { assert(e == 45); pow2_eq(e, 45); tz_cong(t, 35184372088832u64); follows(); }
    else if e <= 46 { assert(e == 46); pow2_eq(e, 46); tz_cong(t, 70368744177664u64); follows(); }
    else if e <= 47 { assert(e == 47); pow2_eq(e, 47); tz_cong(t, 140737488355328u64); follows(); }
    else if e <= 48 { assert(e == 48); pow2_eq(e, 48); tz_cong(t, 281474976710656u64); follows(); }
    else if e <= 49 { assert(e == 49); pow2_eq(e, 49); tz_cong(t, 562949953421312u64); follows(); }
    else if e <= 50 { assert(e == 50); pow2_eq(e, 50); tz_cong(t, 1125899906842624u64); follows(); }
    else if e <= 51 { assert(e == 51); pow2_eq(e, 51); tz_cong(t, 2251799813685248u64); follows(); }
    else if e <= 52 { assert(e == 52); pow2_eq(e, 52); tz_cong(t, 4503599627370496u64); follows(); }
    else if e <= 53 { assert(e == 53); pow2_eq(e, 53); tz_cong(t, 9007199254740992u64); follows(); }
    else if e <= 54 { assert(e == 54); pow2_eq(e, 54); tz_cong(t, 18014398509481984u64); follows(); }
    else if e <= 55 { assert(e == 55); pow2_eq(e, 55); tz_cong(t, 36028797018963968u64); follows(); }
    else if e <= 56 { assert(e == 56); pow2_eq(e, 56); tz_cong(t, 72057594037927936u64); follows(); }
    else if e <= 57 { assert(e == 57); pow2_eq(e, 57); tz_cong(t, 144115188075855872u64); follows(); }
    else if e <= 58 { assert(e == 58); pow2_eq(e, 58); tz_cong(t, 288230376151711744u64); follows(); }
    else if e <= 59 { assert(e == 59); pow2_eq(e, 59); tz_cong(t, 576460752303423488u64); follows(); }
    else if e <= 60 { assert(e == 60); pow2_eq(e, 60); tz_cong(t, 1152921504606846976u64); follows(); }
    else if e <= 61 { assert(e == 61); pow2_eq(e, 61); tz_cong(t, 2305843009213693952u64); follows(); }
    else if e <= 62 { assert(e == 62); pow2_eq(e, 62); tz_cong(t, 4611686018427387904u64); follows(); }
    else if e <= 63 { assert(e == 63); pow2_eq(e, 63); tz_cong(t, 9223372036854775808u64); follows(); }
    else { by_contradiction(); }
}

/// The bits a word needs: its width minus its leading zeros; zero needs
/// none (from the checked bit lemmas, one width case at a time; as in the
/// varint pilot).
#[lemma]
fn lz_bits_chain(x: u64) {
    ensures((((x as Nat) == 0 && (x.leading_zeros() as Int) == 64)
        || (pow2(64 - 1 - (x.leading_zeros() as Int)) <= (x as Int) && (x as Int) < pow2(64 - (x.leading_zeros() as Int)))) == true);
    if x.leading_zeros() <= 0u32 { assert((x.leading_zeros() as Int) == 0); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 64); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 63); if (x as Int) < pow2(63) { sandblaster::lemmas::bits::lz_lower_u64_63(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 1u32 { sandblaster::lemmas::bits::lz_ge_u64_63(x); assert((x.leading_zeros() as Int) == 1); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 63); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 62); if (x as Int) < pow2(62) { sandblaster::lemmas::bits::lz_lower_u64_62(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 2u32 { sandblaster::lemmas::bits::lz_ge_u64_62(x); assert((x.leading_zeros() as Int) == 2); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 62); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 61); if (x as Int) < pow2(61) { sandblaster::lemmas::bits::lz_lower_u64_61(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 3u32 { sandblaster::lemmas::bits::lz_ge_u64_61(x); assert((x.leading_zeros() as Int) == 3); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 61); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 60); if (x as Int) < pow2(60) { sandblaster::lemmas::bits::lz_lower_u64_60(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 4u32 { sandblaster::lemmas::bits::lz_ge_u64_60(x); assert((x.leading_zeros() as Int) == 4); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 60); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 59); if (x as Int) < pow2(59) { sandblaster::lemmas::bits::lz_lower_u64_59(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 5u32 { sandblaster::lemmas::bits::lz_ge_u64_59(x); assert((x.leading_zeros() as Int) == 5); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 59); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 58); if (x as Int) < pow2(58) { sandblaster::lemmas::bits::lz_lower_u64_58(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 6u32 { sandblaster::lemmas::bits::lz_ge_u64_58(x); assert((x.leading_zeros() as Int) == 6); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 58); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 57); if (x as Int) < pow2(57) { sandblaster::lemmas::bits::lz_lower_u64_57(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 7u32 { sandblaster::lemmas::bits::lz_ge_u64_57(x); assert((x.leading_zeros() as Int) == 7); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 57); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 56); if (x as Int) < pow2(56) { sandblaster::lemmas::bits::lz_lower_u64_56(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 8u32 { sandblaster::lemmas::bits::lz_ge_u64_56(x); assert((x.leading_zeros() as Int) == 8); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 56); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 55); if (x as Int) < pow2(55) { sandblaster::lemmas::bits::lz_lower_u64_55(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 9u32 { sandblaster::lemmas::bits::lz_ge_u64_55(x); assert((x.leading_zeros() as Int) == 9); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 55); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 54); if (x as Int) < pow2(54) { sandblaster::lemmas::bits::lz_lower_u64_54(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 10u32 { sandblaster::lemmas::bits::lz_ge_u64_54(x); assert((x.leading_zeros() as Int) == 10); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 54); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 53); if (x as Int) < pow2(53) { sandblaster::lemmas::bits::lz_lower_u64_53(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 11u32 { sandblaster::lemmas::bits::lz_ge_u64_53(x); assert((x.leading_zeros() as Int) == 11); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 53); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 52); if (x as Int) < pow2(52) { sandblaster::lemmas::bits::lz_lower_u64_52(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 12u32 { sandblaster::lemmas::bits::lz_ge_u64_52(x); assert((x.leading_zeros() as Int) == 12); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 52); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 51); if (x as Int) < pow2(51) { sandblaster::lemmas::bits::lz_lower_u64_51(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 13u32 { sandblaster::lemmas::bits::lz_ge_u64_51(x); assert((x.leading_zeros() as Int) == 13); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 51); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 50); if (x as Int) < pow2(50) { sandblaster::lemmas::bits::lz_lower_u64_50(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 14u32 { sandblaster::lemmas::bits::lz_ge_u64_50(x); assert((x.leading_zeros() as Int) == 14); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 50); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 49); if (x as Int) < pow2(49) { sandblaster::lemmas::bits::lz_lower_u64_49(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 15u32 { sandblaster::lemmas::bits::lz_ge_u64_49(x); assert((x.leading_zeros() as Int) == 15); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 49); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 48); if (x as Int) < pow2(48) { sandblaster::lemmas::bits::lz_lower_u64_48(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 16u32 { sandblaster::lemmas::bits::lz_ge_u64_48(x); assert((x.leading_zeros() as Int) == 16); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 48); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 47); if (x as Int) < pow2(47) { sandblaster::lemmas::bits::lz_lower_u64_47(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 17u32 { sandblaster::lemmas::bits::lz_ge_u64_47(x); assert((x.leading_zeros() as Int) == 17); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 47); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 46); if (x as Int) < pow2(46) { sandblaster::lemmas::bits::lz_lower_u64_46(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 18u32 { sandblaster::lemmas::bits::lz_ge_u64_46(x); assert((x.leading_zeros() as Int) == 18); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 46); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 45); if (x as Int) < pow2(45) { sandblaster::lemmas::bits::lz_lower_u64_45(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 19u32 { sandblaster::lemmas::bits::lz_ge_u64_45(x); assert((x.leading_zeros() as Int) == 19); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 45); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 44); if (x as Int) < pow2(44) { sandblaster::lemmas::bits::lz_lower_u64_44(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 20u32 { sandblaster::lemmas::bits::lz_ge_u64_44(x); assert((x.leading_zeros() as Int) == 20); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 44); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 43); if (x as Int) < pow2(43) { sandblaster::lemmas::bits::lz_lower_u64_43(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 21u32 { sandblaster::lemmas::bits::lz_ge_u64_43(x); assert((x.leading_zeros() as Int) == 21); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 43); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 42); if (x as Int) < pow2(42) { sandblaster::lemmas::bits::lz_lower_u64_42(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 22u32 { sandblaster::lemmas::bits::lz_ge_u64_42(x); assert((x.leading_zeros() as Int) == 22); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 42); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 41); if (x as Int) < pow2(41) { sandblaster::lemmas::bits::lz_lower_u64_41(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 23u32 { sandblaster::lemmas::bits::lz_ge_u64_41(x); assert((x.leading_zeros() as Int) == 23); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 41); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 40); if (x as Int) < pow2(40) { sandblaster::lemmas::bits::lz_lower_u64_40(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 24u32 { sandblaster::lemmas::bits::lz_ge_u64_40(x); assert((x.leading_zeros() as Int) == 24); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 40); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 39); if (x as Int) < pow2(39) { sandblaster::lemmas::bits::lz_lower_u64_39(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 25u32 { sandblaster::lemmas::bits::lz_ge_u64_39(x); assert((x.leading_zeros() as Int) == 25); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 39); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 38); if (x as Int) < pow2(38) { sandblaster::lemmas::bits::lz_lower_u64_38(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 26u32 { sandblaster::lemmas::bits::lz_ge_u64_38(x); assert((x.leading_zeros() as Int) == 26); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 38); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 37); if (x as Int) < pow2(37) { sandblaster::lemmas::bits::lz_lower_u64_37(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 27u32 { sandblaster::lemmas::bits::lz_ge_u64_37(x); assert((x.leading_zeros() as Int) == 27); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 37); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 36); if (x as Int) < pow2(36) { sandblaster::lemmas::bits::lz_lower_u64_36(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 28u32 { sandblaster::lemmas::bits::lz_ge_u64_36(x); assert((x.leading_zeros() as Int) == 28); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 36); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 35); if (x as Int) < pow2(35) { sandblaster::lemmas::bits::lz_lower_u64_35(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 29u32 { sandblaster::lemmas::bits::lz_ge_u64_35(x); assert((x.leading_zeros() as Int) == 29); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 35); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 34); if (x as Int) < pow2(34) { sandblaster::lemmas::bits::lz_lower_u64_34(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 30u32 { sandblaster::lemmas::bits::lz_ge_u64_34(x); assert((x.leading_zeros() as Int) == 30); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 34); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 33); if (x as Int) < pow2(33) { sandblaster::lemmas::bits::lz_lower_u64_33(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 31u32 { sandblaster::lemmas::bits::lz_ge_u64_33(x); assert((x.leading_zeros() as Int) == 31); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 33); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 32); if (x as Int) < pow2(32) { sandblaster::lemmas::bits::lz_lower_u64_32(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 32u32 { sandblaster::lemmas::bits::lz_ge_u64_32(x); assert((x.leading_zeros() as Int) == 32); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 32); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 31); if (x as Int) < pow2(31) { sandblaster::lemmas::bits::lz_lower_u64_31(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 33u32 { sandblaster::lemmas::bits::lz_ge_u64_31(x); assert((x.leading_zeros() as Int) == 33); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 31); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 30); if (x as Int) < pow2(30) { sandblaster::lemmas::bits::lz_lower_u64_30(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 34u32 { sandblaster::lemmas::bits::lz_ge_u64_30(x); assert((x.leading_zeros() as Int) == 34); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 30); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 29); if (x as Int) < pow2(29) { sandblaster::lemmas::bits::lz_lower_u64_29(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 35u32 { sandblaster::lemmas::bits::lz_ge_u64_29(x); assert((x.leading_zeros() as Int) == 35); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 29); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 28); if (x as Int) < pow2(28) { sandblaster::lemmas::bits::lz_lower_u64_28(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 36u32 { sandblaster::lemmas::bits::lz_ge_u64_28(x); assert((x.leading_zeros() as Int) == 36); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 28); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 27); if (x as Int) < pow2(27) { sandblaster::lemmas::bits::lz_lower_u64_27(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 37u32 { sandblaster::lemmas::bits::lz_ge_u64_27(x); assert((x.leading_zeros() as Int) == 37); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 27); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 26); if (x as Int) < pow2(26) { sandblaster::lemmas::bits::lz_lower_u64_26(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 38u32 { sandblaster::lemmas::bits::lz_ge_u64_26(x); assert((x.leading_zeros() as Int) == 38); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 26); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 25); if (x as Int) < pow2(25) { sandblaster::lemmas::bits::lz_lower_u64_25(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 39u32 { sandblaster::lemmas::bits::lz_ge_u64_25(x); assert((x.leading_zeros() as Int) == 39); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 25); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 24); if (x as Int) < pow2(24) { sandblaster::lemmas::bits::lz_lower_u64_24(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 40u32 { sandblaster::lemmas::bits::lz_ge_u64_24(x); assert((x.leading_zeros() as Int) == 40); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 24); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 23); if (x as Int) < pow2(23) { sandblaster::lemmas::bits::lz_lower_u64_23(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 41u32 { sandblaster::lemmas::bits::lz_ge_u64_23(x); assert((x.leading_zeros() as Int) == 41); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 23); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 22); if (x as Int) < pow2(22) { sandblaster::lemmas::bits::lz_lower_u64_22(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 42u32 { sandblaster::lemmas::bits::lz_ge_u64_22(x); assert((x.leading_zeros() as Int) == 42); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 22); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 21); if (x as Int) < pow2(21) { sandblaster::lemmas::bits::lz_lower_u64_21(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 43u32 { sandblaster::lemmas::bits::lz_ge_u64_21(x); assert((x.leading_zeros() as Int) == 43); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 21); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 20); if (x as Int) < pow2(20) { sandblaster::lemmas::bits::lz_lower_u64_20(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 44u32 { sandblaster::lemmas::bits::lz_ge_u64_20(x); assert((x.leading_zeros() as Int) == 44); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 20); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 19); if (x as Int) < pow2(19) { sandblaster::lemmas::bits::lz_lower_u64_19(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 45u32 { sandblaster::lemmas::bits::lz_ge_u64_19(x); assert((x.leading_zeros() as Int) == 45); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 19); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 18); if (x as Int) < pow2(18) { sandblaster::lemmas::bits::lz_lower_u64_18(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 46u32 { sandblaster::lemmas::bits::lz_ge_u64_18(x); assert((x.leading_zeros() as Int) == 46); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 18); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 17); if (x as Int) < pow2(17) { sandblaster::lemmas::bits::lz_lower_u64_17(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 47u32 { sandblaster::lemmas::bits::lz_ge_u64_17(x); assert((x.leading_zeros() as Int) == 47); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 17); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 16); if (x as Int) < pow2(16) { sandblaster::lemmas::bits::lz_lower_u64_16(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 48u32 { sandblaster::lemmas::bits::lz_ge_u64_16(x); assert((x.leading_zeros() as Int) == 48); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 16); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 15); if (x as Int) < pow2(15) { sandblaster::lemmas::bits::lz_lower_u64_15(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 49u32 { sandblaster::lemmas::bits::lz_ge_u64_15(x); assert((x.leading_zeros() as Int) == 49); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 15); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 14); if (x as Int) < pow2(14) { sandblaster::lemmas::bits::lz_lower_u64_14(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 50u32 { sandblaster::lemmas::bits::lz_ge_u64_14(x); assert((x.leading_zeros() as Int) == 50); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 14); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 13); if (x as Int) < pow2(13) { sandblaster::lemmas::bits::lz_lower_u64_13(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 51u32 { sandblaster::lemmas::bits::lz_ge_u64_13(x); assert((x.leading_zeros() as Int) == 51); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 13); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 12); if (x as Int) < pow2(12) { sandblaster::lemmas::bits::lz_lower_u64_12(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 52u32 { sandblaster::lemmas::bits::lz_ge_u64_12(x); assert((x.leading_zeros() as Int) == 52); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 12); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 11); if (x as Int) < pow2(11) { sandblaster::lemmas::bits::lz_lower_u64_11(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 53u32 { sandblaster::lemmas::bits::lz_ge_u64_11(x); assert((x.leading_zeros() as Int) == 53); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 11); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 10); if (x as Int) < pow2(10) { sandblaster::lemmas::bits::lz_lower_u64_10(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 54u32 { sandblaster::lemmas::bits::lz_ge_u64_10(x); assert((x.leading_zeros() as Int) == 54); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 10); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 9); if (x as Int) < pow2(9) { sandblaster::lemmas::bits::lz_lower_u64_9(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 55u32 { sandblaster::lemmas::bits::lz_ge_u64_9(x); assert((x.leading_zeros() as Int) == 55); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 9); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 8); if (x as Int) < pow2(8) { sandblaster::lemmas::bits::lz_lower_u64_8(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 56u32 { sandblaster::lemmas::bits::lz_ge_u64_8(x); assert((x.leading_zeros() as Int) == 56); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 8); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 7); if (x as Int) < pow2(7) { sandblaster::lemmas::bits::lz_lower_u64_7(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 57u32 { sandblaster::lemmas::bits::lz_ge_u64_7(x); assert((x.leading_zeros() as Int) == 57); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 7); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 6); if (x as Int) < pow2(6) { sandblaster::lemmas::bits::lz_lower_u64_6(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 58u32 { sandblaster::lemmas::bits::lz_ge_u64_6(x); assert((x.leading_zeros() as Int) == 58); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 6); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 5); if (x as Int) < pow2(5) { sandblaster::lemmas::bits::lz_lower_u64_5(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 59u32 { sandblaster::lemmas::bits::lz_ge_u64_5(x); assert((x.leading_zeros() as Int) == 59); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 5); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 4); if (x as Int) < pow2(4) { sandblaster::lemmas::bits::lz_lower_u64_4(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 60u32 { sandblaster::lemmas::bits::lz_ge_u64_4(x); assert((x.leading_zeros() as Int) == 60); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 4); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 3); if (x as Int) < pow2(3) { sandblaster::lemmas::bits::lz_lower_u64_3(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 61u32 { sandblaster::lemmas::bits::lz_ge_u64_3(x); assert((x.leading_zeros() as Int) == 61); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 3); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 2); if (x as Int) < pow2(2) { sandblaster::lemmas::bits::lz_lower_u64_2(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 62u32 { sandblaster::lemmas::bits::lz_ge_u64_2(x); assert((x.leading_zeros() as Int) == 62); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 2); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 1); if (x as Int) < pow2(1) { sandblaster::lemmas::bits::lz_lower_u64_1(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 63u32 { sandblaster::lemmas::bits::lz_ge_u64_1(x); assert((x.leading_zeros() as Int) == 63); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 1); crate::proof::pow2_eq(64 - 1 - (x.leading_zeros() as Int), 0); if (x as Int) < pow2(0) { sandblaster::lemmas::bits::lz_lower_u64_0(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 64u32 { sandblaster::lemmas::bits::lz_ge_u64_0(x); assert((x.leading_zeros() as Int) == 64); crate::proof::pow2_eq(64 - (x.leading_zeros() as Int), 0); follows();
    } else { by_contradiction(); }
}

/// The bits a word needs: `2^(63 - lz) <= x < 2^(64 - lz)` for `x != 0`.
#[lemma]
fn lz_bits_u64(x: u64) {
    requires(x != 0u64);
    ensures(x.leading_zeros() < 64u32 && pow2(63 - (x.leading_zeros() as Int)) <= (x as Int) && (x as Int) < pow2(64 - (x.leading_zeros() as Int)));
    sandblaster::lemmas::bits::leading_zeros_lt_u64(x);
    lz_bits_chain(x);
    follows();
}

/// `log2` of a power of two is its exponent.
#[lemma]
fn log2_pow2(e: Int) {
    requires(e >= 0);
    ensures(log2(pow2(e)) == e);
    sandblaster::lemmas::nat::pow2_succ(e);
    crate::stdlib::bits::log2_unique(pow2(e) as Nat, e as Nat);
    follows();
}

// ---------------------------------------------------------------------------
// `fits`: mountains of distinct heights
// ---------------------------------------------------------------------------

/// Below height 0 only nothing fits.
#[lemma]
fn fits_neg(r: Int, h: Int) {
    requires(h < 0);
    ensures(fits(r, h) == (r == 0));
    by_unfolding(fits);
}

/// Below height 0 only nothing fits: what fits is zero.
#[lemma]
fn fits_neg_zero(r: Int, h: Int) {
    requires(h < 0 && fits(r, h));
    ensures(r == 0);
    by_unfolding(fits);
}

/// A tree of height `h` fits: it is taken.
#[lemma]
fn fits_take(r: Int, h: Int) {
    requires(h >= 0 && r + 1 >= pow2(h + 1));
    ensures(fits(r, h) == fits(r + 1 - pow2(h + 1), h - 1));
    by_unfolding(fits);
}

/// A tree of height `h` does not fit: skipped.
#[lemma]
fn fits_skip(r: Int, h: Int) {
    requires(h >= 0 && r + 1 < pow2(h + 1));
    ensures(fits(r, h) == fits(r, h - 1));
    by_unfolding(fits);
}

/// Mountains of distinct heights at most `h` have fewer than
/// `2^(h+2) - h - 2` nodes.
#[lemma]
#[decreases(h + 1)]
fn fits_bound(r: Int, h: Int) {
    requires(h >= -1 && fits(r, h));
    ensures(r + h + 3 <= pow2(h + 2));
    if h < 0 {
        fits_neg_zero(r, h);
        pow2_eq(h + 2, 1);
        follows();
    } else if r + 1 >= pow2(h + 1) {
        fits_take(r, h);
        fits_bound(r + 1 - pow2(h + 1), h - 1);
        pow2_eq(h - 1 + 2, h + 1);
        sandblaster::lemmas::nat::pow2_succ(h + 1);
        pow2_eq(h + 1 + 1, h + 2);
        follows();
    } else {
        fits_skip(r, h);
        fits_bound(r, h - 1);
        pow2_eq(h - 1 + 2, h + 1);
        sandblaster::lemmas::nat::pow2_succ(h + 1);
        pow2_eq(h + 1 + 1, h + 2);
        follows();
    }
}

/// Trees taller than `k` cannot fit in fewer than `2^(k+1)` nodes.
#[lemma]
#[decreases(h - k)]
fn fits_down(r: Int, h: Int, k: Int) {
    requires(-1 <= k && k <= h && r < pow2(k + 1));
    ensures(fits(r, h) == fits(r, k));
    if h == k {
        follows();
    } else {
        crate::stdlib::bits::pow2_mono(k + 1, h);
        sandblaster::lemmas::nat::pow2_succ(h);
        fits_skip(r, h);
        fits_down(r, h - 1, k);
        follows();
    }
}

/// Equal arguments, equal `fits` (congruence, by arithmetic on the
/// arguments).
#[lemma]
fn fits_cong(r1: Int, h1: Int, r2: Int, h2: Int) {
    requires(r1 == r2 && h1 == h2);
    ensures(fits(r1, h1) == fits(r2, h2));
    follows();
}

/// Two `fits` equations chained (a named step: `auto` rewrites with one
/// equation between unfolded terms per branch).
#[lemma]
fn fits_trans(a1: Int, h1: Int, a2: Int, h2: Int, a3: Int, h3: Int) {
    requires(fits(a1, h1) == fits(a2, h2) && fits(a2, h2) == fits(a3, h3));
    ensures(fits(a1, h1) == fits(a3, h3));
    follows();
}

/// Two `fits` equations chained, the second read right to left.
#[lemma]
fn fits_trans2(a1: Int, h1: Int, a2: Int, h2: Int, a3: Int, h3: Int) {
    requires(fits(a1, h1) == fits(a2, h2) && fits(a3, h3) == fits(a2, h2));
    ensures(fits(a1, h1) == fits(a3, h3));
    follows();
}

/// `fits_take` at a known power `t = 2^(h+1)`.
#[lemma]
fn fits_take_t(r: Int, h: Int, t: Int) {
    requires(h >= 0 && t == pow2(h + 1) && r + 1 >= t);
    ensures(fits(r, h) == fits(r + 1 - t, h - 1));
    fits_take(r, h);
    fits_cong(r + 1 - pow2(h + 1), h - 1, r + 1 - t, h - 1);
    follows();
}

/// `fits_skip` at a known power `t = 2^(h+1)`.
#[lemma]
fn fits_skip_t(r: Int, h: Int, t: Int) {
    requires(h >= 0 && t == pow2(h + 1) && r + 1 < t);
    ensures(fits(r, h) == fits(r, h - 1));
    fits_skip(r, h);
    follows();
}

/// `fits_bound` below a known power `t = 2^(h+1)`.
#[lemma]
fn fits_bound_t(r: Int, h: Int, t: Int) {
    requires(h >= 0 && t == pow2(h + 1) && fits(r, h - 1));
    ensures(r + h + 2 <= t);
    fits_bound(r, h - 1);
    pow2_eq(h - 1 + 2, h + 1);
    follows();
}

/// A power of two `t >= 2`: `t = 2^(h+1)` for `h = log2(t) - 1 >= 0`, and
/// `t / 2` is the power `2^h`.
#[lemma]
fn two_pow(t: Nat) {
    requires(2 <= t && pow2(log2(t)) == t);
    ensures(log2(t) >= 1 && t == pow2((log2(t) as Int) - 1 + 1) && t == 2 * pow2((log2(t) as Int) - 1) && t % 2 == 0
        && (log2(t / 2) as Int) == (log2(t) as Int) - 1 && pow2(log2(t / 2)) == t / 2);
    let h = (log2(t) as Int) - 1;
    sandblaster::lemmas::nat::log2_nonneg(t);
    assert(log2(t) >= 1, {
        if log2(t) == 0 {
            pow2_eq(log2(t), 0);
            by_contradiction();
        } else {
            follows();
        }
    });
    pow2_eq(h + 1, log2(t));
    sandblaster::lemmas::nat::pow2_succ(h);
    log2_pow2(h);
    assert(log2(t / 2) == log2(pow2(h)), { follows(); });
    pow2_eq(log2(t / 2), h);
    follows();
}

// ---------------------------------------------------------------------------
// `PeakIterator`: its states
// ---------------------------------------------------------------------------

/// The iterator's state: finished (`two_h <= 1`, `next` returns `None`) or
/// valid.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator)]
fn peak_iterator_state() {
    invariant(crate::proof::iter_ok(self.size.0, self.node_pos.0, self.two_h));
}

/// An iterator state: finished (`t <= 1`), or at the tree of height
/// `log2(t) - 1` whose root is `p`, with `s + t - (p + 2)` nodes from its
/// first one on making mountains of distinct heights below `log2(t)`.
#[spec]
pub fn iter_ok(s: u64, p: u64, t: u64) -> bool {
    t <= 1u64 || (2 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int)
        && 1 <= (s as Int) && (s as Int) < pow2(63) && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int)
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1))
}

/// A state of the iterator from its parts as plain words (a small context
/// for unfolding `iter_ok`).
#[lemma]
fn state_ok(s: u64, p: u64, t: u64) {
    requires(2 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int)
        && 1 <= (s as Int) && (s as Int) < pow2(63) && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int)
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1));
    ensures(iter_ok(s, p, t));
    by_unfolding(iter_ok);
}

/// A finished iterator state.
#[lemma]
fn done_ok(s: u64, p: u64, t: u64) {
    requires(t <= 1u64);
    ensures(iter_ok(s, p, t));
    by_unfolding(iter_ok);
}

/// `PeakIterator::new`: the first state, for a size `s` of an MMR, `1 <= s <
/// 2^63`: the tree of height `b - 1` (`2^(b-1) <= s < 2^b`), rooted at
/// `2^b - 2`.
#[lemma]
fn new_start(s: u64) {
    requires(1 <= (s as Int) && (s as Int) < pow2(63) && valid_size(s as Nat));
    ensures(1u32 <= s.leading_zeros() && s.leading_zeros() < 64u32
        && (u64::MAX >> s.leading_zeros()) as Int == pow2(64 - (s.leading_zeros() as Int)) - 1
        && ((!(u64::MAX >> s.leading_zeros())).trailing_zeros() as Int) == 64 - (s.leading_zeros() as Int)
        && (2 <= (pow2(64 - (s.leading_zeros() as Int))) && (pow2(64 - (s.leading_zeros() as Int))) <= pow2(63) && pow2(log2((pow2(64 - (s.leading_zeros() as Int))))) == (pow2(64 - (s.leading_zeros() as Int))) && 1 <= (s as Nat) && (s as Nat) < pow2(63) && (pow2(64 - (s.leading_zeros() as Int))) <= ((pow2(64 - (s.leading_zeros() as Int)) - 2) as Nat) + 2 && ((pow2(64 - (s.leading_zeros() as Int)) - 2) as Nat) + 2 <= (s as Nat) + (pow2(64 - (s.leading_zeros() as Int))) && fits((s as Nat) + (pow2(64 - (s.leading_zeros() as Int))) - (((pow2(64 - (s.leading_zeros() as Int)) - 2) as Nat) + 2), (log2((pow2(64 - (s.leading_zeros() as Int)))) as Int) - 1)));
    lz_bits_u64(s);
    let k = s.leading_zeros();
    assert(k >= 1u32, {
        if k == 0u32 {
            pow2_eq(63 - (k as Int), 63);
            by_contradiction();
        } else {
            follows();
        }
    });
    mask_facts(k);
    let b = 64 - (k as Int);
    sandblaster::lemmas::nat::pow2_succ(b - 1);
    pow2_eq(b - 1 + 1, b);
    pow2_eq(b - 1, 63 - (k as Int));
    sandblaster::lemmas::nat::pow2_pos(b - 1);
    fits_down(s as Nat, 63, b - 1);
    log2_pow2(b);
    pow2_eq(log2(pow2(b)) as Int, b);
    crate::stdlib::bits::pow2_mono(b, 63);
    fits_cong((s as Nat) + pow2(b) - (((pow2(b) - 2) as Nat) + 2), (log2(pow2(b)) as Int) - 1, s as Int, b - 1);
    follows();
}

/// `PeakIterator::new`: the facts its checks and its result rely on; its
/// state's remaining peaks are the MMR's peaks by size.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::new)]
fn new_facts() {
    at_start! {
        crate::proof::new_facts(size.0);
    }
    ensures(|ret: PeakIterator| crate::proof::peak_list(ret) == crate::proof::srow(0, size.0 as Nat, 63));
}

/// A peak at the state's tree: the tree to its right, of the same height,
/// is not in the MMR, and the rest after it fits as before.
#[lemma]
fn peak_step(s: Nat, p: Nat, t: Nat) {
    requires(2 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) && p < s);
    ensures((p as Int) + (t as Int) - 1 >= (s as Int) && (p as Int) + (t as Int) - 1 < pow2(64)
        && fits((s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), (log2(t) as Int) - 1));
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    two_pow(t);
    fits_take_t(r, h, t);
    fits_bound_t(r + 1 - t, h, t);
    fits_skip_t(r + 1 - t, h, t);
    fits_cong((s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h, r + 1 - t, h);
    follows();
}

/// A descent from the state's tree (not in the MMR) to its left child: a
/// state again at half the height, or finished at height 0.
#[lemma]
fn descend_step(s: Nat, p: Nat, t: Nat) {
    requires(2 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) && p >= s);
    ensures(t / 2 <= p && t % 2 == 0 && pow2(log2(t / 2)) == t / 2 && (log2(t / 2) as Int) == (log2(t) as Int) - 1
        && (t / 2 <= 1 || fits((s as Int) + ((t / 2) as Int) - ((p as Int) - ((t / 2) as Int) + 2), (log2(t / 2) as Int) - 1)));
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    two_pow(t);
    fits_skip_t(r, h, t);
    if t / 2 <= 1 {
        follows();
    } else {
        fits_cong((s as Int) + ((t / 2) as Int) - ((p as Int) - ((t / 2) as Int) + 2), (log2(t / 2) as Int) - 1, r, h - 1);
        follows();
    }
}

/// `PeakIterator::next`'s loop: `two_h` halves on each descent; the state
/// facts each branch needs; what it yields is the head of the state's
/// remaining peaks (`peak_list`), and the state it leaves has the rest.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::next, loop_nr = 0)]
fn next_loop() {
    decreases(self.two_h);
    ensures(|ret: (PeakIterator, Option<(Position, u32)>)| crate::proof::peak_list(self) == crate::proof::step_list(ret.1, crate::proof::peak_list(ret.0)));
    at_start! {
        crate::proof::pos_lt(self.node_pos, self.size);
        crate::proof::next_facts(self.size, self.node_pos, self.two_h);
    }
}

/// `next`: the helper's summary (opaque to its callers, `items` among
/// them: its body's assertion is not unfolded there).
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::next)]
fn next_summary() {
    opaque();
    ensures(|ret: (PeakIterator, Option<(Position, u32)>)| crate::proof::peak_list(self) == crate::proof::step_list(ret.1, crate::proof::peak_list(ret.0)));
}

// ---------------------------------------------------------------------------
// Loop measures
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// `mmr_size`: mountains by the set bits of the leaf count
// ---------------------------------------------------------------------------

/// The top set bit `h` of `n < 2^(h+1)` counts once.
#[lemma]
fn popcount_top(n: Nat, h: Int) {
    requires(h >= 0 && pow2(h) <= n && n < pow2(h + 1));
    ensures(popcount(n) == 1 + popcount(n - pow2(h)));
    crate::stdlib::bits::aligned_pow2(h);
    sandblaster::lemmas::nat::pow2_succ(h);
    crate::stdlib::bits::popcount_add(pow2(h), n - pow2(h), h);
    crate::stdlib::bits::popcount_pow2(h);
    follows();
}

/// The MMR of `n` leaves, `2^h <= n < 2^(h+1)`: a mountain of height `h`
/// (`2^(h+1) - 1` nodes), then the MMR of the other `n - 2^h` leaves.
#[lemma]
fn mmr_size_top(n: Int, h: Int) {
    requires(h >= 0 && pow2(h) <= n && n < pow2(h + 1));
    ensures(mmr_size(n) + 1 == pow2(h + 1) + mmr_size(n - pow2(h)));
    popcount_top(n as Nat, h);
    sandblaster::lemmas::nat::pow2_succ(h);
    by_unfolding(mmr_size);
}

/// Fewer than `2^h` leaves: fewer than `2^(h+1) - 1` nodes.
#[lemma]
fn mmr_size_small(n: Int, h: Int) {
    requires(h >= 0 && 0 <= n && n < pow2(h));
    ensures(mmr_size(n) + 1 < pow2(h + 1));
    sandblaster::lemmas::nat::pow2_succ(h);
    by_unfolding(mmr_size);
}

/// No leaves, no nodes.
#[lemma]
fn mmr_size_zero(n: Int) {
    requires(n == 0);
    ensures(mmr_size(n) == 0);
    by_unfolding(mmr_size);
}

/// One leaf, one node.
#[lemma]
fn mmr_size_one() {
    ensures(mmr_size(1) == 1);
    by_computation();
}

/// An MMR has at least as many nodes as leaves.
#[lemma]
fn mmr_size_ge(n: Nat) {
    ensures(n <= mmr_size(n));
    by_unfolding(mmr_size);
}

/// The MMR of `n < 2^(h+1)` leaves is mountains of distinct heights at most `h`.
#[lemma]
#[decreases(h + 1)]
fn mmr_size_fits(n: Int, h: Int) {
    requires(h >= -1 && 0 <= n && n < pow2(h + 1));
    ensures(fits(mmr_size(n), h));
    if h < 0 {
        pow2_eq(h + 1, 0);
        mmr_size_zero(n);
        fits_zero(h);
        follows();
    } else if n >= pow2(h) {
        sandblaster::lemmas::nat::pow2_succ(h);
        pow2_eq(h - 1 + 1, h);
        mmr_size_top(n, h);
        fits_take(mmr_size(n), h);
        mmr_size_fits(n - pow2(h), h - 1);
        follows();
    } else {
        pow2_eq(h - 1 + 1, h);
        mmr_size_small(n, h);
        fits_skip(mmr_size(n), h);
        mmr_size_fits(n, h - 1);
        follows();
    }
}

/// The leaf count of `r` nodes made of mountains of distinct heights at
/// most `h` (tallest first): `2^k` for each mountain of height `k`.
#[spec]
#[decreases(h + 1)]
#[example(leaves(0, 63) == 0 && leaves(1, 63) == 1 && leaves(3, 63) == 2 && leaves(4, 63) == 3 && leaves(19, 63) == 11)]
#[example(leaves(0, -1) == 0 && leaves(7, 2) == 4)]
pub fn leaves(r: Int, h: Int) -> Int {
    if h < 0 {
        0
    } else if r + 1 >= pow2(h + 1) {
        pow2(h) + leaves(r + 1 - pow2(h + 1), h - 1)
    } else {
        leaves(r, h - 1)
    }
}

/// `leaves`, one step: below height 0.
#[lemma]
fn leaves_neg(r: Int, h: Int) {
    requires(h < 0);
    ensures(leaves(r, h) == 0);
    by_unfolding(leaves);
}

/// `leaves`, one step: a mountain of height `h` taken.
#[lemma]
fn leaves_take(r: Int, h: Int) {
    requires(h >= 0 && r + 1 >= pow2(h + 1));
    ensures(leaves(r, h) == pow2(h) + leaves(r + 1 - pow2(h + 1), h - 1));
    by_unfolding(leaves);
}

/// `leaves`, one step: no mountain of height `h`.
#[lemma]
fn leaves_skip(r: Int, h: Int) {
    requires(h >= 0 && r + 1 < pow2(h + 1));
    ensures(leaves(r, h) == leaves(r, h - 1));
    by_unfolding(leaves);
}

/// Mountains of distinct heights at most `h` are the MMR of `leaves(r, h) <
/// 2^(h+1)` leaves.
#[lemma]
#[decreases(h + 1)]
fn leaves_fits(r: Int, h: Int) {
    requires(h >= -1 && fits(r, h));
    ensures(mmr_size(leaves(r, h)) == r && leaves(r, h) < pow2(h + 1));
    if h < 0 {
        fits_neg_zero(r, h);
        leaves_neg(r, h);
        pow2_eq(h + 1, 0);
        mmr_size_zero(leaves(r, h));
        follows();
    } else if r + 1 >= pow2(h + 1) {
        fits_take(r, h);
        leaves_take(r, h);
        leaves_fits(r + 1 - pow2(h + 1), h - 1);
        pow2_eq(h - 1 + 1, h);
        sandblaster::lemmas::nat::pow2_succ(h);
        mmr_size_top(leaves(r, h), h);
        follows();
    } else {
        fits_skip(r, h);
        leaves_skip(r, h);
        leaves_fits(r, h - 1);
        pow2_eq(h - 1 + 1, h);
        sandblaster::lemmas::nat::pow2_succ(h);
        follows();
    }
}

/// `leaves` is a count.
#[lemma]
#[decreases(h + 1)]
fn leaves_nonneg(r: Int, h: Int) {
    ensures(leaves(r, h) >= 0);
    if h < 0 {
        leaves_neg(r, h);
        follows();
    } else if r + 1 >= pow2(h + 1) {
        leaves_take(r, h);
        leaves_nonneg(r + 1 - pow2(h + 1), h - 1);
        follows();
    } else {
        leaves_skip(r, h);
        leaves_nonneg(r, h - 1);
        follows();
    }
}

/// No nodes, no leaves.
#[lemma]
#[decreases(h + 1)]
fn leaves_zero(h: Int) {
    requires(h >= -1);
    ensures(leaves(0, h) == 0);
    if h < 0 {
        leaves_neg(0, h);
        follows();
    } else {
        sandblaster::lemmas::nat::pow2_succ(h);
        sandblaster::lemmas::nat::pow2_pos(h);
        leaves_skip(0, h);
        leaves_zero(h - 1);
        follows();
    }
}

/// `leaves` inverts `mmr_size` below `2^(h+1)` leaves.
#[lemma]
#[decreases(h + 1)]
fn leaves_inverse(n: Nat, h: Int) {
    requires(h >= -1 && n < pow2(h + 1));
    ensures(leaves(mmr_size(n), h) == n);
    if h < 0 {
        pow2_eq(h + 1, 0);
        leaves_neg(mmr_size(n), h);
        follows();
    } else if n >= pow2(h) {
        sandblaster::lemmas::nat::pow2_succ(h);
        pow2_eq(h - 1 + 1, h);
        mmr_size_top(n, h);
        leaves_take(mmr_size(n), h);
        leaves_inverse(n - pow2(h), h - 1);
        follows();
    } else {
        pow2_eq(h - 1 + 1, h);
        mmr_size_small(n, h);
        leaves_skip(mmr_size(n), h);
        leaves_inverse(n, h - 1);
        follows();
    }
}

/// Adding one leaf adds at most one set bit.
#[lemma]
#[decreases(n)]
fn popcount_succ_le(n: Nat) {
    ensures(popcount(n + 1) <= popcount(n) + 1);
    crate::stdlib::bits::popcount_step(n + 1);
    crate::stdlib::bits::popcount_step(n);
    crate::stdlib::bits::halves(n);
    crate::stdlib::bits::halves(n + 1);
    if n % 2 == 0 {
        assert((n + 1) / 2 == n / 2 && (n + 1) % 2 == 1);
        crate::stdlib::bits::popcount_same((n + 1) / 2, n / 2);
        follows();
    } else {
        assert((n + 1) / 2 == n / 2 + 1 && (n + 1) % 2 == 0);
        crate::stdlib::bits::popcount_same((n + 1) / 2, n / 2 + 1);
        popcount_succ_le(n / 2);
        follows();
    }
}

/// Adding a leaf adds at least one node.
#[lemma]
fn mmr_size_succ(n: Int) {
    requires(n >= 0);
    ensures(mmr_size(n) + 1 <= mmr_size(n + 1));
    popcount_succ_le(n as Nat);
    by_unfolding(mmr_size);
}

/// `mmr_size` is strictly increasing.
#[lemma]
#[decreases(b - a)]
fn mmr_size_mono(a: Int, b: Int) {
    requires(0 <= a && a < b);
    ensures(mmr_size(a) < mmr_size(b));
    mmr_size_succ(b - 1);
    if a + 1 == b {
        follows();
    } else {
        mmr_size_mono(a, b - 1);
        follows();
    }
}

// ---------------------------------------------------------------------------
// `to_nearest_size`: a binary search on the leaf count
// ---------------------------------------------------------------------------

/// The binary search keeps `mmr_size(low) <= size < mmr_size(high + 1)`
/// and narrows `[low, high]`.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::to_nearest_size, loop_nr = 0)]
fn to_nearest_size_loop() {
    invariant(low <= high && high <= size_val && (size_val as Int) < pow2(63)
        && crate::laws::mmr_size(low as Nat) <= size_val as Nat && (size_val as Nat) < crate::laws::mmr_size(high as Nat + 1));
    decreases(high - low);
    at_start! {
        crate::proof::div_ceil2(low + high);
    }
    at_end! {
        crate::stdlib::bits::count_ones_u64(mid);
    }
    after_loop! {
        crate::proof::tns_result(low, high, size_val);
    }
}

/// `to_nearest_size` of the empty size: itself (the hypothesis in the form
/// the size test leaves it).
#[lemma]
fn tns_zero(s: u64) {
    ensures(implies((s == 0u64) == true, (s as Int) == 0 && (s as Int) == mmr_size(leaves(s as Int, 63))
        && 0 < mmr_size(leaves(s as Int, 63) + 1) && leaves(s as Int, 63) <= (s as Int)));
    if s == 0u64 {
        leaves_zero(63);
        mmr_size_zero(0);
        mmr_size_one();
        leaves_cong(s as Int, 0);
        mmr_size_cong(leaves(s as Int, 63), 0);
        mmr_size_cong(leaves(s as Int, 63) + 1, 1);
        follows();
    } else {
        follows();
    }
}

/// The binary search's answer (`low == high` on exit): `2 low -
/// popcount(low)` is `mmr_size(low)`, whose leaf count is `low`, the largest
/// with at most `size` nodes.
#[lemma]
fn tns_result(low: u64, high: u64, size: u64) {
    requires(low >= high && low <= high && (size as Int) < pow2(63) && mmr_size(low as Int) <= (size as Int) && (size as Int) < mmr_size((high as Int) + 1));
    ensures((low.count_ones() as u64) <= 2u64 * low
        && ((2u64 * low - low.count_ones() as u64) as Int) == mmr_size(leaves((2u64 * low - low.count_ones() as u64) as Int, 63))
        && (2u64 * low - low.count_ones() as u64) <= size
        && (size as Int) < mmr_size(leaves((2u64 * low - low.count_ones() as u64) as Int, 63) + 1)
        && leaves((2u64 * low - low.count_ones() as u64) as Int, 63) <= ((2u64 * low - low.count_ones() as u64) as Int));
    crate::stdlib::bits::count_ones_u64(low);
    sandblaster::lemmas::nat::popcount_le(low as Int);
    crate::stdlib::bits::pow2_mono(63, 64);
    mmr_size_ge(low as Nat);
    leaves_inverse(low as Nat, 63);
    let r = (2u64 * low - low.count_ones() as u64) as Int;
    leaves_cong(r, mmr_size(low as Int));
    mmr_size_cong(leaves(r, 63), low as Int);
    mmr_size_cong(leaves(r, 63) + 1, (high as Int) + 1);
    follows();
}

/// Equal sizes, equal leaf counts (congruence).
#[lemma]
fn leaves_cong(a: Int, b: Int) {
    requires(a == b);
    ensures(leaves(a, 63) == leaves(b, 63));
    follows();
}

/// `to_nearest_size`: the result is `mmr_size(L)` for `L` leaves, at most
/// `size`, and `size < mmr_size(L + 1)`.
#[lift_attach(crate::merkle::mmr::iterator::PeakIterator::to_nearest_size)]
fn to_nearest_size_summary() {
    at_start! {
        crate::proof::pos_le(size, crate::merkle::mmr::Family__MAX_NODES());
        crate::proof::mmr_size_ge(size.0 as Nat + 1);
        crate::proof::tns_zero(size.0);
    }
    ensures(|ret: crate::merkle::Position| (ret.0 as Nat) == crate::laws::mmr_size(crate::proof::leaves(ret.0 as Nat, 63))
        && ret.0 <= size.0 && (size.0 as Nat) < crate::laws::mmr_size(crate::proof::leaves(ret.0 as Nat, 63) + 1)
        && crate::proof::leaves(ret.0 as Nat, 63) <= ret.0 as Nat);
}

// ---------------------------------------------------------------------------
// Laws
// ---------------------------------------------------------------------------

/// `mmr_size(n)` fits (`mmr_size_fits` at height 63).
#[proof]
fn mmr_sizes_are_valid(n: Nat) {
    mmr_size_fits(n, 63);
    follows();
}

/// The witness is `leaves(s, 63)`.
#[proof]
fn valid_sizes_have_leaves(s: Nat) {
    leaves_fits(s, 63);
    witness(leaves(s, 63));
    follows();
}

/// From the summary: the result is `mmr_size(L)`; a larger MMR size at most
/// `size` would need more than `L` leaves, hence at least `mmr_size(L + 1)`
/// nodes.
#[proof]
fn to_nearest_size_rounds_down(size: crate::merkle::Position, s: Nat) {
    let r = crate::merkle::mmr::iterator::PeakIterator::to_nearest_size(size);
    leaves_nonneg(r.0 as Nat, 63);
    let l = leaves(r.0 as Nat, 63);
    crate::stdlib::bits::pow2_mono(63, 64);
    mmr_size_fits(l, 63);
    if valid_size(s) && s <= size.0 as Nat {
        leaves_fits(s, 63);
        leaves_nonneg(s, 63);
        if leaves(s, 63) > l {
            if leaves(s, 63) == l + 1 {
                follows();
            } else {
                mmr_size_mono(l + 1, leaves(s, 63));
                follows();
            }
        } else if leaves(s, 63) == l {
            follows();
        } else {
            mmr_size_mono(leaves(s, 63), l);
            follows();
        }
    } else {
        follows();
    }
}

/// No nodes: every `fits`.
#[lemma]
#[decreases(h + 1)]
fn fits_zero(h: Int) {
    requires(h >= -1);
    ensures(fits(0, h));
    if h < 0 {
        fits_neg(0, h);
        follows();
    } else {
        sandblaster::lemmas::nat::pow2_succ(h);
        sandblaster::lemmas::nat::pow2_pos(h);
        fits_skip(0, h);
        fits_zero(h - 1);
        follows();
    }
}

// ---------------------------------------------------------------------------
// `is_valid_size`: the peak search, deciding `fits`
// ---------------------------------------------------------------------------

/// The search ends at height `-1` with nothing left: the rest fits.
#[lemma]
fn search_done(s: Nat, p: Nat, t: Nat) {
    requires(1 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t && s <= p + t && t <= 1);
    ensures(fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1));
    crate::stdlib::bits::pow2_zero(0);
    log2_pow2(0);
    fits_neg((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1);
    follows();
}

/// A leaf-high peak: the rest fits iff it is exactly that leaf.
#[lemma]
fn search_leaf(s: Nat, p: Nat, t: Nat) {
    requires(1 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t && s <= p + t && t == 2 && p < s);
    ensures(fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) == ((p as Int) + 1 == (s as Int)));
    log2_pow2(1);
    pow2_eq(log2(t), 1);
    fits_take((s as Int) + (t as Int) - ((p as Int) + 2), 0);
    fits_neg((s as Int) + (t as Int) - ((p as Int) + 2) + 1 - 2, -1);
    follows();
}

/// A peak whose right sibling is in the MMR too: two trees of one height,
/// the rest does not fit.
#[lemma]
fn search_twice(s: Nat, p: Nat, t: Nat) {
    requires(1 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t && s <= p + t && t >= 4 && p < s && (p as Int) + (t as Int) - 1 < (s as Int));
    ensures(fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) == false);
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    two_pow(t);
    fits_take_t(r, h, t);
    if fits(r + 1 - t, h - 1) {
        fits_bound_t(r + 1 - t, h, t);
        by_contradiction();
    } else {
        follows();
    }
}

/// A peak, then the step right: the same answer from the tree to its
/// right.
#[lemma]
fn search_peak(s: Nat, p: Nat, t: Nat) {
    requires(1 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t && s <= p + t && t >= 4 && p < s && (p as Int) + (t as Int) - 1 >= (s as Int));
    ensures((p as Int) + (t as Int) - 1 < pow2(64)
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) == fits((s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), (log2(t) as Int) - 1));
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    two_pow(t);
    fits_take_t(r, h, t);
    fits_skip_t(r + 1 - t, h, t);
    fits_cong((s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h, r + 1 - t, h);
    follows();
}

/// A descent: the same answer at half the height.
#[lemma]
fn search_descend(s: Nat, p: Nat, t: Nat) {
    requires(1 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t && s <= p + t && t >= 2 && p >= s);
    ensures(t / 2 <= p && t % 2 == 0 && pow2(log2(t / 2)) == t / 2 && (log2(t / 2) as Int) == (log2(t) as Int) - 1
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) == fits((s as Int) + ((t / 2) as Int) - ((p as Int) - ((t / 2) as Int) + 2), (log2(t / 2) as Int) - 1));
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    two_pow(t);
    fits_skip_t(r, h, t);
    fits_cong((s as Int) + ((t / 2) as Int) - ((p as Int) - ((t / 2) as Int) + 2), (log2(t / 2) as Int) - 1, r, h - 1);
    follows();
}

/// A state of `is_valid_size`'s search: the tree of height `log2(t) - 1`
/// rooted at `p`, with the nodes from its first one on still to decide
/// (opaque: the search's facts name it whole).
#[spec]
#[opaque]
pub fn search_ok(s: u64, p: u64, t: u64) -> bool {
    1 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int) && 1 <= (s as Int) && (s as Int) < pow2(63)
        && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int) && (s as Int) <= (p as Int) + (t as Int)
}

/// The first search state of `is_valid_size` for `1 <= s < 2^63`.
#[lemma]
fn search_start(s: u64) {
    requires(1 <= (s as Int) && (s as Int) < pow2(63));
    ensures(1u32 <= s.leading_zeros() && s.leading_zeros() < 64u32
        && (u64::MAX >> s.leading_zeros()) as Int == pow2(64 - (s.leading_zeros() as Int)) - 1
        && ((!(u64::MAX >> s.leading_zeros())).trailing_zeros() as Int) == 64 - (s.leading_zeros() as Int)
        && (1 <= (pow2(64 - (s.leading_zeros() as Int))) && (pow2(64 - (s.leading_zeros() as Int))) <= pow2(63) && pow2(log2((pow2(64 - (s.leading_zeros() as Int))))) == (pow2(64 - (s.leading_zeros() as Int))) && 1 <= (s as Nat) && (s as Nat) < pow2(63) && (pow2(64 - (s.leading_zeros() as Int))) <= ((pow2(64 - (s.leading_zeros() as Int)) - 2) as Nat) + 2 && ((pow2(64 - (s.leading_zeros() as Int)) - 2) as Nat) + 2 <= (s as Nat) + (pow2(64 - (s.leading_zeros() as Int))) && (s as Nat) <= ((pow2(64 - (s.leading_zeros() as Int)) - 2) as Nat) + (pow2(64 - (s.leading_zeros() as Int))))
        && fits(s as Nat, 63 - (s.leading_zeros() as Int)) == valid_size(s as Nat));
    lz_bits_u64(s);
    let k = s.leading_zeros();
    assert(k >= 1u32, {
        if k == 0u32 {
            pow2_eq(63 - (k as Int), 63);
            by_contradiction();
        } else {
            follows();
        }
    });
    mask_facts(k);
    let b = 64 - (k as Int);
    sandblaster::lemmas::nat::pow2_succ(b - 1);
    fits_down(s as Nat, 63, b - 1);
    log2_pow2(b);
    crate::stdlib::bits::pow2_mono(b, 63);
    follows();
}

/// `is_valid_size`'s loop decides `fits` of what is left.
#[lift_attach(crate::merkle::mmr::Family::is_valid_size, loop_nr = 0)]
fn is_valid_size_loop() {
    invariant(crate::proof::search_ok(size, node_pos, two_h));
    decreases(2 * (two_h as Nat) + ((node_pos < size) as u64 as Nat));
    ensures(|ret: bool| ret == crate::laws::fits((size as Int) + (two_h as Int) - ((node_pos as Int) + 2), (log2(two_h as Nat) as Int) - 1));
    at_start! {
        crate::proof::search_facts(size, node_pos, two_h);
    }
}

/// `is_valid_size` decides "an MMR size up to `MAX_NODES`".
#[lift_attach(crate::merkle::mmr::Family::is_valid_size)]
fn is_valid_size_summary() {
    at_start! {
        crate::proof::valid_facts(size.0);
    }
    ensures(|ret: bool| ret == ((size.0 as Int) < pow2(63) && crate::laws::valid_size(size.0 as Nat)));
}

/// From the summary.
#[proof]
fn is_valid_size_characterizes_mmr_sizes(size: Position) {
    let r = Family::is_valid_size(size);
    follows();
}

// ---------------------------------------------------------------------------
// The peaks: by size (`srow`), by leaves (`mountains`), and the iterator
// ---------------------------------------------------------------------------

/// The peaks of `r` nodes of mountains of distinct heights at most `h`,
/// laid out from `at`, tallest first (as `mountains`, by size).
#[spec]
#[decreases(h + 1)]
#[example(srow(0, 19, 63) == seq![(14 as Int, 3 as Int), (17 as Int, 1 as Int), (18 as Int, 0 as Int)])]
#[example(srow(0, 0, 63) == seq![] && srow(5, 1, 0) == seq![(5 as Int, 0 as Int)])]
pub fn srow(at: Int, r: Int, h: Int) -> Seq<(Int, Int)> {
    if h < 0 {
        seq![]
    } else if r + 1 >= pow2(h + 1) {
        seq![(at + pow2(h + 1) - 2, h), ..srow(at + pow2(h + 1) - 1, r + 1 - pow2(h + 1), h - 1)]
    } else {
        srow(at, r, h - 1)
    }
}

/// The remaining peaks of an iterator state (none when finished); opaque
/// (`next_facts` states what `next` needs of it).
#[spec]
#[opaque]
pub fn plist(s: u64, p: u64, t: u64) -> Seq<(Int, Int)> {
    if t <= 1u64 {
        seq![]
    } else {
        srow((p as Int) + 2 - (t as Int), (s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1)
    }
}

/// The remaining peaks of an iterator.
#[spec]
pub fn peak_list(it: PeakIterator) -> Seq<(Int, Int)> {
    plist(it.size.0, it.node_pos.0, it.two_h)
}

/// An item as numbers before `rest`, or nothing.
#[spec]
pub fn step_list(o: Option<(Position, u32)>, rest: Seq<(Int, Int)>) -> Seq<(Int, Int)> {
    match o {
        None => seq![],
        Some(x) => seq![(x.0.0 as Int, x.1 as Int), ..rest],
    }
}

/// `srow`, one step: below height 0.
#[lemma]
fn srow_neg(at: Int, r: Int, h: Int) {
    requires(h < 0);
    ensures(srow(at, r, h) == seq![]);
    by_unfolding(srow);
}

/// `srow`, one step: a mountain of height `h`.
#[lemma]
fn srow_take(at: Int, r: Int, h: Int) {
    requires(h >= 0 && r + 1 >= pow2(h + 1));
    ensures(srow(at, r, h) == seq![(at + pow2(h + 1) - 2, h), ..srow(at + pow2(h + 1) - 1, r + 1 - pow2(h + 1), h - 1)]);
    by_unfolding(srow);
}

/// `srow`, one step: no mountain of height `h`.
#[lemma]
fn srow_skip(at: Int, r: Int, h: Int) {
    requires(h >= 0 && r + 1 < pow2(h + 1));
    ensures(srow(at, r, h) == srow(at, r, h - 1));
    by_unfolding(srow);
}

/// Equal arguments, equal `srow` (congruence).
#[lemma]
fn srow_cong(at1: Int, r1: Int, h1: Int, at2: Int, r2: Int, h2: Int) {
    requires(at1 == at2 && r1 == r2 && h1 == h2);
    ensures(srow(at1, r1, h1) == srow(at2, r2, h2));
    follows();
}

/// `srow_take` at a known power `t = 2^(h+1)`.
#[lemma]
fn srow_take_t(at: Int, r: Int, h: Int, t: Int) {
    requires(h >= 0 && t == pow2(h + 1) && r + 1 >= t);
    ensures(srow(at, r, h) == seq![(at + t - 2, h), ..srow(at + t - 1, r + 1 - t, h - 1)]);
    srow_take(at, r, h);
    srow_cong(at + pow2(h + 1) - 1, r + 1 - pow2(h + 1), h - 1, at + t - 1, r + 1 - t, h - 1);
    follows();
}

/// `srow_skip` at a known power `t = 2^(h+1)`.
#[lemma]
fn srow_skip_t(at: Int, r: Int, h: Int, t: Int) {
    requires(h >= 0 && t == pow2(h + 1) && r + 1 < t);
    ensures(srow(at, r, h) == srow(at, r, h - 1));
    srow_skip(at, r, h);
    follows();
}

/// No nodes, no peaks.
#[lemma]
#[decreases(h + 1)]
fn srow_zero(at: Int, h: Int) {
    requires(h >= -1);
    ensures(srow(at, 0, h) == seq![]);
    if h < 0 {
        srow_neg(at, 0, h);
        follows();
    } else {
        sandblaster::lemmas::nat::pow2_succ(h);
        sandblaster::lemmas::nat::pow2_pos(h);
        srow_skip(at, 0, h);
        srow_zero(at, h - 1);
        follows();
    }
}

/// Mountains taller than `k` cannot be in fewer than `2^(k+1)` nodes.
#[lemma]
#[decreases(h - k)]
fn srow_down(at: Int, r: Int, h: Int, k: Int) {
    requires(-1 <= k && k <= h && r < pow2(k + 1));
    ensures(srow(at, r, h) == srow(at, r, k));
    if h == k {
        follows();
    } else {
        crate::stdlib::bits::pow2_mono(k + 1, h);
        sandblaster::lemmas::nat::pow2_succ(h);
        srow_skip(at, r, h);
        srow_down(at, r, h - 1, k);
        follows();
    }
}

/// At most one peak per height.
#[lemma]
#[decreases(h + 1)]
fn srow_len(at: Int, r: Int, h: Int) {
    requires(h >= -1);
    ensures(srow(at, r, h).len() <= h + 1);
    if h < 0 {
        srow_neg(at, r, h);
        follows();
    } else if r + 1 >= pow2(h + 1) {
        srow_take(at, r, h);
        srow_len(at + pow2(h + 1) - 1, r + 1 - pow2(h + 1), h - 1);
        follows();
    } else {
        srow_skip(at, r, h);
        srow_len(at, r, h - 1);
        follows();
    }
}

/// `mountains`, one step: below height 0.
#[lemma]
fn mountains_neg(at: Int, n: Nat, h: Int) {
    requires(h < 0);
    ensures(mountains(at, n, h) == seq![]);
    by_unfolding(mountains);
}

/// `mountains`, one step: bit `h` set.
#[lemma]
fn mountains_take(at: Int, n: Nat, h: Int) {
    requires(h >= 0 && n >= pow2(h));
    ensures(mountains(at, n, h) == seq![(at + pow2(h + 1) - 2, h), ..mountains(at + pow2(h + 1) - 1, n - pow2(h), h - 1)]);
    by_unfolding(mountains);
}

/// `mountains`, one step: bit `h` clear.
#[lemma]
fn mountains_skip(at: Int, n: Nat, h: Int) {
    requires(h >= 0 && n < pow2(h));
    ensures(mountains(at, n, h) == mountains(at, n, h - 1));
    by_unfolding(mountains);
}

/// The peaks by size of the MMR of `n` leaves are its peaks by leaves.
#[lemma]
#[decreases(h + 1)]
fn srow_mountains(at: Int, n: Nat, h: Int) {
    requires(h >= -1 && n < pow2(h + 1));
    ensures(srow(at, mmr_size(n), h) == mountains(at, n, h));
    if h < 0 {
        srow_neg(at, mmr_size(n), h);
        mountains_neg(at, n, h);
        follows();
    } else if n >= pow2(h) {
        sandblaster::lemmas::nat::pow2_succ(h);
        pow2_eq(h - 1 + 1, h);
        mmr_size_top(n, h);
        srow_take(at, mmr_size(n), h);
        mountains_take(at, n, h);
        srow_mountains(at + pow2(h + 1) - 1, n - pow2(h), h - 1);
        follows();
    } else {
        pow2_eq(h - 1 + 1, h);
        mmr_size_small(n, h);
        srow_skip(at, mmr_size(n), h);
        mountains_skip(at, n, h);
        srow_mountains(at, n, h - 1);
        follows();
    }
}

/// A peak: the state's peaks are it, then those of the state to its right.
#[lemma]
fn list_peak(s: Nat, p: Nat, t: Nat) {
    requires(2 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) && p < s);
    ensures(srow((p as Int) + 2 - (t as Int), (s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1)
        == seq![(p as Int, (log2(t) as Int) - 1), ..srow((p as Int) + (t as Int) - 1 + 2 - (t as Int), (s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), (log2(t) as Int) - 1)]);
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    let a = (p as Int) + 2 - (t as Int);
    two_pow(t);
    fits_take_t(r, h, t);
    fits_bound_t(r + 1 - t, h, t);
    srow_take_t(a, r, h, t);
    srow_skip_t(a + t - 1, r + 1 - t, h, t);
    srow_cong((p as Int) + (t as Int) - 1 + 2 - (t as Int), (s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h, a + t - 1, r + 1 - t, h);
    follows();
}

/// A descent: the same peaks, from the left child's state (none when the
/// iterator finishes).
#[lemma]
fn list_descend(s: Nat, p: Nat, t: Nat) {
    requires(2 <= t && t <= pow2(63) && pow2(log2(t)) == t && 1 <= s && s < pow2(63) && t <= p + 2 && p + 2 <= s + t
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1) && p >= s);
    ensures(srow((p as Int) + 2 - (t as Int), (s as Int) + (t as Int) - ((p as Int) + 2), (log2(t) as Int) - 1)
        == (if t / 2 <= 1 { seq![] } else { srow((p as Int) - ((t / 2) as Int) + 2 - ((t / 2) as Int), (s as Int) + ((t / 2) as Int) - ((p as Int) - ((t / 2) as Int) + 2), (log2(t / 2) as Int) - 1) }));
    let h = (log2(t) as Int) - 1;
    let r = (s as Int) + (t as Int) - ((p as Int) + 2);
    let a = (p as Int) + 2 - (t as Int);
    two_pow(t);
    fits_skip_t(r, h, t);
    srow_skip_t(a, r, h, t);
    if t / 2 <= 1 {
        assert(log2(t / 2) == log2(1), { follows(); });
        srow_neg(a, r, h - 1);
        follows();
    } else {
        srow_cong((p as Int) - ((t / 2) as Int) + 2 - ((t / 2) as Int), (s as Int) + ((t / 2) as Int) - ((p as Int) - ((t / 2) as Int) + 2), (log2(t / 2) as Int) - 1, a, r, h - 1);
        follows();
    }
}

/// `new`'s first state: its peaks are the MMR's peaks by size.
#[lemma]
fn new_list(s: u64) {
    requires(1 <= (s as Int) && (s as Int) < pow2(63) && valid_size(s as Nat));
    ensures(srow(0, s as Nat, 63) == srow(0, s as Nat, 63 - (s.leading_zeros() as Int)));
    new_start(s);
    lz_bits_u64(s);
    srow_down(0, s as Nat, 63, 63 - (s.leading_zeros() as Int));
    follows();
}

/// With enough fuel, `items` yields exactly the state's remaining peaks.
#[lemma]
#[decreases(k)]
fn items_list(it: PeakIterator, k: Int) {
    requires(peak_list(it).len() < k);
    ensures(items(it, k) == peak_list(it));
    let mut i = it;
    let r = i.next();
    unfold(crate::laws::items);
    match r {
        None => follows(),
        Some(x) => {
            assert(peak_list(it) == seq![(x.0.0 as Int, x.1 as Int), ..peak_list(i)], { follows(); });
            assert(peak_list(it).len() == (seq![(x.0.0 as Int, x.1 as Int), ..peak_list(i)]).len(), { follows(); });
            assert((seq![(x.0.0 as Int, x.1 as Int), ..peak_list(i)]).len() == peak_list(i).len() + 1, { follows(); });
            assert(peak_list(i).len() < k - 1, { follows(); });
            items_list(i, k - 1);
            follows();
        }
    }
}

/// A word-sized integer converts to `u64` and back unchanged.
#[lemma]
fn u64_of_int(x: Int) {
    requires(0 <= x && x < pow2(64));
    ensures(((x as u64) as Int) == x);
    follows();
}

/// Equal sequences chained (a named step: the chain's links are
/// equations between unfolded terms).
#[lemma]
fn seq_chain(a: Seq<(Int, Int)>, b: Seq<(Int, Int)>, c: Seq<(Int, Int)>, d: Seq<(Int, Int)>) {
    requires(a == b && b == c && c == d);
    ensures(a == d && a.len() == d.len());
    follows();
}

/// From `new`'s and `next`'s summaries.
#[proof]
fn peak_iterator_yields_the_peaks(n: Nat) {
    let size = Position::new(mmr_size(n) as u64);
    let it = PeakIterator::new(size);
    mmr_sizes_are_valid_lemma(n);
    mmr_size_ge(n);
    crate::stdlib::bits::pow2_mono(63, 64);
    u64_of_int(mmr_size(n));
    srow_mountains(0, n, 63);
    srow_cong(0, (mmr_size(n) as u64) as Int, 63, 0, mmr_size(n), 63);
    srow_down(0, mmr_size(n), 63, 62);
    srow_len(0, mmr_size(n), 62);
    seq_chain(peak_list(it), srow(0, (mmr_size(n) as u64) as Int, 63), srow(0, mmr_size(n), 63), srow(0, mmr_size(n), 62));
    seq_chain(peak_list(it), srow(0, (mmr_size(n) as u64) as Int, 63), srow(0, mmr_size(n), 63), mountains(0, n, 63));
    items_list(it, 64);
    seq_chain(items(it, 64), peak_list(it), mountains(0, n, 63), mountains(0, n, 63));
    follows();
}

/// (`mmr_sizes_are_valid` as a lemma.)
#[lemma]
fn mmr_sizes_are_valid_lemma(n: Nat) {
    requires(mmr_size(n) < pow2(63));
    ensures(valid_size(mmr_size(n)) && n < pow2(64));
    mmr_size_ge(n);
    crate::stdlib::bits::pow2_mono(63, 64);
    mmr_size_fits(n, 63);
    follows();
}

// ---------------------------------------------------------------------------
// Case facts for the attachments (exec `proof!` blocks hold lemma
// applications only: each lemma below splits the cases itself)
// ---------------------------------------------------------------------------

/// The first search state, with the mask `m = 2^b - 1` and the power
/// `t = 2^b` as plain words (a small context for unfolding `search_ok`).
#[lemma]
fn start_ok(s: u64, m: u64, t: u64, b: Int) {
    requires(1 <= b && b <= 63 && (m as Int) == pow2(b) - 1 && (t as Int) == pow2(b) && (log2(t as Nat) as Int) == b
        && 1 <= (s as Int) && (s as Int) < pow2(b) && pow2(b) <= pow2(63));
    ensures(1u64 <= m && search_ok(s, m - 1u64, t)
        && fits((s as Int) + (t as Int) - (((m - 1u64) as Int) + 2), (log2(t as Nat) as Int) - 1) == fits(s as Int, b - 1));
    sandblaster::lemmas::nat::pow2_pos(b - 1);
    sandblaster::lemmas::nat::pow2_succ(b - 1);
    pow2_eq(b - 1 + 1, b);
    pow2_eq(log2(t as Nat), b);
    fits_cong((s as Int) + (t as Int) - (((m - 1u64) as Int) + 2), (log2(t as Nat) as Int) - 1, s as Int, b - 1);
    assert(search_ok(s, m - 1u64, t), { by_unfolding(search_ok); });
    follows();
}

/// The first iterator state of an MMR size (`fits` at its top height).
#[lemma]
fn start_iter(s: u64, m: u64, t: u64, b: Int) {
    requires(1 <= b && b <= 63 && (m as Int) == pow2(b) - 1 && (t as Int) == pow2(b) && (log2(t as Nat) as Int) == b
        && 1 <= (s as Int) && (s as Int) < pow2(b) && pow2(b) <= pow2(63) && fits(s as Int, b - 1));
    ensures(1u64 <= m && iter_ok(s, m - 1u64, t));
    start_ok(s, m, t, b);
    pow2_eq(log2(t as Nat), b);
    assert(iter_ok(s, m - 1u64, t), { by_unfolding(iter_ok); });
    follows();
}

/// The first iterator state's peaks are the MMR's (a small context for
/// unfolding `plist`).
#[lemma]
fn start_list(s: u64, m: u64, t: u64, b: Int) {
    requires(1 <= b && b <= 63 && (m as Int) == pow2(b) - 1 && (t as Int) == pow2(b) && (log2(t as Nat) as Int) == b
        && srow(0, s as Nat, 63) == srow(0, s as Int, b - 1));
    ensures(1u64 <= m && plist(s, m - 1u64, t) == srow(0, s as Nat, 63));
    sandblaster::lemmas::nat::pow2_pos(b - 1);
    sandblaster::lemmas::nat::pow2_succ(b - 1);
    pow2_eq(b - 1 + 1, b);
    srow_cong(((m - 1u64) as Int) + 2 - (t as Int), (s as Int) + (t as Int) - (((m - 1u64) as Int) + 2), (log2(t as Nat) as Int) - 1, 0, s as Int, b - 1);
    assert(plist(s, m - 1u64, t) == srow(0, s as Int, b - 1), { by_unfolding(plist); });
    follows();
}

/// The empty MMR: no peaks, and the default iterator has none.
#[lemma]
fn new_zero() {
    ensures(plist(0u64, 0u64, 0u64) == seq![] && srow(0, 0, 63) == seq![]);
    srow_zero(0, 63);
    assert(plist(0u64, 0u64, 0u64) == seq![], { by_unfolding(plist); });
    follows();
}

/// `new`'s first state for a nonzero size of an MMR: the tree of height
/// `63 - lz(s)` at `2^(64 - lz(s)) - 2`, whose peaks are the MMR's.
#[lemma]
fn new_pos(s: u64) {
    requires(1 <= (s as Int) && (s as Int) < pow2(63) && valid_size(s as Nat));
    ensures(1u32 <= s.leading_zeros() && s.leading_zeros() < 64u32
            && (u64::MAX >> s.leading_zeros()) as Int == pow2(64 - (s.leading_zeros() as Int)) - 1
            && ((!(u64::MAX >> s.leading_zeros())).trailing_zeros() as Int) == 64 - (s.leading_zeros() as Int)
            && ((1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros()) as Int) == pow2(64 - (s.leading_zeros() as Int))
            && 2 <= pow2(64 - (s.leading_zeros() as Int)) && pow2(64 - (s.leading_zeros() as Int)) <= pow2(63)
            && iter_ok(s, (u64::MAX >> s.leading_zeros()) - 1u64, 1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros())
            && plist(s, (u64::MAX >> s.leading_zeros()) - 1u64, 1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros()) == srow(0, s as Nat, 63));
    new_start(s);
    shl_one((!(u64::MAX >> s.leading_zeros())).trailing_zeros());
    new_list(s);
    lz_bits_u64(s);
    let k = s.leading_zeros();
    let b = 64 - (k as Int);
    pow2_eq(b - 1 + 1, b);
    fits_down(s as Nat, 63, b - 1);
    let m = u64::MAX >> k;
    let tt = 1u64 << (!m).trailing_zeros();
    pow2_eq((!m).trailing_zeros() as Int, b);
    log2_pow2(b);
    assert(log2(tt as Nat) == log2(pow2(b)), { follows(); });
    srow_cong(0, s as Int, 63 - (k as Int), 0, s as Int, b - 1);
    start_iter(s, m, tt, b);
    start_list(s, m, tt, b);
    by_arithmetic();
}

/// `new`'s facts, for a zero size (the default iterator) and for a valid
/// one (hypotheses in the form the size test leaves them).
#[lemma]
fn new_facts(s: u64) {
    requires((s as Int) < pow2(63) && valid_size(s as Nat));
    ensures(implies((s == 0u64) == true, plist(0u64, 0u64, 0u64) == seq![] && srow(0, s as Nat, 63) == seq![])
        && implies((s == 0u64) == false, 1u32 <= s.leading_zeros() && s.leading_zeros() < 64u32
            && (u64::MAX >> s.leading_zeros()) as Int == pow2(64 - (s.leading_zeros() as Int)) - 1
            && ((!(u64::MAX >> s.leading_zeros())).trailing_zeros() as Int) == 64 - (s.leading_zeros() as Int)
            && ((1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros()) as Int) == pow2(64 - (s.leading_zeros() as Int))
            && 2 <= pow2(64 - (s.leading_zeros() as Int)) && pow2(64 - (s.leading_zeros() as Int)) <= pow2(63)
            && iter_ok(s, (u64::MAX >> s.leading_zeros()) - 1u64, 1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros())
            && plist(s, (u64::MAX >> s.leading_zeros()) - 1u64, 1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros()) == srow(0, s as Nat, 63)));
    if s == 0u64 {
        new_zero();
        follows();
    } else {
        new_pos(s);
        follows();
    }
}

/// A finished iterator state has no peaks left.
#[lemma]
fn next_done(s: u64, p: u64, t: u64) {
    requires(t <= 1u64);
    ensures(plist(s, p, t) == seq![]);
    by_unfolding(plist);
}

/// A peak at the state's tree: its height is `tz(t) - 1`, the tree to its
/// right is the next state, and the remaining peaks are this one, then that
/// state's.
#[lemma]
fn next_peak(s: u64, p: u64, t: u64) {
    requires(iter_ok(s, p, t) && t > 1u64 && p < s);
    ensures(1u32 <= t.trailing_zeros() && (p as Int) + ((t - 1u64) as Int) < pow2(64) && s <= p + (t - 1u64)
        && iter_ok(s, p + (t - 1u64), t)
        && plist(s, p, t) == seq![(p as Int, (t.trailing_zeros() - 1u32) as Int), ..plist(s, p + (t - 1u64), t)]);
    assert(2 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int)
        && 1 <= (s as Int) && (s as Int) < pow2(63) && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int)
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1), { follows(); });
    two_pow(t as Nat);
    assert(log2(t as Nat) < 64, {
        if log2(t as Nat) >= 64 {
            crate::stdlib::bits::pow2_mono(64, log2(t as Nat));
            by_contradiction();
        } else {
            follows();
        }
    });
    tz_pow2(t, log2(t as Nat));
    let h = (log2(t as Nat) as Int) - 1;
    peak_step(s as Nat, p as Nat, t as Nat);
    list_peak(s as Nat, p as Nat, t as Nat);
    let q = p + (t - 1u64);
    fits_cong((s as Int) + (t as Int) - ((q as Int) + 2), h, (s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h);
    state_ok(s, q, t);
    srow_cong((q as Int) + 2 - (t as Int), (s as Int) + (t as Int) - ((q as Int) + 2), h, (p as Int) + (t as Int) - 1 + 2 - (t as Int), (s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h);
    assert(plist(s, p, t) == seq![(p as Int, (t.trailing_zeros() - 1u32) as Int), ..plist(s, q, t)], { by_unfolding(plist); });
    follows();
}

/// A descent to the left child: the next state, with the same remaining
/// peaks.
#[lemma]
fn next_desc(s: u64, p: u64, t: u64) {
    requires(iter_ok(s, p, t) && t > 1u64 && p >= s);
    ensures((t >> 1u32) <= p && iter_ok(s, p - (t >> 1u32), t >> 1u32) && plist(s, p, t) == plist(s, p - (t >> 1u32), t >> 1u32));
    assert(2 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int)
        && 1 <= (s as Int) && (s as Int) < pow2(63) && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int)
        && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1), { follows(); });
    two_pow(t as Nat);
    assert(log2(t as Nat) < 64, {
        if log2(t as Nat) >= 64 {
            crate::stdlib::bits::pow2_mono(64, log2(t as Nat));
            by_contradiction();
        } else {
            follows();
        }
    });
    tz_pow2(t, log2(t as Nat));
    let h = (log2(t as Nat) as Int) - 1;
    descend_step(s as Nat, p as Nat, t as Nat);
    list_descend(s as Nat, p as Nat, t as Nat);
    let u = t >> 1u32;
    let q = p - u;
    assert((u as Int) == ((t as Nat) / 2) as Int, { follows(); });
    assert(log2(u as Nat) == log2((t as Nat) / 2), { follows(); });
    pow2_eq(log2(u as Nat), log2((t as Nat) / 2));
    if u <= 1u64 {
        done_ok(s, q, u);
        assert(plist(s, p, t) == plist(s, q, u), { by_unfolding(plist); });
        follows();
    } else {
        assert((((t as Nat) / 2) <= 1) == false, { follows(); });
        fits_cong((s as Int) + (u as Int) - ((q as Int) + 2), (log2(u as Nat) as Int) - 1, (s as Int) + (((t as Nat) / 2) as Int) - ((p as Int) - (((t as Nat) / 2) as Int) + 2), (log2((t as Nat) / 2) as Int) - 1);
        state_ok(s, q, u);
        srow_cong((q as Int) + 2 - (u as Int), (s as Int) + (u as Int) - ((q as Int) + 2), (log2(u as Nat) as Int) - 1,
            (p as Int) - (((t as Nat) / 2) as Int) + 2 - (((t as Nat) / 2) as Int), (s as Int) + (((t as Nat) / 2) as Int) - ((p as Int) - (((t as Nat) / 2) as Int) + 2), (log2((t as Nat) / 2) as Int) - 1);
        assert(plist(s, p, t) == plist(s, q, u), { by_unfolding(plist); });
        follows();
    }
}

/// `next`'s facts per branch: the loop test `t > 1`, then the peak test
/// (hypotheses in the form the code's tests leave them; `Position`'s `<` is
/// `<` on the values by the bridge `position_lt`, applied where the loop
/// starts).
#[lemma]
fn next_facts(s: Position, p: Position, t: u64) {
    requires(iter_ok(s.0, p.0, t));
    ensures(implies((t > 1u64) == false, plist(s.0, p.0, t) == seq![])
        && implies(p.0 < s.0, implies(t > 1u64,
            1u32 <= t.trailing_zeros() && (p.0 as Int) + ((t - 1u64) as Int) < pow2(64)
            && s.0 <= crate::merkle::position::Position::add_assign__u64(p, t - 1u64).0
            && iter_ok(s.0, crate::merkle::position::Position::add_assign__u64(p, t - 1u64).0, t)
            && plist(s.0, p.0, t) == seq![(p.0 as Int, (t.trailing_zeros() - 1u32) as Int), ..plist(s.0, crate::merkle::position::Position::add_assign__u64(p, t - 1u64).0, t)]))
        && implies((p.0 < s.0) == false, implies(t > 1u64,
            (t >> 1u32) <= p.0
            && iter_ok(s.0, crate::merkle::position::Position::sub_assign__u64(p, t >> 1u32).0, t >> 1u32)
            && plist(s.0, p.0, t) == plist(s.0, crate::merkle::position::Position::sub_assign__u64(p, t >> 1u32).0, t >> 1u32))));
    if t <= 1u64 {
        next_done(s.0, p.0, t);
        follows();
    } else if p.0 < s.0 {
        next_peak(s.0, p.0, t);
        assert(crate::merkle::position::Position::add_assign__u64(p, t - 1u64).0 == p.0 + (t - 1u64), { follows(); });
        assert(iter_ok(s.0, crate::merkle::position::Position::add_assign__u64(p, t - 1u64).0, t), { follows(); });
        assert(plist(s.0, p.0, t) == seq![(p.0 as Int, (t.trailing_zeros() - 1u32) as Int), ..plist(s.0, crate::merkle::position::Position::add_assign__u64(p, t - 1u64).0, t)], { follows(); });
        follows();
    } else {
        next_desc(s.0, p.0, t);
        follows();
    }
}

/// `is_valid_size`'s search facts per branch: the loop test `t > 1`, the
/// peak test `p < s`, the leaf test `t == 2` and the sibling test
/// (hypotheses in the form the branches leave them).
#[lemma]
fn search_facts(s: u64, p: u64, t: u64) {
    requires(search_ok(s, p, t));
    ensures(implies((t > 1u64) == false, fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1))
        && implies(t > 1u64, implies(p < s, implies(t == 2u64, fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1) == (p == s - 1u64))))
        && implies(t > 1u64, implies(p < s, implies((t == 2u64) == false, (p as Int) + (t as Int) - 1 < pow2(64)
            && implies(p + (t - 1u64) < s, fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1) == false)
            && implies((p + (t - 1u64) < s) == false, search_ok(s, p + (t - 1u64), t)
                && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1) == fits((s as Int) + (t as Int) - (((p + (t - 1u64)) as Int) + 2), (log2(t as Nat) as Int) - 1)))))
        && implies(t > 1u64, implies((p < s) == false, (t >> 1u32) <= p && search_ok(s, p - (t >> 1u32), t >> 1u32)
            && fits((s as Int) + (t as Int) - ((p as Int) + 2), (log2(t as Nat) as Int) - 1) == fits((s as Int) + ((t >> 1u32) as Int) - (((p - (t >> 1u32)) as Int) + 2), (log2((t >> 1u32) as Nat) as Int) - 1))));
    assert(1 <= (t as Int) && (t as Int) <= pow2(63) && pow2(log2(t as Nat)) == (t as Int) && 1 <= (s as Int) && (s as Int) < pow2(63)
        && (t as Int) <= (p as Int) + 2 && (p as Int) + 2 <= (s as Int) + (t as Int) && (s as Int) <= (p as Int) + (t as Int), { by_unfolding(search_ok); });
    let h = (log2(t as Nat) as Int) - 1;
    if t <= 1u64 {
        search_done(s as Nat, p as Nat, t as Nat);
        follows();
    } else if p >= s {
        search_descend(s as Nat, p as Nat, t as Nat);
        let u = t >> 1u32;
        let q = p - u;
        assert((u as Int) == ((t as Nat) / 2) as Int, { follows(); });
        assert(log2(u as Nat) == log2((t as Nat) / 2), { follows(); });
        pow2_eq(log2(u as Nat), log2((t as Nat) / 2));
        fits_cong((s as Int) + (((t as Nat) / 2) as Int) - ((p as Int) - (((t as Nat) / 2) as Int) + 2), (log2((t as Nat) / 2) as Int) - 1, (s as Int) + (u as Int) - ((q as Int) + 2), (log2(u as Nat) as Int) - 1);
        fits_trans((s as Int) + (t as Int) - ((p as Int) + 2), h, (s as Int) + (((t as Nat) / 2) as Int) - ((p as Int) - (((t as Nat) / 2) as Int) + 2), (log2((t as Nat) / 2) as Int) - 1, (s as Int) + (u as Int) - ((q as Int) + 2), (log2(u as Nat) as Int) - 1);
        assert(search_ok(s, q, u), { by_unfolding(search_ok); });
        follows();
    } else if t == 2u64 {
        search_leaf(s as Nat, p as Nat, t as Nat);
        follows();
    } else {
        assert((t as Nat) >= 4, {
            sandblaster::lemmas::nat::log2_nonneg(t as Nat);
            if log2(t as Nat) <= 1 {
                if log2(t as Nat) == 0 { pow2_eq(log2(t as Nat), 0); follows(); } else { pow2_eq(log2(t as Nat), 1); follows(); }
                by_contradiction();
            } else {
                crate::stdlib::bits::pow2_mono(2, log2(t as Nat));
                follows();
            }
        });
        if p + (t - 1u64) < s {
            search_twice(s as Nat, p as Nat, t as Nat);
            follows();
        } else {
            search_peak(s as Nat, p as Nat, t as Nat);
            let q = p + (t - 1u64);
            fits_cong((s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h, (s as Int) + (t as Int) - ((q as Int) + 2), h);
            fits_trans((s as Int) + (t as Int) - ((p as Int) + 2), h, (s as Int) + (t as Int) - ((p as Int) + (t as Int) - 1 + 2), h, (s as Int) + (t as Int) - ((q as Int) + 2), h);
            assert(search_ok(s, q, t), { by_unfolding(search_ok); });
            follows();
        }
    }
}

/// `is_valid_size`'s facts: zero, a size with a leading zero (below
/// `2^63`), a larger one (hypotheses in the form the tests leave them).
#[lemma]
fn valid_facts(s: u64) {
    ensures(implies((s == 0u64) == true, valid_size(s as Nat))
        && implies((s == 0u64) == false, implies((s.leading_zeros() == 0u32) == true, (s as Int) >= pow2(63)))
        && implies((s == 0u64) == false, implies((s.leading_zeros() == 0u32) == false,
            (s as Int) < pow2(63) && 1u32 <= s.leading_zeros() && s.leading_zeros() < 64u32
            && 1u64 <= (u64::MAX >> s.leading_zeros())
            && (!(u64::MAX >> s.leading_zeros())).trailing_zeros() < 64u32
            && search_ok(s, (u64::MAX >> s.leading_zeros()) - 1u64, 1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros())
            && fits((s as Int) + ((1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros()) as Int) - ((((u64::MAX >> s.leading_zeros()) - 1u64) as Int) + 2),
                (log2((1u64 << (!(u64::MAX >> s.leading_zeros())).trailing_zeros()) as Nat) as Int) - 1) == valid_size(s as Nat))));
    if s == 0u64 {
        fits_zero(63);
        follows();
    } else if s.leading_zeros() == 0u32 {
        lz_bits_u64(s);
        pow2_eq(63 - (s.leading_zeros() as Int), 63);
        follows();
    } else {
        lz_bits_u64(s);
        let k = s.leading_zeros();
        mask_facts(k);
        let b = 64 - (k as Int);
        sandblaster::lemmas::nat::pow2_succ(b - 1);
        pow2_eq(b - 1 + 1, b);
        sandblaster::lemmas::nat::pow2_pos(b - 1);
        fits_down(s as Nat, 63, b - 1);
        crate::stdlib::bits::pow2_mono(b, 63);
        let m = u64::MAX >> k;
        shl_one((!m).trailing_zeros());
        let tt = 1u64 << (!m).trailing_zeros();
        pow2_eq((!m).trailing_zeros() as Int, b);
        log2_pow2(b);
        assert(log2(tt as Nat) == log2(pow2(b)), { follows(); });
        start_ok(s, m, tt, b);
        fits_trans2((s as Int) + (tt as Int) - (((m - 1u64) as Int) + 2), (log2(tt as Nat) as Int) - 1, s as Int, b - 1, s as Int, 63);
        by_unfolding(valid_size);
    }
}

// ---------------------------------------------------------------------------
// `pos_to_height`: peeling off left subtrees
// ---------------------------------------------------------------------------

/// `height_in`, one step: height 0.
#[lemma]
fn height_in_zero(p: Int, h: Int) {
    requires(h == 0);
    ensures(height_in(p, h) == 0);
    by_unfolding(height_in);
}

/// `height_in`, one step: the root.
#[lemma]
fn height_in_root(p: Int, h: Int) {
    requires(h >= 1 && p + 2 >= pow2(h + 1));
    ensures(height_in(p, h) == h);
    by_unfolding(height_in);
}

/// `height_in`, one step: the left subtree.
#[lemma]
fn height_in_left(p: Int, h: Int) {
    requires(h >= 1 && p + 2 < pow2(h + 1) && p + 1 < pow2(h));
    ensures(height_in(p, h) == height_in(p, h - 1));
    by_unfolding(height_in);
}

/// `height_in`, one step: the right subtree.
#[lemma]
fn height_in_right(p: Int, h: Int) {
    requires(h >= 1 && p + 2 < pow2(h + 1) && p + 1 >= pow2(h));
    ensures(height_in(p, h) == height_in(p + 1 - pow2(h), h - 1));
    by_unfolding(height_in);
}

/// A node's height is at most its tree's.
#[lemma]
#[decreases(h)]
fn height_in_le(p: Int, h: Nat) {
    ensures(height_in(p, h) <= h);
    if h == 0 {
        height_in_zero(p, h);
        follows();
    } else if p + 2 >= pow2(h + 1) {
        height_in_root(p, h);
        follows();
    } else if p + 1 < pow2(h) {
        height_in_left(p, h);
        height_in_le(p, h - 1);
        follows();
    } else {
        height_in_right(p, h);
        height_in_le(p + 1 - pow2(h), h - 1);
        follows();
    }
}

/// A position among the first `2^k` of a taller tree is in its leftmost
/// subtree of height `k`.
#[lemma]
#[decreases(big - k)]
fn height_down(p: Int, big: Nat, k: Nat) {
    requires(k <= big && p + 1 <= pow2(k));
    ensures(height_in(p, big) == height_in(p, k));
    if big == k {
        follows();
    } else {
        crate::stdlib::bits::pow2_mono(k, big - 1);
        sandblaster::lemmas::nat::pow2_succ(big - 1);
        sandblaster::lemmas::nat::pow2_succ(big);
        pow2_eq(big - 1 + 1, big);
        height_in_left(p, big);
        height_down(p, big - 1, k);
        follows();
    }
}

/// The height a state of `pos_to_height` stands for, with `size = 2^k -
/// 1`: a node of the tree of height `k` (`height_in`), or, one past its
/// root and beyond, the height of the root last peeled plus the steps since.
#[spec]
#[example(alg_height(0, 0) == 0 && alg_height(2, 1) == 1 && alg_height(3, 1) == 2 && alg_height(1, 0) == 1)]
pub fn alg_height(q: Int, k: Int) -> Int {
    if q + 1 >= pow2(k + 1) {
        q + 1 + k + 1 - pow2(k + 1)
    } else {
        height_in(q, k)
    }
}

/// Equal arguments, equal `alg_height` (congruence).
#[lemma]
fn alg_cong(q1: Int, k1: Int, q2: Int, k2: Int) {
    requires(q1 == q2 && k1 == k2);
    ensures(alg_height(q1, k1) == alg_height(q2, k2));
    follows();
}

/// `div_ceil(2)`: the upper half.
#[lemma]
fn div_ceil2(a: u64) {
    ensures((a.div_ceil(2u64) as Int) * 2 >= (a as Int) && (a.div_ceil(2u64) as Int) * 2 <= (a as Int) + 1);
    if a % 2u64 == 0u64 {
        follows();
    } else {
        follows();
    }
}

/// One step of `pos_to_height` keeps the height it stands for.
#[lemma]
fn alg_step(q: Int, k: Nat) {
    requires(k >= 1);
    ensures(implies(q + 1 >= pow2(k), alg_height(q + 1 - pow2(k), (k as Int) - 1) == alg_height(q, k))
        && implies(q + 1 < pow2(k), alg_height(q, (k as Int) - 1) == alg_height(q, k)));
    sandblaster::lemmas::nat::pow2_succ(k);
    sandblaster::lemmas::nat::pow2_succ(k - 1);
    pow2_eq(k - 1 + 1, k);
    if q + 1 >= pow2(k + 1) {
        by_unfolding(alg_height);
    } else if q + 2 == pow2(k + 1) {
        height_in_root(q, k);
        by_unfolding(alg_height);
    } else if q + 1 >= pow2(k) {
        height_in_right(q, k);
        by_unfolding(alg_height);
    } else {
        height_in_left(q, k);
        by_unfolding(alg_height);
    }
}

/// A step of `pos_to_height` that peels the tree off.
#[lemma]
fn alg_peel(q: Int, k: Nat) {
    requires(k >= 1 && q + 1 >= pow2(k));
    ensures(alg_height(q + 1 - pow2(k), (k as Int) - 1) == alg_height(q, k));
    alg_step(q, k);
    follows();
}

/// A step of `pos_to_height` that keeps the position.
#[lemma]
fn alg_keep(q: Int, k: Nat) {
    requires(k >= 1 && q + 1 < pow2(k));
    ensures(alg_height(q, (k as Int) - 1) == alg_height(q, k));
    alg_step(q, k);
    follows();
}

/// `pos_to_height`'s loop: the facts of one step.
#[lemma]
fn pth_facts(q: u64, size: u64) {
    requires(pow2(log2(size as Nat + 1)) == size as Nat + 1);
    ensures(implies((size != 0u64) == false, log2(size as Nat + 1) == 0 && alg_height(q as Nat, log2(size as Nat + 1)) == q as Nat)
        && implies((size != 0u64) == true, log2(size as Nat + 1) >= 1 && size >> 1u32 == size / 2u64
            && pow2(log2((size >> 1u32) as Nat + 1)) == (size >> 1u32) as Nat + 1
            && (log2((size >> 1u32) as Nat + 1) as Int) == (log2(size as Nat + 1) as Int) - 1
            && implies(q >= size, alg_height((q - size) as Nat, log2((size >> 1u32) as Nat + 1)) == alg_height(q as Nat, log2(size as Nat + 1)))
            && implies((q >= size) == false, alg_height(q as Nat, log2((size >> 1u32) as Nat + 1)) == alg_height(q as Nat, log2(size as Nat + 1)))));
    let k = log2(size as Nat + 1);
    sandblaster::lemmas::nat::log2_nonneg(size as Nat + 1);
    if size == 0u64 {
        crate::stdlib::bits::pow2_zero(0);
        log2_pow2(0);
        assert(log2(size as Nat + 1) == log2(pow2(0)), { follows(); });
        height_in_zero(q as Nat, 0);
        alg_cong(q as Nat, log2(size as Nat + 1), q as Nat, 0);
        follows();
    } else {
        assert(k >= 1, {
            if k == 0 {
                pow2_eq(k, 0);
                by_contradiction();
            } else {
                follows();
            }
        });
        sandblaster::lemmas::nat::pow2_succ(k - 1);
        pow2_eq(k - 1 + 1, k);
        log2_pow2(k - 1);
        assert(log2((size >> 1u32) as Nat + 1) == log2(pow2(k - 1)), { follows(); });
        pow2_eq(log2((size >> 1u32) as Nat + 1), k - 1);
        assert(size >> 1u32 == size / 2u64, { follows(); });
        if q >= size {
            alg_peel(q as Nat, k);
            alg_cong((q - size) as Nat, log2((size >> 1u32) as Nat + 1), q as Nat + 1 - pow2(k), (k as Int) - 1);
            follows();
        } else {
            alg_keep(q as Nat, k);
            alg_cong(q as Nat, log2((size >> 1u32) as Nat + 1), q as Nat, (k as Int) - 1);
            follows();
        }
    }
}

/// `pos_to_height`'s loop (lifted with the rest of the body as a helper,
/// for its summary): the height the state stands for is the answer.
#[lift_attach(crate::merkle::mmr::iterator::pos_to_height, loop_nr = 0)]
fn pos_to_height_loop() {
    invariant(pow2(log2(size as Nat + 1)) == size as Nat + 1 && crate::proof::alg_height(pos as Nat, log2(size as Nat + 1)) <= 64);
    decreases(size);
    ensures(|ret: u32| (ret as Nat) == crate::proof::alg_height(pos as Nat, log2(size as Nat + 1)));
    at_start! {
        crate::proof::pth_facts(pos, size);
    }
}

/// `pos_to_height`'s start: `size = 2^b - 1` for `2^(b-1) <= p < 2^b`, and
/// the state stands for the node's height.
#[lemma]
fn pth_start(p: u64) {
    ensures(implies((p == 0u64) == true, node_height(p as Nat) == 0)
        && implies((p == 0u64) == false, p.leading_zeros() < 64u32
            && (u64::MAX >> p.leading_zeros()) as Int == pow2(64 - (p.leading_zeros() as Int)) - 1
            && pow2(log2((u64::MAX >> p.leading_zeros()) as Nat + 1)) == (u64::MAX >> p.leading_zeros()) as Nat + 1
            && alg_height(p as Nat, log2((u64::MAX >> p.leading_zeros()) as Nat + 1)) == node_height(p as Nat)
            && node_height(p as Nat) <= 64));
    if p == 0u64 {
        crate::stdlib::bits::pow2_zero(0);
        height_down(0, 64, 0);
        height_in_zero(0, 0);
        follows();
    } else {
        lz_bits_u64(p);
        let b = 64 - (p.leading_zeros() as Int);
        mask_facts(p.leading_zeros());
        log2_pow2(b);
        assert(log2((u64::MAX >> p.leading_zeros()) as Nat + 1) == log2(pow2(b)), { follows(); });
        pow2_eq(log2((u64::MAX >> p.leading_zeros()) as Nat + 1), b);
        alg_cong(p as Nat, log2((u64::MAX >> p.leading_zeros()) as Nat + 1), p as Nat, b);
        sandblaster::lemmas::nat::pow2_succ(b);
        height_down(p as Nat, 64, b as Nat);
        height_in_le(p as Nat, 64);
        by_unfolding(alg_height, node_height);
    }
}

/// `pos_to_height` is the node's height.
#[lift_attach(crate::merkle::mmr::iterator::pos_to_height)]
fn pos_to_height_summary() {
    at_start! {
        crate::proof::pth_start(pos.0);
    }
    ensures(|ret: u32| (ret as Nat) == crate::laws::node_height(pos.0 as Nat));
}

/// From the summary (`Family::pos_to_height` calls it).
#[proof]
fn pos_to_height_is_the_node_height(pos: Position) {
    let r = crate::merkle::mmr::iterator::pos_to_height(pos);
    follows();
}

/// Congruence: equal shift amounts, equal shifts.
#[lemma]
fn shlx_cong(x: u64, b: u32, j: u32) {
    requires(b < 64u32 && b == j);
    ensures(x << b == x << j);
    follows();
}

/// `chunk_peaks`'s shifts: the chunk's bounds `c * 2^g` and `(c + 1) *
/// 2^g` (at most `2^62`) and `2^(g+1)`, exactly (one case per height).
#[lemma]
fn chunk_facts(c: u64, g: u32) {
    requires(g <= 62u32 && ((c as Int) + 1) * pow2(g as Int) <= pow2(62));
    ensures((c as Int) + 1 <= pow2(62) && pow2(g as Int) >= 1
        && ((c as Int) + 1) * pow2(g as Int) == (c as Int) * pow2(g as Int) + pow2(g as Int)
        && ((c + 1u64) << g) as Int == ((c as Int) + 1) * pow2(g as Int)
        && (c << g) as Int == (c as Int) * pow2(g as Int)
        && ((1u64 << (g + 1u32)) as Int) == 2 * pow2(g as Int));
    if g <= 0u32 { assert(g == 0u32); shlx_cong(c + 1u64, g, 0u32); shlx_cong(c, g, 0u32); shl_cong(g + 1u32, 1u32); pow2_eq(g as Int, 0); pow2_eq((g as Int) + 1, 1); follows(); }
    else if g <= 1u32 { assert(g == 1u32); shlx_cong(c + 1u64, g, 1u32); shlx_cong(c, g, 1u32); shl_cong(g + 1u32, 2u32); pow2_eq(g as Int, 1); pow2_eq((g as Int) + 1, 2); sandblaster::lemmas::bits::shl_exact_u64_1(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_1(c); follows(); }
    else if g <= 2u32 { assert(g == 2u32); shlx_cong(c + 1u64, g, 2u32); shlx_cong(c, g, 2u32); shl_cong(g + 1u32, 3u32); pow2_eq(g as Int, 2); pow2_eq((g as Int) + 1, 3); sandblaster::lemmas::bits::shl_exact_u64_2(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_2(c); follows(); }
    else if g <= 3u32 { assert(g == 3u32); shlx_cong(c + 1u64, g, 3u32); shlx_cong(c, g, 3u32); shl_cong(g + 1u32, 4u32); pow2_eq(g as Int, 3); pow2_eq((g as Int) + 1, 4); sandblaster::lemmas::bits::shl_exact_u64_3(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_3(c); follows(); }
    else if g <= 4u32 { assert(g == 4u32); shlx_cong(c + 1u64, g, 4u32); shlx_cong(c, g, 4u32); shl_cong(g + 1u32, 5u32); pow2_eq(g as Int, 4); pow2_eq((g as Int) + 1, 5); sandblaster::lemmas::bits::shl_exact_u64_4(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_4(c); follows(); }
    else if g <= 5u32 { assert(g == 5u32); shlx_cong(c + 1u64, g, 5u32); shlx_cong(c, g, 5u32); shl_cong(g + 1u32, 6u32); pow2_eq(g as Int, 5); pow2_eq((g as Int) + 1, 6); sandblaster::lemmas::bits::shl_exact_u64_5(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_5(c); follows(); }
    else if g <= 6u32 { assert(g == 6u32); shlx_cong(c + 1u64, g, 6u32); shlx_cong(c, g, 6u32); shl_cong(g + 1u32, 7u32); pow2_eq(g as Int, 6); pow2_eq((g as Int) + 1, 7); sandblaster::lemmas::bits::shl_exact_u64_6(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_6(c); follows(); }
    else if g <= 7u32 { assert(g == 7u32); shlx_cong(c + 1u64, g, 7u32); shlx_cong(c, g, 7u32); shl_cong(g + 1u32, 8u32); pow2_eq(g as Int, 7); pow2_eq((g as Int) + 1, 8); sandblaster::lemmas::bits::shl_exact_u64_7(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_7(c); follows(); }
    else if g <= 8u32 { assert(g == 8u32); shlx_cong(c + 1u64, g, 8u32); shlx_cong(c, g, 8u32); shl_cong(g + 1u32, 9u32); pow2_eq(g as Int, 8); pow2_eq((g as Int) + 1, 9); sandblaster::lemmas::bits::shl_exact_u64_8(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_8(c); follows(); }
    else if g <= 9u32 { assert(g == 9u32); shlx_cong(c + 1u64, g, 9u32); shlx_cong(c, g, 9u32); shl_cong(g + 1u32, 10u32); pow2_eq(g as Int, 9); pow2_eq((g as Int) + 1, 10); sandblaster::lemmas::bits::shl_exact_u64_9(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_9(c); follows(); }
    else if g <= 10u32 { assert(g == 10u32); shlx_cong(c + 1u64, g, 10u32); shlx_cong(c, g, 10u32); shl_cong(g + 1u32, 11u32); pow2_eq(g as Int, 10); pow2_eq((g as Int) + 1, 11); sandblaster::lemmas::bits::shl_exact_u64_10(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_10(c); follows(); }
    else if g <= 11u32 { assert(g == 11u32); shlx_cong(c + 1u64, g, 11u32); shlx_cong(c, g, 11u32); shl_cong(g + 1u32, 12u32); pow2_eq(g as Int, 11); pow2_eq((g as Int) + 1, 12); sandblaster::lemmas::bits::shl_exact_u64_11(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_11(c); follows(); }
    else if g <= 12u32 { assert(g == 12u32); shlx_cong(c + 1u64, g, 12u32); shlx_cong(c, g, 12u32); shl_cong(g + 1u32, 13u32); pow2_eq(g as Int, 12); pow2_eq((g as Int) + 1, 13); sandblaster::lemmas::bits::shl_exact_u64_12(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_12(c); follows(); }
    else if g <= 13u32 { assert(g == 13u32); shlx_cong(c + 1u64, g, 13u32); shlx_cong(c, g, 13u32); shl_cong(g + 1u32, 14u32); pow2_eq(g as Int, 13); pow2_eq((g as Int) + 1, 14); sandblaster::lemmas::bits::shl_exact_u64_13(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_13(c); follows(); }
    else if g <= 14u32 { assert(g == 14u32); shlx_cong(c + 1u64, g, 14u32); shlx_cong(c, g, 14u32); shl_cong(g + 1u32, 15u32); pow2_eq(g as Int, 14); pow2_eq((g as Int) + 1, 15); sandblaster::lemmas::bits::shl_exact_u64_14(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_14(c); follows(); }
    else if g <= 15u32 { assert(g == 15u32); shlx_cong(c + 1u64, g, 15u32); shlx_cong(c, g, 15u32); shl_cong(g + 1u32, 16u32); pow2_eq(g as Int, 15); pow2_eq((g as Int) + 1, 16); sandblaster::lemmas::bits::shl_exact_u64_15(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_15(c); follows(); }
    else if g <= 16u32 { assert(g == 16u32); shlx_cong(c + 1u64, g, 16u32); shlx_cong(c, g, 16u32); shl_cong(g + 1u32, 17u32); pow2_eq(g as Int, 16); pow2_eq((g as Int) + 1, 17); sandblaster::lemmas::bits::shl_exact_u64_16(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_16(c); follows(); }
    else if g <= 17u32 { assert(g == 17u32); shlx_cong(c + 1u64, g, 17u32); shlx_cong(c, g, 17u32); shl_cong(g + 1u32, 18u32); pow2_eq(g as Int, 17); pow2_eq((g as Int) + 1, 18); sandblaster::lemmas::bits::shl_exact_u64_17(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_17(c); follows(); }
    else if g <= 18u32 { assert(g == 18u32); shlx_cong(c + 1u64, g, 18u32); shlx_cong(c, g, 18u32); shl_cong(g + 1u32, 19u32); pow2_eq(g as Int, 18); pow2_eq((g as Int) + 1, 19); sandblaster::lemmas::bits::shl_exact_u64_18(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_18(c); follows(); }
    else if g <= 19u32 { assert(g == 19u32); shlx_cong(c + 1u64, g, 19u32); shlx_cong(c, g, 19u32); shl_cong(g + 1u32, 20u32); pow2_eq(g as Int, 19); pow2_eq((g as Int) + 1, 20); sandblaster::lemmas::bits::shl_exact_u64_19(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_19(c); follows(); }
    else if g <= 20u32 { assert(g == 20u32); shlx_cong(c + 1u64, g, 20u32); shlx_cong(c, g, 20u32); shl_cong(g + 1u32, 21u32); pow2_eq(g as Int, 20); pow2_eq((g as Int) + 1, 21); sandblaster::lemmas::bits::shl_exact_u64_20(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_20(c); follows(); }
    else if g <= 21u32 { assert(g == 21u32); shlx_cong(c + 1u64, g, 21u32); shlx_cong(c, g, 21u32); shl_cong(g + 1u32, 22u32); pow2_eq(g as Int, 21); pow2_eq((g as Int) + 1, 22); sandblaster::lemmas::bits::shl_exact_u64_21(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_21(c); follows(); }
    else if g <= 22u32 { assert(g == 22u32); shlx_cong(c + 1u64, g, 22u32); shlx_cong(c, g, 22u32); shl_cong(g + 1u32, 23u32); pow2_eq(g as Int, 22); pow2_eq((g as Int) + 1, 23); sandblaster::lemmas::bits::shl_exact_u64_22(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_22(c); follows(); }
    else if g <= 23u32 { assert(g == 23u32); shlx_cong(c + 1u64, g, 23u32); shlx_cong(c, g, 23u32); shl_cong(g + 1u32, 24u32); pow2_eq(g as Int, 23); pow2_eq((g as Int) + 1, 24); sandblaster::lemmas::bits::shl_exact_u64_23(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_23(c); follows(); }
    else if g <= 24u32 { assert(g == 24u32); shlx_cong(c + 1u64, g, 24u32); shlx_cong(c, g, 24u32); shl_cong(g + 1u32, 25u32); pow2_eq(g as Int, 24); pow2_eq((g as Int) + 1, 25); sandblaster::lemmas::bits::shl_exact_u64_24(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_24(c); follows(); }
    else if g <= 25u32 { assert(g == 25u32); shlx_cong(c + 1u64, g, 25u32); shlx_cong(c, g, 25u32); shl_cong(g + 1u32, 26u32); pow2_eq(g as Int, 25); pow2_eq((g as Int) + 1, 26); sandblaster::lemmas::bits::shl_exact_u64_25(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_25(c); follows(); }
    else if g <= 26u32 { assert(g == 26u32); shlx_cong(c + 1u64, g, 26u32); shlx_cong(c, g, 26u32); shl_cong(g + 1u32, 27u32); pow2_eq(g as Int, 26); pow2_eq((g as Int) + 1, 27); sandblaster::lemmas::bits::shl_exact_u64_26(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_26(c); follows(); }
    else if g <= 27u32 { assert(g == 27u32); shlx_cong(c + 1u64, g, 27u32); shlx_cong(c, g, 27u32); shl_cong(g + 1u32, 28u32); pow2_eq(g as Int, 27); pow2_eq((g as Int) + 1, 28); sandblaster::lemmas::bits::shl_exact_u64_27(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_27(c); follows(); }
    else if g <= 28u32 { assert(g == 28u32); shlx_cong(c + 1u64, g, 28u32); shlx_cong(c, g, 28u32); shl_cong(g + 1u32, 29u32); pow2_eq(g as Int, 28); pow2_eq((g as Int) + 1, 29); sandblaster::lemmas::bits::shl_exact_u64_28(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_28(c); follows(); }
    else if g <= 29u32 { assert(g == 29u32); shlx_cong(c + 1u64, g, 29u32); shlx_cong(c, g, 29u32); shl_cong(g + 1u32, 30u32); pow2_eq(g as Int, 29); pow2_eq((g as Int) + 1, 30); sandblaster::lemmas::bits::shl_exact_u64_29(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_29(c); follows(); }
    else if g <= 30u32 { assert(g == 30u32); shlx_cong(c + 1u64, g, 30u32); shlx_cong(c, g, 30u32); shl_cong(g + 1u32, 31u32); pow2_eq(g as Int, 30); pow2_eq((g as Int) + 1, 31); sandblaster::lemmas::bits::shl_exact_u64_30(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_30(c); follows(); }
    else if g <= 31u32 { assert(g == 31u32); shlx_cong(c + 1u64, g, 31u32); shlx_cong(c, g, 31u32); shl_cong(g + 1u32, 32u32); pow2_eq(g as Int, 31); pow2_eq((g as Int) + 1, 32); sandblaster::lemmas::bits::shl_exact_u64_31(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_31(c); follows(); }
    else if g <= 32u32 { assert(g == 32u32); shlx_cong(c + 1u64, g, 32u32); shlx_cong(c, g, 32u32); shl_cong(g + 1u32, 33u32); pow2_eq(g as Int, 32); pow2_eq((g as Int) + 1, 33); sandblaster::lemmas::bits::shl_exact_u64_32(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_32(c); follows(); }
    else if g <= 33u32 { assert(g == 33u32); shlx_cong(c + 1u64, g, 33u32); shlx_cong(c, g, 33u32); shl_cong(g + 1u32, 34u32); pow2_eq(g as Int, 33); pow2_eq((g as Int) + 1, 34); sandblaster::lemmas::bits::shl_exact_u64_33(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_33(c); follows(); }
    else if g <= 34u32 { assert(g == 34u32); shlx_cong(c + 1u64, g, 34u32); shlx_cong(c, g, 34u32); shl_cong(g + 1u32, 35u32); pow2_eq(g as Int, 34); pow2_eq((g as Int) + 1, 35); sandblaster::lemmas::bits::shl_exact_u64_34(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_34(c); follows(); }
    else if g <= 35u32 { assert(g == 35u32); shlx_cong(c + 1u64, g, 35u32); shlx_cong(c, g, 35u32); shl_cong(g + 1u32, 36u32); pow2_eq(g as Int, 35); pow2_eq((g as Int) + 1, 36); sandblaster::lemmas::bits::shl_exact_u64_35(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_35(c); follows(); }
    else if g <= 36u32 { assert(g == 36u32); shlx_cong(c + 1u64, g, 36u32); shlx_cong(c, g, 36u32); shl_cong(g + 1u32, 37u32); pow2_eq(g as Int, 36); pow2_eq((g as Int) + 1, 37); sandblaster::lemmas::bits::shl_exact_u64_36(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_36(c); follows(); }
    else if g <= 37u32 { assert(g == 37u32); shlx_cong(c + 1u64, g, 37u32); shlx_cong(c, g, 37u32); shl_cong(g + 1u32, 38u32); pow2_eq(g as Int, 37); pow2_eq((g as Int) + 1, 38); sandblaster::lemmas::bits::shl_exact_u64_37(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_37(c); follows(); }
    else if g <= 38u32 { assert(g == 38u32); shlx_cong(c + 1u64, g, 38u32); shlx_cong(c, g, 38u32); shl_cong(g + 1u32, 39u32); pow2_eq(g as Int, 38); pow2_eq((g as Int) + 1, 39); sandblaster::lemmas::bits::shl_exact_u64_38(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_38(c); follows(); }
    else if g <= 39u32 { assert(g == 39u32); shlx_cong(c + 1u64, g, 39u32); shlx_cong(c, g, 39u32); shl_cong(g + 1u32, 40u32); pow2_eq(g as Int, 39); pow2_eq((g as Int) + 1, 40); sandblaster::lemmas::bits::shl_exact_u64_39(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_39(c); follows(); }
    else if g <= 40u32 { assert(g == 40u32); shlx_cong(c + 1u64, g, 40u32); shlx_cong(c, g, 40u32); shl_cong(g + 1u32, 41u32); pow2_eq(g as Int, 40); pow2_eq((g as Int) + 1, 41); sandblaster::lemmas::bits::shl_exact_u64_40(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_40(c); follows(); }
    else if g <= 41u32 { assert(g == 41u32); shlx_cong(c + 1u64, g, 41u32); shlx_cong(c, g, 41u32); shl_cong(g + 1u32, 42u32); pow2_eq(g as Int, 41); pow2_eq((g as Int) + 1, 42); sandblaster::lemmas::bits::shl_exact_u64_41(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_41(c); follows(); }
    else if g <= 42u32 { assert(g == 42u32); shlx_cong(c + 1u64, g, 42u32); shlx_cong(c, g, 42u32); shl_cong(g + 1u32, 43u32); pow2_eq(g as Int, 42); pow2_eq((g as Int) + 1, 43); sandblaster::lemmas::bits::shl_exact_u64_42(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_42(c); follows(); }
    else if g <= 43u32 { assert(g == 43u32); shlx_cong(c + 1u64, g, 43u32); shlx_cong(c, g, 43u32); shl_cong(g + 1u32, 44u32); pow2_eq(g as Int, 43); pow2_eq((g as Int) + 1, 44); sandblaster::lemmas::bits::shl_exact_u64_43(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_43(c); follows(); }
    else if g <= 44u32 { assert(g == 44u32); shlx_cong(c + 1u64, g, 44u32); shlx_cong(c, g, 44u32); shl_cong(g + 1u32, 45u32); pow2_eq(g as Int, 44); pow2_eq((g as Int) + 1, 45); sandblaster::lemmas::bits::shl_exact_u64_44(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_44(c); follows(); }
    else if g <= 45u32 { assert(g == 45u32); shlx_cong(c + 1u64, g, 45u32); shlx_cong(c, g, 45u32); shl_cong(g + 1u32, 46u32); pow2_eq(g as Int, 45); pow2_eq((g as Int) + 1, 46); sandblaster::lemmas::bits::shl_exact_u64_45(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_45(c); follows(); }
    else if g <= 46u32 { assert(g == 46u32); shlx_cong(c + 1u64, g, 46u32); shlx_cong(c, g, 46u32); shl_cong(g + 1u32, 47u32); pow2_eq(g as Int, 46); pow2_eq((g as Int) + 1, 47); sandblaster::lemmas::bits::shl_exact_u64_46(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_46(c); follows(); }
    else if g <= 47u32 { assert(g == 47u32); shlx_cong(c + 1u64, g, 47u32); shlx_cong(c, g, 47u32); shl_cong(g + 1u32, 48u32); pow2_eq(g as Int, 47); pow2_eq((g as Int) + 1, 48); sandblaster::lemmas::bits::shl_exact_u64_47(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_47(c); follows(); }
    else if g <= 48u32 { assert(g == 48u32); shlx_cong(c + 1u64, g, 48u32); shlx_cong(c, g, 48u32); shl_cong(g + 1u32, 49u32); pow2_eq(g as Int, 48); pow2_eq((g as Int) + 1, 49); sandblaster::lemmas::bits::shl_exact_u64_48(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_48(c); follows(); }
    else if g <= 49u32 { assert(g == 49u32); shlx_cong(c + 1u64, g, 49u32); shlx_cong(c, g, 49u32); shl_cong(g + 1u32, 50u32); pow2_eq(g as Int, 49); pow2_eq((g as Int) + 1, 50); sandblaster::lemmas::bits::shl_exact_u64_49(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_49(c); follows(); }
    else if g <= 50u32 { assert(g == 50u32); shlx_cong(c + 1u64, g, 50u32); shlx_cong(c, g, 50u32); shl_cong(g + 1u32, 51u32); pow2_eq(g as Int, 50); pow2_eq((g as Int) + 1, 51); sandblaster::lemmas::bits::shl_exact_u64_50(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_50(c); follows(); }
    else if g <= 51u32 { assert(g == 51u32); shlx_cong(c + 1u64, g, 51u32); shlx_cong(c, g, 51u32); shl_cong(g + 1u32, 52u32); pow2_eq(g as Int, 51); pow2_eq((g as Int) + 1, 52); sandblaster::lemmas::bits::shl_exact_u64_51(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_51(c); follows(); }
    else if g <= 52u32 { assert(g == 52u32); shlx_cong(c + 1u64, g, 52u32); shlx_cong(c, g, 52u32); shl_cong(g + 1u32, 53u32); pow2_eq(g as Int, 52); pow2_eq((g as Int) + 1, 53); sandblaster::lemmas::bits::shl_exact_u64_52(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_52(c); follows(); }
    else if g <= 53u32 { assert(g == 53u32); shlx_cong(c + 1u64, g, 53u32); shlx_cong(c, g, 53u32); shl_cong(g + 1u32, 54u32); pow2_eq(g as Int, 53); pow2_eq((g as Int) + 1, 54); sandblaster::lemmas::bits::shl_exact_u64_53(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_53(c); follows(); }
    else if g <= 54u32 { assert(g == 54u32); shlx_cong(c + 1u64, g, 54u32); shlx_cong(c, g, 54u32); shl_cong(g + 1u32, 55u32); pow2_eq(g as Int, 54); pow2_eq((g as Int) + 1, 55); sandblaster::lemmas::bits::shl_exact_u64_54(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_54(c); follows(); }
    else if g <= 55u32 { assert(g == 55u32); shlx_cong(c + 1u64, g, 55u32); shlx_cong(c, g, 55u32); shl_cong(g + 1u32, 56u32); pow2_eq(g as Int, 55); pow2_eq((g as Int) + 1, 56); sandblaster::lemmas::bits::shl_exact_u64_55(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_55(c); follows(); }
    else if g <= 56u32 { assert(g == 56u32); shlx_cong(c + 1u64, g, 56u32); shlx_cong(c, g, 56u32); shl_cong(g + 1u32, 57u32); pow2_eq(g as Int, 56); pow2_eq((g as Int) + 1, 57); sandblaster::lemmas::bits::shl_exact_u64_56(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_56(c); follows(); }
    else if g <= 57u32 { assert(g == 57u32); shlx_cong(c + 1u64, g, 57u32); shlx_cong(c, g, 57u32); shl_cong(g + 1u32, 58u32); pow2_eq(g as Int, 57); pow2_eq((g as Int) + 1, 58); sandblaster::lemmas::bits::shl_exact_u64_57(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_57(c); follows(); }
    else if g <= 58u32 { assert(g == 58u32); shlx_cong(c + 1u64, g, 58u32); shlx_cong(c, g, 58u32); shl_cong(g + 1u32, 59u32); pow2_eq(g as Int, 58); pow2_eq((g as Int) + 1, 59); sandblaster::lemmas::bits::shl_exact_u64_58(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_58(c); follows(); }
    else if g <= 59u32 { assert(g == 59u32); shlx_cong(c + 1u64, g, 59u32); shlx_cong(c, g, 59u32); shl_cong(g + 1u32, 60u32); pow2_eq(g as Int, 59); pow2_eq((g as Int) + 1, 60); sandblaster::lemmas::bits::shl_exact_u64_59(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_59(c); follows(); }
    else if g <= 60u32 { assert(g == 60u32); shlx_cong(c + 1u64, g, 60u32); shlx_cong(c, g, 60u32); shl_cong(g + 1u32, 61u32); pow2_eq(g as Int, 60); pow2_eq((g as Int) + 1, 61); sandblaster::lemmas::bits::shl_exact_u64_60(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_60(c); follows(); }
    else if g <= 61u32 { assert(g == 61u32); shlx_cong(c + 1u64, g, 61u32); shlx_cong(c, g, 61u32); shl_cong(g + 1u32, 62u32); pow2_eq(g as Int, 61); pow2_eq((g as Int) + 1, 62); sandblaster::lemmas::bits::shl_exact_u64_61(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_61(c); follows(); }
    else if g <= 62u32 { assert(g == 62u32); shlx_cong(c + 1u64, g, 62u32); shlx_cong(c, g, 62u32); shl_cong(g + 1u32, 63u32); pow2_eq(g as Int, 62); pow2_eq((g as Int) + 1, 63); sandblaster::lemmas::bits::shl_exact_u64_62(c + 1u64); sandblaster::lemmas::bits::shl_exact_u64_62(c); follows(); }
    else { by_contradiction(); }
}

/// `chunk_peaks`'s location checks (`is_valid`: at most `MAX_LEAVES`), in
/// the form the checks test them.
#[lemma]
fn chunk_valid(c: u64, g: u32) {
    requires(g <= 62u32 && ((c as Int) + 1) * pow2(g as Int) <= pow2(62));
    ensures((c as Int) + 1 <= pow2(62) && (((c + 1u64) << g) <= 4611686018427387904u64) == true && ((c << g) <= 4611686018427387904u64) == true);
    chunk_facts(c, g);
    follows();
}

/// Equal leaf counts, equal sizes (congruence).
#[lemma]
fn mmr_size_cong(a: Int, b: Int) {
    requires(a == b);
    ensures(mmr_size(a) == mmr_size(b));
    follows();
}

/// An MMR has at most twice as many nodes as leaves.
#[lemma]
fn mmr_size_le(n: Int) {
    requires(n >= 0);
    ensures(mmr_size(n) <= 2 * n);
    sandblaster::lemmas::nat::popcount_nonneg(n);
    by_unfolding(mmr_size);
}

/// `location_to_position`: the node count before the leaf (opaque to its
/// callers: they use this summary, not its body's `expect`).
#[lift_attach(crate::merkle::mmr::Family::location_to_position)]
fn location_to_position_summary() {
    opaque();
    at_start! {
        crate::stdlib::bits::count_ones_u64(loc.0);
        crate::proof::double_fits(loc.0);
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

/// A location found for `pos` is that of the leaf at `pos`.
#[spec]
pub fn sound_loc(o: Option<Location>, pos: Int) -> bool {
    match o {
        None => true,
        Some(l) => crate::laws::mmr_size(l.0 as Int) == pos,
    }
}

/// `position_to_location`: every candidate is checked exactly.
#[lift_attach(crate::merkle::mmr::Family::position_to_location)]
fn position_to_location_summary() {
    opaque();
    ensures(|ret: Option<Location>| crate::proof::sound_loc(ret, pos.0 as Int));
}

/// `Position`'s `PartialOrd` is opaque to its callers (a comparison is a
/// small term); `pos_lt`, `pos_le` and `pos_ge` read its tests as the
/// comparisons of the values, in the form the tests leave them.
#[lift_attach(crate::merkle::position::Position::partial_cmp)]
fn position_partial_cmp_opaque() {
    opaque();
}

/// `a < b` on positions, both outcomes.
#[lemma]
fn pos_lt(a: Position, b: Position) {
    ensures(implies(crate::__lift::ord_lt(a.partial_cmp(&b)) == true, a.0 < b.0)
        && implies(crate::__lift::ord_lt(a.partial_cmp(&b)) == false, (a.0 < b.0) == false));
    crate::words::position_lt(a, b);
    follows();
}

/// `a <= b` on positions, both outcomes.
#[lemma]
fn pos_le(a: Position, b: Position) {
    ensures(implies(crate::__lift::ord_le(a.partial_cmp(&b)) == true, a.0 <= b.0)
        && implies(crate::__lift::ord_le(a.partial_cmp(&b)) == false, (a.0 <= b.0) == false));
    crate::words::position_le(a, b);
    follows();
}

/// `a >= b` on positions, both outcomes.
#[lemma]
fn pos_ge(a: Position, b: Position) {
    ensures(implies(crate::__lift::ord_ge(a.partial_cmp(&b)) == true, a.0 >= b.0)
        && implies(crate::__lift::ord_ge(a.partial_cmp(&b)) == false, (a.0 >= b.0) == false));
    crate::words::position_ge(a, b);
    follows();
}

/// `chunk_peaks`'s range check on the converted chunk end, both outcomes.
#[lemma]
fn chunk_end_le(r: crate::__lift::Result<Position, crate::merkle::Error>, size: Position) {
    ensures(match r {
        crate::__lift::Result::Ok(q) => implies(crate::__lift::ord_le(q.partial_cmp(&size)) == true, q.0 <= size.0)
            && implies(crate::__lift::ord_le(q.partial_cmp(&size)) == false, (q.0 <= size.0) == false),
        crate::__lift::Result::Err(_) => true,
    });
    match r {
        crate::__lift::Result::Ok(q) => {
            pos_le(q, size);
            follows();
        }
        crate::__lift::Result::Err(_) => follows(),
    }
}

/// `Position::try_from(loc)`'s answer: a location up to `MAX_LEAVES`
/// converts to its leaf's position.
#[spec]
pub fn try_from_ok(loc: Location, r: crate::__lift::Result<Position, crate::merkle::Error>) -> bool {
    match r {
        crate::__lift::Result::Ok(q) => (loc.0 as Int) <= pow2(62) && (q.0 as Int) == crate::laws::mmr_size(loc.0 as Int),
        crate::__lift::Result::Err(_) => (loc.0 as Int) > pow2(62),
    }
}

/// `Position::checked_add` (opaque to its callers, which see its answer as
/// a value: the sum up to `MAX_NODES`, else `None`).
#[lift_attach(crate::merkle::position::Position::checked_add)]
fn checked_add_summary() {
    opaque();
    ensures(|ret: Option<Position>| ret == (if (self.0 as Int) + (rhs as Int) <= pow2(63) - 1 { Some(Position::new(self.0 + rhs)) } else { None }));
}


/// `Position::try_from(Location)` (opaque to its callers).
#[lift_attach(crate::merkle::position::Position::try_from__Location)]
fn try_from_summary() {
    opaque();
    ensures(|ret: crate::__lift::Result<Position, crate::merkle::Error>| crate::proof::try_from_ok(loc, ret));
}

/// `chunk_peaks`: the chunk's bounds and the root's offset.
#[lift_attach(crate::merkle::mmr::Family::chunk_peaks)]
fn chunk_peaks_facts() {
    at_start! {
        crate::proof::chunk_facts(chunk_idx, grafting_height);
        crate::proof::chunk_valid(chunk_idx, grafting_height);
        crate::proof::chunk_end_le(crate::merkle::position::Position::try_from__Location(crate::merkle::location::Location::new((chunk_idx + 1u64) << grafting_height)), size);
        crate::proof::mmr_size_cong(((chunk_idx + 1u64) << grafting_height) as Int, ((chunk_idx as Int) + 1) * pow2(grafting_height as Int));
        crate::proof::mmr_size_le((chunk_idx << grafting_height) as Int);
    }
}

/// From the summary (the call in a proof step brings it in).
#[proof]
fn location_to_position_counts_nodes(loc: Location) {
    let r = Family::location_to_position(loc);
    follows();
}

/// From the summaries; a location above `2^62` has at least `2^63` nodes
/// before it.
#[proof]
fn position_to_location_is_sound(pos: Position, loc: Location) {
    let o = Family::position_to_location(pos);
    assert(mmr_size(loc.0 as Int) == pos.0 as Int, { by_unfolding(sound_loc); });
    if (loc.0 as Int) > pow2(62) {
        mmr_size_mono(pow2(62), loc.0 as Int);
        by_contradiction();
    } else {
        let r = Family::location_to_position(loc);
        follows();
    }
}

/// `children`: `1 << height` is `2^height`.
#[lift_attach(crate::merkle::mmr::Family::children)]
fn children_facts() {
    at_start! {
        crate::proof::shl_one(height);
    }
}
