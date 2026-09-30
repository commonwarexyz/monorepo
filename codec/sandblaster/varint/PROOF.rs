//! Proofs of LAWS.rs and of the safety of `varint.rs` as written. Machine
//! artifacts: attachments (`#[lift_attach]`) give the lifted code its loop
//! measures, invariants and function summaries without touching the file.

use sandblaster::prelude::*;
use crate::varint::{Decoder, SInt, SPrim, UInt, UPrim};
use crate::Error;

// ---------------------------------------------------------------------------
// Byte facts (by the 256 cases)
// ---------------------------------------------------------------------------

/// The continuation bit is clear exactly below 128.
#[lemma]
fn top_bit_lt(b: u8) {
    ensures((b & 0x80u8 == 0u8) == (b < 128u8));
    by_cases(b, 0..=255);
}

/// Below 128 the continuation bit is clear.
#[lemma]
fn top_bit_clear(b: u8) {
    requires(b < 128u8);
    ensures(b & 0x80u8 == 0u8);
    by_cases(b, 0..=255);
}

/// From 128 on the continuation bit is set.
#[lemma]
fn top_bit_set(b: u8) {
    requires(b >= 128u8);
    ensures(b & 0x80u8 != 0u8);
    by_cases(b, 0..=255);
}

/// A clear continuation bit: below 128.
#[lemma]
fn top_bit_clear_rev(b: u8) {
    requires(b & 0x80u8 == 0u8);
    ensures(b < 128u8);
    if b >= 128u8 {
        top_bit_set(b);
        by_contradiction();
    } else {
        follows();
    }
}

/// A set continuation bit: 128 or more.
#[lemma]
fn top_bit_set_rev(b: u8) {
    requires(b & 0x80u8 != 0u8);
    ensures(b >= 128u8);
    if b < 128u8 {
        top_bit_clear(b);
        by_contradiction();
    } else {
        follows();
    }
}

/// A byte with its top bit set has no leading zeros.
#[lemma]
fn top_bit(b: u8) {
    ensures((b & 0x80u8 == 0u8 || b.leading_zeros() == 0u32) == true);
    by_cases(b, 0..=255);
}



// ---------------------------------------------------------------------------
// Powers of two
// ---------------------------------------------------------------------------

/// 2^(e+7) = 128 · 2^e.
#[lemma]
fn pow2_plus7(e: Int) {
    requires(e >= 0);
    ensures(pow2(e + 7) == 128 * pow2(e));
    assert(pow2(e + 1) == 2 * pow2(e));
    assert(pow2(e + 2) == 2 * pow2(e + 1));
    assert(pow2(e + 3) == 2 * pow2(e + 2));
    assert(pow2(e + 4) == 2 * pow2(e + 3));
    assert(pow2(e + 5) == 2 * pow2(e + 4));
    assert(pow2(e + 6) == 2 * pow2(e + 5));
    assert(pow2(e + 7) == 2 * pow2(e + 6));
    by_arithmetic();
}

/// A value of at least 128 below 2^e has more than seven bits of room, and a
/// seventh of its bits fewer after dropping seven: below 2^(e−7).
#[lemma]
fn shift7(v: Int, e: Int) {
    requires(128 <= v && v < pow2(e));
    ensures(e >= 8 && v / 128 < pow2(e - 7));
    if e <= 7 {
        if e >= 0 {
            // 2^0 .. 2^7 are all at most 128
            assert(pow2(e) <= 128, { by_cases(e, 0..8); });
            by_contradiction();
        } else {
            assert(pow2(e) == 1);
            by_contradiction();
        }
    } else {
        pow2_plus7(e - 7);
        follows();
    }
}

// ---------------------------------------------------------------------------
// LEB128
// ---------------------------------------------------------------------------

/// One LEB128 step: a value of at least 128 is its low seven bits with 0x80,
/// then the rest.
#[lemma]
fn varint_step(x: Nat) {
    requires(x >= 128);
    ensures(crate::laws::varint(x) == seq![(128 + x % 128) as u8, ..crate::laws::varint(x / 128)]);
    by_unfolding(crate::laws::varint);
}

/// A value below 128 is one byte.
#[lemma]
fn varint_small(x: Nat) {
    requires(x < 128);
    ensures(crate::laws::varint(x) == seq![x as u8]);
    by_unfolding(crate::laws::varint);
}

/// A byte with its top bit set: its low seven bits plus 128.
#[lemma]
fn or_top(b: u8) {
    ensures((b | 0x80u8) == ((128 + (b as Nat) % 128) as u8));
    by_cases(b, 0..=255);
}

/// The byte `write` stages for a value: its low seven bits with 0x80.
#[lemma]
fn stage_byte<T: UPrim>(v: T) {
    ensures((v.as_u8() | 0x80u8) == ((128 + (v as Nat) % 128) as u8));
    or_top(v.as_u8());
    assert((v.as_u8() as Int) == (v as Int) % 256);
    let r = (v as Int) % 256;
    assert((v as Int) == 256 * ((v as Int) / 256) + r);
    assert(r == 128 * (r / 128) + r % 128);
    assert((v as Int) == 128 * (2 * ((v as Int) / 256) + r / 128) + r % 128);
    assert((v as Int) % 128 == r % 128);
    follows();
}

/// Updating element `i` extends the first `i` elements by the new one.
#[lemma]
fn take_update(l: Seq<u8>, i: Nat, v: u8) {
    requires(i < l.len());
    ensures(l.update(i, v).take(i + 1) == seq![..l.take(i), v]);
    match l {
        [] => by_contradiction(),
        [h, t @ ..] => {
            if i == 0 {
                rewrite(i == 0);
                follows();
            } else {
                calc! {
                    seq![h, ..t].update(i, v).take(i + 1)
                        == seq![h, ..t.update(i - 1, v)].take(i + 1) by { follows(); };
                        == seq![h, ..t.update(i - 1, v).take(i)] by { follows(); };
                        == seq![h, ..seq![..t.take(i - 1), v]] by { take_update(t, i - 1, v); follows(); };
                        == seq![..seq![h, ..t].take(i), v] by { follows(); };
                }
            }
        }
    }
}

/// The first `n` bytes of `write`'s staging buffer. Opaque: the buffer is a
/// 19-byte array, which evaluation expands element by element, so proofs use
/// the two lemmas below instead of its body.
#[spec]
#[opaque]
#[example(staged([1u8; 19], 2) == seq![1u8, 1u8])]
pub fn staged(a: [u8; 19], n: Nat) -> Seq<u8> {
    seq![..a].take(n)
}

/// Staging a byte at position `i` extends the staged prefix by it.
#[lemma]
fn staged_set(a: [u8; 19], i: usize, v: u8) {
    requires(i < 19usize);
    ensures(staged({ let mut b = a; b[i] = v; b }, i as Nat + 1) == seq![..staged(a, i as Nat), v]);
    take_update(seq![..a], i as Nat, v);
    by_unfolding(staged);
}


/// One staging step keeps "staged bytes, then the encoding of what is left,
/// is the encoding of the value".
#[lemma]
fn stage_step(prefix: Seq<u8>, s: u8, v: Nat, value: Nat, next: Seq<u8>) {
    requires(v >= 128 && seq![..prefix, ..crate::laws::varint(v)] == crate::laws::varint(value));
    requires(s == ((128 + v % 128) as u8) && next == seq![..prefix, s]);
    ensures(seq![..next, ..crate::laws::varint(v / 128)] == crate::laws::varint(value));
    varint_step(v);
    follows();
}

/// Putting the first `n` staged bytes appends the staged prefix.
#[lemma]
fn put_staged(buf: Seq<u8>, a: [u8; 19], n: usize) {
    requires(n <= 19usize);
    ensures(crate::__lift_model::bufmut_put_slice(buf, &a[..n]) == seq![..buf, ..staged(a, n as Nat)]);
    by_unfolding(staged, crate::__lift_model::bufmut_put_slice);
}

/// A byte is the byte of its value.
#[lemma]
fn byte_of_value<T: UPrim>(v: T) {
    requires((v as Nat) < 128);
    ensures(v.as_u8() == ((v as Nat) as u8));
    assert((v.as_u8() as Int) == (v as Int));
    follows();
}

/// `write`'s fast path: a value below 128 is its own byte.
#[lemma]
fn fast_path<T: UPrim>(v: T, buf: Seq<u8>) {
    ensures((v as Nat) >= 128 || crate::__lift_model::bufmut_put_u8(buf, v.as_u8()) == seq![..buf, ..crate::laws::varint(v as Nat)]);
    if (v as Nat) >= 128 {
        follows();
    } else {
        varint_small(v as Nat);
        byte_of_value::<T>(v);
        by_unfolding(crate::__lift_model::bufmut_put_u8);
    }
}

/// Nothing is staged at first.
#[lemma]
fn staged_none(a: [u8; 19]) {
    ensures(staged(a, 0) == seq![]);
    unfold(staged);
    follows();
}

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

/// LEB128 takes ⌈e/7⌉ bytes for a value of exactly  bits, and one byte for zero.
#[lemma]
#[decreases(x)]
fn varint_len(x: Nat, e: Nat) {
    requires((x == 0 && e == 0) || (x > 0 && pow2((e as Int) - 1) <= (x as Int) && (x as Int) < pow2(e as Int)));
    ensures(crate::laws::varint(x).len() == if e == 0 { 1 } else { (e + 6) / 7 });
    if x < 128 {
        varint_small(x);
        if x == 0 {
            follows();
        } else {
            // 2^(e-1) <= x < 128: e is 1..7
            assert(e <= 7, {
                if e >= 8 {
                    pow2_plus7((e as Int) - 8);
                    by_contradiction();
                } else {
                    follows();
                }
            });
            follows();
        }
    } else {
        varint_step(x);
        // 128 <= x < 2^e: e >= 8, and x / 128 has e - 7 bits
        shift7(x as Int, e as Int);
        pow2_plus7((e as Int) - 8);
        varint_len(x / 128, e - 7);
        follows();
    }
}

/// `div_ceil` by seven, as division.
#[lemma]
fn div_ceil7(a: usize, d: usize) {
    requires(d == 7usize);
    ensures((a.div_ceil(d) as Int) == ((a as Int) + 6) / 7);
    follows();
}

/// `size`'s last line: at least one byte, else ⌈e/7⌉.
#[lemma]
fn size_arith(e: usize, d: usize, n: Nat) {
    requires(d == 7usize && n == if e == 0usize { 1 } else { (e as Nat + 6) / 7 });
    ensures(((1usize).max(e.div_ceil(d)) as Nat) == n);
    div_ceil7(e, d);
    if e == 0usize {
        follows();
    } else {
        assert(n == (e as Nat + 6) / 7);
        assert((e.div_ceil(d) as Int) >= 1);
        assert((1usize).max(e.div_ceil(d)) == e.div_ceil(d));
        follows();
    }
}

/// Equal exponents, equal powers.
#[lemma]
fn pow2_eq(a: Int, b: Int) {
    requires(a == b);
    ensures(pow2(a) == pow2(b));
    rewrite(a == b);
    follows();
}

/// The bits a value needs: its width minus its leading zeros. Zero needs
/// none. (Proven per width from the checked bit lemmas below.)
#[lemma]
fn lz_bits<T: UPrim>(x: T) {
    ensures((((x as Nat) == 0 && (x.leading_zeros() as Int) == 8 * (T::SIZE as Int))
        || (pow2(8 * (T::SIZE as Int) - 1 - (x.leading_zeros() as Int)) <= (x as Int) && (x as Int) < pow2(8 * (T::SIZE as Int) - (x.leading_zeros() as Int)))) == true);
}

#[lemma]
fn lz_bits__u16(x: u16) {
    ensures((((x as Nat) == 0 && (x.leading_zeros() as Int) == 16)
        || (pow2(16 - 1 - (x.leading_zeros() as Int)) <= (x as Int) && (x as Int) < pow2(16 - (x.leading_zeros() as Int)))) == true);
    if x.leading_zeros() <= 0u32 { assert((x.leading_zeros() as Int) == 0); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 16); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 15); if (x as Int) < pow2(15) { sandblaster::lemmas::bits::lz_lower_u16_15(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 1u32 { sandblaster::lemmas::bits::lz_ge_u16_15(x); assert((x.leading_zeros() as Int) == 1); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 15); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 14); if (x as Int) < pow2(14) { sandblaster::lemmas::bits::lz_lower_u16_14(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 2u32 { sandblaster::lemmas::bits::lz_ge_u16_14(x); assert((x.leading_zeros() as Int) == 2); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 14); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 13); if (x as Int) < pow2(13) { sandblaster::lemmas::bits::lz_lower_u16_13(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 3u32 { sandblaster::lemmas::bits::lz_ge_u16_13(x); assert((x.leading_zeros() as Int) == 3); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 13); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 12); if (x as Int) < pow2(12) { sandblaster::lemmas::bits::lz_lower_u16_12(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 4u32 { sandblaster::lemmas::bits::lz_ge_u16_12(x); assert((x.leading_zeros() as Int) == 4); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 12); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 11); if (x as Int) < pow2(11) { sandblaster::lemmas::bits::lz_lower_u16_11(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 5u32 { sandblaster::lemmas::bits::lz_ge_u16_11(x); assert((x.leading_zeros() as Int) == 5); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 11); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 10); if (x as Int) < pow2(10) { sandblaster::lemmas::bits::lz_lower_u16_10(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 6u32 { sandblaster::lemmas::bits::lz_ge_u16_10(x); assert((x.leading_zeros() as Int) == 6); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 10); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 9); if (x as Int) < pow2(9) { sandblaster::lemmas::bits::lz_lower_u16_9(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 7u32 { sandblaster::lemmas::bits::lz_ge_u16_9(x); assert((x.leading_zeros() as Int) == 7); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 9); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 8); if (x as Int) < pow2(8) { sandblaster::lemmas::bits::lz_lower_u16_8(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 8u32 { sandblaster::lemmas::bits::lz_ge_u16_8(x); assert((x.leading_zeros() as Int) == 8); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 8); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 7); if (x as Int) < pow2(7) { sandblaster::lemmas::bits::lz_lower_u16_7(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 9u32 { sandblaster::lemmas::bits::lz_ge_u16_7(x); assert((x.leading_zeros() as Int) == 9); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 7); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 6); if (x as Int) < pow2(6) { sandblaster::lemmas::bits::lz_lower_u16_6(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 10u32 { sandblaster::lemmas::bits::lz_ge_u16_6(x); assert((x.leading_zeros() as Int) == 10); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 6); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 5); if (x as Int) < pow2(5) { sandblaster::lemmas::bits::lz_lower_u16_5(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 11u32 { sandblaster::lemmas::bits::lz_ge_u16_5(x); assert((x.leading_zeros() as Int) == 11); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 5); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 4); if (x as Int) < pow2(4) { sandblaster::lemmas::bits::lz_lower_u16_4(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 12u32 { sandblaster::lemmas::bits::lz_ge_u16_4(x); assert((x.leading_zeros() as Int) == 12); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 4); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 3); if (x as Int) < pow2(3) { sandblaster::lemmas::bits::lz_lower_u16_3(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 13u32 { sandblaster::lemmas::bits::lz_ge_u16_3(x); assert((x.leading_zeros() as Int) == 13); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 3); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 2); if (x as Int) < pow2(2) { sandblaster::lemmas::bits::lz_lower_u16_2(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 14u32 { sandblaster::lemmas::bits::lz_ge_u16_2(x); assert((x.leading_zeros() as Int) == 14); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 2); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 1); if (x as Int) < pow2(1) { sandblaster::lemmas::bits::lz_lower_u16_1(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 15u32 { sandblaster::lemmas::bits::lz_ge_u16_1(x); assert((x.leading_zeros() as Int) == 15); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 1); crate::proof::pow2_eq(16 - 1 - (x.leading_zeros() as Int), 0); if (x as Int) < pow2(0) { sandblaster::lemmas::bits::lz_lower_u16_0(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 16u32 { sandblaster::lemmas::bits::lz_ge_u16_0(x); assert((x.leading_zeros() as Int) == 16); crate::proof::pow2_eq(16 - (x.leading_zeros() as Int), 0); follows();
    } else { by_contradiction(); }
}

#[lemma]
fn lz_bits__u32(x: u32) {
    ensures((((x as Nat) == 0 && (x.leading_zeros() as Int) == 32)
        || (pow2(32 - 1 - (x.leading_zeros() as Int)) <= (x as Int) && (x as Int) < pow2(32 - (x.leading_zeros() as Int)))) == true);
    if x.leading_zeros() <= 0u32 { assert((x.leading_zeros() as Int) == 0); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 32); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 31); if (x as Int) < pow2(31) { sandblaster::lemmas::bits::lz_lower_u32_31(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 1u32 { sandblaster::lemmas::bits::lz_ge_u32_31(x); assert((x.leading_zeros() as Int) == 1); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 31); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 30); if (x as Int) < pow2(30) { sandblaster::lemmas::bits::lz_lower_u32_30(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 2u32 { sandblaster::lemmas::bits::lz_ge_u32_30(x); assert((x.leading_zeros() as Int) == 2); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 30); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 29); if (x as Int) < pow2(29) { sandblaster::lemmas::bits::lz_lower_u32_29(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 3u32 { sandblaster::lemmas::bits::lz_ge_u32_29(x); assert((x.leading_zeros() as Int) == 3); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 29); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 28); if (x as Int) < pow2(28) { sandblaster::lemmas::bits::lz_lower_u32_28(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 4u32 { sandblaster::lemmas::bits::lz_ge_u32_28(x); assert((x.leading_zeros() as Int) == 4); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 28); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 27); if (x as Int) < pow2(27) { sandblaster::lemmas::bits::lz_lower_u32_27(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 5u32 { sandblaster::lemmas::bits::lz_ge_u32_27(x); assert((x.leading_zeros() as Int) == 5); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 27); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 26); if (x as Int) < pow2(26) { sandblaster::lemmas::bits::lz_lower_u32_26(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 6u32 { sandblaster::lemmas::bits::lz_ge_u32_26(x); assert((x.leading_zeros() as Int) == 6); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 26); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 25); if (x as Int) < pow2(25) { sandblaster::lemmas::bits::lz_lower_u32_25(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 7u32 { sandblaster::lemmas::bits::lz_ge_u32_25(x); assert((x.leading_zeros() as Int) == 7); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 25); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 24); if (x as Int) < pow2(24) { sandblaster::lemmas::bits::lz_lower_u32_24(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 8u32 { sandblaster::lemmas::bits::lz_ge_u32_24(x); assert((x.leading_zeros() as Int) == 8); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 24); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 23); if (x as Int) < pow2(23) { sandblaster::lemmas::bits::lz_lower_u32_23(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 9u32 { sandblaster::lemmas::bits::lz_ge_u32_23(x); assert((x.leading_zeros() as Int) == 9); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 23); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 22); if (x as Int) < pow2(22) { sandblaster::lemmas::bits::lz_lower_u32_22(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 10u32 { sandblaster::lemmas::bits::lz_ge_u32_22(x); assert((x.leading_zeros() as Int) == 10); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 22); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 21); if (x as Int) < pow2(21) { sandblaster::lemmas::bits::lz_lower_u32_21(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 11u32 { sandblaster::lemmas::bits::lz_ge_u32_21(x); assert((x.leading_zeros() as Int) == 11); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 21); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 20); if (x as Int) < pow2(20) { sandblaster::lemmas::bits::lz_lower_u32_20(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 12u32 { sandblaster::lemmas::bits::lz_ge_u32_20(x); assert((x.leading_zeros() as Int) == 12); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 20); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 19); if (x as Int) < pow2(19) { sandblaster::lemmas::bits::lz_lower_u32_19(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 13u32 { sandblaster::lemmas::bits::lz_ge_u32_19(x); assert((x.leading_zeros() as Int) == 13); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 19); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 18); if (x as Int) < pow2(18) { sandblaster::lemmas::bits::lz_lower_u32_18(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 14u32 { sandblaster::lemmas::bits::lz_ge_u32_18(x); assert((x.leading_zeros() as Int) == 14); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 18); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 17); if (x as Int) < pow2(17) { sandblaster::lemmas::bits::lz_lower_u32_17(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 15u32 { sandblaster::lemmas::bits::lz_ge_u32_17(x); assert((x.leading_zeros() as Int) == 15); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 17); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 16); if (x as Int) < pow2(16) { sandblaster::lemmas::bits::lz_lower_u32_16(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 16u32 { sandblaster::lemmas::bits::lz_ge_u32_16(x); assert((x.leading_zeros() as Int) == 16); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 16); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 15); if (x as Int) < pow2(15) { sandblaster::lemmas::bits::lz_lower_u32_15(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 17u32 { sandblaster::lemmas::bits::lz_ge_u32_15(x); assert((x.leading_zeros() as Int) == 17); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 15); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 14); if (x as Int) < pow2(14) { sandblaster::lemmas::bits::lz_lower_u32_14(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 18u32 { sandblaster::lemmas::bits::lz_ge_u32_14(x); assert((x.leading_zeros() as Int) == 18); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 14); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 13); if (x as Int) < pow2(13) { sandblaster::lemmas::bits::lz_lower_u32_13(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 19u32 { sandblaster::lemmas::bits::lz_ge_u32_13(x); assert((x.leading_zeros() as Int) == 19); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 13); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 12); if (x as Int) < pow2(12) { sandblaster::lemmas::bits::lz_lower_u32_12(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 20u32 { sandblaster::lemmas::bits::lz_ge_u32_12(x); assert((x.leading_zeros() as Int) == 20); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 12); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 11); if (x as Int) < pow2(11) { sandblaster::lemmas::bits::lz_lower_u32_11(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 21u32 { sandblaster::lemmas::bits::lz_ge_u32_11(x); assert((x.leading_zeros() as Int) == 21); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 11); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 10); if (x as Int) < pow2(10) { sandblaster::lemmas::bits::lz_lower_u32_10(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 22u32 { sandblaster::lemmas::bits::lz_ge_u32_10(x); assert((x.leading_zeros() as Int) == 22); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 10); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 9); if (x as Int) < pow2(9) { sandblaster::lemmas::bits::lz_lower_u32_9(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 23u32 { sandblaster::lemmas::bits::lz_ge_u32_9(x); assert((x.leading_zeros() as Int) == 23); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 9); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 8); if (x as Int) < pow2(8) { sandblaster::lemmas::bits::lz_lower_u32_8(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 24u32 { sandblaster::lemmas::bits::lz_ge_u32_8(x); assert((x.leading_zeros() as Int) == 24); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 8); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 7); if (x as Int) < pow2(7) { sandblaster::lemmas::bits::lz_lower_u32_7(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 25u32 { sandblaster::lemmas::bits::lz_ge_u32_7(x); assert((x.leading_zeros() as Int) == 25); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 7); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 6); if (x as Int) < pow2(6) { sandblaster::lemmas::bits::lz_lower_u32_6(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 26u32 { sandblaster::lemmas::bits::lz_ge_u32_6(x); assert((x.leading_zeros() as Int) == 26); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 6); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 5); if (x as Int) < pow2(5) { sandblaster::lemmas::bits::lz_lower_u32_5(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 27u32 { sandblaster::lemmas::bits::lz_ge_u32_5(x); assert((x.leading_zeros() as Int) == 27); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 5); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 4); if (x as Int) < pow2(4) { sandblaster::lemmas::bits::lz_lower_u32_4(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 28u32 { sandblaster::lemmas::bits::lz_ge_u32_4(x); assert((x.leading_zeros() as Int) == 28); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 4); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 3); if (x as Int) < pow2(3) { sandblaster::lemmas::bits::lz_lower_u32_3(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 29u32 { sandblaster::lemmas::bits::lz_ge_u32_3(x); assert((x.leading_zeros() as Int) == 29); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 3); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 2); if (x as Int) < pow2(2) { sandblaster::lemmas::bits::lz_lower_u32_2(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 30u32 { sandblaster::lemmas::bits::lz_ge_u32_2(x); assert((x.leading_zeros() as Int) == 30); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 2); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 1); if (x as Int) < pow2(1) { sandblaster::lemmas::bits::lz_lower_u32_1(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 31u32 { sandblaster::lemmas::bits::lz_ge_u32_1(x); assert((x.leading_zeros() as Int) == 31); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 1); crate::proof::pow2_eq(32 - 1 - (x.leading_zeros() as Int), 0); if (x as Int) < pow2(0) { sandblaster::lemmas::bits::lz_lower_u32_0(x); by_contradiction(); } else { follows(); }
    } else if x.leading_zeros() <= 32u32 { sandblaster::lemmas::bits::lz_ge_u32_0(x); assert((x.leading_zeros() as Int) == 32); crate::proof::pow2_eq(32 - (x.leading_zeros() as Int), 0); follows();
    } else { by_contradiction(); }
}

#[lemma]
fn lz_bits__u64(x: u64) {
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


// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

/// A read result that is a success, `EndOfBuffer`, or `InvalidVarint(SIZE)`.
#[spec]
#[example(classified::<T>(Err(Error::EndOfBuffer)) && classified::<T>(Err(Error::InvalidVarint(T::SIZE))) && !classified::<T>(Err(Error::InvalidVarint(T::SIZE + 1))))]
#[example(classified::<T>(Ok(T::from(0u8))))]
pub fn classified<T: UPrim>(r: Result<T, Error>) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => e == Error::EndOfBuffer || e == Error::InvalidVarint(T::SIZE),
    }
}

/// The same for what `UInt::read_cfg` returns.
#[spec]
#[example(read_classified::<T>(Err(Error::EndOfBuffer)) && read_classified::<T>(Err(Error::InvalidVarint(T::SIZE))) && !read_classified::<T>(Err(Error::InvalidVarint(T::SIZE + 1))))]
#[example(read_classified::<T>(Ok(UInt(T::from(0u8)))))]
pub fn read_classified<T: UPrim>(r: Result<UInt<T>, Error>) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => e == Error::EndOfBuffer || e == Error::InvalidVarint(T::SIZE),
    }
}

/// A classified failure is `EndOfBuffer` or `InvalidVarint(SIZE)`.
#[lemma]
fn classified_err<T: UPrim>(r: Result<UInt<T>, Error>, e: Error) {
    requires(r == Err(e) && read_classified::<T>(r));
    ensures(e == Error::EndOfBuffer || e == Error::InvalidVarint(T::SIZE));
    unfold(read_classified::<T>);
    follows();
}

/// The same for what `feed` returns.
#[spec]
#[example(feed_classified::<T>(Ok(None)) && feed_classified::<T>(Err(Error::InvalidVarint(T::SIZE))) && !feed_classified::<T>(Err(Error::InvalidVarint(T::SIZE + 1))))]
#[example(feed_classified::<T>(Err(Error::EndOfBuffer)) && feed_classified::<T>(Ok(Some(T::from(0u8)))))]
pub fn feed_classified<T: UPrim>(r: Result<Option<T>, Error>) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => e == Error::EndOfBuffer || e == Error::InvalidVarint(T::SIZE),
    }
}
// ---------------------------------------------------------------------------
// The decoder
// ---------------------------------------------------------------------------

/// The decoder's accumulate step: when the low `s` bits hold `acc`, or-ing
/// the group `g` in at bit `s` adds `g * 2^s`. (Per width below.)
#[lemma]
fn or_shift<T: UPrim>(acc: T, g: u8, s: usize) {
    requires(s % 7usize == 0usize && s < 8 * T::SIZE && (acc as Int) < pow2(s as Int) && g < 128u8);
    requires((g as Int) < pow2(8 * (T::SIZE as Int) - (s as Int)));
    ensures(((acc | ((g as T) << s)) as Int) == (acc as Int) + (g as Int) * pow2(s as Int));
}

#[lemma]
fn or_shift__u16(acc: u16, g: u8, s: usize) {
    requires(s % 7usize == 0usize && s < 16usize && (acc as Int) < pow2(s as Int) && g < 128u8);
    requires((g as Int) < pow2(16 - (s as Int)));
    ensures(((acc | ((g as u16) << s)) as Int) == (acc as Int) + (g as Int) * pow2(s as Int));
    if s <= 0usize { assert(s == 0usize); pow2_eq(s as Int, 0); pow2_eq(16 - (s as Int), 16); assert(((g as u16) << s) == (g as u16).wrapping_shl(s as u32)); assert((g as u16).wrapping_shl(s as u32) == (g as u16).wrapping_shl(0u32)); assert((g as u16).wrapping_shl(0u32) == ((g as u16) << 0u32)); follows();
    } else if s <= 7usize { assert(s == 7usize); pow2_eq(s as Int, 7); pow2_eq(16 - (s as Int), 9); assert(((g as u16) << s) == (g as u16).wrapping_shl(s as u32)); assert((g as u16).wrapping_shl(s as u32) == (g as u16).wrapping_shl(7u32)); assert((g as u16).wrapping_shl(7u32) == ((g as u16) << 7u32)); assert(acc & 127u16 == acc); assert((g as Int) <= 511); sandblaster::lemmas::bits::shl_exact_u16_7(g as u16); assert(((acc & 127u16) | ((g as u16) << 7u32)) == (acc & 127u16).wrapping_add((g as u16) << 7u32), { bv(); }); calc! {     ((acc | ((g as u16) << 7u32)) as Int)         == (((acc & 127u16) | ((g as u16) << 7u32)) as Int) by { follows(); };         == ((acc & 127u16).wrapping_add((g as u16) << 7u32) as Int) by { follows(); };         == (acc as Int) + (((g as u16) << 7u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 128 by { follows(); }; } follows();
    } else if s <= 14usize { assert(s == 14usize); pow2_eq(s as Int, 14); pow2_eq(16 - (s as Int), 2); assert(((g as u16) << s) == (g as u16).wrapping_shl(s as u32)); assert((g as u16).wrapping_shl(s as u32) == (g as u16).wrapping_shl(14u32)); assert((g as u16).wrapping_shl(14u32) == ((g as u16) << 14u32)); assert(acc & 16383u16 == acc); assert((g as Int) <= 3); sandblaster::lemmas::bits::shl_exact_u16_14(g as u16); assert(((acc & 16383u16) | ((g as u16) << 14u32)) == (acc & 16383u16).wrapping_add((g as u16) << 14u32), { bv(); }); calc! {     ((acc | ((g as u16) << 14u32)) as Int)         == (((acc & 16383u16) | ((g as u16) << 14u32)) as Int) by { follows(); };         == ((acc & 16383u16).wrapping_add((g as u16) << 14u32) as Int) by { follows(); };         == (acc as Int) + (((g as u16) << 14u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 16384 by { follows(); }; } follows();
    } else { by_contradiction(); }
}

#[lemma]
fn or_shift__u32(acc: u32, g: u8, s: usize) {
    requires(s % 7usize == 0usize && s < 32usize && (acc as Int) < pow2(s as Int) && g < 128u8);
    requires((g as Int) < pow2(32 - (s as Int)));
    ensures(((acc | ((g as u32) << s)) as Int) == (acc as Int) + (g as Int) * pow2(s as Int));
    if s <= 0usize { assert(s == 0usize); pow2_eq(s as Int, 0); pow2_eq(32 - (s as Int), 32); assert(((g as u32) << s) == (g as u32).wrapping_shl(s as u32)); assert((g as u32).wrapping_shl(s as u32) == (g as u32).wrapping_shl(0u32)); assert((g as u32).wrapping_shl(0u32) == ((g as u32) << 0u32)); follows();
    } else if s <= 7usize { assert(s == 7usize); pow2_eq(s as Int, 7); pow2_eq(32 - (s as Int), 25); assert(((g as u32) << s) == (g as u32).wrapping_shl(s as u32)); assert((g as u32).wrapping_shl(s as u32) == (g as u32).wrapping_shl(7u32)); assert((g as u32).wrapping_shl(7u32) == ((g as u32) << 7u32)); assert(acc & 127u32 == acc); assert((g as Int) <= 33554431); sandblaster::lemmas::bits::shl_exact_u32_7(g as u32); assert(((acc & 127u32) | ((g as u32) << 7u32)) == (acc & 127u32).wrapping_add((g as u32) << 7u32), { bv(); }); calc! {     ((acc | ((g as u32) << 7u32)) as Int)         == (((acc & 127u32) | ((g as u32) << 7u32)) as Int) by { follows(); };         == ((acc & 127u32).wrapping_add((g as u32) << 7u32) as Int) by { follows(); };         == (acc as Int) + (((g as u32) << 7u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 128 by { follows(); }; } follows();
    } else if s <= 14usize { assert(s == 14usize); pow2_eq(s as Int, 14); pow2_eq(32 - (s as Int), 18); assert(((g as u32) << s) == (g as u32).wrapping_shl(s as u32)); assert((g as u32).wrapping_shl(s as u32) == (g as u32).wrapping_shl(14u32)); assert((g as u32).wrapping_shl(14u32) == ((g as u32) << 14u32)); assert(acc & 16383u32 == acc); assert((g as Int) <= 262143); sandblaster::lemmas::bits::shl_exact_u32_14(g as u32); assert(((acc & 16383u32) | ((g as u32) << 14u32)) == (acc & 16383u32).wrapping_add((g as u32) << 14u32), { bv(); }); calc! {     ((acc | ((g as u32) << 14u32)) as Int)         == (((acc & 16383u32) | ((g as u32) << 14u32)) as Int) by { follows(); };         == ((acc & 16383u32).wrapping_add((g as u32) << 14u32) as Int) by { follows(); };         == (acc as Int) + (((g as u32) << 14u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 16384 by { follows(); }; } follows();
    } else if s <= 21usize { assert(s == 21usize); pow2_eq(s as Int, 21); pow2_eq(32 - (s as Int), 11); assert(((g as u32) << s) == (g as u32).wrapping_shl(s as u32)); assert((g as u32).wrapping_shl(s as u32) == (g as u32).wrapping_shl(21u32)); assert((g as u32).wrapping_shl(21u32) == ((g as u32) << 21u32)); assert(acc & 2097151u32 == acc); assert((g as Int) <= 2047); sandblaster::lemmas::bits::shl_exact_u32_21(g as u32); assert(((acc & 2097151u32) | ((g as u32) << 21u32)) == (acc & 2097151u32).wrapping_add((g as u32) << 21u32), { bv(); }); calc! {     ((acc | ((g as u32) << 21u32)) as Int)         == (((acc & 2097151u32) | ((g as u32) << 21u32)) as Int) by { follows(); };         == ((acc & 2097151u32).wrapping_add((g as u32) << 21u32) as Int) by { follows(); };         == (acc as Int) + (((g as u32) << 21u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 2097152 by { follows(); }; } follows();
    } else if s <= 28usize { assert(s == 28usize); pow2_eq(s as Int, 28); pow2_eq(32 - (s as Int), 4); assert(((g as u32) << s) == (g as u32).wrapping_shl(s as u32)); assert((g as u32).wrapping_shl(s as u32) == (g as u32).wrapping_shl(28u32)); assert((g as u32).wrapping_shl(28u32) == ((g as u32) << 28u32)); assert(acc & 268435455u32 == acc); assert((g as Int) <= 15); sandblaster::lemmas::bits::shl_exact_u32_28(g as u32); assert(((acc & 268435455u32) | ((g as u32) << 28u32)) == (acc & 268435455u32).wrapping_add((g as u32) << 28u32), { bv(); }); calc! {     ((acc | ((g as u32) << 28u32)) as Int)         == (((acc & 268435455u32) | ((g as u32) << 28u32)) as Int) by { follows(); };         == ((acc & 268435455u32).wrapping_add((g as u32) << 28u32) as Int) by { follows(); };         == (acc as Int) + (((g as u32) << 28u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 268435456 by { follows(); }; } follows();
    } else { by_contradiction(); }
}

#[lemma]
fn or_shift__u64(acc: u64, g: u8, s: usize) {
    requires(s % 7usize == 0usize && s < 64usize && (acc as Int) < pow2(s as Int) && g < 128u8);
    requires((g as Int) < pow2(64 - (s as Int)));
    ensures(((acc | ((g as u64) << s)) as Int) == (acc as Int) + (g as Int) * pow2(s as Int));
    if s <= 0usize { assert(s == 0usize); pow2_eq(s as Int, 0); pow2_eq(64 - (s as Int), 64); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(0u32)); assert((g as u64).wrapping_shl(0u32) == ((g as u64) << 0u32)); follows();
    } else if s <= 7usize { assert(s == 7usize); pow2_eq(s as Int, 7); pow2_eq(64 - (s as Int), 57); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(7u32)); assert((g as u64).wrapping_shl(7u32) == ((g as u64) << 7u32)); assert(acc & 127u64 == acc); assert((g as Int) <= 144115188075855871); sandblaster::lemmas::bits::shl_exact_u64_7(g as u64); assert(((acc & 127u64) | ((g as u64) << 7u32)) == (acc & 127u64).wrapping_add((g as u64) << 7u32), { bv(); }); calc! {     ((acc | ((g as u64) << 7u32)) as Int)         == (((acc & 127u64) | ((g as u64) << 7u32)) as Int) by { follows(); };         == ((acc & 127u64).wrapping_add((g as u64) << 7u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 7u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 128 by { follows(); }; } follows();
    } else if s <= 14usize { assert(s == 14usize); pow2_eq(s as Int, 14); pow2_eq(64 - (s as Int), 50); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(14u32)); assert((g as u64).wrapping_shl(14u32) == ((g as u64) << 14u32)); assert(acc & 16383u64 == acc); assert((g as Int) <= 1125899906842623); sandblaster::lemmas::bits::shl_exact_u64_14(g as u64); assert(((acc & 16383u64) | ((g as u64) << 14u32)) == (acc & 16383u64).wrapping_add((g as u64) << 14u32), { bv(); }); calc! {     ((acc | ((g as u64) << 14u32)) as Int)         == (((acc & 16383u64) | ((g as u64) << 14u32)) as Int) by { follows(); };         == ((acc & 16383u64).wrapping_add((g as u64) << 14u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 14u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 16384 by { follows(); }; } follows();
    } else if s <= 21usize { assert(s == 21usize); pow2_eq(s as Int, 21); pow2_eq(64 - (s as Int), 43); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(21u32)); assert((g as u64).wrapping_shl(21u32) == ((g as u64) << 21u32)); assert(acc & 2097151u64 == acc); assert((g as Int) <= 8796093022207); sandblaster::lemmas::bits::shl_exact_u64_21(g as u64); assert(((acc & 2097151u64) | ((g as u64) << 21u32)) == (acc & 2097151u64).wrapping_add((g as u64) << 21u32), { bv(); }); calc! {     ((acc | ((g as u64) << 21u32)) as Int)         == (((acc & 2097151u64) | ((g as u64) << 21u32)) as Int) by { follows(); };         == ((acc & 2097151u64).wrapping_add((g as u64) << 21u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 21u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 2097152 by { follows(); }; } follows();
    } else if s <= 28usize { assert(s == 28usize); pow2_eq(s as Int, 28); pow2_eq(64 - (s as Int), 36); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(28u32)); assert((g as u64).wrapping_shl(28u32) == ((g as u64) << 28u32)); assert(acc & 268435455u64 == acc); assert((g as Int) <= 68719476735); sandblaster::lemmas::bits::shl_exact_u64_28(g as u64); assert(((acc & 268435455u64) | ((g as u64) << 28u32)) == (acc & 268435455u64).wrapping_add((g as u64) << 28u32), { bv(); }); calc! {     ((acc | ((g as u64) << 28u32)) as Int)         == (((acc & 268435455u64) | ((g as u64) << 28u32)) as Int) by { follows(); };         == ((acc & 268435455u64).wrapping_add((g as u64) << 28u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 28u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 268435456 by { follows(); }; } follows();
    } else if s <= 35usize { assert(s == 35usize); pow2_eq(s as Int, 35); pow2_eq(64 - (s as Int), 29); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(35u32)); assert((g as u64).wrapping_shl(35u32) == ((g as u64) << 35u32)); assert(acc & 34359738367u64 == acc); assert((g as Int) <= 536870911); sandblaster::lemmas::bits::shl_exact_u64_35(g as u64); assert(((acc & 34359738367u64) | ((g as u64) << 35u32)) == (acc & 34359738367u64).wrapping_add((g as u64) << 35u32), { bv(); }); calc! {     ((acc | ((g as u64) << 35u32)) as Int)         == (((acc & 34359738367u64) | ((g as u64) << 35u32)) as Int) by { follows(); };         == ((acc & 34359738367u64).wrapping_add((g as u64) << 35u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 35u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 34359738368 by { follows(); }; } follows();
    } else if s <= 42usize { assert(s == 42usize); pow2_eq(s as Int, 42); pow2_eq(64 - (s as Int), 22); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(42u32)); assert((g as u64).wrapping_shl(42u32) == ((g as u64) << 42u32)); assert(acc & 4398046511103u64 == acc); assert((g as Int) <= 4194303); sandblaster::lemmas::bits::shl_exact_u64_42(g as u64); assert(((acc & 4398046511103u64) | ((g as u64) << 42u32)) == (acc & 4398046511103u64).wrapping_add((g as u64) << 42u32), { bv(); }); calc! {     ((acc | ((g as u64) << 42u32)) as Int)         == (((acc & 4398046511103u64) | ((g as u64) << 42u32)) as Int) by { follows(); };         == ((acc & 4398046511103u64).wrapping_add((g as u64) << 42u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 42u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 4398046511104 by { follows(); }; } follows();
    } else if s <= 49usize { assert(s == 49usize); pow2_eq(s as Int, 49); pow2_eq(64 - (s as Int), 15); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(49u32)); assert((g as u64).wrapping_shl(49u32) == ((g as u64) << 49u32)); assert(acc & 562949953421311u64 == acc); assert((g as Int) <= 32767); sandblaster::lemmas::bits::shl_exact_u64_49(g as u64); assert(((acc & 562949953421311u64) | ((g as u64) << 49u32)) == (acc & 562949953421311u64).wrapping_add((g as u64) << 49u32), { bv(); }); calc! {     ((acc | ((g as u64) << 49u32)) as Int)         == (((acc & 562949953421311u64) | ((g as u64) << 49u32)) as Int) by { follows(); };         == ((acc & 562949953421311u64).wrapping_add((g as u64) << 49u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 49u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 562949953421312 by { follows(); }; } follows();
    } else if s <= 56usize { assert(s == 56usize); pow2_eq(s as Int, 56); pow2_eq(64 - (s as Int), 8); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(56u32)); assert((g as u64).wrapping_shl(56u32) == ((g as u64) << 56u32)); assert(acc & 72057594037927935u64 == acc); assert((g as Int) <= 255); sandblaster::lemmas::bits::shl_exact_u64_56(g as u64); assert(((acc & 72057594037927935u64) | ((g as u64) << 56u32)) == (acc & 72057594037927935u64).wrapping_add((g as u64) << 56u32), { bv(); }); calc! {     ((acc | ((g as u64) << 56u32)) as Int)         == (((acc & 72057594037927935u64) | ((g as u64) << 56u32)) as Int) by { follows(); };         == ((acc & 72057594037927935u64).wrapping_add((g as u64) << 56u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 56u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 72057594037927936 by { follows(); }; } follows();
    } else if s <= 63usize { assert(s == 63usize); pow2_eq(s as Int, 63); pow2_eq(64 - (s as Int), 1); assert(((g as u64) << s) == (g as u64).wrapping_shl(s as u32)); assert((g as u64).wrapping_shl(s as u32) == (g as u64).wrapping_shl(63u32)); assert((g as u64).wrapping_shl(63u32) == ((g as u64) << 63u32)); assert(acc & 9223372036854775807u64 == acc); assert((g as Int) <= 1); sandblaster::lemmas::bits::shl_exact_u64_63(g as u64); assert(((acc & 9223372036854775807u64) | ((g as u64) << 63u32)) == (acc & 9223372036854775807u64).wrapping_add((g as u64) << 63u32), { bv(); }); calc! {     ((acc | ((g as u64) << 63u32)) as Int)         == (((acc & 9223372036854775807u64) | ((g as u64) << 63u32)) as Int) by { follows(); };         == ((acc & 9223372036854775807u64).wrapping_add((g as u64) << 63u32) as Int) by { follows(); };         == (acc as Int) + (((g as u64) << 63u32) as Int) by { follows(); };         == (acc as Int) + (g as Int) * 9223372036854775808 by { follows(); }; } follows();
    } else { by_contradiction(); }
}


/// `or_shift` in the form `feed` can use before its checks.
#[lemma]
fn or_shift_or<T: UPrim>(acc: T, g: u8, s: usize) {
    ensures(((acc as Int) >= pow2(s as Int) || s % 7usize != 0usize || s >= 8 * T::SIZE || g >= 128u8
        || (g as Int) >= pow2(8 * (T::SIZE as Int) - (s as Int))
        || ((acc | ((g as T) << s)) as Int) == (acc as Int) + (g as Int) * pow2(s as Int)) == true);
    if (acc as Int) >= pow2(s as Int) || s % 7usize != 0usize || s >= 8 * T::SIZE || g >= 128u8
        || (g as Int) >= pow2(8 * (T::SIZE as Int) - (s as Int)) {
        follows();
    } else {
        or_shift::<T>(acc, g, s);
        follows();
    }
}

/// `relevant_bits` for any number of remaining bits.
#[lemma]
fn relevant_bits_or(b: u8, r: usize) {
    ensures((r > 7usize || (8usize - (b.leading_zeros() as usize) > r) == ((b as Int) >= pow2(r as Int))) == true);
    if r > 7usize { follows(); } else { relevant_bits(b, r); follows(); }
}

/// 2^e is at least 128 from e = 7 on.
#[lemma]
fn pow2_ge128_or(e: Int) {
    ensures((e < 7 || pow2(e) >= 128) == true);
    if e < 7 { follows(); } else { pow2_plus7(e - 7); follows(); }
}

/// A byte's low seven bits: its remainder mod 128, at most the byte.
#[lemma]
fn low_bits(b: u8) {
    ensures(((b & 0x7Fu8) as Int) == (b as Int) % 128 && (b & 0x7Fu8) <= b && (b & 0x7Fu8) < 128u8);
    follows();
}

/// A decoder level's bound: below 2^s, plus a group below 128 at bit s, stays
/// below 2^(s+7). (Per width below: the powers are literals there.)
/// A value of the type, through `Int` and back, is itself.
#[lemma]
fn int_back<T: UPrim>(x: T) {
    ensures(((x as Int) as T) == x);
    follows();
}

/// What `read`'s decoder loop computes, in numbers: from a decoder whose low
/// `s` bits hold `acc`, the byte `b` is rejected (zero after the first, or
/// bits beyond the width), finishes the value (below 128), or adds its low
/// seven bits at bit `s` and the loop goes on with the next byte (none left:

/// A byte needs more than `r` bits exactly when it is at least 2^r.
#[lemma]
fn relevant_bits(b: u8, r: usize) {
    requires(r <= 7usize);
    ensures((8usize - (b.leading_zeros() as usize) > r) == ((b as Int) >= pow2(r as Int)));
    by_cases(b, 0..=255);
    by_cases(r, 0..8);
}

/// `m - x` fits when `x <= m`.

/// Scaling one group up: `(a + 128·y)·2^k = a·2^k + y·2^(k+7)` at every
/// decoder level `k` (a multiple of seven below 64; the powers are literals
/// case by case, so this is linear arithmetic).
#[lemma]
fn scale7(k: Int, a: Int, y: Int) {
    requires(k >= 0 && k % 7 == 0 && k < 64);
    ensures((a + 128 * y) * pow2(k) == a * pow2(k) + y * pow2(k + 7));
    if k <= 0 { assert(k == 0); pow2_eq(k as Int, 0); pow2_eq(k as Int + 7, 7); by_arithmetic();
    } else if k <= 7 { assert(k == 7); pow2_eq(k as Int, 7); pow2_eq(k as Int + 7, 14); by_arithmetic();
    } else if k <= 14 { assert(k == 14); pow2_eq(k as Int, 14); pow2_eq(k as Int + 7, 21); by_arithmetic();
    } else if k <= 21 { assert(k == 21); pow2_eq(k as Int, 21); pow2_eq(k as Int + 7, 28); by_arithmetic();
    } else if k <= 28 { assert(k == 28); pow2_eq(k as Int, 28); pow2_eq(k as Int + 7, 35); by_arithmetic();
    } else if k <= 35 { assert(k == 35); pow2_eq(k as Int, 35); pow2_eq(k as Int + 7, 42); by_arithmetic();
    } else if k <= 42 { assert(k == 42); pow2_eq(k as Int, 42); pow2_eq(k as Int + 7, 49); by_arithmetic();
    } else if k <= 49 { assert(k == 49); pow2_eq(k as Int, 49); pow2_eq(k as Int + 7, 56); by_arithmetic();
    } else if k <= 56 { assert(k == 56); pow2_eq(k as Int, 56); pow2_eq(k as Int + 7, 63); by_arithmetic();
    } else if k <= 63 { assert(k == 63); pow2_eq(k as Int, 63); pow2_eq(k as Int + 7, 70); by_arithmetic();
    } else { by_contradiction(); }
}

// ---------------------------------------------------------------------------
// The decoder in numbers
// ---------------------------------------------------------------------------

/// The decoder's rejection test for the byte `b` after `k` bits of an
/// `8·sz`-bit value: a zero byte after the first, or, when at most seven
/// bits are left, a byte that needs more bits than are left.
#[spec]
#[opaque]
#[example(rejects(2usize, 7, 0u8) && !rejects(2usize, 0, 0u8))]
#[example(rejects(2usize, 14, 4u8) && !rejects(2usize, 14, 3u8) && !rejects(2usize, 7, 255u8))]
#[example(rejects(2usize, 1, 0u8) && rejects(1usize, 1, 0x80u8) && rejects(1usize, 16, 1u8))]
#[example(rejects(1usize, 9, 0u8))]
pub fn rejects(sz: usize, k: Int, b: u8) -> bool {
    ((b == 0u8) & (k > 0)) | ((8 * (sz as Int) - k <= 7) & (8 - (b.leading_zeros() as Int) > 8 * (sz as Int) - k))
}

/// A continuation byte `b` in front of what the rest decodes to: its low
/// seven bits below the rest's number.
#[spec]
#[example(more(0xACu8, (seq![], Ok(2))) == (seq![], Ok(300)))]
#[example(more(0x80u8, (seq![1u8], Err(Error::EndOfBuffer))) == (seq![1u8], Err(Error::EndOfBuffer)))]
pub fn more(b: u8, r: (Seq<u8>, Result<Nat, Error>)) -> (Seq<u8>, Result<Nat, Error>) {
    match r {
        (s, Ok(y)) => (s, Ok((b as Nat) % 128 + 128 * y)),
        (s, Err(e)) => (s, Err(e)),
    }
}

/// What the decoder does from `k` bits read of an `8·sz`-bit value: the
/// number the rest of the encoding carries (it lands at bit `k`) and the
/// bytes after it, or the failure and the bytes after the deciding byte.
#[spec]
#[decreases(bs.len())]
#[example(sdec(2usize, 0, seq![0xACu8, 0x02u8, 7u8]) == (seq![7u8], Ok(300)))]
#[example(sdec(2usize, 0, seq![0x80u8]) == (seq![], Err(Error::EndOfBuffer)))]
#[example(sdec(2usize, 0, seq![0xFFu8, 0xFFu8, 0x04u8, 9u8]) == (seq![9u8], Err(Error::InvalidVarint(2usize))))]
#[example(sdec(1usize, 0, seq![1u8]) == (seq![], Ok(1)) && sdec(1usize, 0, seq![16u8]) == (seq![], Ok(16)))]
pub fn sdec(sz: usize, k: Int, bs: Seq<u8>) -> (Seq<u8>, Result<Nat, Error>) {
    match bs {
        [] => (seq![], Err(Error::EndOfBuffer)),
        [b, t @ ..] => {
            if rejects(sz, k, b) {
                (t, Err(Error::InvalidVarint(sz)))
            } else if b & 0x80u8 == 0u8 {
                (t, Ok(b as Nat))
            } else {
                more(b, sdec(sz, k + 7, t))
            }
        }
    }
}

/// The decoder's result for a value of type `T`: the rest's number `v`
/// placed at bit `k` above the bits `r` already read.
#[spec]
#[example(placed::<T>(1, 7, (seq![], Ok(2))) == (seq![], Ok(T::from(1u8) | (T::from(2u8) << 7usize))))]
#[example(placed::<T>(0, 0, (seq![5u8], Err(Error::EndOfBuffer))) == (seq![5u8], Err(Error::EndOfBuffer)))]
pub fn placed<T: UPrim>(r: Int, k: Int, d: (Seq<u8>, Result<Nat, Error>)) -> (Seq<u8>, Result<T, Error>) {
    match d {
        (s, Ok(v)) => (s, Ok((r + (v as Int) * pow2(k)) as T)),
        (s, Err(e)) => (s, Err(e)),
    }
}

/// What `read` does: `EndOfBuffer` on no input, a first byte without the
/// continuation bit is the value (the fast path), else the decoder from
/// zero bits.
#[spec]
#[opaque]
#[example(sdec0(2usize, seq![5u8, 6u8]) == (seq![6u8], Ok(5)))]
#[example(sdec0(2usize, seq![]) == (seq![], Err(Error::EndOfBuffer)))]
#[example(sdec0(2usize, seq![0xACu8, 0x02u8]) == (seq![], Ok(300)))]
#[example(sdec0(0usize, seq![1u8]) == (seq![], Ok(1)) && sdec0(0usize, seq![16u8]) == (seq![], Ok(16)))]
pub fn sdec0(sz: usize, bs: Seq<u8>) -> (Seq<u8>, Result<Nat, Error>) {
    match bs {
        [] => (seq![], Err(Error::EndOfBuffer)),
        [b, t @ ..] => if b & 0x80u8 == 0u8 { (t, Ok(b as Nat)) } else { sdec(sz, 0, bs) },
    }
}

/// `read_cfg`'s result: `read`'s value wrapped in `UInt`.
#[spec]
#[example(wrap::<T>((seq![1u8], Ok(T::from(5u8)))) == (seq![1u8], Ok(UInt(T::from(5u8)))))]
#[example(wrap::<T>((seq![], Err(Error::EndOfBuffer))) == (seq![], Err(Error::EndOfBuffer)))]
pub fn wrap<T: UPrim>(r: (Seq<u8>, Result<T, Error>)) -> (Seq<u8>, Result<UInt<T>, Error>) {
    match r {
        (s, Ok(x)) => (s, Ok(UInt(x))),
        (s, Err(e)) => (s, Err(e)),
    }
}

/// `feed`'s two rejection tests, as the code writes them, are `rejects`
/// (the last comparison as an `if`, so that a path fact about it rewrites
/// it).
#[lemma]
fn rejects_code<U: UPrim>(k: usize, byte: u8) {
    requires(k < U::SIZE * 8);
    ensures(rejects(U::SIZE, k as Int, byte) == ((byte == 0u8 && k > 0usize)
        || (U::SIZE * crate::varint::BITS_PER_BYTE - k <= crate::varint::DATA_BITS_PER_BYTE
            && (if crate::varint::BITS_PER_BYTE - (byte.leading_zeros() as usize) > U::SIZE * crate::varint::BITS_PER_BYTE - k { true } else { false }))));
    unfold(rejects);
    by_cases(byte == 0u8, k > 0usize);
}

/// One decoder step in numbers: a continuation byte's low bits land at bit
/// `k`, then the rest's number at bit `k + 7`.
#[lemma]
fn placed_more<T: UPrim>(r: Int, k: Int, b: u8, r2: Int, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(k >= 0 && k % 7 == 0 && k < 64 && r2 == r + ((b as Int) % 128) * pow2(k));
    ensures(placed::<T>(r2, k + 7, d) == placed::<T>(r, k, more(b, d)));
    match d {
        (s, Ok(y)) => {
            scale7(k, (b as Int) % 128, y as Int);
            assert(((b as Nat) % 128 + 128 * y) as Int == (b as Int) % 128 + 128 * (y as Int));
            by_unfolding(placed::<T>, more);
        }
        (s, Err(e)) => by_unfolding(placed::<T>, more),
    }
}

/// A byte needs more than `e` bits exactly when it is at least 2^e.
#[lemma]
fn relevant_bits_i(b: u8, e: Int) {
    requires(0 <= e && e <= 7);
    ensures((8 - (b.leading_zeros() as Int) > e) == ((b as Int) >= pow2(e)));
    by_cases(e, 0..8);
    by_cases(b, 0..=255);
}

/// A zero byte the decoder does not reject is the first.
#[lemma]
fn not_rejects_zero(sz: usize, k: Int, b: u8) {
    requires(!rejects(sz, k, b) && b == 0u8);
    ensures(k <= 0);
    if k > 0 {
        assert(rejects(sz, k, b), { unfold(rejects); by_cases(8 * (sz as Int) - k <= 7); });
        by_contradiction();
    } else {
        follows();
    }
}

/// When at most seven bits are left, a byte the decoder does not reject
/// fits in them.
#[lemma]
fn not_rejects_fits(sz: usize, k: Int, b: u8) {
    requires(!rejects(sz, k, b) && 0 <= 8 * (sz as Int) - k && 8 * (sz as Int) - k <= 7);
    ensures((b as Int) < pow2(8 * (sz as Int) - k));
    relevant_bits_i(b, 8 * (sz as Int) - k);
    if (b as Int) >= pow2(8 * (sz as Int) - k) {
        assert(8 - (b.leading_zeros() as Int) > 8 * (sz as Int) - k);
        assert(rejects(sz, k, b), { unfold(rejects); by_cases(b == 0u8); });
        by_contradiction();
    } else {
        follows();
    }
}


/// 2^e is at least 128 from e = 7 on.
#[lemma]
fn pow2_ge128(e: Int) {
    requires(e >= 7);
    ensures(pow2(e) >= 128);
    pow2_plus7(e - 7);
    follows();
}

/// 2^e is at most 128 up to e = 7.
#[lemma]
fn pow2_le128(e: Int) {
    requires(e <= 7);
    ensures(pow2(e) <= 128);
    if e < 0 {
        follows();
    } else {
        by_cases(e, 0..8);
    }
}

/// The next decoder level is a multiple of seven too.
#[lemma]
fn mod7_step(x: usize) {
    requires(x % 7usize == 0usize && x < 64usize);
    ensures((x + 7usize) % 7usize == 0usize);
    if x <= 0usize { assert(x == 0usize); follows();
    } else if x <= 7usize { assert(x == 7usize); follows();
    } else if x <= 14usize { assert(x == 14usize); follows();
    } else if x <= 21usize { assert(x == 21usize); follows();
    } else if x <= 28usize { assert(x == 28usize); follows();
    } else if x <= 35usize { assert(x == 35usize); follows();
    } else if x <= 42usize { assert(x == 42usize); follows();
    } else if x <= 49usize { assert(x == 49usize); follows();
    } else if x <= 56usize { assert(x == 56usize); follows();
    } else if x <= 63usize { assert(x == 63usize); follows();
    } else { by_contradiction(); }
}

/// A finishing byte the decoder accepts lands at bit `k` above `r`.
#[lemma]
fn step_done<T: UPrim>(r: T, k: usize, byte: u8) {
    requires(k % 7usize == 0usize && k < T::SIZE * 8 && (r as Int) < pow2(k as Int));
    requires(!rejects(T::SIZE, k as Int, byte) && byte < 128u8);
    ensures((r | ((byte & 0x7Fu8) as T) << k) == (((r as Int) + (byte as Int) * pow2(k as Int)) as T));
    low_bits(byte);
    // the byte fits above bit `k`
    assert(((byte & 0x7Fu8) as Int) < pow2(8 * (T::SIZE as Int) - (k as Int)), {
        if 8 * (T::SIZE as Int) - (k as Int) <= 7 {
            not_rejects_fits(T::SIZE, k as Int, byte);
            follows();
        } else {
            pow2_ge128(8 * (T::SIZE as Int) - (k as Int));
            follows();
        }
    });
    or_shift::<T>(r, byte & 0x7Fu8, k);
    let r2 = r | ((byte & 0x7Fu8) as T) << k;
    assert((byte as Int) % 128 == (byte as Int));
    assert((r2 as Int) == (r as Int) + (byte as Int) * pow2(k as Int));
    int_back::<T>(r2);
    follows();
}

/// After a continuation byte the decoder accepts, the next level's
/// placement is this level's.
#[lemma]
fn step_more<T: UPrim>(r: T, k: usize, byte: u8, buf: Seq<u8>) {
    requires(k % 7usize == 0usize && k < T::SIZE * 8 && (r as Int) < pow2(k as Int));
    requires(!rejects(T::SIZE, k as Int, byte) && byte >= 128u8);
    ensures(placed::<T>(((r | ((byte & 0x7Fu8) as T) << k) as Int), k as Int + 7, sdec(T::SIZE, k as Int + 7, buf))
        == placed::<T>(r as Int, k as Int, more(byte, sdec(T::SIZE, k as Int + 7, buf))));
    low_bits(byte);
    // not rejected with the top bit set: more than seven bits are left
    assert(8 * (T::SIZE as Int) - (k as Int) > 7, {
        if 8 * (T::SIZE as Int) - (k as Int) <= 7 {
            not_rejects_fits(T::SIZE, k as Int, byte);
            pow2_le128(8 * (T::SIZE as Int) - (k as Int));
            by_contradiction();
        } else {
            follows();
        }
    });
    pow2_ge128(8 * (T::SIZE as Int) - (k as Int));
    assert(((byte & 0x7Fu8) as Int) < pow2(8 * (T::SIZE as Int) - (k as Int)));
    or_shift::<T>(r, byte & 0x7Fu8, k);
    let r2 = r | ((byte & 0x7Fu8) as T) << k;
    assert((r2 as Int) == (r as Int) + ((byte as Int) % 128) * pow2(k as Int));
    placed_more::<T>(r as Int, k as Int, byte, r2 as Int, sdec(T::SIZE, k as Int + 7, buf));
    follows();
}

/// The decoder loop's two continuing cases, stated so that the loop's start
/// can use them before `feed` has decided the case.
#[lemma]
fn loop_step<T: UPrim>(r: T, k: usize, byte: u8, buf: Seq<u8>) {
    requires(k % 7usize == 0usize && k < T::SIZE * 8 && (r as Int) < pow2(k as Int));
    ensures(implies(!rejects(T::SIZE, k as Int, byte) && byte & 0x80u8 == 0u8,
            (r | ((byte & 0x7Fu8) as T) << k) == (((r as Int) + (byte as Int) * pow2(k as Int)) as T))
        && implies(!rejects(T::SIZE, k as Int, byte) && byte & 0x80u8 != 0u8,
            placed::<T>(((r | ((byte & 0x7Fu8) as T) << k) as Int), k as Int + 7, sdec(T::SIZE, k as Int + 7, buf))
                == placed::<T>(r as Int, k as Int, more(byte, sdec(T::SIZE, k as Int + 7, buf)))));
    if rejects(T::SIZE, k as Int, byte) {
        follows();
    } else if byte < 128u8 {
        top_bit_clear(byte);
        step_done::<T>(r, k, byte);
        follows();
    } else {
        top_bit_set(byte);
        step_more::<T>(r, k, byte, buf);
        follows();
    }
}

/// A level's bound: below 2^k, plus a group below 128 at bit `k`, stays
/// below 2^(k+7) (per level: the powers are literals case by case).
#[lemma]
fn acc_bound7(k: Int, acc: Int, g: Int) {
    requires(k >= 0 && k % 7 == 0 && k < 64 && 0 <= acc && acc < pow2(k) && 0 <= g && g < 128);
    ensures(acc + g * pow2(k) < pow2(k + 7));
    if k <= 0 { assert(k == 0); pow2_eq(k, 0); pow2_eq(k + 7, 7); by_arithmetic();
    } else if k <= 7 { assert(k == 7); pow2_eq(k, 7); pow2_eq(k + 7, 14); by_arithmetic();
    } else if k <= 14 { assert(k == 14); pow2_eq(k, 14); pow2_eq(k + 7, 21); by_arithmetic();
    } else if k <= 21 { assert(k == 21); pow2_eq(k, 21); pow2_eq(k + 7, 28); by_arithmetic();
    } else if k <= 28 { assert(k == 28); pow2_eq(k, 28); pow2_eq(k + 7, 35); by_arithmetic();
    } else if k <= 35 { assert(k == 35); pow2_eq(k, 35); pow2_eq(k + 7, 42); by_arithmetic();
    } else if k <= 42 { assert(k == 42); pow2_eq(k, 42); pow2_eq(k + 7, 49); by_arithmetic();
    } else if k <= 49 { assert(k == 49); pow2_eq(k, 49); pow2_eq(k + 7, 56); by_arithmetic();
    } else if k <= 56 { assert(k == 56); pow2_eq(k, 56); pow2_eq(k + 7, 63); by_arithmetic();
    } else if k <= 63 { assert(k == 63); pow2_eq(k, 63); pow2_eq(k + 7, 70); by_arithmetic();
    } else { by_contradiction(); }
}

/// After a continuation byte the decoder accepts, its value bits are below
/// 2^(k+7).
#[lemma]
fn step_bound<T: UPrim>(r: T, k: usize, byte: u8) {
    requires(k % 7usize == 0usize && k < T::SIZE * 8 && (r as Int) < pow2(k as Int));
    requires(!rejects(T::SIZE, k as Int, byte) && byte >= 128u8);
    ensures(((r | ((byte & 0x7Fu8) as T) << k) as Int) < pow2((k + 7usize) as Int));
    low_bits(byte);
    // not rejected with the top bit set: more than seven bits are left
    assert(8 * (T::SIZE as Int) - (k as Int) > 7, {
        if 8 * (T::SIZE as Int) - (k as Int) <= 7 {
            not_rejects_fits(T::SIZE, k as Int, byte);
            pow2_le128(8 * (T::SIZE as Int) - (k as Int));
            by_contradiction();
        } else {
            follows();
        }
    });
    pow2_ge128(8 * (T::SIZE as Int) - (k as Int));
    assert(((byte & 0x7Fu8) as Int) < pow2(8 * (T::SIZE as Int) - (k as Int)));
    or_shift::<T>(r, byte & 0x7Fu8, k);
    acc_bound7(k as Int, r as Int, (byte & 0x7Fu8) as Int);
    pow2_eq((k + 7usize) as Int, k as Int + 7);
    follows();
}

/// What `feed` returns for the state `(r, k)` and the byte `b`.
#[spec]
#[requires(k < U::SIZE * 8)]
#[example(feed_res::<U>(U::from(0u8), 0usize, 5u8) == Ok(Some(U::from(5u8))))]
#[example(feed_res::<U>(U::from(0u8), 0usize, 0x80u8) == Ok(None) && feed_res::<U>(U::from(0u8), 7usize, 0u8) == Err(Error::InvalidVarint(U::SIZE)))]
#[example(feed_res::<U>(U::from(0u8), U::SIZE * 8usize - 4usize, 16u8) == Err(Error::InvalidVarint(U::SIZE)))]
#[example(feed_res::<U>(U::from(0u8), 0usize, 16u8) == Ok(Some(U::from(16u8))) && feed_res::<U>(U::from(1u8), 0usize, 1u8) == Ok(Some(U::from(1u8))) && feed_res::<U>(U::from(0u8), 1usize, 1u8) == Ok(Some(U::from(2u8))))]
#[example(feed_res::<U>(U::from(0u8), 6usize, 4u8) == Ok(Some(U::from(1u8) << 8usize)))]
pub fn feed_res<U: UPrim>(r: U, k: usize, b: u8) -> Result<Option<U>, Error> {
    if rejects(U::SIZE, k as Int, b) {
        Err(Error::InvalidVarint(U::SIZE))
    } else if b & 0x80u8 == 0u8 {
        Ok(Some(r | ((b & 0x7Fu8) as U) << k))
    } else {
        Ok(None)
    }
}

/// The value bits `feed` holds after the byte `b`.
#[spec]
#[requires(k < U::SIZE * 8)]
#[example(feed_acc::<U>(U::from(1u8), 7usize, 2u8) == (U::from(1u8) | (U::from(2u8) << 7usize)))]
#[example(feed_acc::<U>(U::from(1u8), 7usize, 0u8) == U::from(1u8))]
#[example(feed_acc::<U>(U::from(0u8), U::SIZE * 8usize - 4usize, 17u8) == U::from(0u8))]
#[example(feed_acc::<U>(U::from(1u8), 0usize, 1u8) == U::from(1u8) && feed_acc::<U>(U::from(0u8), 0usize, 16u8) == U::from(16u8))]
pub fn feed_acc<U: UPrim>(r: U, k: usize, b: u8) -> U {
    if rejects(U::SIZE, k as Int, b) { r } else { r | ((b & 0x7Fu8) as U) << k }
}

/// The bits `feed` has read after the byte `b`: seven more after a
/// continuation byte it accepts.
#[spec]
#[requires(k < U::SIZE * 8)]
#[example(feed_bits::<U>(0usize, 0x80u8) == 7usize && feed_bits::<U>(0usize, 5u8) == 0usize && feed_bits::<U>(7usize, 0u8) == 7usize)]
#[example(feed_bits::<U>(U::SIZE * 8usize - 7usize, 0x80u8) == U::SIZE * 8usize - 7usize && feed_bits::<U>(U::SIZE * 8usize - 15usize, 0x80u8) == U::SIZE * 8usize - 8usize && feed_bits::<U>(0usize, 16u8) == 0usize)]
pub fn feed_bits<U: UPrim>(k: usize, b: u8) -> usize {
    if rejects(U::SIZE, k as Int, b) { k } else if b & 0x80u8 == 0u8 { k } else { k + 7usize }
}

/// The loop's finishing case: equal to the value placed in numbers (by
/// `step_done` where the byte finishes; the same by definition elsewhere).
#[spec]
#[requires(k < T::SIZE * 8)]
#[example(done_val::<T>(T::from(1u8), 7usize, 2u8) == (T::from(1u8) | (T::from(2u8) << 7usize)))]
#[example(done_val::<T>(T::from(0u8), 0usize, 0x80u8) == T::from(0x80u8))]
#[example(done_val::<T>(T::from(1u8), 0usize, 1u8) == T::from(1u8) && done_val::<T>(T::from(0u8), 1usize, 0u8) == T::from(0u8))]
#[example(done_val::<T>(T::from(0u8), T::SIZE * 8usize - 4usize, 17u8) == (T::from(1u8) << (T::SIZE * 8usize - 4usize)))]
#[example(done_val::<T>(T::from(0u8), 0usize, 1u8) == T::from(1u8) && done_val::<T>(T::from(0u8), 0usize, 16u8) == T::from(16u8))]
pub fn done_val<T: UPrim>(r: T, k: usize, b: u8) -> T {
    if rejects(T::SIZE, k as Int, b) {
        (((r as Int) + (b as Int) * pow2(k as Int)) as T)
    } else if b & 0x80u8 == 0u8 {
        r | ((b & 0x7Fu8) as T) << k
    } else {
        (((r as Int) + (b as Int) * pow2(k as Int)) as T)
    }
}

/// The loop's continuing case: the next level's placement (by `step_more`
/// equal to this level's; the same by definition elsewhere).
#[spec]
#[requires(k < T::SIZE * 8)]
#[example(more_val::<T>(T::from(0u8), 0usize, 5u8, seq![]) == placed::<T>(0, 0, more(5u8, sdec(T::SIZE, 7, seq![]))))]
#[example(more_val::<T>(T::from(0u8), 0usize, 0x81u8, seq![1u8]) == placed::<T>(1, 7, sdec(T::SIZE, 7, seq![1u8])))]
#[example(more_val::<T>(T::from(4u8), 2usize, 249u8, seq![1u8]) == (seq![], Ok(T::from(0xE4u8) | (T::from(3u8) << 8usize))))]
#[example(more_val::<T>(T::from(4u8), 0usize, 140u8, seq![1u8]) == (seq![], Ok(T::from(140u8))) && more_val::<T>(T::from(1u8), 0usize, 0u8, seq![1u8]) == (seq![], Ok(T::from(129u8))))]
#[example(more_val::<T>(T::from(0u8), 1usize, 0u8, seq![1u8]) == (seq![], Ok(T::from(1u8) << 8usize)))]
#[example(more_val::<T>(T::from(0u8), 1usize, 0u8, seq![0u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))) && more_val::<T>(T::from(0u8), T::SIZE * 8usize - 7usize, 0u8, seq![1u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))))]
#[example(more_val::<T>(T::from(0u8), 0usize, 0u8, seq![0u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))) && more_val::<T>(T::from(0u8), 0usize, 1u8, seq![0u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))))]
#[example(more_val::<T>(T::from(0u8), 0usize, 16u8, seq![0u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))) && more_val::<T>(T::from(0u8), 0usize, 128u8, seq![0u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))))]
#[example(more_val::<T>(T::from(0u8), T::SIZE * 8usize - 9usize, 1u8, seq![2u8]) == (seq![], Ok((T::from(1u8) << (T::SIZE * 8usize - 9usize)) | (T::from(1u8) << (T::SIZE * 8usize - 1usize)))))]
#[example(more_val::<T>(T::from(0u8), T::SIZE * 8usize - 9usize, 1u8, seq![4u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))))]
#[example(more_val::<T>(T::from(0u8), T::SIZE * 8usize - 7usize, 0xC5u8, seq![1u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))) && more_val::<T>(T::from(0u8), T::SIZE * 8usize - 7usize, 228u8, seq![1u8]) == (seq![], Err(Error::InvalidVarint(T::SIZE))))]
pub fn more_val<T: UPrim>(r: T, k: usize, b: u8, buf: Seq<u8>) -> (Seq<u8>, Result<T, Error>) {
    if rejects(T::SIZE, k as Int, b) {
        placed::<T>(r as Int, k as Int, more(b, sdec(T::SIZE, k as Int + 7, buf)))
    } else if b & 0x80u8 == 0u8 {
        placed::<T>(r as Int, k as Int, more(b, sdec(T::SIZE, k as Int + 7, buf)))
    } else {
        placed::<T>(feed_acc::<T>(r, k, b) as Int, feed_bits::<T>(k, b) as Int, sdec(T::SIZE, feed_bits::<T>(k, b) as Int, buf))
    }
}

/// The next level's bound: after a continuation byte the decoder accepts,
/// its value bits are below 2^(bits read).
#[spec]
pub fn acc_ok<T: UPrim>(r: T, k: usize, b: u8) -> Prop {
    if k >= T::SIZE * 8 {
        true
    } else if rejects(T::SIZE, k as Int, b) {
        true
    } else if b & 0x80u8 == 0u8 {
        true
    } else {
        (feed_acc::<T>(r, k, b) as Int) < pow2(feed_bits::<T>(k, b) as Int)
    }
}

/// The loop's facts in numbers, stated without a case split so that its
/// start can state them before `feed` has decided the case.
#[lemma]
fn loop_facts<T: UPrim>(r: T, k: usize, byte: u8, buf: Seq<u8>) {
    requires(k % 7usize == 0usize && k < T::SIZE * 8 && (r as Int) < pow2(k as Int));
    ensures(done_val::<T>(r, k, byte) == (((r as Int) + (byte as Int) * pow2(k as Int)) as T)
        && more_val::<T>(r, k, byte, buf) == placed::<T>(r as Int, k as Int, more(byte, sdec(T::SIZE, k as Int + 7, buf)))
        && acc_ok::<T>(r, k, byte));
    if rejects(T::SIZE, k as Int, byte) {
        follows();
    } else if byte < 128u8 {
        top_bit_clear(byte);
        step_done::<T>(r, k, byte);
        follows();
    } else {
        top_bit_set(byte);
        step_more::<T>(r, k, byte, buf);
        step_bound::<T>(r, k, byte);
        assert(feed_bits::<T>(k, byte) == k + 7usize);
        assert(feed_acc::<T>(r, k, byte) == (r | ((byte & 0x7Fu8) as T) << k));
        follows();
    }
}

/// The decoder loop in numbers (u32).
#[lemma]
#[induction(buf)]
fn loop_spec__u32(d: Decoder<u32>, byte: u8, buf: Seq<u8>) {
    requires((d.result as Int) < pow2(d.bits_read as Int));
    ensures(crate::varint::read__u32__loop0(d, byte, buf) == placed::<u32>(d.result as Int, d.bits_read as Int, sdec(4usize, d.bits_read as Int, seq![byte, ..buf])));
    rejects_code::<u32>(d.bits_read, byte);
    loop_facts::<u32>(d.result, d.bits_read, byte, buf);
    unfold(crate::varint::read__u32__loop0);
    if rejects(4usize, d.bits_read as Int, byte) {
        follows();
    } else if byte & 0x80u8 == 0u8 {
        follows();
    } else {
        match buf {
            [] => follows(),
            [h, t @ ..] => {
                ih({ let mut d2 = d; let r = d2.feed(byte); d2 }, h, t);
                follows();
            }
        }
    }
}

/// The decoder loop in numbers (u16).
#[lemma]
#[induction(buf)]
fn loop_spec__u16(d: Decoder<u16>, byte: u8, buf: Seq<u8>) {
    requires((d.result as Int) < pow2(d.bits_read as Int));
    ensures(crate::varint::read__u16__loop0(d, byte, buf) == placed::<u16>(d.result as Int, d.bits_read as Int, sdec(2usize, d.bits_read as Int, seq![byte, ..buf])));
    rejects_code::<u16>(d.bits_read, byte);
    loop_facts::<u16>(d.result, d.bits_read, byte, buf);
    unfold(crate::varint::read__u16__loop0);
    if rejects(2usize, d.bits_read as Int, byte) {
        follows();
    } else if byte & 0x80u8 == 0u8 {
        follows();
    } else {
        match buf {
            [] => follows(),
            [h, t @ ..] => {
                ih({ let mut d2 = d; let r = d2.feed(byte); d2 }, h, t);
                follows();
            }
        }
    }
}

/// The decoder loop in numbers (u64).
#[lemma]
#[induction(buf)]
fn loop_spec__u64(d: Decoder<u64>, byte: u8, buf: Seq<u8>) {
    requires((d.result as Int) < pow2(d.bits_read as Int));
    ensures(crate::varint::read__u64__loop0(d, byte, buf) == placed::<u64>(d.result as Int, d.bits_read as Int, sdec(8usize, d.bits_read as Int, seq![byte, ..buf])));
    rejects_code::<u64>(d.bits_read, byte);
    loop_facts::<u64>(d.result, d.bits_read, byte, buf);
    unfold(crate::varint::read__u64__loop0);
    if rejects(8usize, d.bits_read as Int, byte) {
        follows();
    } else if byte & 0x80u8 == 0u8 {
        follows();
    } else {
        match buf {
            [] => follows(),
            [h, t @ ..] => {
                ih({ let mut d2 = d; let r = d2.feed(byte); d2 }, h, t);
                follows();
            }
        }
    }
}

/// A decoder result as a value of the type.
#[spec]
#[example(view_t::<T>((seq![1u8], Ok(5))) == (seq![1u8], Ok(T::from(5u8))))]
#[example(view_t::<T>((seq![], Err(Error::EndOfBuffer))) == (seq![], Err(Error::EndOfBuffer)))]
pub fn view_t<T: UPrim>(d: (Seq<u8>, Result<Nat, Error>)) -> (Seq<u8>, Result<T, Error>) {
    match d {
        (s, Ok(v)) => (s, Ok(v as T)),
        (s, Err(e)) => (s, Err(e)),
    }
}

/// The decoder's value placed at bit 0 above nothing: the value.
#[lemma]
fn placed0<T: UPrim>(d: (Seq<u8>, Result<Nat, Error>)) {
    ensures(placed::<T>(0, 0, d) == view_t::<T>(d));
    assert(pow2(0) == 1);
    match d {
        (s, Ok(v)) => {
            assert(0 + (v as Int) * pow2(0) == (v as Int));
            by_unfolding(placed::<T>, view_t::<T>);
        }
        (s, Err(e)) => by_unfolding(placed::<T>, view_t::<T>),
    }
}

/// `read` in numbers (per width below).
#[lemma]
fn read_spec<T: UPrim>(buf: Seq<u8>) {
    ensures({ let mut b = buf; let r = crate::varint::read::<T>(&mut b); (b, r) } == view_t::<T>(sdec(T::SIZE, 0, buf)));
}

#[lemma]
fn read_spec__u32(buf: Seq<u8>) {
    ensures({ let mut b = buf; let r = crate::varint::read::<u32>(&mut b); (b, r) } == view_t::<u32>(sdec(4usize, 0, buf)));
    unfold(crate::varint::read__u32);
    match buf {
        [] => {
            sdec_nil(4usize, 0);
            follows();
        }
        [x, t @ ..] => {
            if x & 0x80u8 == 0u8 {
                top_bit_clear_rev(x);
                accepts(4usize, 0, x);
                sdec_done(4usize, 0, x, t);
                follows();
            } else {
                loop_spec__u32(crate::varint::Decoder::<u32>::new(), x, t);
                placed0::<u32>(sdec(4usize, 0, seq![x, ..t]));
                follows();
            }
        }
    }
}

#[lemma]
fn read_spec__u16(buf: Seq<u8>) {
    ensures({ let mut b = buf; let r = crate::varint::read::<u16>(&mut b); (b, r) } == view_t::<u16>(sdec(2usize, 0, buf)));
    unfold(crate::varint::read__u16);
    match buf {
        [] => {
            sdec_nil(2usize, 0);
            follows();
        }
        [x, t @ ..] => {
            if x & 0x80u8 == 0u8 {
                top_bit_clear_rev(x);
                accepts(2usize, 0, x);
                sdec_done(2usize, 0, x, t);
                follows();
            } else {
                loop_spec__u16(crate::varint::Decoder::<u16>::new(), x, t);
                placed0::<u16>(sdec(2usize, 0, seq![x, ..t]));
                follows();
            }
        }
    }
}

#[lemma]
fn read_spec__u64(buf: Seq<u8>) {
    ensures({ let mut b = buf; let r = crate::varint::read::<u64>(&mut b); (b, r) } == view_t::<u64>(sdec(8usize, 0, buf)));
    unfold(crate::varint::read__u64);
    match buf {
        [] => {
            sdec_nil(8usize, 0);
            follows();
        }
        [x, t @ ..] => {
            if x & 0x80u8 == 0u8 {
                top_bit_clear_rev(x);
                accepts(8usize, 0, x);
                sdec_done(8usize, 0, x, t);
                follows();
            } else {
                loop_spec__u64(crate::varint::Decoder::<u64>::new(), x, t);
                placed0::<u64>(sdec(8usize, 0, seq![x, ..t]));
                follows();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The decoder in numbers against LEB128 (no machine words below)
// ---------------------------------------------------------------------------




/// `sdec` on no input.
#[lemma]
fn sdec_nil(sz: usize, k: Int) {
    ensures(sdec(sz, k, seq![]) == (seq![], Err(Error::EndOfBuffer)));
    by_unfolding(sdec);
}

/// `sdec` on a rejected byte.
#[lemma]
fn sdec_rej(sz: usize, k: Int, b: u8, t: Seq<u8>) {
    requires(rejects(sz, k, b));
    ensures(sdec(sz, k, seq![b, ..t]) == (t, Err(Error::InvalidVarint(sz))));
    by_unfolding(sdec);
}

/// `sdec` on an accepted last byte.
#[lemma]
fn sdec_done(sz: usize, k: Int, b: u8, t: Seq<u8>) {
    requires(!rejects(sz, k, b) && b & 0x80u8 == 0u8);
    ensures(sdec(sz, k, seq![b, ..t]) == (t, Ok(b as Nat)));
    by_unfolding(sdec);
}

/// `sdec` on an accepted continuation byte.
#[lemma]
fn sdec_more(sz: usize, k: Int, b: u8, t: Seq<u8>) {
    requires(!rejects(sz, k, b) && b & 0x80u8 != 0u8);
    ensures(sdec(sz, k, seq![b, ..t]) == more(b, sdec(sz, k + 7, t)));
    by_unfolding(sdec);
}

/// A byte that fits in `e <= 7` bits needs at most `e` bits.
#[lemma]
fn fits_bits(b: u8, e: Int) {
    requires(0 <= e && e <= 7 && (b as Int) < pow2(e));
    ensures(8 - (b.leading_zeros() as Int) <= e);
    fits_bits_or(b, e);
    follows();
}

/// A byte is at least 2^e or needs at most `e` bits (by the cases).
#[lemma]
fn fits_bits_or(b: u8, e: Int) {
    requires(0 <= e && e <= 7);
    ensures(((b as Int) >= pow2(e) || 8 - (b.leading_zeros() as Int) <= e) == true);
    by_cases(e, 0..8);
    by_cases(b, 0..=255);
}

/// A byte the decoder accepts: not a zero byte after the first, and when at
/// most seven bits are left, it fits in them.
#[lemma]
fn accepts(sz: usize, k: Int, b: u8) {
    requires(k < 8 * (sz as Int) && implies(k > 0, b != 0u8));
    requires(implies(8 * (sz as Int) - k <= 7, (b as Int) < pow2(8 * (sz as Int) - k)));
    ensures(!rejects(sz, k, b));
    if 8 * (sz as Int) - k <= 7 {
        assert((b as Int) < pow2(8 * (sz as Int) - k));
        fits_bits(b, 8 * (sz as Int) - k);
        if k > 0 {
            assert(b != 0u8);
            unfold(rejects);
            follows();
        } else {
            unfold(rejects);
            follows();
        }
    } else if k > 0 {
        assert(b != 0u8);
        unfold(rejects);
        follows();
    } else {
        unfold(rejects);
        follows();
    }
}

/// A continuation byte the decoder accepts leaves more than seven bits.
#[lemma]
fn more_room(sz: usize, k: Int, b: u8) {
    requires(!rejects(sz, k, b) && b >= 128u8 && k < 8 * (sz as Int));
    ensures(8 * (sz as Int) - k > 7);
    if 8 * (sz as Int) - k <= 7 {
        not_rejects_fits(sz, k, b);
        pow2_le128(8 * (sz as Int) - k);
        by_contradiction();
    } else {
        follows();
    }
}

/// The continuation byte LEB128 writes for `v >= 128`.
#[lemma]
fn lead_byte(v: Nat) {
    requires(v >= 128);
    ensures(((128 + v % 128) as u8) >= 128u8 && ((((128 + v % 128) as u8) as Nat) % 128) == v % 128);
    assert((((128 + v % 128) as u8) as Int) == 128 + v % 128);
    follows();
}

/// Round trip: from level `k`, the encoding of a value the level admits
/// decodes to it and leaves the rest.
#[lemma]
#[decreases(v)]
fn sdec_varint(sz: usize, k: Int, v: Nat, rest: Seq<u8>) {
    requires(k >= 0 && k < 8 * (sz as Int) && implies(k > 0, v >= 1) && (v as Int) < pow2(8 * (sz as Int) - k));
    ensures(sdec(sz, k, seq![..crate::laws::varint(v), ..rest]) == (rest, Ok(v)));
    if v < 128 {
        varint_small(v);
        let b = v as u8;
        assert((b as Nat) == v);
        assert(implies(k > 0, b != 0u8), {
            if k > 0 {
                assert(v >= 1);
                follows();
            } else {
                follows();
            }
        });
        accepts(sz, k, b);
        top_bit_clear(b);
        sdec_done(sz, k, b, rest);
        follows();
    } else {
        varint_step(v);
        let c = (128 + v % 128) as u8;
        lead_byte(v);
        shift7(v as Int, 8 * (sz as Int) - k);
        pow2_eq(8 * (sz as Int) - k - 7, 8 * (sz as Int) - (k + 7));
        accepts(sz, k, c);
        top_bit_set(c);
        assert(v / 128 >= 1);
        assert(k + 7 < 8 * (sz as Int));
        assert(((v / 128) as Int) < pow2(8 * (sz as Int) - (k + 7)));
        sdec_varint(sz, k + 7, v / 128, rest);
        sdec_more(sz, k, c, seq![..crate::laws::varint(v / 128), ..rest]);
        assert(v % 128 + 128 * (v / 128) == v);
        follows();
    }
}

/// A continuation byte `b` then the encoding of `y > 0`: the encoding of
/// `b % 128 + 128·y`.
#[lemma]
fn varint_cont(b: u8, y: Nat, s: Seq<u8>) {
    requires(b >= 128u8 && y > 0);
    ensures(seq![b, ..crate::laws::varint(y), ..s] == seq![..crate::laws::varint((b as Nat) % 128 + 128 * y), ..s]);
    let x = (b as Nat) % 128 + 128 * y;
    assert(x >= 128 && x % 128 == (b as Nat) % 128 && x / 128 == y);
    varint_step(x);
    assert(((128 + x % 128) as u8) == b);
    follows();
}

/// A continuation byte `b` then the encoding of `y > 0`: the encoding of
/// `b % 128 + 128·y` (nothing after it).
#[lemma]
fn varint_cont0(b: u8, y: Nat) {
    requires(b >= 128u8 && y > 0);
    ensures(seq![b, ..crate::laws::varint(y)] == crate::laws::varint((b as Nat) % 128 + 128 * y));
    let x = (b as Nat) % 128 + 128 * y;
    assert(x >= 128 && x % 128 == (b as Nat) % 128 && x / 128 == y);
    varint_step(x);
    assert(((128 + x % 128) as u8) == b);
    follows();
}

/// Canonicity: whatever `sdec` accepts from level `k` is the encoding of a
/// value the level admits, followed by the rest.
#[lemma]
#[induction(bs)]
fn sdec_ok(sz: usize, k: Int, bs: Seq<u8>, rest: Seq<u8>, v: Nat) {
    requires(k >= 0 && k < 8 * (sz as Int) && sdec(sz, k, bs) == (rest, Ok(v)));
    ensures(bs == seq![..crate::laws::varint(v), ..rest] && implies(k > 0, v >= 1) && (v as Int) < pow2(8 * (sz as Int) - k));
    match bs {
        [] => {
            sdec_nil(sz, k);
            by_contradiction();
        }
        [b, t @ ..] => {
            if rejects(sz, k, b) {
                sdec_rej(sz, k, b, t);
                by_contradiction();
            } else if b & 0x80u8 == 0u8 {
                sdec_done(sz, k, b, t);
                top_bit_clear_rev(b);
                assert(v == (b as Nat) && rest == t);
                varint_small(v);
                // not a zero byte after the first
                assert(k == 0 || v >= 1, {
                    if k > 0 {
                        if b == 0u8 {
                            not_rejects_zero(sz, k, b);
                            by_contradiction();
                        } else {
                            follows();
                        }
                    } else {
                        follows();
                    }
                });
                // the width: at most seven bits left, the byte fits; else 2^(bits) >= 256
                assert((v as Int) < pow2(8 * (sz as Int) - k), {
                    if 8 * (sz as Int) - k <= 7 {
                        not_rejects_fits(sz, k, b);
                        follows();
                    } else {
                        pow2_ge128(8 * (sz as Int) - k);
                        follows();
                    }
                });
                follows();
            } else {
                top_bit_set_rev(b);
                more_room(sz, k, b);
                sdec_more(sz, k, b, t);
                match sdec(sz, k + 7, t) {
                    (s, Ok(y)) => {
                        ih(sz, k + 7, t, s, y);
                        pow2_eq(8 * (sz as Int) - (k + 7), 8 * (sz as Int) - k - 7);
                        assert(k + 7 > 0);
                        assert(y >= 1);
                        assert(rest == s && v == (b as Nat) % 128 + 128 * y);
                        varint_cont(b, y, s);
                        pow2_plus7(8 * (sz as Int) - k - 7);
                        follows();
                    }
                    (s, Err(e)) => by_contradiction(),
                }
            }
        }
    }
}

/// A value that the bytes `bs` begin to encode, when `sdec` runs out of
/// input on them (the witness of `sdec_eob`).
#[spec]
#[decreases(bs.len())]
#[example(eob_wit(seq![]) == 1 && eob_wit(seq![0x80u8]) == 128 && eob_wit(seq![0xFFu8, 0x81u8]) == 16639)]
pub fn eob_wit(bs: Seq<u8>) -> Nat {
    match bs {
        [] => 1,
        [b, t @ ..] => (b as Nat) % 128 + 128 * eob_wit(t),
    }
}

/// `sdec` runs out of input only on a proper prefix of an encoding: the
/// byte 1 completes the bytes to the encoding of `eob_wit(bs)`; and then
/// it has consumed everything.
#[lemma]
#[induction(bs)]
fn sdec_eob(sz: usize, k: Int, bs: Seq<u8>, rest: Seq<u8>) {
    requires(k >= 0 && k < 8 * (sz as Int) && sdec(sz, k, bs) == (rest, Err(Error::EndOfBuffer)));
    ensures(rest == seq![] && eob_wit(bs) >= 1 && (eob_wit(bs) as Int) < pow2(8 * (sz as Int) - k)
        && seq![..bs, 1u8] == crate::laws::varint(eob_wit(bs)));
    match bs {
        [] => {
            sdec_nil(sz, k);
            assert(eob_wit(seq![]) == 1, { by_unfolding(eob_wit); });
            varint_small(1);
            pow2_ge2(8 * (sz as Int) - k);
            follows();
        }
        [b, t @ ..] => {
            if rejects(sz, k, b) {
                sdec_rej(sz, k, b, t);
                by_contradiction();
            } else if b & 0x80u8 == 0u8 {
                sdec_done(sz, k, b, t);
                by_contradiction();
            } else {
                top_bit_set_rev(b);
                more_room(sz, k, b);
                sdec_more(sz, k, b, t);
                match sdec(sz, k + 7, t) {
                    (s, Ok(y)) => by_contradiction(),
                    (s, Err(e)) => {
                        assert(e == Error::EndOfBuffer && s == rest);
                        ih(sz, k + 7, t, s);
                        pow2_eq(8 * (sz as Int) - (k + 7), 8 * (sz as Int) - k - 7);
                        let w = eob_wit(t);
                        assert(eob_wit(seq![b, ..t]) == (b as Nat) % 128 + 128 * w, { by_unfolding(eob_wit); });
                        varint_cont0(b, w);
                        pow2_plus7(8 * (sz as Int) - k - 7);
                        assert(seq![b, ..t, 1u8] == crate::laws::varint(eob_wit(seq![b, ..t])), {
                            calc! {
                                seq![b, ..t, 1u8]
                                    == seq![b, ..seq![..t, 1u8]] by { follows(); };
                                    == seq![b, ..crate::laws::varint(w)] by { follows(); };
                                    == crate::laws::varint((b as Nat) % 128 + 128 * w) by { follows(); };
                                    == crate::laws::varint(eob_wit(seq![b, ..t])) by { follows(); };
                            }
                        });
                        follows();
                    }
                }
            }
        }
    }
}

/// Bytes on which `sdec` runs out of input: the byte 1 completes them to
/// the encoding of `eob_wit(bs)`, a value the level admits.
#[lemma]
fn eob_prefix_of(sz: usize, k: Int, bs: Seq<u8>) {
    requires(k >= 0 && k < 8 * (sz as Int) && sdec(sz, k, bs).1 == Err(Error::EndOfBuffer));
    ensures(seq![..bs, 1u8] == crate::laws::varint(eob_wit(bs)) && (eob_wit(bs) as Int) < pow2(8 * (sz as Int) - k) && eob_wit(bs) >= 1);
    match sdec(sz, k, bs) {
        (s, Ok(v)) => by_contradiction(),
        (s, Err(e)) => {
            sdec_eob(sz, k, bs, s);
            follows();
        }
    }
}

/// A proper prefix of the encoding of a value of the type: the decoder
/// runs out of input.
#[lemma]
fn prefix_eob0<T: UPrim>(bs: Seq<u8>, x: Nat, m: Seq<u8>) {
    requires((x as Int) < pow2(8 * (T::SIZE as Int)));
    requires(m.len() > 0);
    requires(seq![..bs, ..m] == crate::laws::varint(x));
    ensures(sdec(T::SIZE, 0, bs).1 == Err(Error::EndOfBuffer));
    sdec_prefix(T::SIZE, 0, bs, x, m);
    follows();
}

/// An incomplete encoding of a value of the type: the decoder runs out of
/// input.
#[lemma]
fn eob_of_incomplete<T: UPrim>(bs: Seq<u8>) {
    requires(exists(|x: Nat| (x as Int) < pow2(8 * (T::SIZE as Int)) && seq![..bs, 1u8] == crate::laws::varint(x)));
    ensures(sdec(T::SIZE, 0, bs).1 == Err(Error::EndOfBuffer));
    using(prefix_eob0::<T>);
    follows();
}

/// Equal inputs, equal decoder results.
#[lemma]
fn sdec_same_input(sz: usize, k: Int, a: Seq<u8>, b: Seq<u8>) {
    requires(a == b);
    ensures(sdec(sz, k, a) == sdec(sz, k, b));
    rewrite(a == b);
    follows();
}

/// 2^e is at least 2 from e = 1 on.
#[lemma]
fn pow2_ge2(e: Int) {
    requires(e >= 1);
    ensures(pow2(e) >= 2);
    assert(pow2(e) == 2 * pow2(e - 1));
    follows();
}


/// A proper prefix of an encoding the level admits (some nonempty `m`
/// completes it): `sdec` runs out of input.
#[lemma]
#[induction(bs)]
fn sdec_prefix(sz: usize, k: Int, bs: Seq<u8>, v: Nat, m: Seq<u8>) {
    requires(k >= 0 && k < 8 * (sz as Int) && implies(k > 0, v >= 1) && (v as Int) < pow2(8 * (sz as Int) - k));
    requires(m.len() > 0 && seq![..bs, ..m] == crate::laws::varint(v));
    ensures(sdec(sz, k, bs).1 == Err(Error::EndOfBuffer));
    match bs {
        [] => {
            sdec_nil(sz, k);
            follows();
        }
        [b, t @ ..] => {
            if v < 128 {
                varint_small(v);
                assert(seq![b, ..t, ..m] == seq![v as u8]);
                assert(seq![..t, ..m] == seq![]);
                assert(seq![..t, ..m].len() == t.len() + m.len());
                by_contradiction();
            } else {
                varint_step(v);
                let c = (128 + v % 128) as u8;
                lead_byte(v);
                shift7(v as Int, 8 * (sz as Int) - k);
                pow2_eq(8 * (sz as Int) - k - 7, 8 * (sz as Int) - (k + 7));
                assert(seq![b, ..t, ..m] == seq![c, ..crate::laws::varint(v / 128)]);
                assert(b == c && seq![..t, ..m] == crate::laws::varint(v / 128));
                accepts(sz, k, c);
                top_bit_set(c);
                sdec_more(sz, k, c, t);
                ih(sz, k + 7, t, v / 128, m);
                match sdec(sz, k + 7, t) {
                    (s, Ok(y)) => by_contradiction(),
                    (s, Err(e)) => by_unfolding(more),
                }
            }
        }
    }
}

/// Where `sdec` fails with `InvalidVarint`: the bytes before the deciding
/// byte ...
#[spec]
#[decreases(bs.len())]
#[example(inv_pre(2usize, 0, seq![0xFFu8, 0xFFu8, 0x04u8, 9u8]) == seq![0xFFu8, 0xFFu8] && inv_pre(2usize, 0, seq![]) == seq![])]
#[example(inv_pre(0usize, 0, seq![128u8]) == seq![] && inv_pre(0usize, 0, seq![0u8]) == seq![] && inv_pre(1usize, 0, seq![1u8]) == seq![] && inv_pre(2usize, 0, seq![16u8, 1u8]) == seq![])]
pub fn inv_pre(sz: usize, k: Int, bs: Seq<u8>) -> Seq<u8> {
    match bs {
        [] => seq![],
        [b, t @ ..] => if rejects(sz, k, b) { seq![] } else if b & 0x80u8 == 0u8 { seq![] } else { seq![b, ..inv_pre(sz, k + 7, t)] },
    }
}

/// ... and the deciding byte.
#[spec]
#[decreases(bs.len())]
#[example(inv_byte(2usize, 0, seq![0xFFu8, 0xFFu8, 0x04u8, 9u8]) == 0x04u8 && inv_byte(2usize, 0, seq![]) == 0u8)]
#[example(inv_byte(0usize, 0, seq![218u8]) == 218u8 && inv_byte(1usize, 0, seq![1u8]) == 1u8 && inv_byte(2usize, 0, seq![16u8, 1u8]) == 16u8)]
pub fn inv_byte(sz: usize, k: Int, bs: Seq<u8>) -> u8 {
    match bs {
        [] => 0u8,
        [b, t @ ..] => if rejects(sz, k, b) { b } else if b & 0x80u8 == 0u8 { b } else { inv_byte(sz, k + 7, t) },
    }
}

/// `sdec` fails with `InvalidVarint` at a deciding byte: the bytes before it
/// run out of input, the bytes through it fail the same way on their own.
#[lemma]
#[induction(bs)]
fn sdec_inv(sz: usize, k: Int, bs: Seq<u8>, rest: Seq<u8>, e: Error) {
    requires(k >= 0 && k < 8 * (sz as Int) && sdec(sz, k, bs) == (rest, Err(e)) && eqb(e, Error::EndOfBuffer) == false);
    ensures(bs == seq![..inv_pre(sz, k, bs), inv_byte(sz, k, bs), ..rest]
        && sdec(sz, k, inv_pre(sz, k, bs)).1 == Err(Error::EndOfBuffer)
        && sdec(sz, k, seq![..inv_pre(sz, k, bs), inv_byte(sz, k, bs)]).1 == Err(e));
    match bs {
        [] => {
            sdec_nil(sz, k);
            by_contradiction();
        }
        [b, t @ ..] => {
            if rejects(sz, k, b) {
                sdec_rej(sz, k, b, t);
                sdec_rej(sz, k, b, seq![]);
                sdec_nil(sz, k);
                assert(inv_pre(sz, k, seq![b, ..t]) == seq![], { by_unfolding(inv_pre); });
                assert(inv_byte(sz, k, seq![b, ..t]) == b, { by_unfolding(inv_byte); });
                follows();
            } else if b & 0x80u8 == 0u8 {
                sdec_done(sz, k, b, t);
                by_contradiction();
            } else {
                top_bit_set_rev(b);
                more_room(sz, k, b);
                sdec_more(sz, k, b, t);
                match sdec(sz, k + 7, t) {
                    (s, Ok(y)) => by_contradiction(),
                    (s, Err(e2)) => {
                        assert(e2 == e && s == rest);
                        assert(eqb(e2, Error::EndOfBuffer) == false);
                        ih(sz, k + 7, t, s, e2);
                        let p = inv_pre(sz, k + 7, t);
                        let d = inv_byte(sz, k + 7, t);
                        assert(inv_pre(sz, k, seq![b, ..t]) == seq![b, ..p], { by_unfolding(inv_pre); });
                        assert(inv_byte(sz, k, seq![b, ..t]) == d, { by_unfolding(inv_byte); });
                        sdec_more(sz, k, b, p);
                        sdec_more(sz, k, b, seq![..p, d]);
                        match sdec(sz, k + 7, p) {
                            (s1, Ok(y1)) => by_contradiction(),
                            (s1, Err(e1)) => {
                                match sdec(sz, k + 7, seq![..p, d]) {
                                    (s3, Ok(y3)) => by_contradiction(),
                                    (s3, Err(e3)) => {
                                        assert(sdec(sz, k, seq![b, ..p]) == (s1, Err(e1)), { by_unfolding(more); });
                                        assert(sdec(sz, k, seq![b, ..p, d]) == (s3, Err(e3)), { by_unfolding(more); });
                                        follows();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `EndOfBuffer`, or `InvalidVarint` with the width `sz`.
#[spec]
#[example(err_ok(Error::EndOfBuffer, 4usize) && err_ok(Error::InvalidVarint(4usize), 4usize) && !err_ok(Error::InvalidVarint(2usize), 4usize))]
pub fn err_ok(e: Error, sz: usize) -> bool {
    match e {
        Error::EndOfBuffer => true,
        Error::InvalidVarint(n) => n == sz,
    }
}

/// `sdec` fails only with `EndOfBuffer` or `InvalidVarint(sz)`.
#[lemma]
#[induction(bs)]
fn sdec_errs(sz: usize, k: Int, bs: Seq<u8>, s: Seq<u8>, e: Error) {
    requires(sdec(sz, k, bs) == (s, Err(e)));
    ensures(err_ok(e, sz));
    match bs {
        [] => {
            sdec_nil(sz, k);
            follows();
        }
        [b, t @ ..] => {
            if rejects(sz, k, b) {
                sdec_rej(sz, k, b, t);
                follows();
            } else if b & 0x80u8 == 0u8 {
                sdec_done(sz, k, b, t);
                by_contradiction();
            } else {
                sdec_more(sz, k, b, t);
                match sdec(sz, k + 7, t) {
                    (s2, Ok(y)) => by_contradiction(),
                    (s2, Err(e2)) => {
                        ih(sz, k + 7, t, s2, e2);
                        assert(e == e2, { by_unfolding(more); });
                        rewrite(e == e2);
                        follows();
                    }
                }
            }
        }
    }
}

/// The continuation bytes `p` in front of what the rest decodes to.
#[spec]
#[decreases(p.len())]
#[example(more_all(seq![0x81u8], (seq![], Ok(2))) == (seq![], Ok(257)))]
#[example(more_all(seq![0x81u8], (seq![], Err(Error::EndOfBuffer))) == (seq![], Err(Error::EndOfBuffer)))]
pub fn more_all(p: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) -> (Seq<u8>, Result<Nat, Error>) {
    match p {
        [] => d,
        [b, t @ ..] => more(b, more_all(t, d)),
    }
}

/// Whether a decoder result is a value.
#[spec]
#[example(is_ok(Ok(3)) && !is_ok(Err(Error::EndOfBuffer)))]
pub fn is_ok(r: Result<Nat, Error>) -> bool {
    match r {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Failures pass through continuation bytes.
#[lemma]
#[induction(p)]
fn more_all_err(p: Seq<u8>, r: Seq<u8>, e: Error) {
    ensures(more_all(p, (r, Err(e))) == (r, Err(e)));
    match p {
        [] => by_unfolding(more_all),
        [b, t @ ..] => {
            ih(t, r, e);
            assert(more_all(seq![b, ..t], (r, Err(e))) == more(b, more_all(t, (r, Err(e)))), { by_unfolding(more_all); });
            by_unfolding(more);
        }
    }
}

/// Values stay values under continuation bytes.
#[lemma]
#[induction(p)]
fn more_all_ok(p: Seq<u8>, r: Seq<u8>, y: Nat) {
    ensures(is_ok(more_all(p, (r, Ok(y))).1));
    match p {
        [] => by_unfolding(more_all, is_ok),
        [b, t @ ..] => {
            ih(t, r, y);
            assert(more_all(seq![b, ..t], (r, Ok(y))) == more(b, more_all(t, (r, Ok(y)))), { by_unfolding(more_all); });
            match more_all(t, (r, Ok(y))) {
                (s1, Ok(y1)) => by_unfolding(more, is_ok),
                (s1, Err(e1)) => by_unfolding(is_ok),
            }
        }
    }
}

/// A value is no failure.
#[lemma]
fn is_ok_not_err(x: Result<Nat, Error>, e: Error) {
    requires(is_ok(x));
    ensures(x != Err(e));
    match x {
        Ok(v) => follows(),
        Err(e2) => {
            assert(is_ok(Err(e2)) == false, { by_unfolding(is_ok); });
            by_contradiction();
        }
    }
}

/// A value under continuation bytes is no failure.
#[lemma]
fn more_all_not_err(p: Seq<u8>, r: Seq<u8>, y: Nat, e: Error) {
    ensures(more_all(p, (r, Ok(y))).1 != Err(e));
    more_all_ok(p, r, y);
    is_ok_not_err(more_all(p, (r, Ok(y))).1, e);
    follows();
}

/// On bytes `p` where `sdec` runs out of input, `sdec` on `p` then `q` is
/// `sdec` on `q` from the level after `p`, under `p`'s continuation bytes.
#[lemma]
#[induction(p)]
fn sdec_eob_ext(sz: usize, k: Int, p: Seq<u8>, q: Seq<u8>) {
    requires(sdec(sz, k, p).1 == Err(Error::EndOfBuffer));
    ensures(sdec(sz, k, seq![..p, ..q]) == more_all(p, sdec(sz, k + (p.len() as Int) * 7, q)));
    match p {
        [] => {
            assert(k + 0 * 7 == k);
            assert(more_all(seq![], sdec(sz, k, q)) == sdec(sz, k, q), { by_unfolding(more_all); });
            follows();
        }
        [b, t @ ..] => {
            if rejects(sz, k, b) {
                sdec_rej(sz, k, b, t);
                by_contradiction();
            } else if b & 0x80u8 == 0u8 {
                sdec_done(sz, k, b, t);
                by_contradiction();
            } else {
                sdec_more(sz, k, b, t);
                sdec_more(sz, k, b, seq![..t, ..q]);
                match sdec(sz, k + 7, t) {
                    (s1, Ok(y1)) => by_contradiction(),
                    (s1, Err(e1)) => {
                        assert(e1 == Error::EndOfBuffer, { by_unfolding(more); });
                        ih(sz, k + 7, t, q);
                        assert(k + 7 + (t.len() as Int) * 7 == k + (seq![b, ..t].len() as Int) * 7);
                        assert(more_all(seq![b, ..t], sdec(sz, k + (seq![b, ..t].len() as Int) * 7, q))
                            == more(b, more_all(t, sdec(sz, k + (seq![b, ..t].len() as Int) * 7, q))), { by_unfolding(more_all); });
                        follows();
                    }
                }
            }
        }
    }
}

/// A single byte on which `sdec` fails with `InvalidVarint` is rejected.
#[lemma]
fn sdec_one_inv(sz: usize, k: Int, d: u8, e: Error) {
    requires(sdec(sz, k, seq![d]).1 == Err(e) && eqb(e, Error::EndOfBuffer) == false);
    ensures(rejects(sz, k, d));
    if rejects(sz, k, d) {
        follows();
    } else if d & 0x80u8 == 0u8 {
        sdec_done(sz, k, d, seq![]);
        by_contradiction();
    } else {
        sdec_more(sz, k, d, seq![]);
        sdec_nil(sz, k + 7);
        assert(more(d, (seq![], Err(Error::EndOfBuffer))) == (seq![], Err(Error::EndOfBuffer)), { by_unfolding(more); });
        by_contradiction();
    }
}

/// Two results equal to the same one are equal.
#[lemma]
fn tr3(a: (Seq<u8>, Result<Nat, Error>), b: (Seq<u8>, Result<Nat, Error>), c: (Seq<u8>, Result<Nat, Error>)) {
    requires(a == b && a == c);
    ensures(b == c);
    follows();
}

/// After incomplete bytes `p`, a byte `d` on which `sdec` fails: `sdec`
/// fails there whatever follows, leaving what follows (the step on `d`'s
/// level result `d1`).
#[lemma]
fn inv_ext_step(sz: usize, p: Seq<u8>, d: u8, rest: Seq<u8>, e: Error, d1: (Seq<u8>, Result<Nat, Error>)) {
    requires(d1 == sdec(sz, (p.len() as Int) * 7, seq![d]));
    requires(sdec(sz, 0, seq![..p, d]) == more_all(p, d1));
    requires(sdec(sz, 0, seq![..p, d, ..rest]) == more_all(p, sdec(sz, (p.len() as Int) * 7, seq![d, ..rest])));
    requires(sdec(sz, 0, seq![..p, d]).1 == Err(e) && eqb(e, Error::EndOfBuffer) == false);
    ensures(sdec(sz, 0, seq![..p, d, ..rest]) == (rest, Err(e)) && e == Error::InvalidVarint(sz));
    match d1 {
        (s1, Ok(v1)) => {
            more_all_ok(p, s1, v1);
            more_all_not_err(p, s1, v1, e);
            by_contradiction();
        }
        (s1, Err(e1)) => {
            more_all_err(p, s1, e1);
            assert(sdec(sz, 0, seq![..p, d]) == (s1, Err(e1)));
            assert(sdec(sz, 0, seq![..p, d]).1 == Err(e1));
            assert(e1 == e);
            assert(eqb(e1, Error::EndOfBuffer) == false);
            sdec_one_inv(sz, (p.len() as Int) * 7, d, e1);
            sdec_rej(sz, (p.len() as Int) * 7, d, seq![]);
            sdec_rej(sz, (p.len() as Int) * 7, d, rest);
            assert(sdec(sz, (p.len() as Int) * 7, seq![d]) == (s1, Err(e1)));
            tr3(sdec(sz, (p.len() as Int) * 7, seq![d]), (s1, Err(e1)), (seq![], Err(Error::InvalidVarint(sz))));
            assert(e1 == Error::InvalidVarint(sz));
            assert(e == Error::InvalidVarint(sz), { rewrite_rev(e1 == e); follows(); });
            more_all_err(p, rest, Error::InvalidVarint(sz));
            follows();
        }
    }
}

/// After incomplete bytes `p`, a byte `d` on which `sdec` fails: `sdec`
/// fails there whatever follows.
#[lemma]
fn sdec_inv_ext(sz: usize, p: Seq<u8>, d: u8, rest: Seq<u8>, e: Error) {
    requires(sdec(sz, 0, p).1 == Err(Error::EndOfBuffer));
    requires(sdec(sz, 0, seq![..p, d]).1 == Err(e) && eqb(e, Error::EndOfBuffer) == false);
    ensures(sdec(sz, 0, seq![..p, d, ..rest]) == (rest, Err(e)) && e == Error::InvalidVarint(sz));
    sdec_eob_ext(sz, 0, p, seq![d]);
    sdec_eob_ext(sz, 0, p, seq![d, ..rest]);
    assert(0 + (p.len() as Int) * 7 == (p.len() as Int) * 7);
    inv_ext_step(sz, p, d, rest, e, sdec(sz, (p.len() as Int) * 7, seq![d]));
    follows();
}

/// `read`'s fast path is the decoder's first step.
#[lemma]
fn sdec0_is_sdec(sz: usize, bs: Seq<u8>) {
    requires(sz >= 1usize);
    ensures(sdec0(sz, bs) == sdec(sz, 0, bs));
    match bs {
        [] => {
            sdec_nil(sz, 0);
            by_unfolding(sdec0);
        }
        [b, t @ ..] => {
            if b & 0x80u8 == 0u8 {
                top_bit_lt(b);
                accepts(sz, 0, b);
                sdec_done(sz, 0, b, t);
                by_unfolding(sdec0);
            } else {
                by_unfolding(sdec0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `read_cfg` in numbers
// ---------------------------------------------------------------------------

/// `read_cfg`'s result and the bytes it leaves, from the decoder's.
#[spec]
#[example(cfg_view::<T>((seq![1u8], Ok(5))) == (Ok(UInt(T::from(5u8))), seq![1u8]))]
#[example(cfg_view::<T>((seq![], Err(Error::EndOfBuffer))) == (Err(Error::EndOfBuffer), seq![]))]
pub fn cfg_view<T: UPrim>(d: (Seq<u8>, Result<Nat, Error>)) -> (Result<UInt<T>, Error>, Seq<u8>) {
    match d {
        (s, Ok(v)) => (Ok(UInt(v as T)), s),
        (s, Err(e)) => (Err(e), s),
    }
}

/// A number below 2^(bits of the type) survives the round trip through it.
#[lemma]
fn cast_back<T: UPrim>(v: Nat) {
    requires((v as Int) < pow2(8 * (T::SIZE as Int)));
    ensures(((v as T) as Nat) == v);
    follows();
}

/// A value of the type, through `Nat` and back, is itself; it is below
/// 2^(bits of the type).
#[lemma]
fn nat_back<T: UPrim>(x: T) {
    ensures(((x as Nat) as T) == x && (x as Int) < pow2(8 * (T::SIZE as Int)));
    follows();
}



/// `read_cfg` is the decoder from zero bits (per width below).
#[lemma]
fn read_cfg_spec<T: UPrim>(bytes: Seq<u8>) {
    ensures({ let mut b = bytes; let r = UInt::<T>::read_cfg(&mut b, &()); (b, r) } == wrap::<T>(view_t::<T>(sdec(T::SIZE, 0, bytes))));
}

/// `read` in numbers, as a pair.
#[lemma]
fn read_raw__u32(bytes: Seq<u8>) {
    ensures(crate::varint::read__u32(bytes) == view_t::<u32>(sdec(4usize, 0, bytes)));
    read_spec__u32(bytes);
    follows();
}

/// `read` in numbers, as a pair.
#[lemma]
fn read_raw__u16(bytes: Seq<u8>) {
    ensures(crate::varint::read__u16(bytes) == view_t::<u16>(sdec(2usize, 0, bytes)));
    read_spec__u16(bytes);
    follows();
}

/// `read` in numbers, as a pair.
#[lemma]
fn read_raw__u64(bytes: Seq<u8>) {
    ensures(crate::varint::read__u64(bytes) == view_t::<u64>(sdec(8usize, 0, bytes)));
    read_spec__u64(bytes);
    follows();
}

#[lemma]
fn read_cfg_spec_d__u32(bytes: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(crate::varint::read__u32(bytes) == view_t::<u32>(d));
    ensures({ let mut b = bytes; let r = UInt::<u32>::read_cfg(&mut b, &()); (b, r) } == wrap::<u32>(view_t::<u32>(d)));
    match d {
        (s, Ok(v)) => {
            assert(view_t::<u32>((s, Ok(v))) == (s, Ok(v as u32)), { by_unfolding(view_t::<u32>); });
            assert(crate::varint::read__u32(bytes) == (s, Ok(v as u32)));
            unfold(crate::varint::UInt__u32::read_cfg);
            rewrite(crate::varint::read__u32(bytes) == (s, Ok(v as u32)));
            by_unfolding(wrap::<u32>, view_t::<u32>);
        }
        (s, Err(e)) => {
            assert(view_t::<u32>((s, Err(e))) == (s, Err(e)), { by_unfolding(view_t::<u32>); });
            assert(crate::varint::read__u32(bytes) == (s, Err(e)));
            unfold(crate::varint::UInt__u32::read_cfg);
            rewrite(crate::varint::read__u32(bytes) == (s, Err(e)));
            by_unfolding(wrap::<u32>, view_t::<u32>);
        }
    }
}

#[lemma]
fn read_cfg_spec_d__u16(bytes: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(crate::varint::read__u16(bytes) == view_t::<u16>(d));
    ensures({ let mut b = bytes; let r = UInt::<u16>::read_cfg(&mut b, &()); (b, r) } == wrap::<u16>(view_t::<u16>(d)));
    match d {
        (s, Ok(v)) => {
            assert(view_t::<u16>((s, Ok(v))) == (s, Ok(v as u16)), { by_unfolding(view_t::<u16>); });
            assert(crate::varint::read__u16(bytes) == (s, Ok(v as u16)));
            unfold(crate::varint::UInt__u16::read_cfg);
            rewrite(crate::varint::read__u16(bytes) == (s, Ok(v as u16)));
            by_unfolding(wrap::<u16>, view_t::<u16>);
        }
        (s, Err(e)) => {
            assert(view_t::<u16>((s, Err(e))) == (s, Err(e)), { by_unfolding(view_t::<u16>); });
            assert(crate::varint::read__u16(bytes) == (s, Err(e)));
            unfold(crate::varint::UInt__u16::read_cfg);
            rewrite(crate::varint::read__u16(bytes) == (s, Err(e)));
            by_unfolding(wrap::<u16>, view_t::<u16>);
        }
    }
}

#[lemma]
fn read_cfg_spec_d__u64(bytes: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(crate::varint::read__u64(bytes) == view_t::<u64>(d));
    ensures({ let mut b = bytes; let r = UInt::<u64>::read_cfg(&mut b, &()); (b, r) } == wrap::<u64>(view_t::<u64>(d)));
    match d {
        (s, Ok(v)) => {
            assert(view_t::<u64>((s, Ok(v))) == (s, Ok(v as u64)), { by_unfolding(view_t::<u64>); });
            assert(crate::varint::read__u64(bytes) == (s, Ok(v as u64)));
            unfold(crate::varint::UInt__u64::read_cfg);
            rewrite(crate::varint::read__u64(bytes) == (s, Ok(v as u64)));
            by_unfolding(wrap::<u64>, view_t::<u64>);
        }
        (s, Err(e)) => {
            assert(view_t::<u64>((s, Err(e))) == (s, Err(e)), { by_unfolding(view_t::<u64>); });
            assert(crate::varint::read__u64(bytes) == (s, Err(e)));
            unfold(crate::varint::UInt__u64::read_cfg);
            rewrite(crate::varint::read__u64(bytes) == (s, Err(e)));
            by_unfolding(wrap::<u64>, view_t::<u64>);
        }
    }
}

#[lemma]
fn read_cfg_spec__u32(bytes: Seq<u8>) {
    ensures({ let mut b = bytes; let r = UInt::<u32>::read_cfg(&mut b, &()); (b, r) } == wrap::<u32>(view_t::<u32>(sdec(4usize, 0, bytes))));
    read_raw__u32(bytes);
    read_cfg_spec_d__u32(bytes, sdec(4usize, 0, bytes));
    follows();
}

#[lemma]
fn read_cfg_spec__u16(bytes: Seq<u8>) {
    ensures({ let mut b = bytes; let r = UInt::<u16>::read_cfg(&mut b, &()); (b, r) } == wrap::<u16>(view_t::<u16>(sdec(2usize, 0, bytes))));
    read_raw__u16(bytes);
    read_cfg_spec_d__u16(bytes, sdec(2usize, 0, bytes));
    follows();
}

#[lemma]
fn read_cfg_spec__u64(bytes: Seq<u8>) {
    ensures({ let mut b = bytes; let r = UInt::<u64>::read_cfg(&mut b, &()); (b, r) } == wrap::<u64>(view_t::<u64>(sdec(8usize, 0, bytes))));
    read_raw__u64(bytes);
    read_cfg_spec_d__u64(bytes, sdec(8usize, 0, bytes));
    follows();
}

/// Equal results wrap to equal results.
#[lemma]
fn wrap_eq<T: UPrim>(x: (Seq<u8>, Result<T, Error>), y: (Seq<u8>, Result<T, Error>)) {
    requires(x == y);
    ensures(wrap::<T>(x) == wrap::<T>(y));
    rewrite(x == y);
    follows();
}

/// `read_cfg`'s result from the decoder's.
#[spec]
#[example(cfg_r::<T>(Ok(5)) == Ok(UInt(T::from(5u8))) && cfg_r::<T>(Err(Error::EndOfBuffer)) == Err(Error::EndOfBuffer))]
pub fn cfg_r<T: UPrim>(x: Result<Nat, Error>) -> Result<UInt<T>, Error> {
    match x {
        Ok(v) => Ok(UInt(v as T)),
        Err(e) => Err(e),
    }
}

/// `read_cfg`'s pair, component by component.
#[lemma]
fn wv_split<T: UPrim>(d: (Seq<u8>, Result<Nat, Error>)) {
    ensures(wrap::<T>(view_t::<T>(d)) == (d.0, cfg_r::<T>(d.1)));
    match d {
        (s, Ok(v)) => by_unfolding(wrap::<T>, view_t::<T>, cfg_r::<T>),
        (s, Err(e)) => by_unfolding(wrap::<T>, view_t::<T>, cfg_r::<T>),
    }
}

/// A failure of `read_cfg` is the decoder's failure.
#[lemma]
fn cfg_r_err<T: UPrim>(x: Result<Nat, Error>, e: Error) {
    requires(cfg_r::<T>(x) == Err(e));
    ensures(x == Err(e));
    match x {
        Ok(v) => {
            assert(cfg_r::<T>(Ok(v)) == Ok(UInt(v as T)), { by_unfolding(cfg_r::<T>); });
            by_contradiction();
        }
        Err(e2) => {
            assert(cfg_r::<T>(Err(e2)) == Err(e2), { by_unfolding(cfg_r::<T>); });
            follows();
        }
    }
}

/// `read_cfg`'s result and rest are the decoder's.
#[lemma]
fn rc_parts<T: UPrim>(bytes: Seq<u8>) {
    ensures({ let mut q = bytes; UInt::<T>::read_cfg(&mut q, &()) } == cfg_r::<T>(sdec(T::SIZE, 0, bytes).1)
        && { let mut q = bytes; let r = UInt::<T>::read_cfg(&mut q, &()); q } == sdec(T::SIZE, 0, bytes).0);
    read_cfg_spec::<T>(bytes);
    wv_split::<T>(sdec(T::SIZE, 0, bytes));
    follows();
}

/// A decoded value, as `read_cfg` returns it.
#[lemma]
fn wv_ok<T: UPrim>(d: (Seq<u8>, Result<Nat, Error>), s: Seq<u8>, v: Nat) {
    requires(d == (s, Ok(v)));
    ensures(wrap::<T>(view_t::<T>(d)) == (s, Ok(UInt(v as T))));
    rewrite(d == (s, Ok(v)));
    by_unfolding(wrap::<T>, view_t::<T>);
}

/// A failure, as `read_cfg` returns it.
#[lemma]
fn wv_err<T: UPrim>(d: (Seq<u8>, Result<Nat, Error>), s: Seq<u8>, e: Error) {
    requires(d == (s, Err(e)));
    ensures(wrap::<T>(view_t::<T>(d)) == (s, Err(e)));
    rewrite(d == (s, Err(e)));
    by_unfolding(wrap::<T>, view_t::<T>);
}



// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

/// A decoder has read fewer bits than its type has.
#[lift_attach(crate::varint::Decoder)]
fn decoder_state<U: UPrim>() {
    invariant(self.bits_read < U::SIZE * 8 && self.bits_read % 7usize == 0usize);
}

/// A new decoder has read nothing.
#[lift_attach(crate::varint::Decoder::new)]
fn new_summary<U: UPrim>() {
    ensures(|ret: Decoder<U>| (ret.result as Int) == 0 && ret.bits_read == 0usize);
}

/// `feed`: the facts its checks rely on.
#[lift_attach(crate::varint::Decoder::feed)]
fn feed_facts<U: UPrim>() {
    opaque();
    at_start! {
        crate::proof::top_bit(byte);
        crate::proof::top_bit_lt(byte);
        crate::proof::rejects_code::<U>(self.bits_read, byte);
        crate::proof::mod7_step(self.bits_read);
        assert((self.bits_read <= U::SIZE * 8) == true);
        assert(DATA_BITS_PER_BYTE == 7);
    }
    ensures(|ret: (Decoder<U>, Result<Option<U>, Error>)| crate::proof::feed_classified::<U>(ret.1)
        // what `feed` returns and the state it leaves, in its own terms
        && ret.1 == crate::proof::feed_res::<U>(self.result, self.bits_read, byte)
        && ret.0.result == crate::proof::feed_acc::<U>(self.result, self.bits_read, byte)
        && ret.0.bits_read == crate::proof::feed_bits::<U>(self.bits_read, byte));
}

/// `write`'s staging loop: `val` loses seven bits per byte staged, and what is
/// left fits in the bits not yet staged.
#[lift_attach(crate::varint::write, loop_nr = 0)]
fn write_loop<T: UPrim>() {
    invariant(7 * (len as Int) <= 8 * (T::SIZE as Int) && (val as Int) < pow2(8 * (T::SIZE as Int) - 7 * (len as Int)));
    invariant(seq![..crate::proof::staged(bytes, len as Nat), ..crate::laws::varint(val as Nat)] == crate::laws::varint(value as Nat));
    decreases(val as Int);
    crate::proof::shift7(val as Int, 8 * (T::SIZE as Int) - 7 * (len as Int));
    crate::proof::varint_step(val as Nat);
    crate::proof::stage_byte::<T>(val);
    crate::proof::staged_set(bytes, len, val.as_u8() | CONTINUATION_BIT_MASK);
    crate::proof::stage_step(crate::proof::staged(bytes, len as Nat), val.as_u8() | CONTINUATION_BIT_MASK, val as Nat, value as Nat,
        crate::proof::staged({ let mut b = bytes; b[len] = val.as_u8() | CONTINUATION_BIT_MASK; b }, len as Nat + 1));
    after_loop! {
        crate::proof::varint_small(val as Nat);
        crate::proof::byte_of_value::<T>(val);
        crate::proof::staged_set(bytes, len, val.as_u8());
        let x = val.as_u8();
        let bb = { let mut b = bytes; b[len] = x; b };
        calc! {
            crate::__lift_model::bufmut_put_slice(buf, &bb[..len + 1])
                == seq![..buf, ..crate::proof::staged(bb, len as Nat + 1)] by {
                    crate::proof::put_staged(buf, bb, len + 1);
                };
                == seq![..buf, ..crate::proof::staged(bytes, len as Nat), x] by { follows(); };
                == seq![..buf, ..crate::proof::staged(bytes, len as Nat), ..crate::laws::varint(val as Nat)] by { follows(); };
                == seq![..buf, ..crate::laws::varint(value as Nat)] by { follows(); };
        }
    }
}

/// `size` is the length of the encoding.
#[lift_attach(crate::varint::size)]
fn size_summary<T: UPrim>() {
    at_start! {
        crate::proof::lz_bits::<T>(value);
        crate::proof::varint_len(value as Nat, (8 * (T::SIZE as Int) - (value.leading_zeros() as Int)) as Nat);
        crate::proof::size_arith(8 * T::SIZE - value.leading_zeros() as usize, DATA_BITS_PER_BYTE, crate::laws::varint(value as Nat).len());
    }
    ensures(|ret: usize| (ret as Nat) == crate::laws::varint(value as Nat).len());
}

/// `write` appends the LEB128 encoding of `value`.
#[lift_attach(crate::varint::write)]
fn write_summary<T: UPrim>() {
    at_start! {
        crate::proof::staged_none([0u8; 19]);
        crate::proof::fast_path::<T>(value, buf);
    }
    ensures(|ret: Seq<u8>| ret == seq![..buf, ..crate::laws::varint(value as Nat)]);
}

/// `read`'s decoder loop consumes a byte per turn.
#[lift_attach(crate::varint::read, loop_nr = 0)]
fn read_loop<T: UPrim>() {
    decreases(buf.len());
    ensures(|ret: (Seq<u8>, Result<T, Error>)| crate::proof::classified::<T>(ret.1));
}


/// `read` fails only with `EndOfBuffer` or `InvalidVarint(SIZE)`; callers
/// use it through its summary and `read_spec`.
#[lift_attach(crate::varint::read)]
fn read_summary<T: UPrim>() {
    opaque();
    ensures(|ret: (Seq<u8>, Result<T, Error>)| crate::proof::classified::<T>(ret.1));
}


// ---------------------------------------------------------------------------
// Laws
// ---------------------------------------------------------------------------

/// `UInt(x).write` is `write(x, ..)`, whose summary is the law.
#[proof]
fn write_appends_leb128<T: UPrim>(v: UInt<T>, buf: Seq<u8>) {
    unfold(crate::varint::UInt::<T>::write);
    follows();
}

/// `size`: the length of the encoding, at most ⌈bits/7⌉.
#[lemma]
fn encode_size_of<T: UPrim>(x: T) {
    ensures(crate::varint::size::<T>(x) as Nat == crate::laws::varint(x as Nat).len() && crate::varint::size::<T>(x) as Nat <= (8 * T::SIZE as Nat + 6) / 7);
    // the call's summary becomes a fact
    let n = crate::varint::size::<T>(x);
    lz_bits::<T>(x);
    let e = (8 * (T::SIZE as Int) - (x.leading_zeros() as Int)) as Nat;
    if (x as Nat) == 0 {
        assert((x.leading_zeros() as Int) == 8 * (T::SIZE as Int), {
            if (x.leading_zeros() as Int) == 8 * (T::SIZE as Int) { follows(); } else { by_contradiction(); }
        });
        assert(e == 0);
        varint_len(x as Nat, e);
        follows();
    } else {
        assert(pow2((e as Int) - 1) <= (x as Int) && (x as Int) < pow2(e as Int));
        varint_len(x as Nat, e);
        follows();
    }
}

/// `encode_size` is `size`, whose summary is the length; the bound is the
/// length of an encoding of at most 8·SIZE bits.
#[proof]
fn encode_size_counts_bytes<T: UPrim>(v: UInt<T>) {
    encode_size_of::<T>(v.0);
    unfold(crate::varint::UInt::<T>::encode_size);
    follows();
}

/// By `sdec_errs`.
#[proof]
fn read_errors_are_classified<T: UPrim>(bytes: Seq<u8>, e: Error) {
    read_cfg_spec::<T>(bytes);
    match sdec(T::SIZE, 0, bytes) {
        (s, Ok(v)) => {
            wv_ok::<T>(sdec(T::SIZE, 0, bytes), s, v);
            by_contradiction();
        }
        (s, Err(e2)) => {
            wv_err::<T>(sdec(T::SIZE, 0, bytes), s, e2);
            sdec_errs(T::SIZE, 0, bytes, s, e2);
            assert(e == e2);
            match e {
                Error::EndOfBuffer => follows(),
                Error::InvalidVarint(n) => {
                    assert(err_ok(Error::InvalidVarint(n), T::SIZE));
                    follows();
                }
            }
        }
    }
}

/// By `sdec_varint`.
#[proof]
fn read_round_trips<T: UPrim>(x: Nat, rest: Seq<u8>) {
    read_cfg_spec::<T>(seq![..crate::laws::varint(x), ..rest]);
    sdec_varint(T::SIZE, 0, x, rest);
    wv_ok::<T>(sdec(T::SIZE, 0, seq![..crate::laws::varint(x), ..rest]), rest, x);
    follows();
}

/// By `sdec_ok`: what the decoder accepts is an encoding.
#[proof]
fn read_accepts_only_encodings<T: UPrim>(bytes: Seq<u8>, x: T, rest: Seq<u8>) {
    read_cfg_spec::<T>(bytes);
    match sdec(T::SIZE, 0, bytes) {
        (s, Ok(v)) => {
            wv_ok::<T>(sdec(T::SIZE, 0, bytes), s, v);
            sdec_ok(T::SIZE, 0, bytes, s, v);
            cast_back::<T>(v);
            assert((v as T) == x && s == rest);
            follows();
        }
        (s, Err(e)) => {
            wv_err::<T>(sdec(T::SIZE, 0, bytes), s, e);
            by_contradiction();
        }
    }
}

/// By `sdec_prefix`.
#[proof]
fn read_end_of_buffer_on_prefixes<T: UPrim>(bytes: Seq<u8>, x: Nat, more: Seq<u8>) {
    read_cfg_spec::<T>(bytes);
    sdec_prefix(T::SIZE, 0, bytes, x, more);
    match sdec(T::SIZE, 0, bytes) {
        (s, Ok(v)) => by_contradiction(),
        (s, Err(e)) => {
            wv_err::<T>(sdec(T::SIZE, 0, bytes), s, e);
            follows();
        }
    }
}

/// By `sdec_eob`: the byte 1 completes the bytes to the encoding of
/// `eob_wit(bytes)`, a value of the type.
#[proof]
fn read_end_of_buffer_only_on_prefixes<T: UPrim>(bytes: Seq<u8>) {
    rc_parts::<T>(bytes);
    cfg_r_err::<T>(sdec(T::SIZE, 0, bytes).1, Error::EndOfBuffer);
    match sdec(T::SIZE, 0, bytes) {
        (s, Ok(v)) => by_contradiction(),
        (s, Err(e)) => {
            sdec_eob(T::SIZE, 0, bytes, s);
            let w = eob_wit(bytes);
            assert(exists(|x: Nat| (x as Int) < pow2(8 * (T::SIZE as Int)) && seq![..bytes, 1u8] == crate::laws::varint(x)), {
                witness(w);
                follows();
            });
            follows();
        }
    }
}

/// By `sdec_inv_ext`: after the incomplete bytes `p`, the byte `d` is
/// rejected at the level `p` reaches, whatever follows.
#[proof]
fn read_invalid_stops_at_the_deciding_byte<T: UPrim>(bytes: Seq<u8>, p: Seq<u8>, d: u8, rest: Seq<u8>, n: usize) {
    rewrite(bytes == seq![..p, d, ..rest]);
    rc_parts::<T>(p);
    rc_parts::<T>(seq![..p, d]);
    cfg_r_err::<T>(sdec(T::SIZE, 0, p).1, Error::EndOfBuffer);
    cfg_r_err::<T>(sdec(T::SIZE, 0, seq![..p, d]).1, Error::InvalidVarint(n));
    assert(eqb(Error::InvalidVarint(n), Error::EndOfBuffer) == false);
    sdec_inv_ext(T::SIZE, p, d, rest, Error::InvalidVarint(n));
    read_cfg_spec::<T>(seq![..p, d, ..rest]);
    wv_err::<T>(sdec(T::SIZE, 0, seq![..p, d, ..rest]), rest, Error::InvalidVarint(n));
    follows();
}

// ---------------------------------------------------------------------------
// Determinacy (DESIGN.md §15.5): the laws pin each boundary function
// ---------------------------------------------------------------------------


/// `read_cfg` is pinned by the read laws: on the encoding of a value the
/// round trip fixes it; on an incomplete encoding the two `EndOfBuffer`
/// laws; on invalid bytes, the bytes before the deciding byte are
/// incomplete for any implementation that satisfies the laws, and the
/// deciding byte is invalid for it, so the stopping law fixes the result.
#[proof(complete = crate::varint::UInt__u32::read_cfg)]
fn read_cfg_determined__u32(buf: Seq<u8>, _c: &()) {
    assert(_c == &());
    rc_parts::<u32>(buf);
    match sdec(4usize, 0, buf) {
        (s, Ok(v)) => {
            sdec_ok(4usize, 0, buf, s, v);
            use_hyp(0, v, s);
            follows();
        }
        (s, Err(e)) => {
            sdec_errs(4usize, 0, buf, s, e);
            if eqb(e, Error::EndOfBuffer) {
                assert(e == Error::EndOfBuffer);
                sdec_eob(4usize, 0, buf, s);
                use_hyp(2, buf, eob_wit(buf), seq![1u8]);
                use_hyp(3, buf);
                follows();
            } else {
                assert(e == Error::InvalidVarint(4usize), {
                    match e {
                        Error::EndOfBuffer => by_contradiction(),
                        Error::InvalidVarint(n0) => {
                            assert(err_ok(Error::InvalidVarint(n0), 4usize));
                            by_unfolding(err_ok);
                        }
                    }
                });
                sdec_inv(4usize, 0, buf, s, e);
                eob_prefix_of(4usize, 0, inv_pre(4usize, 0, buf));
                use_hyp(2, inv_pre(4usize, 0, buf), eob_wit(inv_pre(4usize, 0, buf)), seq![1u8]);
                match { let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; UInt::<u32>::read_cfg(&mut b, &()) } {
                    Ok(u) => {
                        // canonicity for the implementation: the bytes would be an
                        // encoding, which the decoder accepts
                        use_hyp(1, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)], u.0,
                            { let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = UInt::<u32>::read_cfg(&mut b, &()); b });
                        sdec_varint(4usize, 0, u.0 as Nat, { let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = UInt::<u32>::read_cfg(&mut b, &()); b });
                        sdec_same_input(4usize, 0, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)],
                            seq![..crate::laws::varint(u.0 as Nat), ..{ let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = UInt::<u32>::read_cfg(&mut b, &()); b }]);
                        tr3(sdec(4usize, 0, seq![..crate::laws::varint(u.0 as Nat), ..{ let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = UInt::<u32>::read_cfg(&mut b, &()); b }]),
                            sdec(4usize, 0, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]),
                            ({ let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = UInt::<u32>::read_cfg(&mut b, &()); b }, Ok(u.0 as Nat)));
                        by_contradiction();
                    }
                    Err(e2) => {
                        if eqb(e2, Error::EndOfBuffer) {
                            // the implementation runs out of input only on a proper
                            // prefix of an encoding, where the decoder does too
                            assert(e2 == Error::EndOfBuffer);
                            use_hyp(3, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]);
                            eob_of_incomplete::<u32>(seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]);
                            by_contradiction();
                        } else {
                            use_hyp(5, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)], e2);
                            assert(e2 == Error::InvalidVarint(4usize));
                            use_hyp(4, buf, inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf), s, 4usize);
                            rc_parts::<u32>(inv_pre(4usize, 0, buf));
                            rc_parts::<u32>(seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]);
                            read_invalid_stops_at_the_deciding_byte__u32(buf, inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf), s, 4usize);
                            follows();
                        }
                    }
                }
            }
        }
    }
}

/// `read_cfg` is pinned by the read laws: on the encoding of a value the
/// round trip fixes it; on an incomplete encoding the two `EndOfBuffer`
/// laws; on invalid bytes, the bytes before the deciding byte are
/// incomplete for any implementation that satisfies the laws, and the
/// deciding byte is invalid for it, so the stopping law fixes the result.
#[proof(complete = crate::varint::UInt__u16::read_cfg)]
fn read_cfg_determined__u16(buf: Seq<u8>, _c: &()) {
    assert(_c == &());
    rc_parts::<u16>(buf);
    match sdec(2usize, 0, buf) {
        (s, Ok(v)) => {
            sdec_ok(2usize, 0, buf, s, v);
            use_hyp(0, v, s);
            follows();
        }
        (s, Err(e)) => {
            sdec_errs(2usize, 0, buf, s, e);
            if eqb(e, Error::EndOfBuffer) {
                assert(e == Error::EndOfBuffer);
                sdec_eob(2usize, 0, buf, s);
                use_hyp(2, buf, eob_wit(buf), seq![1u8]);
                use_hyp(3, buf);
                follows();
            } else {
                assert(e == Error::InvalidVarint(2usize), {
                    match e {
                        Error::EndOfBuffer => by_contradiction(),
                        Error::InvalidVarint(n0) => {
                            assert(err_ok(Error::InvalidVarint(n0), 2usize));
                            by_unfolding(err_ok);
                        }
                    }
                });
                sdec_inv(2usize, 0, buf, s, e);
                eob_prefix_of(2usize, 0, inv_pre(2usize, 0, buf));
                use_hyp(2, inv_pre(2usize, 0, buf), eob_wit(inv_pre(2usize, 0, buf)), seq![1u8]);
                match { let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; UInt::<u16>::read_cfg(&mut b, &()) } {
                    Ok(u) => {
                        // canonicity for the implementation: the bytes would be an
                        // encoding, which the decoder accepts
                        use_hyp(1, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)], u.0,
                            { let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = UInt::<u16>::read_cfg(&mut b, &()); b });
                        sdec_varint(2usize, 0, u.0 as Nat, { let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = UInt::<u16>::read_cfg(&mut b, &()); b });
                        sdec_same_input(2usize, 0, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)],
                            seq![..crate::laws::varint(u.0 as Nat), ..{ let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = UInt::<u16>::read_cfg(&mut b, &()); b }]);
                        tr3(sdec(2usize, 0, seq![..crate::laws::varint(u.0 as Nat), ..{ let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = UInt::<u16>::read_cfg(&mut b, &()); b }]),
                            sdec(2usize, 0, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]),
                            ({ let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = UInt::<u16>::read_cfg(&mut b, &()); b }, Ok(u.0 as Nat)));
                        by_contradiction();
                    }
                    Err(e2) => {
                        if eqb(e2, Error::EndOfBuffer) {
                            // the implementation runs out of input only on a proper
                            // prefix of an encoding, where the decoder does too
                            assert(e2 == Error::EndOfBuffer);
                            use_hyp(3, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]);
                            eob_of_incomplete::<u16>(seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]);
                            by_contradiction();
                        } else {
                            use_hyp(5, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)], e2);
                            assert(e2 == Error::InvalidVarint(2usize));
                            use_hyp(4, buf, inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf), s, 2usize);
                            rc_parts::<u16>(inv_pre(2usize, 0, buf));
                            rc_parts::<u16>(seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]);
                            read_invalid_stops_at_the_deciding_byte__u16(buf, inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf), s, 2usize);
                            follows();
                        }
                    }
                }
            }
        }
    }
}

/// `read_cfg` is pinned by the read laws: on the encoding of a value the
/// round trip fixes it; on an incomplete encoding the two `EndOfBuffer`
/// laws; on invalid bytes, the bytes before the deciding byte are
/// incomplete for any implementation that satisfies the laws, and the
/// deciding byte is invalid for it, so the stopping law fixes the result.
#[proof(complete = crate::varint::UInt__u64::read_cfg)]
fn read_cfg_determined__u64(buf: Seq<u8>, _c: &()) {
    assert(_c == &());
    rc_parts::<u64>(buf);
    match sdec(8usize, 0, buf) {
        (s, Ok(v)) => {
            sdec_ok(8usize, 0, buf, s, v);
            use_hyp(0, v, s);
            follows();
        }
        (s, Err(e)) => {
            sdec_errs(8usize, 0, buf, s, e);
            if eqb(e, Error::EndOfBuffer) {
                assert(e == Error::EndOfBuffer);
                sdec_eob(8usize, 0, buf, s);
                use_hyp(2, buf, eob_wit(buf), seq![1u8]);
                use_hyp(3, buf);
                follows();
            } else {
                assert(e == Error::InvalidVarint(8usize), {
                    match e {
                        Error::EndOfBuffer => by_contradiction(),
                        Error::InvalidVarint(n0) => {
                            assert(err_ok(Error::InvalidVarint(n0), 8usize));
                            by_unfolding(err_ok);
                        }
                    }
                });
                sdec_inv(8usize, 0, buf, s, e);
                eob_prefix_of(8usize, 0, inv_pre(8usize, 0, buf));
                use_hyp(2, inv_pre(8usize, 0, buf), eob_wit(inv_pre(8usize, 0, buf)), seq![1u8]);
                match { let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; UInt::<u64>::read_cfg(&mut b, &()) } {
                    Ok(u) => {
                        // canonicity for the implementation: the bytes would be an
                        // encoding, which the decoder accepts
                        use_hyp(1, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)], u.0,
                            { let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = UInt::<u64>::read_cfg(&mut b, &()); b });
                        sdec_varint(8usize, 0, u.0 as Nat, { let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = UInt::<u64>::read_cfg(&mut b, &()); b });
                        sdec_same_input(8usize, 0, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)],
                            seq![..crate::laws::varint(u.0 as Nat), ..{ let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = UInt::<u64>::read_cfg(&mut b, &()); b }]);
                        tr3(sdec(8usize, 0, seq![..crate::laws::varint(u.0 as Nat), ..{ let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = UInt::<u64>::read_cfg(&mut b, &()); b }]),
                            sdec(8usize, 0, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]),
                            ({ let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = UInt::<u64>::read_cfg(&mut b, &()); b }, Ok(u.0 as Nat)));
                        by_contradiction();
                    }
                    Err(e2) => {
                        if eqb(e2, Error::EndOfBuffer) {
                            // the implementation runs out of input only on a proper
                            // prefix of an encoding, where the decoder does too
                            assert(e2 == Error::EndOfBuffer);
                            use_hyp(3, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]);
                            eob_of_incomplete::<u64>(seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]);
                            by_contradiction();
                        } else {
                            use_hyp(5, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)], e2);
                            assert(e2 == Error::InvalidVarint(8usize));
                            use_hyp(4, buf, inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf), s, 8usize);
                            rc_parts::<u64>(inv_pre(8usize, 0, buf));
                            rc_parts::<u64>(seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]);
                            read_invalid_stops_at_the_deciding_byte__u64(buf, inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf), s, 8usize);
                            follows();
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signed integers: ZigZag
// ---------------------------------------------------------------------------

/// ZigZag's bit twiddling is used through its lemmas in numbers
/// (`as_zigzag_val`, `un_zigzag_val`, `unzz_num`), which unfold it.
#[lift_attach(crate::varint::as_zigzag)]
fn as_zigzag_summary() {
    opaque();
}

/// (See `as_zigzag_summary`.)
#[lift_attach(crate::varint::un_zigzag)]
fn un_zigzag_summary() {
    opaque();
}

/// `SInt::read_cfg` is used through `src_parts` and `sread_rt`, which
/// unfold it.
#[lift_attach(crate::varint::SInt::read_cfg)]
fn sread_summary<S: SPrim>() {
    opaque();
}

/// A byte's complement in numbers.
#[lemma]
fn not_val_u8(b: u8) {
    ensures(((b ^ 255u8) as Int) == 255 - (b as Int));
    by_cases(b, 0..=255);
}

/// ZigZag's definition (it is opaque in proofs: its uses stay folded).
#[lemma]
fn zigzag_def(i: Int) {
    ensures((crate::laws::zigzag(i) as Int) == (if i >= 0 { 2 * i } else { -2 * i - 1 }));
    by_unfolding(crate::laws::zigzag);
}

/// ZigZag is one-to-one: even and odd numbers never meet, and on each side
/// it is a line.
#[lemma]
fn zigzag_inj(a: Int, b: Int) {
    requires(crate::laws::zigzag(a) == crate::laws::zigzag(b));
    ensures(a == b);
    zigzag_def(a);
    zigzag_def(b);
    by_cases(a >= 0, b >= 0, a + b < 0);
}

/// `as_zigzag` in numbers: the ZigZag of the value (per width below).
#[lemma]
fn as_zigzag_val<S: SPrim>(x: S) {
    ensures((x.as_zigzag() as Int) == crate::laws::zigzag(x as Int));
}

/// `un_zigzag` in numbers: the value whose ZigZag is `v` (per width below).
#[lemma]
fn un_zigzag_val<S: SPrim>(v: S::UnsignedEquivalent) {
    ensures(crate::laws::zigzag(S::un_zigzag(v) as Int) == (v as Int));
}

/// A signed value is determined by its number.
#[lemma]
fn sval_inj<S: SPrim>(x: S, y: S) {
    requires((x as Int) == (y as Int));
    ensures(x == y);
    sval_back::<S>(x);
    sval_back::<S>(y);
    assert(((x as Int) as S) == ((y as Int) as S), { rewrite((x as Int) == (y as Int)); follows(); });
    rewrite_rev(((x as Int) as S) == x);
    rewrite(((x as Int) as S) == ((y as Int) as S));
    rewrite(((y as Int) as S) == y);
    follows();
}

/// `un_zigzag` undoes `as_zigzag`.
#[lemma]
fn zz_inv<S: SPrim>(x: S) {
    ensures(S::un_zigzag(x.as_zigzag()) == x);
    as_zigzag_val::<S>(x);
    un_zigzag_val::<S>(x.as_zigzag());
    zigzag_inj(S::un_zigzag(x.as_zigzag()) as Int, x as Int);
    sval_inj::<S>(S::un_zigzag(x.as_zigzag()), x);
}

/// `as_zigzag` undoes `un_zigzag`.
#[lemma]
fn zz_surj<S: SPrim>(v: S::UnsignedEquivalent) {
    ensures(S::un_zigzag(v).as_zigzag() == v);
    as_zigzag_val::<S>(S::un_zigzag(v));
    un_zigzag_val::<S>(v);
    follows();
}

/// The inverse of ZigZag: an even number to its half, an odd number to
/// minus its half rounded up. (Opaque in proofs, like `zigzag`.)
#[spec]
#[opaque]
#[example(unzigzag(0) == 0 && unzigzag(1) == -1 && unzigzag(2) == 1 && unzigzag(3) == -2 && unzigzag(4) == 2)]
#[example(unzigzag(65534) == 32767 && unzigzag(65535) == -32768 && unzigzag(4294967295) == -2147483648)]
pub fn unzigzag(v: Nat) -> Int {
    if v % 2 == 0 { (v / 2) as Int } else { -(((v as Int) + 1) / 2) }
}

/// `SInt::read_cfg`'s result from the decoder's: its number, as a word of
/// the type's width, un-ZigZagged.
#[spec]
#[example(scfg_r::<S>(Err(Error::EndOfBuffer)) == Err(Error::EndOfBuffer) && scfg_r::<S>(Err(Error::InvalidVarint(3usize))) == Err(Error::InvalidVarint(3usize)))]
#[example(match scfg_r::<S>(Ok(0)) { Ok(y) => (y.0 as Int) == 0, Err(_) => false })]
#[example(match scfg_r::<S>(Ok(3)) { Ok(y) => (y.0 as Int) == -2, Err(_) => false })]
#[example(match scfg_r::<S>(Ok(4)) { Ok(y) => (y.0 as Int) == 2, Err(_) => false })]
pub fn scfg_r<S: SPrim>(x: Result<Nat, Error>) -> Result<SInt<S>, Error> {
    match x {
        Ok(v) => Ok(SInt(unzigzag((v as S::UnsignedEquivalent) as Nat) as S)),
        Err(e) => Err(e),
    }
}

/// A signed value through its number and back is itself (per width below).
#[lemma]
fn sval_back<S: SPrim>(x: S) {
    ensures(((x as Int) as S) == x);
}

/// `un_zigzag` in numbers, by `unzigzag` (per width below).
#[lemma]
fn unzz_num<S: SPrim>(v: S::UnsignedEquivalent) {
    ensures(unzigzag(v as Nat) == (S::un_zigzag(v) as Int));
}

/// `un_zigzag` is `unzigzag`.
#[lemma]
fn unzz_spec<S: SPrim>(v: S::UnsignedEquivalent) {
    ensures(S::un_zigzag(v) == (unzigzag(v as Nat) as S));
    unzz_num::<S>(v);
    sval_back::<S>(S::un_zigzag(v));
    rewrite(unzigzag(v as Nat) == (S::un_zigzag(v) as Int));
    rewrite(((S::un_zigzag(v) as Int) as S) == S::un_zigzag(v));
    follows();
}

/// ZigZag of the value `unzigzag` gives a number of the type's width is
/// that number.
#[lemma]
fn zz_unzz_nat<S: SPrim>(v: Nat) {
    requires((v as Int) < pow2(8 * (S::SIZE as Int)));
    ensures(crate::laws::zigzag((unzigzag(v) as S) as Int) == v);
    cast_back::<S::UnsignedEquivalent>(v);
    unzz_spec::<S>(v as S::UnsignedEquivalent);
    un_zigzag_val::<S>(v as S::UnsignedEquivalent);
    rewrite_rev(((v as S::UnsignedEquivalent) as Nat) == v);
    rewrite_rev(S::un_zigzag(v as S::UnsignedEquivalent) == (unzigzag((v as S::UnsignedEquivalent) as Nat) as S));
    follows();
}

/// A failure of `SInt::read_cfg` is the decoder's failure.
#[lemma]
fn scfg_r_err<S: SPrim>(x: Result<Nat, Error>, e: Error) {
    requires(scfg_r::<S>(x) == Err(e));
    ensures(x == Err(e));
    match x {
        Ok(v) => {
            assert(scfg_r::<S>(Ok(v)) == Ok(SInt(unzigzag((v as S::UnsignedEquivalent) as Nat) as S)), { by_unfolding(scfg_r::<S>); });
            by_contradiction();
        }
        Err(e2) => {
            assert(scfg_r::<S>(Err(e2)) == Err(e2), { by_unfolding(scfg_r::<S>); });
            follows();
        }
    }
}

/// `SInt::read_cfg`'s result and rest are the decoder's (per width below).
#[lemma]
fn src_parts<S: SPrim>(bytes: Seq<u8>) {
    ensures({ let mut q = bytes; SInt::<S>::read_cfg(&mut q, &()) } == scfg_r::<S>(sdec(S::SIZE, 0, bytes).1)
        && { let mut q = bytes; let r = SInt::<S>::read_cfg(&mut q, &()); q } == sdec(S::SIZE, 0, bytes).0);
}

/// The ZigZag of a value is a number of the type's width.
#[lemma]
fn zigzag_lt<S: SPrim>(x: S) {
    ensures((crate::laws::zigzag(x as Int) as Int) < pow2(8 * (S::SIZE as Int)));
    as_zigzag_val::<S>(x);
    nat_back::<S::UnsignedEquivalent>(x.as_zigzag());
    follows();
}

// ---------------------------------------------------------------------------
// Signed laws
// ---------------------------------------------------------------------------

/// `SInt(x).write` is `write(x.as_zigzag(), ..)`, whose summary is LEB128.
#[proof]
fn write_signed_appends_zigzag<S: SPrim>(v: SInt<S>, buf: Seq<u8>) {
    as_zigzag_val::<S>(v.0);
    unfold(crate::varint::SInt::<S>::write);
    unfold(crate::varint::write_signed::<S>);
    follows();
}

/// `encode_size` is `size` of the ZigZag.
#[proof]
fn encode_size_signed_counts_bytes<S: SPrim>(v: SInt<S>) {
    as_zigzag_val::<S>(v.0);
    encode_size_of::<S::UnsignedEquivalent>(v.0.as_zigzag());
    unfold(crate::varint::SInt::<S>::encode_size);
    unfold(crate::varint::size_signed::<S>);
    follows();
}

/// The decoder's number for the ZigZag of `x`, un-ZigZagged, is `x`.
#[lemma]
fn unzz_zz<S: SPrim>(x: S) {
    ensures((unzigzag((crate::laws::zigzag(x as Int) as S::UnsignedEquivalent) as Nat) as S) == x);
    as_zigzag_val::<S>(x);
    nat_back::<S::UnsignedEquivalent>(x.as_zigzag());
    assert((crate::laws::zigzag(x as Int) as S::UnsignedEquivalent) == x.as_zigzag());
    rewrite((crate::laws::zigzag(x as Int) as S::UnsignedEquivalent) == x.as_zigzag());
    unzz_spec::<S>(x.as_zigzag());
    rewrite_rev(S::un_zigzag(x.as_zigzag()) == (unzigzag(x.as_zigzag() as Nat) as S));
    zz_inv::<S>(x);
    follows();
}

/// By `sdec_varint`: the decoder reads the ZigZag, which `un_zigzag` undoes.
#[proof]
fn read_signed_round_trips<S: SPrim>(x: S, rest: Seq<u8>) {
    zigzag_lt::<S>(x);
    sdec_varint(S::SIZE, 0, crate::laws::zigzag(x as Int), rest);
    src_parts::<S>(seq![..crate::laws::varint(crate::laws::zigzag(x as Int)), ..rest]);
    unzz_zz::<S>(x);
    assert(scfg_r::<S>(Ok(crate::laws::zigzag(x as Int))) == Ok(SInt(x)), {
        unfold(scfg_r::<S>);
        rewrite((unzigzag((crate::laws::zigzag(x as Int) as S::UnsignedEquivalent) as Nat) as S) == x);
        follows();
    });
    follows();
}

/// Results with equal components are equal.
#[lemma]
fn sresult_eq<S: SPrim>(a: (Seq<u8>, Result<SInt<S>, Error>), b: (Seq<u8>, Result<SInt<S>, Error>)) {
    requires(a.0 == b.0 && a.1 == b.1);
    ensures(a == b);
    match a {
        (a0, a1) => match b {
            (b0, b1) => follows(),
        },
    }
}

/// The round trip, component by component.
#[lemma]
fn sread_rt<S: SPrim>(x: S, rest: Seq<u8>) {
    ensures({ let mut b = seq![..crate::laws::varint(crate::laws::zigzag(x as Int)), ..rest]; SInt::<S>::read_cfg(&mut b, &()) } == Ok(SInt(x))
        && { let mut b = seq![..crate::laws::varint(crate::laws::zigzag(x as Int)), ..rest]; let r = SInt::<S>::read_cfg(&mut b, &()); b } == rest);
    read_signed_round_trips::<S>(x, rest);
    follows();
}

/// By `sdec_ok`: the decoder's number is the ZigZag of the value.
#[proof]
fn read_signed_accepts_only_encodings<S: SPrim>(bytes: Seq<u8>, x: S, rest: Seq<u8>) {
    match sdec(S::SIZE, 0, bytes) {
        (s, Ok(v)) => {
            sdec_ok(S::SIZE, 0, bytes, s, v);
            src_parts::<S>(bytes);
            assert(scfg_r::<S>(Ok(v)) == Ok(SInt(unzigzag((v as S::UnsignedEquivalent) as Nat) as S)), { by_unfolding(scfg_r::<S>); });
            assert((unzigzag((v as S::UnsignedEquivalent) as Nat) as S) == x && s == rest);
            cast_back::<S::UnsignedEquivalent>(v);
            unzz_spec::<S>(v as S::UnsignedEquivalent);
            un_zigzag_val::<S>(v as S::UnsignedEquivalent);
            assert(S::un_zigzag(v as S::UnsignedEquivalent) == x);
            assert(crate::laws::zigzag(x as Int) == v);
            follows();
        }
        (s, Err(e)) => {
            src_parts::<S>(bytes);
            assert(scfg_r::<S>(Err(e)) == Err(e), { by_unfolding(scfg_r::<S>); });
            by_contradiction();
        }
    }
}

/// By `sdec_prefix`.
#[proof]
fn read_signed_end_of_buffer_on_prefixes<S: SPrim>(bytes: Seq<u8>, x: Nat, more: Seq<u8>) {
    src_parts::<S>(bytes);
    sdec_prefix(S::SIZE, 0, bytes, x, more);
    assert(scfg_r::<S>(Err(Error::EndOfBuffer)) == Err(Error::EndOfBuffer), { by_unfolding(scfg_r::<S>); });
    follows();
}

/// By `sdec_eob`, as for `UInt`.
#[proof]
fn read_signed_end_of_buffer_only_on_prefixes<S: SPrim>(bytes: Seq<u8>) {
    src_parts::<S>(bytes);
    scfg_r_err::<S>(sdec(S::SIZE, 0, bytes).1, Error::EndOfBuffer);
    match sdec(S::SIZE, 0, bytes) {
        (s, Ok(v)) => by_contradiction(),
        (s, Err(e)) => {
            sdec_eob(S::SIZE, 0, bytes, s);
            let w = eob_wit(bytes);
            assert(exists(|x: Nat| (x as Int) < pow2(8 * (S::SIZE as Int)) && seq![..bytes, 1u8] == crate::laws::varint(x)), {
                witness(w);
                follows();
            });
            follows();
        }
    }
}

/// By `sdec_inv_ext`, as for `UInt`.
#[proof]
fn read_signed_invalid_stops_at_the_deciding_byte<S: SPrim>(bytes: Seq<u8>, p: Seq<u8>, d: u8, rest: Seq<u8>, n: usize) {
    rewrite(bytes == seq![..p, d, ..rest]);
    src_parts::<S>(p);
    src_parts::<S>(seq![..p, d]);
    scfg_r_err::<S>(sdec(S::SIZE, 0, p).1, Error::EndOfBuffer);
    scfg_r_err::<S>(sdec(S::SIZE, 0, seq![..p, d]).1, Error::InvalidVarint(n));
    assert(eqb(Error::InvalidVarint(n), Error::EndOfBuffer) == false);
    sdec_inv_ext(S::SIZE, p, d, rest, Error::InvalidVarint(n));
    src_parts::<S>(seq![..p, d, ..rest]);
    assert(scfg_r::<S>(Err(Error::InvalidVarint(n))) == Err(Error::InvalidVarint(n)), { by_unfolding(scfg_r::<S>); });
    follows();
}

/// By `sdec_errs`.
#[proof]
fn read_signed_errors_are_classified<S: SPrim>(bytes: Seq<u8>, e: Error) {
    src_parts::<S>(bytes);
    scfg_r_err::<S>(sdec(S::SIZE, 0, bytes).1, e);
    match sdec(S::SIZE, 0, bytes) {
        (s, Ok(v)) => by_contradiction(),
        (s, Err(e2)) => {
            sdec_errs(S::SIZE, 0, bytes, s, e2);
            match e {
                Error::EndOfBuffer => follows(),
                Error::InvalidVarint(n) => {
                    assert(err_ok(Error::InvalidVarint(n), S::SIZE));
                    by_unfolding(err_ok);
                }
            }
        }
    }
}

// ----- ZigZag at i16 -------------------------------------------------------

/// A word's complement in numbers (u16), byte by byte.
#[lemma]
fn not_val_u16(y: u16) {
    ensures(((y ^ 65535u16) as Int) == 65535 - (y as Int));
    let (b0, b1) = (y as u8, (y >> 8u32) as u8);
    assert(y == (b0 as u16) + (b1 as u16) * 256u16, { bv(); });
    assert((y ^ 65535u16) == ((b0 ^ 255u8) as u16) + ((b1 ^ 255u8) as u16) * 256u16, { bv(); });
    assert((y as Int) == (b0 as Int) + (b1 as Int) * 256);
    assert(((y ^ 65535u16) as Int) == ((b0 ^ 255u8) as Int) + ((b1 ^ 255u8) as Int) * 256);
    not_val_u8(b0);
    not_val_u8(b1);
    follows();
}

#[lemma]
fn as_zigzag_val__i16(x: i16) {
    ensures((x.as_zigzag() as Int) == crate::laws::zigzag(x as Int));
    let u = x as u16;
    // the sign word: `u >> 15` is the sign bit
    assert((u >> 15usize == 0u16) == (u < 32768u16), { bv(); });
    assert(((u << 1u32) ^ 0u16) == (u << 1u32), { bv(); });
    assert((u.wrapping_sub(32768u16) << 1u32) == (u << 1u32), { bv(); });
    unfold(crate::varint::SPrim__i16__as_zigzag);
    unfold(crate::__lift::i16_shr);
    if u < 32768u16 {
        // non-negative: the sign word is zero, and `u << 1` is `2u`
        assert(u >> 15usize == 0u16);
        sandblaster::lemmas::bits::shl_exact_u16_1(u);
        assert((x as Int) == (u as Int), { by_unfolding(crate::__lift_model::int_of_i16); });
        assert(crate::laws::zigzag(u as Int) == (2 * (u as Int)) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    } else {
        // negative: the sign word is all ones, and `u << 1` is `2(u - 2^15)`
        assert((!u) >> 15usize == (u >> 15usize) ^ 1u16, { bv(); });
        assert(u >> 15usize == 1u16);
        sandblaster::lemmas::bits::shl_exact_u16_1(u - 32768u16);
        not_val_u16(u << 1u32);
        int_of_bits__i16(x);
        zigzag_def(x as Int);
        follows();
    }
}

#[lemma]
fn un_zigzag_val__i16(v: u16) {
    ensures(crate::laws::zigzag(i16::un_zigzag(v) as Int) == (v as Int));
    let h = v >> 1u32;
    assert(v == (v >> 1u32) * 2u16 + (v & 1u16), { bv(); });
    assert(((v >> 1u32) ^ 0u16) == (v >> 1u32), { bv(); });
    assert((h as Int) < 32768);
    if v & 1u16 == 0u16 {
        // even: the value is `v / 2`
        // `-(v & 1)` is 0
        assert(crate::__lift::i16_neg(crate::__lift::I16(v & 1u16)) == crate::__lift::I16(0u16), { rewrite(v & 1u16 == 0u16); by_computation(); });
        assert((i16::un_zigzag(v) as u16) == h, { unfold(crate::varint::SPrim__i16__un_zigzag); follows(); });
        assert((i16::un_zigzag(v) as Int) == (h as Int), { by_unfolding(crate::__lift_model::int_of_i16); });
        assert(crate::laws::zigzag(h as Int) == (2 * (h as Int)) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    } else {
        // odd: the value is `-(v + 1) / 2`, whose bits are the complement of `v / 2`
        assert(v & 1u16 == 1u16);
        not_val_u16(h);
        // `-(v & 1)` is -1, all ones
        assert(crate::__lift::i16_neg(crate::__lift::I16(v & 1u16)) == crate::__lift::I16(65535u16), { rewrite(v & 1u16 == 1u16); by_computation(); });
        assert((i16::un_zigzag(v) as u16) == h ^ 65535u16, { unfold(crate::varint::SPrim__i16__un_zigzag); follows(); });
        assert((i16::un_zigzag(v) as Int) == -1 - (h as Int), { by_unfolding(crate::__lift_model::int_of_i16); });
        assert(crate::laws::zigzag(-1 - (h as Int)) == (2 * (h as Int) + 1) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    }
}

/// `un_zigzag` in numbers, by `unzigzag`.
#[lemma]
fn unzz_num__i16(v: u16) {
    ensures(unzigzag(v as Nat) == (i16::un_zigzag(v) as Int));
    assert((v as Int) == 2 * ((v >> 1u32) as Int) + ((v & 1u16) as Int));
    let h = v >> 1u32;
    assert(v == (v >> 1u32) * 2u16 + (v & 1u16), { bv(); });
    assert(((v >> 1u32) ^ 0u16) == (v >> 1u32), { bv(); });
    assert((h as Int) < 32768);
    if v & 1u16 == 0u16 {
        // even: the value is `v / 2`
        // `-(v & 1)` is 0
        assert(crate::__lift::i16_neg(crate::__lift::I16(v & 1u16)) == crate::__lift::I16(0u16), { rewrite(v & 1u16 == 0u16); by_computation(); });
        assert((i16::un_zigzag(v) as u16) == h, { unfold(crate::varint::SPrim__i16__un_zigzag); follows(); });
        assert((i16::un_zigzag(v) as Int) == (h as Int), { by_unfolding(crate::__lift_model::int_of_i16); });
        assert((v as Int) % 2 == 0 && (v as Int) / 2 == (h as Int));
        assert(unzigzag(v as Nat) == (h as Int), { by_unfolding(unzigzag); });
        follows();
    } else {
        // odd: the value is `-(v + 1) / 2`, whose bits are the complement of `v / 2`
        assert(v & 1u16 == 1u16);
        not_val_u16(h);
        // `-(v & 1)` is -1, all ones
        assert(crate::__lift::i16_neg(crate::__lift::I16(v & 1u16)) == crate::__lift::I16(65535u16), { rewrite(v & 1u16 == 1u16); by_computation(); });
        assert((i16::un_zigzag(v) as u16) == h ^ 65535u16, { unfold(crate::varint::SPrim__i16__un_zigzag); follows(); });
        assert((i16::un_zigzag(v) as Int) == -1 - (h as Int), { by_unfolding(crate::__lift_model::int_of_i16); });
        assert((v as Int) % 2 == 1 && ((v as Int) + 1) / 2 == (h as Int) + 1);
        assert(unzigzag(v as Nat) == -1 - (h as Int), { by_unfolding(unzigzag); });
        follows();
    }
}

/// The value of an `i16` from its bits.
#[lemma]
fn int_of_bits__i16(x: i16) {
    ensures((x as Int) == (if (x as u16) < 32768u16 { (x as u16) as Int } else { ((x as u16) as Int) - 65536 }));
    by_unfolding(crate::__lift_model::int_of_i16);
}

/// The bits of an `i16` from its value.
#[lemma]
fn of_int_bits__i16(i: Int) {
    requires(i >= -32768 && i < 32768);
    ensures((((i as i16) as u16) as Int) == (if i >= 0 { i } else { i + 65536 }));
    unfold(crate::__lift_model::i16_of_int);
    if i >= 0 {
        follows();
    } else {
        assert(((-i) as Nat) % 65536 == ((-i) as Nat));
        follows();
    }
}

#[lemma]
fn sval_back__i16(x: i16) {
    ensures(((x as Int) as i16) == x);
    int_of_bits__i16(x);
    of_int_bits__i16(x as Int);
    assert((((x as Int) as i16) as u16) == (x as u16));
    follows();
}

/// `SInt::read_cfg` from `read`: its number un-ZigZagged.
#[lemma]
fn sread_of_read__i16(bytes: Seq<u8>, s: Seq<u8>, r: Result<u16, Error>) {
    requires(crate::varint::read__u16(bytes) == (s, r));
    ensures({ let mut q = bytes; SInt::<i16>::read_cfg(&mut q, &()) } == (match r { Ok(u) => Ok(SInt(i16::un_zigzag(u))), Err(e) => Err(e) })
        && { let mut q = bytes; let x = SInt::<i16>::read_cfg(&mut q, &()); q } == s);
    unfold(crate::varint::SInt__i16::read_cfg);
    unfold(crate::varint::read_signed__i16);
    rewrite(crate::varint::read__u16(bytes) == (s, r));
    match r {
        Ok(u) => follows(),
        Err(e) => follows(),
    }
}

#[lemma]
fn src_parts_d__i16(bytes: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(crate::varint::read__u16(bytes) == view_t::<u16>(d));
    ensures({ let mut q = bytes; SInt::<i16>::read_cfg(&mut q, &()) } == scfg_r::<i16>(d.1)
        && { let mut q = bytes; let r = SInt::<i16>::read_cfg(&mut q, &()); q } == d.0);
    match d {
        (s, Ok(v)) => {
            unzz_spec::<i16>(v as u16);
            assert(view_t::<u16>((s, Ok(v))) == (s, Ok(v as u16)), { by_unfolding(view_t::<u16>); });
            sread_of_read__i16(bytes, s, Ok(v as u16));
            assert(scfg_r::<i16>(Ok(v)) == Ok(SInt(unzigzag((v as u16) as Nat) as i16)), { by_unfolding(scfg_r::<i16>); });
            follows();
        }
        (s, Err(e)) => {
            assert(view_t::<u16>((s, Err(e))) == (s, Err(e)), { by_unfolding(view_t::<u16>); });
            sread_of_read__i16(bytes, s, Err(e));
            assert(scfg_r::<i16>(Err(e)) == Err(e), { by_unfolding(scfg_r::<i16>); });
            follows();
        }
    }
}

#[lemma]
fn src_parts__i16(bytes: Seq<u8>) {
    ensures({ let mut q = bytes; SInt::<i16>::read_cfg(&mut q, &()) } == scfg_r::<i16>(sdec(2usize, 0, bytes).1)
        && { let mut q = bytes; let r = SInt::<i16>::read_cfg(&mut q, &()); q } == sdec(2usize, 0, bytes).0);
    read_raw__u16(bytes);
    src_parts_d__i16(bytes, sdec(2usize, 0, bytes));
    follows();
}

// ----- ZigZag at i32 -------------------------------------------------------

/// A word's complement in numbers (u32), byte by byte.
#[lemma]
fn not_val_u32(y: u32) {
    ensures(((y ^ 4294967295u32) as Int) == 4294967295 - (y as Int));
    let (b0, b1, b2, b3) = (y as u8, (y >> 8u32) as u8, (y >> 16u32) as u8, (y >> 24u32) as u8);
    assert(y == (b0 as u32) + (b1 as u32) * 256u32 + (b2 as u32) * 65536u32 + (b3 as u32) * 16777216u32, { bv(); });
    assert((y ^ 4294967295u32) == ((b0 ^ 255u8) as u32) + ((b1 ^ 255u8) as u32) * 256u32 + ((b2 ^ 255u8) as u32) * 65536u32 + ((b3 ^ 255u8) as u32) * 16777216u32, { bv(); });
    assert((y as Int) == (b0 as Int) + (b1 as Int) * 256 + (b2 as Int) * 65536 + (b3 as Int) * 16777216);
    assert(((y ^ 4294967295u32) as Int) == ((b0 ^ 255u8) as Int) + ((b1 ^ 255u8) as Int) * 256 + ((b2 ^ 255u8) as Int) * 65536 + ((b3 ^ 255u8) as Int) * 16777216);
    not_val_u8(b0);
    not_val_u8(b1);
    not_val_u8(b2);
    not_val_u8(b3);
    follows();
}

#[lemma]
fn as_zigzag_val__i32(x: i32) {
    ensures((x.as_zigzag() as Int) == crate::laws::zigzag(x as Int));
    let u = x as u32;
    // the sign word: `u >> 31` is the sign bit
    assert((u >> 31usize == 0u32) == (u < 2147483648u32), { bv(); });
    assert(((u << 1u32) ^ 0u32) == (u << 1u32), { bv(); });
    assert((u.wrapping_sub(2147483648u32) << 1u32) == (u << 1u32), { bv(); });
    unfold(crate::varint::SPrim__i32__as_zigzag);
    unfold(crate::__lift::i32_shr);
    if u < 2147483648u32 {
        // non-negative: the sign word is zero, and `u << 1` is `2u`
        assert(u >> 31usize == 0u32);
        sandblaster::lemmas::bits::shl_exact_u32_1(u);
        assert((x as Int) == (u as Int), { by_unfolding(crate::__lift_model::int_of_i32); });
        assert(crate::laws::zigzag(u as Int) == (2 * (u as Int)) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    } else {
        // negative: the sign word is all ones, and `u << 1` is `2(u - 2^31)`
        assert((!u) >> 31usize == (u >> 31usize) ^ 1u32, { bv(); });
        assert(u >> 31usize == 1u32);
        sandblaster::lemmas::bits::shl_exact_u32_1(u - 2147483648u32);
        not_val_u32(u << 1u32);
        int_of_bits__i32(x);
        zigzag_def(x as Int);
        follows();
    }
}

#[lemma]
fn un_zigzag_val__i32(v: u32) {
    ensures(crate::laws::zigzag(i32::un_zigzag(v) as Int) == (v as Int));
    let h = v >> 1u32;
    assert(v == (v >> 1u32) * 2u32 + (v & 1u32), { bv(); });
    assert(((v >> 1u32) ^ 0u32) == (v >> 1u32), { bv(); });
    assert((h as Int) < 2147483648);
    if v & 1u32 == 0u32 {
        // even: the value is `v / 2`
        // `-(v & 1)` is 0
        assert(crate::__lift::i32_neg(crate::__lift::I32(v & 1u32)) == crate::__lift::I32(0u32), { rewrite(v & 1u32 == 0u32); by_computation(); });
        assert((i32::un_zigzag(v) as u32) == h, { unfold(crate::varint::SPrim__i32__un_zigzag); follows(); });
        assert((i32::un_zigzag(v) as Int) == (h as Int), { by_unfolding(crate::__lift_model::int_of_i32); });
        assert(crate::laws::zigzag(h as Int) == (2 * (h as Int)) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    } else {
        // odd: the value is `-(v + 1) / 2`, whose bits are the complement of `v / 2`
        assert(v & 1u32 == 1u32);
        not_val_u32(h);
        // `-(v & 1)` is -1, all ones
        assert(crate::__lift::i32_neg(crate::__lift::I32(v & 1u32)) == crate::__lift::I32(4294967295u32), { rewrite(v & 1u32 == 1u32); by_computation(); });
        assert((i32::un_zigzag(v) as u32) == h ^ 4294967295u32, { unfold(crate::varint::SPrim__i32__un_zigzag); follows(); });
        assert((i32::un_zigzag(v) as Int) == -1 - (h as Int), { by_unfolding(crate::__lift_model::int_of_i32); });
        assert(crate::laws::zigzag(-1 - (h as Int)) == (2 * (h as Int) + 1) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    }
}

/// `un_zigzag` in numbers, by `unzigzag`.
#[lemma]
fn unzz_num__i32(v: u32) {
    ensures(unzigzag(v as Nat) == (i32::un_zigzag(v) as Int));
    assert((v as Int) == 2 * ((v >> 1u32) as Int) + ((v & 1u32) as Int));
    let h = v >> 1u32;
    assert(v == (v >> 1u32) * 2u32 + (v & 1u32), { bv(); });
    assert(((v >> 1u32) ^ 0u32) == (v >> 1u32), { bv(); });
    assert((h as Int) < 2147483648);
    if v & 1u32 == 0u32 {
        // even: the value is `v / 2`
        // `-(v & 1)` is 0
        assert(crate::__lift::i32_neg(crate::__lift::I32(v & 1u32)) == crate::__lift::I32(0u32), { rewrite(v & 1u32 == 0u32); by_computation(); });
        assert((i32::un_zigzag(v) as u32) == h, { unfold(crate::varint::SPrim__i32__un_zigzag); follows(); });
        assert((i32::un_zigzag(v) as Int) == (h as Int), { by_unfolding(crate::__lift_model::int_of_i32); });
        assert((v as Int) % 2 == 0 && (v as Int) / 2 == (h as Int));
        assert(unzigzag(v as Nat) == (h as Int), { by_unfolding(unzigzag); });
        follows();
    } else {
        // odd: the value is `-(v + 1) / 2`, whose bits are the complement of `v / 2`
        assert(v & 1u32 == 1u32);
        not_val_u32(h);
        // `-(v & 1)` is -1, all ones
        assert(crate::__lift::i32_neg(crate::__lift::I32(v & 1u32)) == crate::__lift::I32(4294967295u32), { rewrite(v & 1u32 == 1u32); by_computation(); });
        assert((i32::un_zigzag(v) as u32) == h ^ 4294967295u32, { unfold(crate::varint::SPrim__i32__un_zigzag); follows(); });
        assert((i32::un_zigzag(v) as Int) == -1 - (h as Int), { by_unfolding(crate::__lift_model::int_of_i32); });
        assert((v as Int) % 2 == 1 && ((v as Int) + 1) / 2 == (h as Int) + 1);
        assert(unzigzag(v as Nat) == -1 - (h as Int), { by_unfolding(unzigzag); });
        follows();
    }
}

/// The value of an `i32` from its bits.
#[lemma]
fn int_of_bits__i32(x: i32) {
    ensures((x as Int) == (if (x as u32) < 2147483648u32 { (x as u32) as Int } else { ((x as u32) as Int) - 4294967296 }));
    by_unfolding(crate::__lift_model::int_of_i32);
}

/// The bits of an `i32` from its value.
#[lemma]
fn of_int_bits__i32(i: Int) {
    requires(i >= -2147483648 && i < 2147483648);
    ensures((((i as i32) as u32) as Int) == (if i >= 0 { i } else { i + 4294967296 }));
    unfold(crate::__lift_model::i32_of_int);
    if i >= 0 {
        follows();
    } else {
        assert(((-i) as Nat) % 4294967296 == ((-i) as Nat));
        follows();
    }
}

#[lemma]
fn sval_back__i32(x: i32) {
    ensures(((x as Int) as i32) == x);
    int_of_bits__i32(x);
    of_int_bits__i32(x as Int);
    assert((((x as Int) as i32) as u32) == (x as u32));
    follows();
}

/// `SInt::read_cfg` from `read`: its number un-ZigZagged.
#[lemma]
fn sread_of_read__i32(bytes: Seq<u8>, s: Seq<u8>, r: Result<u32, Error>) {
    requires(crate::varint::read__u32(bytes) == (s, r));
    ensures({ let mut q = bytes; SInt::<i32>::read_cfg(&mut q, &()) } == (match r { Ok(u) => Ok(SInt(i32::un_zigzag(u))), Err(e) => Err(e) })
        && { let mut q = bytes; let x = SInt::<i32>::read_cfg(&mut q, &()); q } == s);
    unfold(crate::varint::SInt__i32::read_cfg);
    unfold(crate::varint::read_signed__i32);
    rewrite(crate::varint::read__u32(bytes) == (s, r));
    match r {
        Ok(u) => follows(),
        Err(e) => follows(),
    }
}

#[lemma]
fn src_parts_d__i32(bytes: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(crate::varint::read__u32(bytes) == view_t::<u32>(d));
    ensures({ let mut q = bytes; SInt::<i32>::read_cfg(&mut q, &()) } == scfg_r::<i32>(d.1)
        && { let mut q = bytes; let r = SInt::<i32>::read_cfg(&mut q, &()); q } == d.0);
    match d {
        (s, Ok(v)) => {
            unzz_spec::<i32>(v as u32);
            assert(view_t::<u32>((s, Ok(v))) == (s, Ok(v as u32)), { by_unfolding(view_t::<u32>); });
            sread_of_read__i32(bytes, s, Ok(v as u32));
            assert(scfg_r::<i32>(Ok(v)) == Ok(SInt(unzigzag((v as u32) as Nat) as i32)), { by_unfolding(scfg_r::<i32>); });
            follows();
        }
        (s, Err(e)) => {
            assert(view_t::<u32>((s, Err(e))) == (s, Err(e)), { by_unfolding(view_t::<u32>); });
            sread_of_read__i32(bytes, s, Err(e));
            assert(scfg_r::<i32>(Err(e)) == Err(e), { by_unfolding(scfg_r::<i32>); });
            follows();
        }
    }
}

#[lemma]
fn src_parts__i32(bytes: Seq<u8>) {
    ensures({ let mut q = bytes; SInt::<i32>::read_cfg(&mut q, &()) } == scfg_r::<i32>(sdec(4usize, 0, bytes).1)
        && { let mut q = bytes; let r = SInt::<i32>::read_cfg(&mut q, &()); q } == sdec(4usize, 0, bytes).0);
    read_raw__u32(bytes);
    src_parts_d__i32(bytes, sdec(4usize, 0, bytes));
    follows();
}

// ----- ZigZag at i64 -------------------------------------------------------

/// A word's complement in numbers (u64), byte by byte.
#[lemma]
fn not_val_u64(y: u64) {
    ensures(((y ^ 18446744073709551615u64) as Int) == 18446744073709551615 - (y as Int));
    let (b0, b1, b2, b3, b4, b5, b6, b7) = (y as u8, (y >> 8u32) as u8, (y >> 16u32) as u8, (y >> 24u32) as u8, (y >> 32u32) as u8, (y >> 40u32) as u8, (y >> 48u32) as u8, (y >> 56u32) as u8);
    assert(y == (b0 as u64) + (b1 as u64) * 256u64 + (b2 as u64) * 65536u64 + (b3 as u64) * 16777216u64 + (b4 as u64) * 4294967296u64 + (b5 as u64) * 1099511627776u64 + (b6 as u64) * 281474976710656u64 + (b7 as u64) * 72057594037927936u64, { bv(); });
    assert((y ^ 18446744073709551615u64) == ((b0 ^ 255u8) as u64) + ((b1 ^ 255u8) as u64) * 256u64 + ((b2 ^ 255u8) as u64) * 65536u64 + ((b3 ^ 255u8) as u64) * 16777216u64 + ((b4 ^ 255u8) as u64) * 4294967296u64 + ((b5 ^ 255u8) as u64) * 1099511627776u64 + ((b6 ^ 255u8) as u64) * 281474976710656u64 + ((b7 ^ 255u8) as u64) * 72057594037927936u64, { bv(); });
    assert((y as Int) == (b0 as Int) + (b1 as Int) * 256 + (b2 as Int) * 65536 + (b3 as Int) * 16777216 + (b4 as Int) * 4294967296 + (b5 as Int) * 1099511627776 + (b6 as Int) * 281474976710656 + (b7 as Int) * 72057594037927936);
    assert(((y ^ 18446744073709551615u64) as Int) == ((b0 ^ 255u8) as Int) + ((b1 ^ 255u8) as Int) * 256 + ((b2 ^ 255u8) as Int) * 65536 + ((b3 ^ 255u8) as Int) * 16777216 + ((b4 ^ 255u8) as Int) * 4294967296 + ((b5 ^ 255u8) as Int) * 1099511627776 + ((b6 ^ 255u8) as Int) * 281474976710656 + ((b7 ^ 255u8) as Int) * 72057594037927936);
    not_val_u8(b0);
    not_val_u8(b1);
    not_val_u8(b2);
    not_val_u8(b3);
    not_val_u8(b4);
    not_val_u8(b5);
    not_val_u8(b6);
    not_val_u8(b7);
    follows();
}

#[lemma]
fn as_zigzag_val__i64(x: i64) {
    ensures((x.as_zigzag() as Int) == crate::laws::zigzag(x as Int));
    let u = x as u64;
    // the sign word: `u >> 63` is the sign bit
    assert((u >> 63usize == 0u64) == (u < 9223372036854775808u64), { bv(); });
    assert(((u << 1u32) ^ 0u64) == (u << 1u32), { bv(); });
    assert((u.wrapping_sub(9223372036854775808u64) << 1u32) == (u << 1u32), { bv(); });
    unfold(crate::varint::SPrim__i64__as_zigzag);
    unfold(crate::__lift::i64_shr);
    if u < 9223372036854775808u64 {
        // non-negative: the sign word is zero, and `u << 1` is `2u`
        assert(u >> 63usize == 0u64);
        sandblaster::lemmas::bits::shl_exact_u64_1(u);
        assert((x as Int) == (u as Int), { by_unfolding(crate::__lift_model::int_of_i64); });
        assert(crate::laws::zigzag(u as Int) == (2 * (u as Int)) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    } else {
        // negative: the sign word is all ones, and `u << 1` is `2(u - 2^63)`
        assert((!u) >> 63usize == (u >> 63usize) ^ 1u64, { bv(); });
        assert(u >> 63usize == 1u64);
        sandblaster::lemmas::bits::shl_exact_u64_1(u - 9223372036854775808u64);
        not_val_u64(u << 1u32);
        int_of_bits__i64(x);
        zigzag_def(x as Int);
        follows();
    }
}

#[lemma]
fn un_zigzag_val__i64(v: u64) {
    ensures(crate::laws::zigzag(i64::un_zigzag(v) as Int) == (v as Int));
    let h = v >> 1u32;
    assert(v == (v >> 1u32) * 2u64 + (v & 1u64), { bv(); });
    assert(((v >> 1u32) ^ 0u64) == (v >> 1u32), { bv(); });
    assert((h as Int) < 9223372036854775808);
    if v & 1u64 == 0u64 {
        // even: the value is `v / 2`
        // `-(v & 1)` is 0
        assert(crate::__lift::i64_neg(crate::__lift::I64(v & 1u64)) == crate::__lift::I64(0u64), { rewrite(v & 1u64 == 0u64); by_computation(); });
        assert((i64::un_zigzag(v) as u64) == h, { unfold(crate::varint::SPrim__i64__un_zigzag); follows(); });
        assert((i64::un_zigzag(v) as Int) == (h as Int), { by_unfolding(crate::__lift_model::int_of_i64); });
        assert(crate::laws::zigzag(h as Int) == (2 * (h as Int)) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    } else {
        // odd: the value is `-(v + 1) / 2`, whose bits are the complement of `v / 2`
        assert(v & 1u64 == 1u64);
        not_val_u64(h);
        // `-(v & 1)` is -1, all ones
        assert(crate::__lift::i64_neg(crate::__lift::I64(v & 1u64)) == crate::__lift::I64(18446744073709551615u64), { rewrite(v & 1u64 == 1u64); by_computation(); });
        assert((i64::un_zigzag(v) as u64) == h ^ 18446744073709551615u64, { unfold(crate::varint::SPrim__i64__un_zigzag); follows(); });
        assert((i64::un_zigzag(v) as Int) == -1 - (h as Int), { by_unfolding(crate::__lift_model::int_of_i64); });
        assert(crate::laws::zigzag(-1 - (h as Int)) == (2 * (h as Int) + 1) as Nat, { by_unfolding(crate::laws::zigzag); });
        follows();
    }
}

/// `un_zigzag` in numbers, by `unzigzag`.
#[lemma]
fn unzz_num__i64(v: u64) {
    ensures(unzigzag(v as Nat) == (i64::un_zigzag(v) as Int));
    assert((v as Int) == 2 * ((v >> 1u32) as Int) + ((v & 1u64) as Int));
    let h = v >> 1u32;
    assert(v == (v >> 1u32) * 2u64 + (v & 1u64), { bv(); });
    assert(((v >> 1u32) ^ 0u64) == (v >> 1u32), { bv(); });
    assert((h as Int) < 9223372036854775808);
    if v & 1u64 == 0u64 {
        // even: the value is `v / 2`
        // `-(v & 1)` is 0
        assert(crate::__lift::i64_neg(crate::__lift::I64(v & 1u64)) == crate::__lift::I64(0u64), { rewrite(v & 1u64 == 0u64); by_computation(); });
        assert((i64::un_zigzag(v) as u64) == h, { unfold(crate::varint::SPrim__i64__un_zigzag); follows(); });
        assert((i64::un_zigzag(v) as Int) == (h as Int), { by_unfolding(crate::__lift_model::int_of_i64); });
        assert((v as Int) % 2 == 0 && (v as Int) / 2 == (h as Int));
        assert(unzigzag(v as Nat) == (h as Int), { by_unfolding(unzigzag); });
        follows();
    } else {
        // odd: the value is `-(v + 1) / 2`, whose bits are the complement of `v / 2`
        assert(v & 1u64 == 1u64);
        not_val_u64(h);
        // `-(v & 1)` is -1, all ones
        assert(crate::__lift::i64_neg(crate::__lift::I64(v & 1u64)) == crate::__lift::I64(18446744073709551615u64), { rewrite(v & 1u64 == 1u64); by_computation(); });
        assert((i64::un_zigzag(v) as u64) == h ^ 18446744073709551615u64, { unfold(crate::varint::SPrim__i64__un_zigzag); follows(); });
        assert((i64::un_zigzag(v) as Int) == -1 - (h as Int), { by_unfolding(crate::__lift_model::int_of_i64); });
        assert((v as Int) % 2 == 1 && ((v as Int) + 1) / 2 == (h as Int) + 1);
        assert(unzigzag(v as Nat) == -1 - (h as Int), { by_unfolding(unzigzag); });
        follows();
    }
}

/// The value of an `i64` from its bits.
#[lemma]
fn int_of_bits__i64(x: i64) {
    ensures((x as Int) == (if (x as u64) < 9223372036854775808u64 { (x as u64) as Int } else { ((x as u64) as Int) - 18446744073709551616 }));
    by_unfolding(crate::__lift_model::int_of_i64);
}

/// The bits of an `i64` from its value.
#[lemma]
fn of_int_bits__i64(i: Int) {
    requires(i >= -9223372036854775808 && i < 9223372036854775808);
    ensures((((i as i64) as u64) as Int) == (if i >= 0 { i } else { i + 18446744073709551616 }));
    unfold(crate::__lift_model::i64_of_int);
    if i >= 0 {
        follows();
    } else {
        assert(((-i) as Nat) % 18446744073709551616 == ((-i) as Nat));
        follows();
    }
}

#[lemma]
fn sval_back__i64(x: i64) {
    ensures(((x as Int) as i64) == x);
    int_of_bits__i64(x);
    of_int_bits__i64(x as Int);
    assert((((x as Int) as i64) as u64) == (x as u64));
    follows();
}

/// `SInt::read_cfg` from `read`: its number un-ZigZagged.
#[lemma]
fn sread_of_read__i64(bytes: Seq<u8>, s: Seq<u8>, r: Result<u64, Error>) {
    requires(crate::varint::read__u64(bytes) == (s, r));
    ensures({ let mut q = bytes; SInt::<i64>::read_cfg(&mut q, &()) } == (match r { Ok(u) => Ok(SInt(i64::un_zigzag(u))), Err(e) => Err(e) })
        && { let mut q = bytes; let x = SInt::<i64>::read_cfg(&mut q, &()); q } == s);
    unfold(crate::varint::SInt__i64::read_cfg);
    unfold(crate::varint::read_signed__i64);
    rewrite(crate::varint::read__u64(bytes) == (s, r));
    match r {
        Ok(u) => follows(),
        Err(e) => follows(),
    }
}

#[lemma]
fn src_parts_d__i64(bytes: Seq<u8>, d: (Seq<u8>, Result<Nat, Error>)) {
    requires(crate::varint::read__u64(bytes) == view_t::<u64>(d));
    ensures({ let mut q = bytes; SInt::<i64>::read_cfg(&mut q, &()) } == scfg_r::<i64>(d.1)
        && { let mut q = bytes; let r = SInt::<i64>::read_cfg(&mut q, &()); q } == d.0);
    match d {
        (s, Ok(v)) => {
            unzz_spec::<i64>(v as u64);
            assert(view_t::<u64>((s, Ok(v))) == (s, Ok(v as u64)), { by_unfolding(view_t::<u64>); });
            sread_of_read__i64(bytes, s, Ok(v as u64));
            assert(scfg_r::<i64>(Ok(v)) == Ok(SInt(unzigzag((v as u64) as Nat) as i64)), { by_unfolding(scfg_r::<i64>); });
            follows();
        }
        (s, Err(e)) => {
            assert(view_t::<u64>((s, Err(e))) == (s, Err(e)), { by_unfolding(view_t::<u64>); });
            sread_of_read__i64(bytes, s, Err(e));
            assert(scfg_r::<i64>(Err(e)) == Err(e), { by_unfolding(scfg_r::<i64>); });
            follows();
        }
    }
}

#[lemma]
fn src_parts__i64(bytes: Seq<u8>) {
    ensures({ let mut q = bytes; SInt::<i64>::read_cfg(&mut q, &()) } == scfg_r::<i64>(sdec(8usize, 0, bytes).1)
        && { let mut q = bytes; let r = SInt::<i64>::read_cfg(&mut q, &()); q } == sdec(8usize, 0, bytes).0);
    read_raw__u64(bytes);
    src_parts_d__i64(bytes, sdec(8usize, 0, bytes));
    follows();
}

/// `SInt::read_cfg` is pinned by the signed read laws, as `UInt::read_cfg`
/// by the unsigned ones: on an encoding the round trip (at the value whose
/// ZigZag the decoder reads) fixes it; on incomplete and invalid bytes the
/// same laws as for `UInt` do.
#[proof(complete = crate::varint::SInt__i16::read_cfg)]
fn sread_cfg_determined__i16(buf: Seq<u8>, _c: &()) {
    assert(_c == &());
    match sdec(2usize, 0, buf) {
        (s, Ok(v)) => {
            sdec_ok(2usize, 0, buf, s, v);
            // the value whose ZigZag the decoder reads: the round trip fixes
            // both the implementation and any function with the laws
            zz_unzz_nat::<i16>(v);
            assert(buf == seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i16) as Int)), ..sdec(2usize, 0, buf).0]);
            rewrite(buf == seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i16) as Int)), ..sdec(2usize, 0, buf).0]);
            use_hyp(0, unzigzag(v) as i16, sdec(2usize, 0, buf).0);
            sread_rt::<i16>(unzigzag(v) as i16, sdec(2usize, 0, buf).0);
            // a function with the laws, component by component
            assert({{ let mut b = seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i16) as Int)), ..sdec(2usize, 0, buf).0]; SInt::<i16>::read_cfg(&mut b, &()) }} == Ok(SInt(unzigzag(v) as i16)));
            assert({{ let mut b = seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i16) as Int)), ..sdec(2usize, 0, buf).0]; let r = SInt::<i16>::read_cfg(&mut b, &()); b }} == sdec(2usize, 0, buf).0);
            rewrite(_c == &());
            apply(sresult_eq::<i16>);
            follows();
        }
        (s, Err(e)) => {
            src_parts::<i16>(buf);
            sdec_errs(2usize, 0, buf, s, e);
            assert(scfg_r::<i16>(Err(e)) == Err(e), { by_unfolding(scfg_r::<i16>); });
            if eqb(e, Error::EndOfBuffer) {
                assert(e == Error::EndOfBuffer);
                sdec_eob(2usize, 0, buf, s);
                use_hyp(2, buf, eob_wit(buf), seq![1u8]);
                use_hyp(3, buf);
                follows();
            } else {
                assert(e == Error::InvalidVarint(2usize), {
                    match e {
                        Error::EndOfBuffer => by_contradiction(),
                        Error::InvalidVarint(n0) => {
                            assert(err_ok(Error::InvalidVarint(n0), 2usize));
                            by_unfolding(err_ok);
                        }
                    }
                });
                sdec_inv(2usize, 0, buf, s, e);
                eob_prefix_of(2usize, 0, inv_pre(2usize, 0, buf));
                use_hyp(2, inv_pre(2usize, 0, buf), eob_wit(inv_pre(2usize, 0, buf)), seq![1u8]);
                match { let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; SInt::<i16>::read_cfg(&mut b, &()) } {
                    Ok(u) => {
                        // canonicity for the implementation: the bytes would be an
                        // encoding, which the decoder accepts
                        use_hyp(1, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)], u.0, { let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = SInt::<i16>::read_cfg(&mut b, &()); b });
                        zigzag_lt::<i16>(u.0);
                        sdec_varint(2usize, 0, crate::laws::zigzag(u.0 as Int), { let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = SInt::<i16>::read_cfg(&mut b, &()); b });
                        sdec_same_input(2usize, 0, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)],
                            seq![..crate::laws::varint(crate::laws::zigzag(u.0 as Int)), ..{ let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = SInt::<i16>::read_cfg(&mut b, &()); b }]);
                        tr3(sdec(2usize, 0, seq![..crate::laws::varint(crate::laws::zigzag(u.0 as Int)), ..{ let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = SInt::<i16>::read_cfg(&mut b, &()); b }]),
                            sdec(2usize, 0, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]),
                            ({ let mut b = seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]; let r = SInt::<i16>::read_cfg(&mut b, &()); b }, Ok(crate::laws::zigzag(u.0 as Int))));
                        by_contradiction();
                    }
                    Err(e2) => {
                        if eqb(e2, Error::EndOfBuffer) {
                            // the implementation runs out of input only on a proper
                            // prefix of an encoding, where the decoder does too
                            assert(e2 == Error::EndOfBuffer);
                            use_hyp(3, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]);
                            eob_of_incomplete::<u16>(seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]);
                            by_contradiction();
                        } else {
                            use_hyp(5, seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)], e2);
                            assert(e2 == Error::InvalidVarint(2usize));
                            use_hyp(4, buf, inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf), s, 2usize);
                            src_parts::<i16>(inv_pre(2usize, 0, buf));
                            src_parts::<i16>(seq![..inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf)]);
                            read_signed_invalid_stops_at_the_deciding_byte__i16(buf, inv_pre(2usize, 0, buf), inv_byte(2usize, 0, buf), s, 2usize);
                            follows();
                        }
                    }
                }
            }
        }
    }
}

/// `SInt::read_cfg` is pinned by the signed read laws, as `UInt::read_cfg`
/// by the unsigned ones: on an encoding the round trip (at the value whose
/// ZigZag the decoder reads) fixes it; on incomplete and invalid bytes the
/// same laws as for `UInt` do.
#[proof(complete = crate::varint::SInt__i32::read_cfg)]
fn sread_cfg_determined__i32(buf: Seq<u8>, _c: &()) {
    assert(_c == &());
    match sdec(4usize, 0, buf) {
        (s, Ok(v)) => {
            sdec_ok(4usize, 0, buf, s, v);
            // the value whose ZigZag the decoder reads: the round trip fixes
            // both the implementation and any function with the laws
            zz_unzz_nat::<i32>(v);
            assert(buf == seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i32) as Int)), ..sdec(4usize, 0, buf).0]);
            rewrite(buf == seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i32) as Int)), ..sdec(4usize, 0, buf).0]);
            use_hyp(0, unzigzag(v) as i32, sdec(4usize, 0, buf).0);
            sread_rt::<i32>(unzigzag(v) as i32, sdec(4usize, 0, buf).0);
            // a function with the laws, component by component
            assert({{ let mut b = seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i32) as Int)), ..sdec(4usize, 0, buf).0]; SInt::<i32>::read_cfg(&mut b, &()) }} == Ok(SInt(unzigzag(v) as i32)));
            assert({{ let mut b = seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i32) as Int)), ..sdec(4usize, 0, buf).0]; let r = SInt::<i32>::read_cfg(&mut b, &()); b }} == sdec(4usize, 0, buf).0);
            rewrite(_c == &());
            apply(sresult_eq::<i32>);
            follows();
        }
        (s, Err(e)) => {
            src_parts::<i32>(buf);
            sdec_errs(4usize, 0, buf, s, e);
            assert(scfg_r::<i32>(Err(e)) == Err(e), { by_unfolding(scfg_r::<i32>); });
            if eqb(e, Error::EndOfBuffer) {
                assert(e == Error::EndOfBuffer);
                sdec_eob(4usize, 0, buf, s);
                use_hyp(2, buf, eob_wit(buf), seq![1u8]);
                use_hyp(3, buf);
                follows();
            } else {
                assert(e == Error::InvalidVarint(4usize), {
                    match e {
                        Error::EndOfBuffer => by_contradiction(),
                        Error::InvalidVarint(n0) => {
                            assert(err_ok(Error::InvalidVarint(n0), 4usize));
                            by_unfolding(err_ok);
                        }
                    }
                });
                sdec_inv(4usize, 0, buf, s, e);
                eob_prefix_of(4usize, 0, inv_pre(4usize, 0, buf));
                use_hyp(2, inv_pre(4usize, 0, buf), eob_wit(inv_pre(4usize, 0, buf)), seq![1u8]);
                match { let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; SInt::<i32>::read_cfg(&mut b, &()) } {
                    Ok(u) => {
                        // canonicity for the implementation: the bytes would be an
                        // encoding, which the decoder accepts
                        use_hyp(1, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)], u.0, { let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = SInt::<i32>::read_cfg(&mut b, &()); b });
                        zigzag_lt::<i32>(u.0);
                        sdec_varint(4usize, 0, crate::laws::zigzag(u.0 as Int), { let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = SInt::<i32>::read_cfg(&mut b, &()); b });
                        sdec_same_input(4usize, 0, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)],
                            seq![..crate::laws::varint(crate::laws::zigzag(u.0 as Int)), ..{ let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = SInt::<i32>::read_cfg(&mut b, &()); b }]);
                        tr3(sdec(4usize, 0, seq![..crate::laws::varint(crate::laws::zigzag(u.0 as Int)), ..{ let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = SInt::<i32>::read_cfg(&mut b, &()); b }]),
                            sdec(4usize, 0, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]),
                            ({ let mut b = seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]; let r = SInt::<i32>::read_cfg(&mut b, &()); b }, Ok(crate::laws::zigzag(u.0 as Int))));
                        by_contradiction();
                    }
                    Err(e2) => {
                        if eqb(e2, Error::EndOfBuffer) {
                            // the implementation runs out of input only on a proper
                            // prefix of an encoding, where the decoder does too
                            assert(e2 == Error::EndOfBuffer);
                            use_hyp(3, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]);
                            eob_of_incomplete::<u32>(seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]);
                            by_contradiction();
                        } else {
                            use_hyp(5, seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)], e2);
                            assert(e2 == Error::InvalidVarint(4usize));
                            use_hyp(4, buf, inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf), s, 4usize);
                            src_parts::<i32>(inv_pre(4usize, 0, buf));
                            src_parts::<i32>(seq![..inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf)]);
                            read_signed_invalid_stops_at_the_deciding_byte__i32(buf, inv_pre(4usize, 0, buf), inv_byte(4usize, 0, buf), s, 4usize);
                            follows();
                        }
                    }
                }
            }
        }
    }
}

/// `SInt::read_cfg` is pinned by the signed read laws, as `UInt::read_cfg`
/// by the unsigned ones: on an encoding the round trip (at the value whose
/// ZigZag the decoder reads) fixes it; on incomplete and invalid bytes the
/// same laws as for `UInt` do.
#[proof(complete = crate::varint::SInt__i64::read_cfg)]
fn sread_cfg_determined__i64(buf: Seq<u8>, _c: &()) {
    assert(_c == &());
    match sdec(8usize, 0, buf) {
        (s, Ok(v)) => {
            sdec_ok(8usize, 0, buf, s, v);
            // the value whose ZigZag the decoder reads: the round trip fixes
            // both the implementation and any function with the laws
            zz_unzz_nat::<i64>(v);
            assert(buf == seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i64) as Int)), ..sdec(8usize, 0, buf).0]);
            rewrite(buf == seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i64) as Int)), ..sdec(8usize, 0, buf).0]);
            use_hyp(0, unzigzag(v) as i64, sdec(8usize, 0, buf).0);
            sread_rt::<i64>(unzigzag(v) as i64, sdec(8usize, 0, buf).0);
            // a function with the laws, component by component
            assert({{ let mut b = seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i64) as Int)), ..sdec(8usize, 0, buf).0]; SInt::<i64>::read_cfg(&mut b, &()) }} == Ok(SInt(unzigzag(v) as i64)));
            assert({{ let mut b = seq![..crate::laws::varint(crate::laws::zigzag((unzigzag(v) as i64) as Int)), ..sdec(8usize, 0, buf).0]; let r = SInt::<i64>::read_cfg(&mut b, &()); b }} == sdec(8usize, 0, buf).0);
            rewrite(_c == &());
            apply(sresult_eq::<i64>);
            follows();
        }
        (s, Err(e)) => {
            src_parts::<i64>(buf);
            sdec_errs(8usize, 0, buf, s, e);
            assert(scfg_r::<i64>(Err(e)) == Err(e), { by_unfolding(scfg_r::<i64>); });
            if eqb(e, Error::EndOfBuffer) {
                assert(e == Error::EndOfBuffer);
                sdec_eob(8usize, 0, buf, s);
                use_hyp(2, buf, eob_wit(buf), seq![1u8]);
                use_hyp(3, buf);
                follows();
            } else {
                assert(e == Error::InvalidVarint(8usize), {
                    match e {
                        Error::EndOfBuffer => by_contradiction(),
                        Error::InvalidVarint(n0) => {
                            assert(err_ok(Error::InvalidVarint(n0), 8usize));
                            by_unfolding(err_ok);
                        }
                    }
                });
                sdec_inv(8usize, 0, buf, s, e);
                eob_prefix_of(8usize, 0, inv_pre(8usize, 0, buf));
                use_hyp(2, inv_pre(8usize, 0, buf), eob_wit(inv_pre(8usize, 0, buf)), seq![1u8]);
                match { let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; SInt::<i64>::read_cfg(&mut b, &()) } {
                    Ok(u) => {
                        // canonicity for the implementation: the bytes would be an
                        // encoding, which the decoder accepts
                        use_hyp(1, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)], u.0, { let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = SInt::<i64>::read_cfg(&mut b, &()); b });
                        zigzag_lt::<i64>(u.0);
                        sdec_varint(8usize, 0, crate::laws::zigzag(u.0 as Int), { let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = SInt::<i64>::read_cfg(&mut b, &()); b });
                        sdec_same_input(8usize, 0, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)],
                            seq![..crate::laws::varint(crate::laws::zigzag(u.0 as Int)), ..{ let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = SInt::<i64>::read_cfg(&mut b, &()); b }]);
                        tr3(sdec(8usize, 0, seq![..crate::laws::varint(crate::laws::zigzag(u.0 as Int)), ..{ let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = SInt::<i64>::read_cfg(&mut b, &()); b }]),
                            sdec(8usize, 0, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]),
                            ({ let mut b = seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]; let r = SInt::<i64>::read_cfg(&mut b, &()); b }, Ok(crate::laws::zigzag(u.0 as Int))));
                        by_contradiction();
                    }
                    Err(e2) => {
                        if eqb(e2, Error::EndOfBuffer) {
                            // the implementation runs out of input only on a proper
                            // prefix of an encoding, where the decoder does too
                            assert(e2 == Error::EndOfBuffer);
                            use_hyp(3, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]);
                            eob_of_incomplete::<u64>(seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]);
                            by_contradiction();
                        } else {
                            use_hyp(5, seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)], e2);
                            assert(e2 == Error::InvalidVarint(8usize));
                            use_hyp(4, buf, inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf), s, 8usize);
                            src_parts::<i64>(inv_pre(8usize, 0, buf));
                            src_parts::<i64>(seq![..inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf)]);
                            read_signed_invalid_stops_at_the_deciding_byte__i64(buf, inv_pre(8usize, 0, buf), inv_byte(8usize, 0, buf), s, 8usize);
                            follows();
                        }
                    }
                }
            }
        }
    }
}
