//! Bits of natural numbers, one at a time: halving (`x / 2`, `x % 2`), `pow2`, `popcount`, and
//! multiples of `2^e` (`aligned`). Linear arithmetic decides `/ 2` and `% 2`; a division by
//! `pow2(e)` for a symbolic `e` it cannot, so these facts are stated with `aligned` instead. A
//! word's trailing zeros and trailing ones are stated the same way, for every count at once
//! (`trailing_zeros_<w>`, `trailing_ones_<w>`: no lemma per count).

use sandblaster::prelude::*;

/// `x` is twice its half plus its lowest bit.
#[lemma]
pub fn halves(x: Nat) {
    ensures(x == 2 * (x / 2) + x % 2 && x % 2 <= 1 && x / 2 <= x);
    by_arithmetic();
}

/// Halving a sum whose first term is even.
#[lemma]
pub fn halves_sum(x: Nat, y: Nat) {
    requires(x % 2 == 0);
    ensures((x + y) / 2 == x / 2 + y / 2 && (x + y) % 2 == y % 2);
    halves(x);
    halves(y);
    halves(x + y);
    assert((x + y) / 2 == x / 2 + y / 2, { by_arithmetic(); });
    by_arithmetic();
}

/// Halving a difference of two even numbers.
#[lemma]
pub fn halves_diff(x: Nat, y: Nat) {
    requires(x % 2 == 0 && y % 2 == 0 && y <= x);
    ensures((x - y) / 2 == x / 2 - y / 2 && (x - y) % 2 == 0);
    halves(x);
    halves(y);
    halves(x - y);
    assert((x - y) / 2 == x / 2 - y / 2, { by_arithmetic(); });
    by_arithmetic();
}

/// Twice a number is even, and half of it is the number.
#[lemma]
pub fn halves_double(x: Nat) {
    ensures((2 * x) / 2 == x && (2 * x) % 2 == 0);
    halves(2 * x);
    assert((2 * x) / 2 == x, { by_arithmetic(); });
    by_arithmetic();
}

/// One step of `pow2`.
#[lemma]
pub fn pow2_step(e: Int) {
    requires(e >= 1);
    ensures(pow2(e) == 2 * pow2(e - 1) && pow2(e) % 2 == 0 && pow2(e) / 2 == pow2(e - 1));
    sandblaster::lemmas::nat::pow2_succ(e - 1);
    halves_double(pow2(e - 1));
    follows();
}

/// 2^0 is 1.
#[lemma]
pub fn pow2_zero(e: Int) {
    requires(e == 0);
    ensures(pow2(e) == 1);
    rewrite(e == 0);
    by_computation();
}

/// `pow2` of an exponent written differently.
#[lemma]
pub fn pow2_same(a: Int, b: Int) {
    requires(a == b);
    ensures(pow2(a) == pow2(b));
    rewrite(b == a);
    follows();
}

/// 2^a < 2^b for 0 ≤ a < b.
#[lemma]
#[induction(b)]
#[decreases(b)]
pub fn pow2_lt(a: Int, b: Int) {
    requires(0 <= a && a < b);
    ensures(pow2(a) < pow2(b));
    sandblaster::lemmas::nat::pow2_succ(b - 1);
    sandblaster::lemmas::nat::pow2_pos(b - 1);
    if a == b - 1 {
        pow2_same(a, b - 1);
        by_arithmetic();
    } else {
        ih(a, b - 1);
        by_arithmetic();
    }
}

/// Distinct exponents have distinct powers.
#[lemma]
pub fn pow2_ne(a: Int, b: Int) {
    requires(0 <= a && 0 <= b && a != b);
    ensures(pow2(a) != pow2(b));
    if a < b {
        pow2_lt(a, b);
        by_arithmetic();
    } else {
        pow2_lt(b, a);
        by_arithmetic();
    }
}

/// One step of `popcount`: the lowest bit, then the rest.
#[lemma]
pub fn popcount_step(x: Nat) {
    ensures(popcount(x) == x % 2 + popcount(x / 2));
    if x == 0 {
        follows();
    } else {
        by_unfolding(popcount);
    }
}

/// `popcount` of a number written differently.
#[lemma]
pub fn popcount_same(x: Nat, y: Nat) {
    requires(x == y);
    ensures(popcount(x) == popcount(y));
    rewrite(y == x);
    follows();
}

/// `popcount(x) ≤ x`.
#[lemma]
pub fn popcount_le_self(x: Nat) {
    ensures(popcount(x) <= x);
    sandblaster::lemmas::nat::popcount_le(x);
}

/// Twice a number has its bits.
#[lemma]
pub fn popcount_double(x: Nat) {
    ensures(popcount(2 * x) == popcount(x));
    popcount_step(2 * x);
    halves_double(x);
    by_arithmetic();
}

/// Twice a number plus a bit: its bits and that bit.
#[lemma]
pub fn popcount_double_plus(y: Nat, b: Nat) {
    requires(b <= 1);
    ensures(popcount(2 * y + b) == popcount(y) + b);
    popcount_step(2 * y + b);
    halves(2 * y + b);
    assert((2 * y + b) / 2 == y && (2 * y + b) % 2 == b, { by_arithmetic(); });
    by_arithmetic();
}

/// An even number has the bits of its half.
#[lemma]
pub fn popcount_even_half(x: Nat) {
    requires(x % 2 == 0);
    ensures(popcount(x) == popcount(x / 2));
    popcount_step(x);
    by_arithmetic();
}

/// 2^h − 1 has `h` bits set.
#[lemma]
#[induction(h)]
#[decreases(h)]
pub fn popcount_low_ones(h: Int) {
    requires(h >= 0);
    ensures(popcount(pow2(h) - 1) == h);
    if h == 0 {
        follows();
    } else {
        pow2_step(h);
        ih(h - 1);
        popcount_step(pow2(h) - 1);
        halves(pow2(h) - 1);
        assert((pow2(h) - 1) / 2 == pow2(h - 1) - 1, { by_arithmetic(); });
        by_arithmetic();
    }
}

/// 2^h has one bit set.
#[lemma]
#[induction(h)]
#[decreases(h)]
pub fn popcount_pow2(h: Int) {
    requires(h >= 0);
    ensures(popcount(pow2(h)) == 1);
    if h == 0 {
        follows();
    } else {
        pow2_step(h);
        ih(h - 1);
        popcount_step(pow2(h));
        by_arithmetic();
    }
}

/// A `u64`'s `count_ones` is the `popcount` of its value.
#[lemma]
#[decreases(x)]
pub fn count_ones_u64(x: u64) {
    ensures(x.count_ones() as Nat == popcount(x as Nat));
    if x == 0 {
        rewrite(x == 0u64);
        by_computation();
    } else {
        sandblaster::lemmas::bits::popcnt_shr1_u64(x);
        popcount_step(x as Nat);
        count_ones_u64(x >> 1u32);
        assert((x >> 1u32) as Nat == (x as Nat) / 2 && (x & 1u64) as Nat == (x as Nat) % 2, { follows(); });
        by_arithmetic();
    }
}

// ---------------------------------------------------------------------------------------------
// Multiples of 2^e.
// ---------------------------------------------------------------------------------------------

/// `x` is a multiple of 2^e: its lowest `e` bits are zero. Opaque in proofs: [`aligned_step`]
/// reveals one bit. (Library predicates take `Int` parameters: a `Nat` parameter puts a
/// `0 <= x` guard into the unfolded body at every use.)
#[spec]
#[opaque]
#[example(aligned(12, 2) && !aligned(12, 3) && aligned(5, 0))]
// 0 is a multiple of 2; 2 is not a multiple of 4
#[example(aligned(0, 1) && !aligned(2, 2))]
#[decreases(e)]
pub fn aligned(x: Int, e: Int) -> bool {
    if e <= 0 { true } else { x >= 0 && x % 2 == 0 && aligned(x / 2, e - 1) }
}

/// One step of [`aligned`].
#[lemma]
pub fn aligned_step(x: Nat, e: Int) {
    requires(e >= 1);
    ensures(aligned(x, e) == (x % 2 == 0 && aligned(x / 2, e - 1)));
    unfold(aligned);
    follows();
}

/// A multiple of 2^e (e ≥ 1) is even, and its half is a multiple of 2^(e-1).
#[lemma]
pub fn aligned_split(x: Nat, e: Int) {
    requires(e >= 1 && aligned(x, e));
    ensures(x % 2 == 0 && aligned(x / 2, e - 1));
    aligned_step(x, e);
    follows();
}

/// [`aligned_split`], with the half's exponent written `f`.
#[lemma]
pub fn aligned_halve(x: Nat, e: Int, f: Int) {
    requires(e >= 1 && aligned(x, e) && f == e - 1);
    ensures(x % 2 == 0 && aligned(x / 2, f));
    aligned_split(x, e);
    rewrite(f == e - 1);
    by_arithmetic();
}

/// An even number whose half is a multiple of 2^(e-1) is a multiple of 2^e.
#[lemma]
pub fn aligned_join(x: Nat, e: Int) {
    requires(e >= 1 && x % 2 == 0 && aligned(x / 2, e - 1));
    ensures(aligned(x, e));
    aligned_step(x, e);
    follows();
}

/// Every number is a multiple of 2^0.
#[lemma]
pub fn aligned_zero(x: Nat, e: Int) {
    requires(e == 0);
    ensures(aligned(x, e));
    unfold(aligned);
    follows();
}

/// [`aligned`] at an exponent written differently.
#[lemma]
pub fn aligned_eq(x: Nat, e: Int, f: Int) {
    requires(aligned(x, e) && e == f);
    ensures(aligned(x, f));
    rewrite(f == e);
    follows();
}

/// [`aligned`] of a number written differently.
#[lemma]
pub fn aligned_same(x: Nat, y: Nat, e: Int) {
    requires(aligned(x, e) && x == y);
    ensures(aligned(y, e));
    rewrite(y == x);
    follows();
}

/// Twice a multiple of 2^f is a multiple of 2^e, e = f + 1.
#[lemma]
pub fn aligned_double(x: Nat, f: Int, e: Int) {
    requires(aligned(x, f) && f >= 0 && e == f + 1);
    ensures(aligned(2 * x, e));
    halves_double(x);
    aligned_same(x, (2 * x) / 2, f);
    aligned_eq((2 * x) / 2, f, e - 1);
    aligned_join(2 * x, e);
}

/// Zero is a multiple of every power of two.
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn aligned_zero_value(e: Int) {
    requires(e >= 0);
    ensures(aligned(0, e));
    if e == 0 {
        aligned_zero(0, e);
    } else {
        ih(e - 1);
        aligned_join(0, e);
    }
}

/// 2^e is a multiple of 2^e.
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn aligned_pow2(e: Int) {
    requires(e >= 0);
    ensures(aligned(pow2(e), e));
    if e == 0 {
        aligned_zero(pow2(e), e);
    } else {
        ih(e - 1);
        aligned_double(pow2(e - 1), e - 1, e);
        pow2_step(e);
        by_arithmetic();
    }
}

/// A multiple of 2^e is a multiple of 2^(e-1).
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn aligned_weaken(x: Nat, e: Int) {
    requires(aligned(x, e) && e >= 1);
    ensures(aligned(x, e - 1));
    aligned_split(x, e);
    if e == 1 {
        aligned_zero(x, e - 1);
    } else {
        ih(x / 2, e - 1);
        aligned_join(x, e - 1);
    }
}

/// A positive multiple of 2^e is at least 2^e.
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn aligned_ge(x: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && x > 0);
    ensures(x >= pow2(e));
    if e == 0 {
        follows();
    } else {
        aligned_split(x, e);
        pow2_step(e);
        halves(x);
        ih(x / 2, e - 1);
        by_arithmetic();
    }
}

/// The sum of two multiples of 2^e is one.
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn aligned_sum(x: Nat, y: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && aligned(y, e));
    ensures(aligned(x + y, e));
    if e == 0 {
        aligned_zero(x + y, e);
    } else {
        aligned_split(x, e);
        aligned_split(y, e);
        ih(x / 2, y / 2, e - 1);
        halves_sum(x, y);
        aligned_join(x + y, e);
    }
}

/// The difference of two multiples of 2^e is one.
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn aligned_diff(x: Nat, y: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && aligned(y, e) && y <= x);
    ensures(aligned(x - y, e));
    if e == 0 {
        aligned_zero(x - y, e);
    } else {
        aligned_split(x, e);
        aligned_split(y, e);
        halves_diff(x, y);
        ih(x / 2, y / 2, e - 1);
        aligned_join(x - y, e);
    }
}

/// Of two multiples of 2^e, the smaller is at least 2^e below the larger.
#[lemma]
pub fn aligned_gap(x: Nat, m: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && aligned(m, e) && x < m);
    ensures(x + pow2(e) <= m);
    aligned_diff(m, x, e);
    aligned_ge(m - x, e);
    by_arithmetic();
}

/// A multiple of 2^e, plus 2^(e-1), is a multiple of 2^(e-1).
#[lemma]
pub fn aligned_add_pow2(x: Nat, e: Int) {
    requires(e >= 1 && aligned(x, e));
    ensures(aligned(x + pow2(e - 1), e - 1));
    aligned_weaken(x, e);
    aligned_pow2(e - 1);
    aligned_sum(x, pow2(e - 1), e - 1);
}

/// The bits of a multiple of 2^e and of a number below 2^e do not overlap: their counts add up.
#[lemma]
#[induction(e)]
#[decreases(e)]
pub fn popcount_add(x: Nat, y: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && y < pow2(e));
    ensures(popcount(x + y) == popcount(x) + popcount(y));
    if e == 0 {
        // nothing below 2^0 but 0
        pow2_zero(e);
        assert(y == 0, { by_arithmetic(); });
        rewrite(y == 0);
        by_computation();
    } else {
        aligned_split(x, e);
        pow2_step(e);
        halves(y);
        halves_sum(x, y);
        calc! {
            popcount(x + y)
                == (x + y) % 2 + popcount((x + y) / 2) by { popcount_step(x + y); };
                // `x` is even: the lowest bit of the sum is `y`'s, and the halves add up
                == y % 2 + popcount(x / 2 + y / 2) by { rewrite((x + y) / 2 == x / 2 + y / 2); by_arithmetic(); };
                == y % 2 + popcount(x / 2) + popcount(y / 2) by { ih(x / 2, y / 2, e - 1); by_arithmetic(); };
                == popcount(x) + popcount(y) by { popcount_step(x); popcount_step(y); by_arithmetic(); };
        }
    }
}

/// 2^a ≤ 2^b when a ≤ b.
#[lemma]
pub fn pow2_mono(a: Int, b: Int) {
    requires(0 <= a && a <= b);
    ensures(pow2(a) <= pow2(b));
    if a == b { pow2_same(a, b); follows(); } else { pow2_lt(a, b); follows(); }
}

/// The base-2 logarithm of a number between 2^e and 2^(e+1).
#[lemma]
pub fn log2_unique(n: Nat, e: Nat) {
    requires(0 <= e);
    requires(pow2(e) <= n && n < 2 * pow2(e));
    ensures(log2(n) == e);
    sandblaster::lemmas::nat::pow2_pos(e);
    sandblaster::lemmas::nat::log2_bounds(n);
    sandblaster::lemmas::nat::log2_nonneg(n);
    sandblaster::lemmas::nat::pow2_succ(log2(n));
    sandblaster::lemmas::nat::pow2_succ(e);
    if log2(n) < e {
        pow2_mono(log2(n) + 1, e);
        by_arithmetic();
    } else if log2(n) > e {
        pow2_mono(e + 1, log2(n));
        by_arithmetic();
    } else {
        follows();
    }
}

/// The big-endian bytes of a `u64` determine it.
#[lemma]
pub fn u64_bytes_inj(a: u64, b: u64) {
    requires(seq![..a.to_be_bytes()] == seq![..b.to_be_bytes()]);
    ensures(a == b);
    assert(((a >> 56u32) as u8) == ((b >> 56u32) as u8), { follows(); });
    assert(((a >> 48u32) as u8) == ((b >> 48u32) as u8), { follows(); });
    assert(((a >> 40u32) as u8) == ((b >> 40u32) as u8), { follows(); });
    assert(((a >> 32u32) as u8) == ((b >> 32u32) as u8), { follows(); });
    assert(((a >> 24u32) as u8) == ((b >> 24u32) as u8), { follows(); });
    assert(((a >> 16u32) as u8) == ((b >> 16u32) as u8), { follows(); });
    assert(((a >> 8u32) as u8) == ((b >> 8u32) as u8), { follows(); });
    assert((a as u8) == (b as u8), { follows(); });
    assert(a == ((((a >> 56u32) as u8) as u64) << 56u32) | ((((a >> 48u32) as u8) as u64) << 48u32) | ((((a >> 40u32) as u8) as u64) << 40u32) | ((((a >> 32u32) as u8) as u64) << 32u32) | ((((a >> 24u32) as u8) as u64) << 24u32) | ((((a >> 16u32) as u8) as u64) << 16u32) | ((((a >> 8u32) as u8) as u64) << 8u32) | (a as u8 as u64), { bv(); });
    assert(b == ((((b >> 56u32) as u8) as u64) << 56u32) | ((((b >> 48u32) as u8) as u64) << 48u32) | ((((b >> 40u32) as u8) as u64) << 40u32) | ((((b >> 32u32) as u8) as u64) << 32u32) | ((((b >> 24u32) as u8) as u64) << 24u32) | ((((b >> 16u32) as u8) as u64) << 16u32) | ((((b >> 8u32) as u8) as u64) << 8u32) | (b as u8 as u64), { bv(); });
    assert(((((a >> 56u32) as u8) as u64) << 56u32) | ((((a >> 48u32) as u8) as u64) << 48u32) | ((((a >> 40u32) as u8) as u64) << 40u32) | ((((a >> 32u32) as u8) as u64) << 32u32) | ((((a >> 24u32) as u8) as u64) << 24u32) | ((((a >> 16u32) as u8) as u64) << 16u32) | ((((a >> 8u32) as u8) as u64) << 8u32) | (a as u8 as u64) == ((((b >> 56u32) as u8) as u64) << 56u32) | ((((b >> 48u32) as u8) as u64) << 48u32) | ((((b >> 40u32) as u8) as u64) << 40u32) | ((((b >> 32u32) as u8) as u64) << 32u32) | ((((b >> 24u32) as u8) as u64) << 24u32) | ((((b >> 16u32) as u8) as u64) << 16u32) | ((((b >> 8u32) as u8) as u64) << 8u32) | (b as u8 as u64), {
        rewrite(((a >> 56u32) as u8) == ((b >> 56u32) as u8));
        rewrite(((a >> 48u32) as u8) == ((b >> 48u32) as u8));
        rewrite(((a >> 40u32) as u8) == ((b >> 40u32) as u8));
        rewrite(((a >> 32u32) as u8) == ((b >> 32u32) as u8));
        rewrite(((a >> 24u32) as u8) == ((b >> 24u32) as u8));
        rewrite(((a >> 16u32) as u8) == ((b >> 16u32) as u8));
        rewrite(((a >> 8u32) as u8) == ((b >> 8u32) as u8));
        rewrite((a as u8) == (b as u8));
        follows();
    });
    follows();
}

/// A number below 2^e has at most `e` set bits.
#[lemma]
#[decreases(e)]
pub fn popcount_below(x: Nat, e: Int) {
    requires(e >= 0 && x < pow2(e));
    ensures(popcount(x) <= e);
    popcount_step(x);
    halves(x);
    if e == 0 {
        pow2_zero(e);
        assert(x == 0 && x / 2 == 0 && x % 2 == 0, { by_arithmetic(); });
        popcount_same(x / 2, 0);
        assert(popcount(0) == 0, { by_computation(); });
        by_arithmetic();
    } else {
        pow2_step(e);
        assert(x / 2 < pow2(e - 1), { by_arithmetic(); });
        popcount_below(x / 2, e - 1);
        by_arithmetic();
    }
}

/// A multiple of 2^e is a multiple of every smaller power 2^f.
#[lemma]
#[decreases(e)]
pub fn aligned_down(x: Nat, e: Int, f: Int) {
    requires(0 <= f && f <= e && aligned(x, e));
    ensures(aligned(x, f));
    if e == f {
        aligned_eq(x, e, f);
    } else {
        aligned_weaken(x, e);
        aligned_down(x, e - 1, f);
    }
}

/// The lowest set bit of `x` is bit `t` (`x − 2^t` is a multiple of 2^(t+1)): then for every
/// `i <= t`, `2^i <= x` and `x − 2^i` is a multiple of 2^i (it adds the bits `t − 1 .. i`, each a
/// multiple of 2^i, to `x − 2^t`).
#[lemma]
#[decreases(t - i)]
pub fn aligned_below_low_bit(x: Nat, t: Int, i: Int) {
    requires(0 <= i && i <= t && pow2(t) <= x && aligned(x - pow2(t), t + 1));
    ensures(pow2(i) <= x && aligned(x - pow2(i), i));
    if i == t {
        aligned_weaken((x - pow2(t)) as Nat, t + 1);
        aligned_eq((x - pow2(t)) as Nat, t + 1 - 1, i);
        pow2_same(i, t);
        aligned_same((x - pow2(t)) as Nat, (x - pow2(i)) as Nat, i);
        follows();
    } else {
        aligned_below_low_bit(x, t, i + 1);
        pow2_step(i + 1);
        aligned_add_pow2((x - pow2(i + 1)) as Nat, i + 1);
        aligned_eq((x - pow2(i + 1) + pow2(i + 1 - 1)) as Nat, i + 1 - 1, i);
        aligned_same((x - pow2(i + 1) + pow2(i + 1 - 1)) as Nat, (x - pow2(i)) as Nat, i);
        follows();
    }
}

// ---------------------------------------------------------------------------------------------
// Trailing zeros and trailing ones of a word, for every count at once (no lemma per count).
// ---------------------------------------------------------------------------------------------

/// The trailing zeros `z` of a nonzero word (`x.trailing_zeros()`): `x` is `2^z` times an odd
/// number — a multiple of `2^z` (its lowest `z` bits are zero), and `x - 2^z` a multiple of
/// `2^(z+1)` (bit `z` is set). By halving: an odd `x` has none (`bits::tz_range_u64_0`), an even
/// one has one more than its half (`bits::tz_shr1_u64`).
#[lemma]
#[decreases(x)]
pub fn trailing_zeros_u64(x: u64) {
    requires(x != 0u64);
    ensures(pow2(x.trailing_zeros() as Int) <= (x as Int) && aligned(x as Int, x.trailing_zeros() as Int)
        && aligned((x as Int) - pow2(x.trailing_zeros() as Int), (x.trailing_zeros() as Int) + 1));
    if (x & 1u64) == 1u64 {
        // odd: no trailing zero, and `x - 1` is twice `x >> 1`
        sandblaster::lemmas::bits::tz_range_u64_0(x);
        aligned_zero(x as Nat, 0);
        aligned_zero((x >> 1u32) as Nat, 0);
        aligned_double((x >> 1u32) as Nat, 0, 1);
        follows();
    } else {
        // even: one more than `x >> 1`, and twice its multiples
        sandblaster::lemmas::bits::tz_shr1_u64(x);
        trailing_zeros_u64(x >> 1u32);
        let z = (x >> 1u32).trailing_zeros() as Int;
        aligned_double((x >> 1u32) as Nat, z, z + 1);
        aligned_double((((x >> 1u32) as Int) - pow2(z)) as Nat, z + 1, z + 2);
        pow2_step(z + 1);
        follows();
    }
}

/// The trailing ones `t` of a word below `u64::MAX` (`(!n).trailing_zeros()`, the position of
/// its lowest zero bit): `n + 1` is `2^t` times an odd number — `2^t <= n + 1`, and `n + 1 - 2^t`
/// is a multiple of `2^(t+1)` (the lowest `t` bits of `n` are ones, bit `t` is zero). From
/// [`trailing_zeros_u64`] at `!n`, which is `2^64 - 1 - n`.
#[lemma]
pub fn trailing_ones_u64(n: u64) {
    requires(n != 18446744073709551615u64);
    ensures(pow2((!n).trailing_zeros() as Int) <= (n as Int) + 1
        && aligned((n as Int) + 1 - pow2((!n).trailing_zeros() as Int), ((!n).trailing_zeros() as Int) + 1));
    trailing_zeros_u64(!n);
    let t = (!n).trailing_zeros() as Int;
    // `2^64 - (!n - 2^t) = n + 1 + 2^t` is a multiple of 2^(t+1) ...
    aligned_pow2(64);
    aligned_down(pow2(64) as Nat, 64, t + 1);
    aligned_diff(pow2(64) as Nat, (((!n) as Int) - pow2(t)) as Nat, t + 1);
    // ... and positive, so at least 2^(t+1); less 2^(t+1) it is `n + 1 - 2^t`
    aligned_ge(((n as Int) + 1 + pow2(t)) as Nat, t + 1);
    pow2_step(t + 1);
    aligned_pow2(t + 1);
    aligned_diff(((n as Int) + 1 + pow2(t)) as Nat, pow2(t + 1) as Nat, t + 1);
    follows();
}

/// [`trailing_zeros_u64`] for `u8`.
#[lemma]
#[decreases(x)]
pub fn trailing_zeros_u8(x: u8) {
    requires(x != 0u8);
    ensures(pow2(x.trailing_zeros() as Int) <= (x as Int) && aligned(x as Int, x.trailing_zeros() as Int)
        && aligned((x as Int) - pow2(x.trailing_zeros() as Int), (x.trailing_zeros() as Int) + 1));
    if (x & 1u8) == 1u8 {
        // odd: no trailing zero, and `x - 1` is twice `x >> 1`
        sandblaster::lemmas::bits::tz_range_u8_0(x);
        aligned_zero(x as Nat, 0);
        aligned_zero((x >> 1u32) as Nat, 0);
        aligned_double((x >> 1u32) as Nat, 0, 1);
        follows();
    } else {
        // even: one more than `x >> 1`, and twice its multiples
        sandblaster::lemmas::bits::tz_shr1_u8(x);
        trailing_zeros_u8(x >> 1u32);
        let z = (x >> 1u32).trailing_zeros() as Int;
        aligned_double((x >> 1u32) as Nat, z, z + 1);
        aligned_double((((x >> 1u32) as Int) - pow2(z)) as Nat, z + 1, z + 2);
        pow2_step(z + 1);
        follows();
    }
}

/// [`trailing_ones_u64`] for `u8`.
#[lemma]
pub fn trailing_ones_u8(n: u8) {
    requires(n != 255u8);
    ensures(pow2((!n).trailing_zeros() as Int) <= (n as Int) + 1
        && aligned((n as Int) + 1 - pow2((!n).trailing_zeros() as Int), ((!n).trailing_zeros() as Int) + 1));
    trailing_zeros_u8(!n);
    let t = (!n).trailing_zeros() as Int;
    // `2^8 - (!n - 2^t) = n + 1 + 2^t` is a multiple of 2^(t+1) ...
    aligned_pow2(8);
    aligned_down(pow2(8) as Nat, 8, t + 1);
    aligned_diff(pow2(8) as Nat, (((!n) as Int) - pow2(t)) as Nat, t + 1);
    // ... and positive, so at least 2^(t+1); less 2^(t+1) it is `n + 1 - 2^t`
    aligned_ge(((n as Int) + 1 + pow2(t)) as Nat, t + 1);
    pow2_step(t + 1);
    aligned_pow2(t + 1);
    aligned_diff(((n as Int) + 1 + pow2(t)) as Nat, pow2(t + 1) as Nat, t + 1);
    follows();
}

/// [`trailing_zeros_u64`] for `u16`.
#[lemma]
#[decreases(x)]
pub fn trailing_zeros_u16(x: u16) {
    requires(x != 0u16);
    ensures(pow2(x.trailing_zeros() as Int) <= (x as Int) && aligned(x as Int, x.trailing_zeros() as Int)
        && aligned((x as Int) - pow2(x.trailing_zeros() as Int), (x.trailing_zeros() as Int) + 1));
    if (x & 1u16) == 1u16 {
        // odd: no trailing zero, and `x - 1` is twice `x >> 1`
        sandblaster::lemmas::bits::tz_range_u16_0(x);
        aligned_zero(x as Nat, 0);
        aligned_zero((x >> 1u32) as Nat, 0);
        aligned_double((x >> 1u32) as Nat, 0, 1);
        follows();
    } else {
        // even: one more than `x >> 1`, and twice its multiples
        sandblaster::lemmas::bits::tz_shr1_u16(x);
        trailing_zeros_u16(x >> 1u32);
        let z = (x >> 1u32).trailing_zeros() as Int;
        aligned_double((x >> 1u32) as Nat, z, z + 1);
        aligned_double((((x >> 1u32) as Int) - pow2(z)) as Nat, z + 1, z + 2);
        pow2_step(z + 1);
        follows();
    }
}

/// [`trailing_ones_u64`] for `u16`.
#[lemma]
pub fn trailing_ones_u16(n: u16) {
    requires(n != 65535u16);
    ensures(pow2((!n).trailing_zeros() as Int) <= (n as Int) + 1
        && aligned((n as Int) + 1 - pow2((!n).trailing_zeros() as Int), ((!n).trailing_zeros() as Int) + 1));
    trailing_zeros_u16(!n);
    let t = (!n).trailing_zeros() as Int;
    // `2^16 - (!n - 2^t) = n + 1 + 2^t` is a multiple of 2^(t+1) ...
    aligned_pow2(16);
    aligned_down(pow2(16) as Nat, 16, t + 1);
    aligned_diff(pow2(16) as Nat, (((!n) as Int) - pow2(t)) as Nat, t + 1);
    // ... and positive, so at least 2^(t+1); less 2^(t+1) it is `n + 1 - 2^t`
    aligned_ge(((n as Int) + 1 + pow2(t)) as Nat, t + 1);
    pow2_step(t + 1);
    aligned_pow2(t + 1);
    aligned_diff(((n as Int) + 1 + pow2(t)) as Nat, pow2(t + 1) as Nat, t + 1);
    follows();
}

/// [`trailing_zeros_u64`] for `u32`.
#[lemma]
#[decreases(x)]
pub fn trailing_zeros_u32(x: u32) {
    requires(x != 0u32);
    ensures(pow2(x.trailing_zeros() as Int) <= (x as Int) && aligned(x as Int, x.trailing_zeros() as Int)
        && aligned((x as Int) - pow2(x.trailing_zeros() as Int), (x.trailing_zeros() as Int) + 1));
    if (x & 1u32) == 1u32 {
        // odd: no trailing zero, and `x - 1` is twice `x >> 1`
        sandblaster::lemmas::bits::tz_range_u32_0(x);
        aligned_zero(x as Nat, 0);
        aligned_zero((x >> 1u32) as Nat, 0);
        aligned_double((x >> 1u32) as Nat, 0, 1);
        follows();
    } else {
        // even: one more than `x >> 1`, and twice its multiples
        sandblaster::lemmas::bits::tz_shr1_u32(x);
        trailing_zeros_u32(x >> 1u32);
        let z = (x >> 1u32).trailing_zeros() as Int;
        aligned_double((x >> 1u32) as Nat, z, z + 1);
        aligned_double((((x >> 1u32) as Int) - pow2(z)) as Nat, z + 1, z + 2);
        pow2_step(z + 1);
        follows();
    }
}

/// [`trailing_ones_u64`] for `u32`.
#[lemma]
pub fn trailing_ones_u32(n: u32) {
    requires(n != 4294967295u32);
    ensures(pow2((!n).trailing_zeros() as Int) <= (n as Int) + 1
        && aligned((n as Int) + 1 - pow2((!n).trailing_zeros() as Int), ((!n).trailing_zeros() as Int) + 1));
    trailing_zeros_u32(!n);
    let t = (!n).trailing_zeros() as Int;
    // `2^32 - (!n - 2^t) = n + 1 + 2^t` is a multiple of 2^(t+1) ...
    aligned_pow2(32);
    aligned_down(pow2(32) as Nat, 32, t + 1);
    aligned_diff(pow2(32) as Nat, (((!n) as Int) - pow2(t)) as Nat, t + 1);
    // ... and positive, so at least 2^(t+1); less 2^(t+1) it is `n + 1 - 2^t`
    aligned_ge(((n as Int) + 1 + pow2(t)) as Nat, t + 1);
    pow2_step(t + 1);
    aligned_pow2(t + 1);
    aligned_diff(((n as Int) + 1 + pow2(t)) as Nat, pow2(t + 1) as Nat, t + 1);
    follows();
}

/// [`trailing_zeros_u64`] for `usize`.
#[lemma]
#[decreases(x)]
pub fn trailing_zeros_usize(x: usize) {
    requires(x != 0usize);
    ensures(pow2(x.trailing_zeros() as Int) <= (x as Int) && aligned(x as Int, x.trailing_zeros() as Int)
        && aligned((x as Int) - pow2(x.trailing_zeros() as Int), (x.trailing_zeros() as Int) + 1));
    if (x & 1usize) == 1usize {
        // odd: no trailing zero, and `x - 1` is twice `x >> 1`
        sandblaster::lemmas::bits::tz_range_usize_0(x);
        aligned_zero(x as Nat, 0);
        aligned_zero((x >> 1u32) as Nat, 0);
        aligned_double((x >> 1u32) as Nat, 0, 1);
        follows();
    } else {
        // even: one more than `x >> 1`, and twice its multiples
        sandblaster::lemmas::bits::tz_shr1_usize(x);
        trailing_zeros_usize(x >> 1u32);
        let z = (x >> 1u32).trailing_zeros() as Int;
        aligned_double((x >> 1u32) as Nat, z, z + 1);
        aligned_double((((x >> 1u32) as Int) - pow2(z)) as Nat, z + 1, z + 2);
        pow2_step(z + 1);
        follows();
    }
}

/// [`trailing_ones_u64`] for `usize`.
#[lemma]
pub fn trailing_ones_usize(n: usize) {
    requires(n != 18446744073709551615usize);
    ensures(pow2((!n).trailing_zeros() as Int) <= (n as Int) + 1
        && aligned((n as Int) + 1 - pow2((!n).trailing_zeros() as Int), ((!n).trailing_zeros() as Int) + 1));
    trailing_zeros_usize(!n);
    let t = (!n).trailing_zeros() as Int;
    // `2^64 - (!n - 2^t) = n + 1 + 2^t` is a multiple of 2^(t+1) ...
    aligned_pow2(64);
    aligned_down(pow2(64) as Nat, 64, t + 1);
    aligned_diff(pow2(64) as Nat, (((!n) as Int) - pow2(t)) as Nat, t + 1);
    // ... and positive, so at least 2^(t+1); less 2^(t+1) it is `n + 1 - 2^t`
    aligned_ge(((n as Int) + 1 + pow2(t)) as Nat, t + 1);
    pow2_step(t + 1);
    aligned_pow2(t + 1);
    aligned_diff(((n as Int) + 1 + pow2(t)) as Nat, pow2(t + 1) as Nat, t + 1);
    follows();
}
