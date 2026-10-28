//! Unsaturated radix-`2^49` Montgomery arithmetic on several base field elements at once, using
//! 64-bit lane values.
//!
//! A [`Unsat49`] is a matrix with [`LIMBS`] rows and `S::U64_LANES` columns: row `i` holds limb `i`
//! of every element. Elements use radix `2^BITS` in Montgomery form with `R = 2^(8 BITS)`, for
//! `48 <= BITS <= 52`, so eight limbs cover `p` in every radix. `BITS` defaults to `49`; the other
//! radices remain for comparison. Products accumulate with
//! `u64_madd52lo` and `u64_madd52hi`, which AVX-512 IFMA provides natively and other backends
//! emulate. They split each product at bit 52, so a radix below `2^52` shifts each column of high
//! halves left by `52 - BITS` before adding it to its column.
//!
//! # Usage
//!
//! Elements cross the boundary as [`BYTES`]-byte big-endian integers below `2^384`, which loads
//! interpret modulo `p` and stores return canonically.
//!
//! Loads, splats, products, and [`Unsat49::carry`] return carried values, whose limbs are below
//! `2^BITS`; additions, subtractions, negations, and doublings return uncarried ones. A
//! multiplication accepts limbs below `2^52`, so a radix below `2^52` multiplies sums of up to
//! `2^(52 - BITS)` carried values without carrying them. [`Unsat49::ready`] prepares a
//! multiplicand from a static bound on its limbs, carrying only when this radix requires it. A
//! subtraction or negation removes values whose limbs are at most twice those of a carried value.
//!
//! Carrying preserves the represented integer; multiplication is what reduces modulo `p`, and
//! [`Unsat49::store`] returns canonical elements from any value. A subtraction or negation bias
//! `K` must exceed the bound of the value it removes.
//!
//! # Bounds
//!
//! Each value carries two debug-only bound counters: an integer bound in units of `p`, and a
//! limb bound in units of `2^BITS`. For integer bounds `A` and `B`, limb bounds `L` and `M`,
//! `LIMIT = 2^(8 BITS - 381)`, and `SLACK = 2^(52 - BITS)`:
//!
//! | Operation | Requires | Integer bound | Limb bound |
//! |---|---|---|---|
//! | load, splat | | `ceil(10 / LIMIT) + 1`, which is `2` unless `BITS = 48` | `1` |
//! | `a + b` | | `A + B` | `L + M` |
//! | `a - b` with bias `K` | `M <= 2`, `B < K` | `A + K` | `L + 3` |
//! | `-a` with bias `K` | `L <= 2`, `A < K` | `K` | `3` |
//! | carry | | `A` | `1` |
//! | `a * b` | `L, M <= SLACK` | `ceil(A * B / LIMIT) + 1` | `1` |
//!
//! Every integer bound is at most `LIMIT`, so values fit carried limbs because `p < 2^381`. Every
//! limb bound is below `2^(64 - BITS)`, so carries fit the 64-bit lanes. Multiplication returns
//! below `a * b / 2^(8 BITS) + p`, and `p / 2^(8 BITS) < 1 / LIMIT`. Debug builds check these
//! rules; release builds do not, and results are unspecified when a formula violates them.

use super::{BYTES, MAX_LANES, MODULUS, WORDS, bytes_from_words, power_of_two, words_from_bytes};
use crate::{debug_counter::DebugCounter, montgomery::negated_inverse};
use commonware_simd::Simd;

/// Number of limbs in a field element.
pub const LIMBS: usize = 8;

/// Splits a little-endian 64-bit integer below `2^(8 bits)` into `bits`-bit limbs.
const fn limbs_from_words(words: [u64; WORDS], bits: u32) -> [u64; LIMBS] {
    let bits = bits as usize;
    let mask = (1u64 << bits) - 1;
    let mut limbs = [0; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        let (word, shift) = (i * bits / 64, i * bits % 64);
        let mut limb = 0;
        if word < WORDS {
            limb = words[word] >> shift;
            if shift + bits > 64 && word + 1 < WORDS {
                limb |= words[word + 1] << (64 - shift);
            }
        }
        limbs[i] = limb & mask;
        i += 1;
    }
    limbs
}

/// Joins carried `bits`-bit limbs of a value below `2^384` into little-endian 64-bit words.
const fn words_from_limbs(limbs: [u64; LIMBS], bits: u32) -> [u64; WORDS] {
    let bits = bits as usize;
    let mut words = [0u64; WORDS + 1];
    let mut i = 0;
    while i < LIMBS {
        let (word, shift) = (i * bits / 64, i * bits % 64);
        words[word] |= limbs[i] << shift;
        if shift + bits > 64 {
            words[word + 1] |= limbs[i] >> (64 - shift);
        }
        i += 1;
    }
    let mut out = [0; WORDS];
    let mut i = 0;
    while i < WORDS {
        out[i] = words[i];
        i += 1;
    }
    out
}

/// Returns `k * p` in carried `bits`-bit limbs.
const fn multiple(k: u64, bits: u32) -> [u64; LIMBS] {
    let modulus = limbs_from_words(MODULUS, bits);
    let mut limbs = [0; LIMBS];
    let mut carry = 0u128;
    let mut i = 0;
    while i < LIMBS {
        let wide = modulus[i] as u128 * k as u128 + carry;
        limbs[i] = wide as u64 & ((1 << bits) - 1);
        carry = wide >> bits;
        i += 1;
    }
    assert!(carry == 0);
    limbs
}

/// Returns `k * p` with twice `2^bits` moved from each limb into the one below it.
///
/// The low seven limbs are then at least twice `2^bits`, so subtracting a value whose limbs are at
/// most twice those of a carried value never borrows from them. The top limb is two less than that
/// of `k * p`, which still covers the top limb of such a value below `(k - 1) * p`, since the two
/// differ by more than `p > 3 * 2^(7 bits)`.
const fn bias(k: u64, bits: u32) -> [u64; LIMBS] {
    assert!(k >= 1);
    let mut limbs = multiple(k, bits);
    let mut i = 0;
    while i + 1 < LIMBS {
        assert!(limbs[i + 1] >= 2);
        limbs[i] += 2 << bits;
        limbs[i + 1] -= 2;
        i += 1;
    }
    limbs
}

/// `S::U64_LANES` base field elements in radix `2^BITS` Montgomery form, one per lane, with
/// `BITS = 49` by default.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub struct Unsat49<S: Simd, const BITS: u32 = 49> {
    limbs: [S::U64; LIMBS],
    bound: DebugCounter,
    limb_bound: DebugCounter,
}

impl<S: Simd, const BITS: u32> Clone for Unsat49<S, BITS> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd, const BITS: u32> Copy for Unsat49<S, BITS> {}

impl<S: Simd, const BITS: u32> Unsat49<S, BITS> {
    /// The low `BITS` bits of a limb.
    const MASK: u64 = {
        assert!(BITS >= 48 && BITS <= 52);
        (1 << BITS) - 1
    };

    /// Largest integer bound of any value, in units of `p`.
    ///
    /// Because `p < 2^381`, `LIMIT * p < 2^(8 BITS)` and `p / 2^(8 BITS) < 1 / LIMIT`.
    pub const LIMIT: u64 = {
        assert!(MODULUS[WORDS - 1] < 1 << 61);
        1 << (8 * BITS - 381)
    };

    /// Largest limb bound of a multiplicand, in units of `2^BITS`.
    pub const SLACK: u64 = 1 << (52 - BITS);

    /// Largest limb bound of any value, in units of `2^BITS`, so that carries fit the lanes.
    const LIMB_LIMIT: u64 = (1 << (64 - BITS)) - 1;

    /// The modulus `p` in limbs.
    const MODULUS: [u64; LIMBS] = limbs_from_words(MODULUS, BITS);

    /// `-p^(-1) mod 2^BITS`, the Montgomery reduction constant.
    const INV: u64 = negated_inverse(MODULUS[0]) & Self::MASK;

    /// `R^2 mod p` for `R = 2^(8 BITS)`. A Montgomery multiplication by it maps `a` to `a * R`.
    const TO_LANES: [u64; LIMBS] = limbs_from_words(power_of_two(16 * BITS), BITS);

    /// One. A Montgomery multiplication by it maps `a * R` back to `a`.
    const FROM_LANES: [u64; LIMBS] = {
        let mut limbs = [0; LIMBS];
        limbs[0] = 1;
        limbs
    };

    /// Returns every lane set to `element`.
    #[inline(always)]
    pub fn splat(simd: S, element: &[u8; BYTES]) -> Self {
        let limbs = limbs_from_words(words_from_bytes(element), BITS);
        Self::raw(simd, &[limbs; MAX_LANES], 10).to_lanes(simd)
    }

    /// Loads up to `S::U64_LANES` elements, one per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self {
        let mut lanes = [limbs_from_words(words_from_bytes(fill), BITS); MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = limbs_from_words(words_from_bytes(element), BITS);
        }
        // Integers below 2^384 are below 10p.
        Self::raw(simd, &lanes, 10).to_lanes(simd)
    }

    /// Stores the canonical value of each lane into `elements`, dropping lanes beyond its length.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [[u8; BYTES]]) {
        let canonical = self
            .carry(simd)
            .mul(simd, Self::raw(simd, &[Self::FROM_LANES; MAX_LANES], 1))
            .subtract_modulus(simd);
        let lanes = canonical.store_raw(simd);
        for (element, limbs) in elements.iter_mut().zip(lanes).take(S::U64_LANES) {
            *element = bytes_from_words(&words_from_limbs(limbs, BITS));
        }
    }

    /// Transposes carried per-lane limbs, bounded by `bound * p`, into limb rows.
    #[inline(always)]
    fn raw(simd: S, lanes: &[[u64; LIMBS]; MAX_LANES], bound: u64) -> Self {
        const { assert!(S::U64_LANES <= MAX_LANES) };
        let mut rows = [[0; MAX_LANES]; LIMBS];
        for (lane, limbs) in lanes.iter().enumerate() {
            for (row, limb) in rows.iter_mut().zip(limbs) {
                row[lane] = *limb;
            }
        }
        let mut limbs = [simd.u64_splat(0); LIMBS];
        for (limb, row) in limbs.iter_mut().zip(&rows) {
            *limb = simd.u64_load(row);
        }
        Self {
            limbs,
            bound: DebugCounter::new(bound),
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Returns each lane's limbs, without any conversion.
    #[inline(always)]
    fn store_raw(self, simd: S) -> [[u64; LIMBS]; MAX_LANES] {
        let mut lanes = [[0; LIMBS]; MAX_LANES];
        for (i, row) in self.limbs.into_iter().enumerate() {
            let mut values = [0; MAX_LANES];
            simd.u64_store(row, &mut values);
            for (lane, value) in lanes.iter_mut().zip(values) {
                lane[i] = value;
            }
        }
        lanes
    }

    /// Loads per-lane limbs in this module's representation, bounded by `bound * p`.
    ///
    /// The limbs must be carried, as returned by [`Self::to_limbs`] after [`Self::carry`].
    #[inline(always)]
    pub fn from_limbs(simd: S, lanes: &[[u64; LIMBS]; MAX_LANES], bound: u64) -> Self {
        Self::raw(simd, lanes, bound)
    }

    /// Returns each lane's carried limbs in this module's representation, without any
    /// conversion, for a value bounded by `bound * p`.
    #[inline(always)]
    pub fn to_limbs(self, simd: S, bound: u64) -> [[u64; LIMBS]; MAX_LANES] {
        self.limb_bound.assert_le(1);
        self.bound.assert_le(bound);
        self.store_raw(simd)
    }

    /// Converts an integer `a` into this module's Montgomery form `a * 2^(8 BITS)`.
    #[inline(always)]
    fn to_lanes(self, simd: S) -> Self {
        self.mul(simd, Self::raw(simd, &[Self::TO_LANES; MAX_LANES], 1))
    }

    /// Returns `self + rhs`, without carrying.
    #[inline(always)]
    pub fn add(mut self, simd: S, rhs: Self) -> Self {
        self.bound.add(rhs.bound);
        self.bound.assert_le(Self::LIMIT);
        self.limb_bound.add(rhs.limb_bound);
        self.limb_bound.assert_le(Self::LIMB_LIMIT);
        for (limb, rhs) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb = simd.u64_add(*limb, rhs);
        }
        self
    }

    /// Returns `self + K * p - rhs`, which is `self - rhs`, without carrying.
    #[inline(always)]
    pub fn sub<const K: u64>(mut self, simd: S, rhs: Self) -> Self {
        rhs.limb_bound.assert_le(2);
        // The subtrahend must be below (K - 1) * p; see bias.
        self.bound.sub_with_bias(rhs.bound, K - 1);
        self.bound.add(DebugCounter::new(1));
        self.bound.assert_le(Self::LIMIT);
        self.limb_bound.add(DebugCounter::new(3));
        self.limb_bound.assert_le(Self::LIMB_LIMIT);
        let bias = const { bias(K, BITS) };
        for ((limb, rhs), bias) in self.limbs.iter_mut().zip(rhs.limbs).zip(bias) {
            *limb = simd.u64_sub(simd.u64_add(*limb, simd.u64_splat(bias)), rhs);
        }
        self
    }

    /// Returns `K * p - self`, which is `-self`, without carrying.
    #[inline(always)]
    pub fn neg<const K: u64>(mut self, simd: S) -> Self {
        self.limb_bound.assert_le(2);
        let mut bound = DebugCounter::new(1);
        bound.sub_with_bias(self.bound, K - 1);
        bound.assert_le(Self::LIMIT);
        let bias = const { bias(K, BITS) };
        for (limb, bias) in self.limbs.iter_mut().zip(bias) {
            *limb = simd.u64_sub(simd.u64_splat(bias), *limb);
        }
        self.bound = bound;
        self.limb_bound = DebugCounter::new(3);
        self
    }

    /// Returns `2 * self`, without carrying.
    #[inline(always)]
    pub fn double(self, simd: S) -> Self {
        self.add(simd, self)
    }

    /// Propagates carries so every limb is below `2^BITS`, without reducing modulo `p`.
    #[inline(always)]
    pub fn carry(mut self, simd: S) -> Self {
        let mask = simd.u64_splat(Self::MASK);
        for i in 0..LIMBS - 1 {
            let carry = shr::<S, BITS>(simd, self.limbs[i]);
            self.limbs[i + 1] = simd.u64_add(self.limbs[i + 1], carry);
            self.limbs[i] = simd.u64_and(self.limbs[i], mask);
        }
        // The value is below 2^(8 BITS), so the top limb is now below 2^BITS as well.
        self.limb_bound = DebugCounter::new(1);
        self
    }

    /// Returns `self` as a multiplicand, given that its limb bound is at most `U`.
    ///
    /// Carries only when `U` exceeds [`Self::SLACK`], so the decision is made at compile time.
    #[inline(always)]
    pub fn ready<const U: u64>(self, simd: S) -> Self {
        self.limb_bound.assert_le(U);
        if U > Self::SLACK {
            self.carry(simd)
        } else {
            self
        }
    }

    /// Returns `self * rhs`.
    ///
    /// Debug builds keep this a call so that deeply inlined formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul(self, simd: S, rhs: Self) -> Self {
        self.limb_bound.assert_le(Self::SLACK);
        rhs.limb_bound.assert_le(Self::SLACK);
        let mut bound = self.bound;
        bound.mul(rhs.bound);
        bound.div_ceil(Self::LIMIT);
        bound.add(DebugCounter::new(1));
        bound.assert_le(Self::LIMIT);

        // Product scanning: column k sums the low halves of a_i b_j and q_i p_j with i + j = k
        // and the high halves with i + j = k - 1, so only one column's accumulators are live.
        // Below 2^52, high halves share the low accumulator; otherwise they are realigned once
        // per column. A column receives at most 32 terms below 2^52 plus a carry, so neither
        // accumulator overflows.
        let (a, b) = (self.limbs, rhs.limbs);
        let zero = simd.u64_splat(0);
        let mut q = [zero; LIMBS];
        let mut limbs = [zero; LIMBS];
        let mut carry = zero;
        // Each column is a separate inlined call with a constant index, so every loop unrolls.
        macro_rules! columns {
            ($($k:literal)*) => {$(
                Self::column(simd, $k, &a, &b, &mut q, &mut limbs, &mut carry);
            )*};
        }
        columns!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
        Self {
            limbs,
            bound,
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Accumulates and reduces column `k` of [`Self::mul`].
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn column(
        simd: S,
        k: usize,
        a: &[S::U64; LIMBS],
        b: &[S::U64; LIMBS],
        q: &mut [S::U64; LIMBS],
        limbs: &mut [S::U64; LIMBS],
        carry: &mut S::U64,
    ) {
        let zero = simd.u64_splat(0);
        let mut low = zero;
        let mut high = zero;
        for i in 0..LIMBS {
            if i <= k && k - i < LIMBS {
                low = simd.u64_madd52lo(low, a[i], b[k - i]);
            }
            if i < k && k - 1 - i < LIMBS {
                if BITS == 52 {
                    low = simd.u64_madd52hi(low, a[i], b[k - 1 - i]);
                } else {
                    high = simd.u64_madd52hi(high, a[i], b[k - 1 - i]);
                }
            }
        }
        for (i, q) in q.iter().enumerate().take(k.min(LIMBS)) {
            if k - i < LIMBS {
                let modulus = simd.u64_splat(Self::MODULUS[k - i]);
                low = simd.u64_madd52lo(low, *q, modulus);
            }
            if k - 1 - i < LIMBS {
                let modulus = simd.u64_splat(Self::MODULUS[k - 1 - i]);
                if BITS == 52 {
                    low = simd.u64_madd52hi(low, *q, modulus);
                } else {
                    high = simd.u64_madd52hi(high, *q, modulus);
                }
            }
        }
        let mut column = simd.u64_add(low, *carry);
        if BITS < 52 {
            column = simd.u64_add(column, realign::<S, BITS>(simd, high));
        }
        if k < LIMBS {
            // Choose q_k to cancel the low BITS bits of this column, then carry the rest.
            let mut multiplier = simd.u64_madd52lo(zero, column, simd.u64_splat(Self::INV));
            if BITS < 52 {
                multiplier = simd.u64_and(multiplier, simd.u64_splat(Self::MASK));
            }
            column = simd.u64_madd52lo(column, multiplier, simd.u64_splat(Self::MODULUS[0]));
            q[k] = multiplier;
            *carry = shr::<S, BITS>(simd, column);
        } else if k < 2 * LIMBS - 1 {
            limbs[k - LIMBS] = simd.u64_and(column, simd.u64_splat(Self::MASK));
            *carry = shr::<S, BITS>(simd, column);
        } else {
            // The result is below 2^(8 BITS), so the top column needs no carry.
            limbs[LIMBS - 1] = column;
        }
    }

    /// Returns `self * self`.
    #[inline(always)]
    pub fn square(self, simd: S) -> Self {
        self.mul(simd, self)
    }

    /// Returns `self - p` in lanes where `self >= p`, for a carried value below `2p`.
    #[inline(always)]
    fn subtract_modulus(self, simd: S) -> Self {
        self.limb_bound.assert_le(1);
        self.bound.assert_le(2);
        let mask = simd.u64_splat(Self::MASK);
        let mut reduced = self.limbs;
        let mut borrow = simd.u64_splat(0);
        for (i, reduced) in reduced.iter_mut().enumerate() {
            let difference = simd.u64_sub(
                simd.u64_sub(self.limbs[i], simd.u64_splat(Self::MODULUS[i])),
                borrow,
            );
            *reduced = simd.u64_and(difference, mask);
            borrow = simd.u64_shr::<63>(difference);
        }
        // A final borrow means the lane was already below p.
        let keep = simd.u64_sub(simd.u64_splat(0), borrow);
        for (limb, reduced) in reduced.iter_mut().zip(self.limbs) {
            *limb = simd.u64_select(keep, reduced, *limb);
        }
        Self {
            limbs: reduced,
            bound: DebugCounter::new(1),
            limb_bound: self.limb_bound,
        }
    }
}

/// Returns `value >> BITS`.
#[inline(always)]
fn shr<S: Simd, const BITS: u32>(simd: S, value: S::U64) -> S::U64 {
    simd.u64_shr::<BITS>(value)
}

/// Returns `value << (52 - BITS)`, moving a column of high halves to its radix `2^BITS` weight.
#[inline(always)]
fn realign<S: Simd, const BITS: u32>(simd: S, value: S::U64) -> S::U64 {
    match BITS {
        52 => value,
        51 => simd.u64_shl::<1>(value),
        50 => simd.u64_shl::<2>(value),
        49 => simd.u64_shl::<3>(value),
        48 => simd.u64_shl::<4>(value),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::{super::tests as reference, *};
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{Operation, check_consistent, emulated::EmulatedScalar, test_dispatch};
    use reference::Element;
    use std::{panic::catch_unwind, vec::Vec};

    /// A formula evaluated on one pair of elements per lane.
    #[derive(Clone, Copy, Debug)]
    enum Formula {
        Add,
        Sub,
        Neg,
        Double,
        Mul,
        Square,
        /// `(a + a + a) * (b - a) - b`: linear operations chained around a product.
        Chain,
        /// `(a + b) * (b + a)`, multiplying uncarried sums where the radix allows it.
        Ready,
        /// Addition up to the integer limit.
        LooseAdd,
        /// Doublings without carrying, then a product.
        LooseDoubling,
        /// Subtraction with a larger bias, then a square.
        LooseSub,
        /// Multiplication of inputs with large integer bounds.
        LooseMul,
        /// Storing a value at the integer limit.
        LooseStore,
        /// Loading the elements as bytes, then multiplying.
        Load,
    }

    const FORMULAS: [Formula; 14] = [
        Formula::Add,
        Formula::Sub,
        Formula::Neg,
        Formula::Double,
        Formula::Mul,
        Formula::Square,
        Formula::Chain,
        Formula::Ready,
        Formula::LooseAdd,
        Formula::LooseDoubling,
        Formula::LooseSub,
        Formula::LooseMul,
        Formula::LooseStore,
        Formula::Load,
    ];

    impl Formula {
        /// Returns the integer bounds of the inputs, in units of `p`.
        fn bounds<const BITS: u32>(self) -> (u64, u64) {
            let limit = Unsat49::<EmulatedScalar, BITS>::LIMIT;
            match self {
                Self::LooseAdd => (limit / 2, limit / 2),
                Self::LooseMul => (limit, (limit - 1).min(1 << 28)),
                Self::LooseStore => (limit, 1),
                _ => (2, 2),
            }
        }

        /// Returns how many times `LooseDoubling` doubles, staying within the integer limit.
        fn doublings<const BITS: u32>() -> u32 {
            (Unsat49::<EmulatedScalar, BITS>::LIMIT.ilog2() - 1).min(11)
        }

        fn scalar<const BITS: u32>(self, a: Element, b: Element) -> Element {
            match self {
                Self::Add | Self::LooseAdd => reference::add(a, b),
                Self::Sub => reference::sub(a, b),
                Self::Neg => reference::neg(a),
                Self::Double => reference::add(a, a),
                Self::Mul | Self::LooseMul | Self::Load => reference::mul(a, b),
                Self::Square => reference::mul(a, a),
                Self::Chain => {
                    let three = reference::add(reference::add(a, a), a);
                    reference::sub(reference::mul(three, reference::sub(b, a)), b)
                }
                Self::Ready => {
                    let sum = reference::add(a, b);
                    reference::mul(sum, sum)
                }
                Self::LooseDoubling => {
                    let doubled = (0..Self::doublings::<BITS>()).fold(a, |a, _| reference::add(a, a));
                    reference::mul(doubled, b)
                }
                Self::LooseSub => {
                    let difference = reference::sub(a, b);
                    reference::mul(difference, difference)
                }
                Self::LooseStore => a,
            }
        }

        #[inline(always)]
        fn lanes<S: Simd, const BITS: u32>(
            self,
            simd: S,
            a: Unsat49<S, BITS>,
            b: Unsat49<S, BITS>,
        ) -> Unsat49<S, BITS> {
            match self {
                Self::Add | Self::LooseAdd => a.add(simd, b),
                Self::Sub => a.sub::<3>(simd, b),
                Self::Neg => a.neg::<3>(simd),
                Self::Double => a.double(simd),
                Self::Mul | Self::LooseMul | Self::Load => a.mul(simd, b),
                Self::Square => a.square(simd),
                Self::Chain => {
                    let three = a.double(simd).add(simd, a).ready::<3>(simd);
                    let difference = b.sub::<3>(simd, a).ready::<4>(simd);
                    three.mul(simd, difference).sub::<3>(simd, b)
                }
                Self::Ready => {
                    let sum = a.add(simd, b).ready::<2>(simd);
                    sum.mul(simd, b.add(simd, a).ready::<2>(simd))
                }
                Self::LooseDoubling => {
                    let mut a = a;
                    for _ in 0..Self::doublings::<BITS>() {
                        a = a.double(simd);
                    }
                    a.carry(simd).mul(simd, b)
                }
                Self::LooseSub => a.sub::<5>(simd, b).carry(simd).square(simd),
                Self::LooseStore => a,
            }
        }
    }

    /// Returns the representative `a * 2^(8 BITS) mod p` of an element, in limbs.
    fn to_lanes_form<const BITS: u32>(element: Element) -> [u64; LIMBS] {
        limbs_from_words(reference::mul(element, power_of_two(8 * BITS)), BITS)
    }

    /// Returns the element whose representative is `limbs`, a carried value below `p`.
    fn from_lanes_form<const BITS: u32>(limbs: [u64; LIMBS]) -> Element {
        let inverse = reference::invert(power_of_two(8 * BITS));
        reference::mul(words_from_limbs(limbs, BITS), inverse)
    }

    /// Returns the representative of `element` plus `(bound - 1) * p`, in carried limbs.
    fn lift<const BITS: u32>(element: Element, bound: u64) -> [u64; LIMBS] {
        let mask = (1 << BITS) - 1;
        let (value, offset) = (to_lanes_form::<BITS>(element), multiple(bound - 1, BITS));
        let mut limbs = [0; LIMBS];
        let mut carry = 0;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let sum = value[i] + offset[i] + carry;
            *limb = sum & mask;
            carry = sum >> BITS;
        }
        assert_eq!(carry, 0);
        limbs
    }

    /// Loads one element per lane, each lifted by `(bound - 1) * p`.
    fn loose<S: Simd, const BITS: u32>(
        simd: S,
        elements: &[Element],
        bound: u64,
    ) -> Unsat49<S, BITS> {
        let mut lanes = [[0; LIMBS]; MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = lift::<BITS>(*element, bound);
        }
        Unsat49::from_limbs(simd, &lanes, bound)
    }

    /// Returns the element whose representative is `p - 1`, which lifts to `bound * p - 1`.
    fn largest<const BITS: u32>() -> Element {
        let mut limbs = multiple(1, BITS);
        limbs[0] -= 1;
        from_lanes_form::<BITS>(limbs)
    }

    /// Evaluates a formula on every pair of elements, a lane-sized chunk at a time.
    struct Evaluate<'a, const BITS: u32> {
        formula: Formula,
        a: &'a [Element; MAX_LANES],
        b: &'a [Element; MAX_LANES],
    }

    impl<S: Simd, const BITS: u32> Operation<S> for Evaluate<'_, BITS> {
        type Output = [[u8; BYTES]; MAX_LANES];

        fn portable(self, simd: S) -> [[u8; BYTES]; MAX_LANES] {
            let mut output = [[0; BYTES]; MAX_LANES];
            let (a_bound, b_bound) = self.formula.bounds::<BITS>();
            let bytes = self.a.map(reference::to_bytes);
            simd.execute(
                #[inline(always)]
                |simd: S| {
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        let a = match self.formula {
                            Formula::Load => Unsat49::load(simd, &bytes[start..], &[0; BYTES]),
                            _ => loose::<S, BITS>(simd, &self.a[start..], a_bound),
                        };
                        let b = loose::<S, BITS>(simd, &self.b[start..], b_bound);
                        self.formula
                            .lanes(simd, a, b)
                            .store(simd, &mut output[start..]);
                    }
                },
            );
            output
        }
    }

    fn elements(
        u: &mut Unstructured<'_>,
        largest: Element,
    ) -> arbitrary::Result<[Element; MAX_LANES]> {
        let mut elements = [reference::ZERO; MAX_LANES];
        for element in &mut elements {
            *element = match u.int_in_range(0..=9)? {
                0 => reference::ZERO,
                1 => reference::ONE,
                2 => reference::neg(reference::ONE),
                3 => largest,
                _ => reference::canonical(u)?,
            };
        }
        Ok(elements)
    }

    fn representatives_round_trip<const BITS: u32>() {
        let mut limbs = multiple(1, BITS);
        limbs[0] -= 1;
        assert_eq!(to_lanes_form::<BITS>(largest::<BITS>()), limbs);
        let element = reference::neg(reference::ONE);
        assert_eq!(from_lanes_form::<BITS>(to_lanes_form::<BITS>(element)), element);
    }

    fn matches_reference<const BITS: u32>() {
        let largest = largest::<BITS>();
        minifuzz::test(|u| {
            let a = elements(u, largest)?;
            let b = elements(u, largest)?;
            for formula in FORMULAS {
                let expected: Vec<[u8; BYTES]> = a
                    .iter()
                    .zip(&b)
                    .map(|(a, b)| reference::to_bytes(formula.scalar::<BITS>(*a, *b)))
                    .collect();
                let evaluate = || Evaluate::<BITS> {
                    formula,
                    a: &a,
                    b: &b,
                };
                let actual = test_dispatch(evaluate());
                assert_eq!(actual, expected[..actual.len()], "{formula:?}");
                check_consistent(evaluate);
            }
            Ok(())
        });
    }

    /// Loads and stores every lane.
    struct RoundTrip<'a, const BITS: u32>(&'a [[u8; BYTES]; MAX_LANES]);

    impl<S: Simd, const BITS: u32> Operation<S> for RoundTrip<'_, BITS> {
        type Output = [[u8; BYTES]; MAX_LANES];

        fn portable(self, simd: S) -> [[u8; BYTES]; MAX_LANES] {
            let mut output = [[0; BYTES]; MAX_LANES];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                Unsat49::<S, BITS>::load(simd, &self.0[start..], &[0; BYTES])
                    .store(simd, &mut output[start..]);
            }
            output
        }
    }

    fn round_trip_reduces_bytes<const BITS: u32>() {
        let largest = largest::<BITS>();
        minifuzz::test(|u| {
            let a = elements(u, largest)?.map(reference::to_bytes);
            assert_eq!(test_dispatch(RoundTrip::<BITS>(&a)), a);
            check_consistent(|| RoundTrip::<BITS>(&a));
            // Integers at or above p load as their residues.
            let raw: [[u8; BYTES]; MAX_LANES] = u.arbitrary()?;
            let reduced = raw.map(|bytes| reference::to_bytes(reference::reduce(&bytes)));
            assert_eq!(test_dispatch(RoundTrip::<BITS>(&raw)), reduced);
            Ok(())
        });
    }

    /// Splats an element into every lane.
    struct Splat<const BITS: u32>([u8; BYTES]);

    impl<S: Simd, const BITS: u32> Operation<S> for Splat<BITS> {
        type Output = [[u8; BYTES]; MAX_LANES];

        fn portable(self, simd: S) -> [[u8; BYTES]; MAX_LANES] {
            let mut output = [[0; BYTES]; MAX_LANES];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                Unsat49::<S, BITS>::splat(simd, &self.0).store(simd, &mut output[start..]);
            }
            output
        }
    }

    fn splat_fills_every_lane<const BITS: u32>() {
        minifuzz::test(|u| {
            let element = reference::to_bytes(reference::canonical(u)?);
            assert_eq!(test_dispatch(Splat::<BITS>(element)), [element; MAX_LANES]);
            check_consistent(|| Splat::<BITS>(element));
            Ok(())
        });
    }

    fn rejects_values_beyond_the_limits<const BITS: u32>() {
        if !DebugCounter::live() {
            return;
        }
        let simd = EmulatedScalar;
        let limit = Unsat49::<EmulatedScalar, BITS>::LIMIT;
        let slack = Unsat49::<EmulatedScalar, BITS>::SLACK;
        let largest = largest::<BITS>();
        let at = |bound| loose::<EmulatedScalar, BITS>(simd, &[largest], bound);
        assert!(catch_unwind(|| at(limit).add(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(2))).is_ok());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(3))).is_err());
        assert!(catch_unwind(|| at(1).sub::<5>(simd, at(1).double(simd))).is_ok());
        assert!(catch_unwind(|| at(1).sub::<9>(simd, at(1).double(simd).double(simd))).is_err());
        assert!(catch_unwind(|| at(limit).sub::<3>(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(3).neg::<3>(simd)).is_err());
        assert!(catch_unwind(|| at(limit).mul(simd, at(limit))).is_err());
        // A multiplicand may hold the sum of SLACK carried values, but no more.
        let sum = |count: u64| (1..count).fold(at(1), |sum, _| sum.add(simd, at(1)));
        if slack < limit {
            assert!(catch_unwind(|| sum(slack).mul(simd, at(1))).is_ok());
            assert!(catch_unwind(|| sum(slack + 1).mul(simd, at(1))).is_err());
        }
    }

    macro_rules! radix_tests {
        ($($name:ident: $bits:literal),* $(,)?) => {$(
            mod $name {
                #[test]
                fn representatives_round_trip() {
                    super::representatives_round_trip::<$bits>();
                }

                #[test]
                fn matches_reference() {
                    super::matches_reference::<$bits>();
                }

                #[test]
                fn round_trip_reduces_bytes() {
                    super::round_trip_reduces_bytes::<$bits>();
                }

                #[test]
                fn splat_fills_every_lane() {
                    super::splat_fills_every_lane::<$bits>();
                }

                #[test]
                fn rejects_values_beyond_the_limits() {
                    super::rejects_values_beyond_the_limits::<$bits>();
                }
            }
        )*};
    }

    radix_tests!(radix52: 52, radix51: 51, radix50: 50, radix49: 49, radix48: 48);
}
