//! Montgomery arithmetic on several base field elements at once, using 64-bit lane values.
//!
//! A [`Lanes64`] is a matrix with [`LIMBS`] rows and `S::U64_LANES` columns: row `i` holds limb `i`
//! of every element. Elements use radix `2^52` in Montgomery form with `R = 2^416`, so products
//! accumulate with `u64_madd52lo` and `u64_madd52hi`, which AVX-512 IFMA provides natively and
//! other backends emulate. Limbs have twelve spare bits, so additions and subtractions need not
//! carry.
//!
//! # Usage
//!
//! Loads, splats, products, and [`Lanes64::carry`] return carried values; additions,
//! subtractions, negations, and doublings return uncarried ones. A formula must carry a value
//! before multiplying, subtracting, or negating it if it is uncarried. Carrying preserves the
//! represented integer; multiplication is what reduces modulo `p`, and [`Lanes64::store`]
//! returns canonical elements from any value.
//!
//! A subtraction or negation bias `K` must exceed the bound of the value it removes, so `K = 3`
//! suffices for loaded values and products of loaded or product values. The limits below do not
//! arise in practical formulas: they allow about `2^34` additions of products, or about `2^12`
//! additions without a carry.
//!
//! # Bounds
//!
//! Values are lazily reduced and lazily carried. Each value carries two [`DebugCounter`]s: an
//! integer bound in units of `p`, and a limb bound in units of `2^52`. A value is carried when its
//! limb bound is `1`. For integer bounds `A` and `B` and limb bounds `L` and `M`:
//!
//! | Operation | Requires | Integer bound | Limb bound |
//! |---|---|---|---|
//! | load, splat | | `2` | `1` |
//! | `a + b` | | `A + B` | `L + M` |
//! | `a - b` with bias `K` | `b` carried, `B < K` | `A + K` | `L + 2` |
//! | `-a` with bias `K` | `a` carried, `A < K` | `K` | `2` |
//! | carry | | `A` | `1` |
//! | `a * b` | `a` and `b` carried | `ceil(A * B / 2^35) + 1` | `1` |
//!
//! Every integer bound is at most `2^35`, so values fit carried limbs because `p < 2^381`. Every
//! limb bound is below `2^12`, so carries fit the 64-bit lanes. Multiplication requires carried
//! inputs because the 52-bit multipliers ignore higher bits. It returns below `a * b / 2^416 + p`,
//! so inputs below `2^17 p` give products below `2p`. Debug builds check these rules; release
//! builds do not, and results are unspecified when a formula violates them.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Only tests use this representation so far.")
)]

use crate::{
    debug_counter::DebugCounter,
    fp::{Fp, WORDS, lanes::MAX_LANES, power_of_two},
    montgomery::negated_inverse,
};
use commonware_simd::Simd;

/// Number of limbs in a field element.
pub(crate) const LIMBS: usize = 8;

/// Bits per carried limb.
const LIMB_BITS: u32 = 52;

/// The low [`LIMB_BITS`] bits of a limb.
const MASK: u64 = (1 << LIMB_BITS) - 1;

/// Largest integer bound of any value, in units of `p`.
///
/// Because `p < 2^381`, `LIMIT * p < 2^416` and `p / 2^416 < 1 / LIMIT`.
const LIMIT: u64 = 1 << 35;

/// Largest limb bound of any value, in units of `2^52`, so that carries fit the 64-bit lanes.
const LIMB_LIMIT: u64 = (1 << 12) - 1;

/// The modulus `p` in limbs.
const MODULUS: [u64; LIMBS] = {
    assert!(crate::fp::MODULUS[WORDS - 1] < 1 << 61);
    limbs_from_words(crate::fp::MODULUS)
};

/// `-p^(-1) mod 2^52`, the Montgomery reduction constant.
const INV: u64 = negated_inverse(crate::fp::MODULUS[0]) & MASK;

/// `2^448 mod p`. A Montgomery multiplication by it maps `a * 2^384` to `a * 2^416`.
const TO_LANES: [u64; LIMBS] = limbs_from_words(power_of_two(448));

/// `2^384 mod p`. A Montgomery multiplication by it maps `a * 2^416` back to `a * 2^384`.
const FROM_LANES: [u64; LIMBS] = limbs_from_words(power_of_two(384));

/// Splits a little-endian 64-bit integer into 52-bit limbs.
const fn limbs_from_words(words: [u64; WORDS]) -> [u64; LIMBS] {
    let mut limbs = [0; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        let bit = i * LIMB_BITS as usize;
        let (word, shift) = (bit / 64, bit % 64);
        let mut limb = words[word] >> shift;
        if shift > 64 - LIMB_BITS as usize && word + 1 < WORDS {
            limb |= words[word + 1] << (64 - shift);
        }
        limbs[i] = limb & MASK;
        i += 1;
    }
    limbs
}

/// Joins carried 52-bit limbs of a value below `2^384` into little-endian 64-bit words.
const fn words_from_limbs(limbs: [u64; LIMBS]) -> [u64; WORDS] {
    let mut words = [0; WORDS];
    let mut i = 0;
    while i < LIMBS {
        let bit = i * LIMB_BITS as usize;
        let (word, shift) = (bit / 64, bit % 64);
        words[word] |= limbs[i] << shift;
        if shift > 64 - LIMB_BITS as usize && word + 1 < WORDS {
            words[word + 1] |= limbs[i] >> (64 - shift);
        }
        i += 1;
    }
    words
}

/// Returns `k * p` in carried limbs.
const fn multiple(k: u64) -> [u64; LIMBS] {
    assert!(k <= LIMIT);
    let mut limbs = [0; LIMBS];
    let mut carry = 0u128;
    let mut i = 0;
    while i < LIMBS {
        let wide = MODULUS[i] as u128 * k as u128 + carry;
        limbs[i] = wide as u64 & MASK;
        carry = wide >> LIMB_BITS;
        i += 1;
    }
    assert!(carry == 0);
    limbs
}

/// Returns `k * p` with `2^52` moved from each limb into the one below it.
///
/// The low seven limbs are then at least `2^52`, so subtracting a carried value never borrows
/// from them. The top limb is one less than that of `k * p`, which still covers the top limb of a
/// carried value below `(k - 1) * p`, since the two differ by more than `p > 2^364`.
const fn bias(k: u64) -> [u64; LIMBS] {
    assert!(k >= 1);
    let mut limbs = multiple(k);
    let mut i = 0;
    while i + 1 < LIMBS {
        assert!(limbs[i + 1] >= 1);
        limbs[i] += 1 << LIMB_BITS;
        limbs[i + 1] -= 1;
        i += 1;
    }
    limbs
}

/// `S::U64_LANES` base field elements in Montgomery form, one per lane.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub(crate) struct Lanes64<S: Simd> {
    limbs: [S::U64; LIMBS],
    bound: DebugCounter,
    limb_bound: DebugCounter,
}

impl<S: Simd> Clone for Lanes64<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd> Copy for Lanes64<S> {}

impl<S: Simd> Lanes64<S> {
    /// Returns every lane set to `element`.
    #[inline(always)]
    pub fn splat(simd: S, element: Fp) -> Self {
        Self::raw(simd, &[limbs_from_words(element.0); MAX_LANES], 1).to_lanes(simd)
    }

    /// Loads up to `S::U64_LANES` elements, one per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, elements: &[Fp], fill: Fp) -> Self {
        let mut lanes = [limbs_from_words(fill.0); MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = limbs_from_words(element.0);
        }
        Self::raw(simd, &lanes, 1).to_lanes(simd)
    }

    /// Stores the canonical value of each lane into `elements`, dropping lanes beyond its length.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [Fp]) {
        let canonical = self
            .carry(simd)
            .mul(simd, Self::raw(simd, &[FROM_LANES; MAX_LANES], 1))
            .subtract_modulus(simd);
        for (element, limbs) in elements.iter_mut().zip(canonical.store_raw(simd)) {
            *element = Fp(words_from_limbs(limbs));
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
        Self {
            limbs: rows.map(|row| simd.u64_load(&row)),
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

    /// Converts the scalar Montgomery form `a * 2^384` into this module's `a * 2^416`.
    #[inline(always)]
    fn to_lanes(self, simd: S) -> Self {
        self.mul(simd, Self::raw(simd, &[TO_LANES; MAX_LANES], 1))
    }

    /// Returns `self + rhs`, without carrying.
    #[inline(always)]
    pub fn add(mut self, simd: S, rhs: Self) -> Self {
        self.bound.add(rhs.bound);
        self.bound.assert_le(LIMIT);
        self.limb_bound.add(rhs.limb_bound);
        self.limb_bound.assert_le(LIMB_LIMIT);
        for (limb, rhs) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb = simd.u64_add(*limb, rhs);
        }
        self
    }

    /// Returns `self + K * p - rhs`, which is `self - rhs`, without carrying.
    #[inline(always)]
    pub fn sub<const K: u64>(mut self, simd: S, rhs: Self) -> Self {
        rhs.limb_bound.assert_le(1);
        // The subtrahend must be below (K - 1) * p; see bias.
        self.bound.sub_with_bias(rhs.bound, K - 1);
        self.bound.add(DebugCounter::new(1));
        self.bound.assert_le(LIMIT);
        self.limb_bound.add(DebugCounter::new(2));
        self.limb_bound.assert_le(LIMB_LIMIT);
        let bias = const { bias(K) };
        for ((limb, rhs), bias) in self.limbs.iter_mut().zip(rhs.limbs).zip(bias) {
            *limb = simd.u64_sub(simd.u64_add(*limb, simd.u64_splat(bias)), rhs);
        }
        self
    }

    /// Returns `K * p - self`, which is `-self`, without carrying.
    #[inline(always)]
    pub fn neg<const K: u64>(mut self, simd: S) -> Self {
        self.limb_bound.assert_le(1);
        let mut bound = DebugCounter::new(1);
        bound.sub_with_bias(self.bound, K - 1);
        bound.assert_le(LIMIT);
        let bias = const { bias(K) };
        for (limb, bias) in self.limbs.iter_mut().zip(bias) {
            *limb = simd.u64_sub(simd.u64_splat(bias), *limb);
        }
        self.bound = bound;
        self.limb_bound = DebugCounter::new(2);
        self
    }

    /// Returns `2 * self`, without carrying.
    #[inline(always)]
    pub fn double(self, simd: S) -> Self {
        self.add(simd, self)
    }

    /// Propagates carries so every limb is below `2^52`, without reducing modulo `p`.
    #[inline(always)]
    pub fn carry(mut self, simd: S) -> Self {
        let mask = simd.u64_splat(MASK);
        for i in 0..LIMBS - 1 {
            self.limbs[i + 1] =
                simd.u64_add(self.limbs[i + 1], simd.u64_shr::<LIMB_BITS>(self.limbs[i]));
            self.limbs[i] = simd.u64_and(self.limbs[i], mask);
        }
        // The value is below 2^416, so the top limb is now below 2^52 as well.
        self.limb_bound = DebugCounter::new(1);
        self
    }

    /// Returns `self * rhs`.
    ///
    /// Debug builds keep this a call so that deeply inlined formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul(self, simd: S, rhs: Self) -> Self {
        self.limb_bound.assert_le(1);
        rhs.limb_bound.assert_le(1);
        let mut bound = self.bound;
        bound.mul(rhs.bound);
        bound.div_ceil(LIMIT);
        bound.add(DebugCounter::new(1));
        bound.assert_le(LIMIT);

        // Each column receives at most 16 terms below 2^52 from the product and 16 from the
        // reduction, plus a carry, so no column overflows.
        let zero = simd.u64_splat(0);
        let mut columns = [zero; 2 * LIMBS];
        for (i, a) in self.limbs.into_iter().enumerate() {
            for (j, b) in rhs.limbs.into_iter().enumerate() {
                columns[i + j] = simd.u64_madd52lo(columns[i + j], a, b);
                columns[i + j + 1] = simd.u64_madd52hi(columns[i + j + 1], a, b);
            }
        }
        let inv = simd.u64_splat(INV);
        for i in 0..LIMBS {
            // Cancel the low 52 bits of this column with a multiple of p, then carry the rest.
            let q = simd.u64_madd52lo(zero, columns[i], inv);
            for (j, modulus) in MODULUS.into_iter().enumerate() {
                let modulus = simd.u64_splat(modulus);
                columns[i + j] = simd.u64_madd52lo(columns[i + j], q, modulus);
                columns[i + j + 1] = simd.u64_madd52hi(columns[i + j + 1], q, modulus);
            }
            columns[i + 1] = simd.u64_add(columns[i + 1], simd.u64_shr::<LIMB_BITS>(columns[i]));
        }
        let mut limbs = [zero; LIMBS];
        limbs.copy_from_slice(&columns[LIMBS..]);
        Self {
            limbs,
            bound,
            limb_bound: DebugCounter::new(LIMB_LIMIT),
        }
        .carry(simd)
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
        let mask = simd.u64_splat(MASK);
        let mut reduced = self.limbs;
        let mut borrow = simd.u64_splat(0);
        for (i, reduced) in reduced.iter_mut().enumerate() {
            let difference = simd.u64_sub(
                simd.u64_sub(self.limbs[i], simd.u64_splat(MODULUS[i])),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fp::tests::canonical;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{Operation, check_consistent, emulated::EmulatedScalar, test_dispatch};
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
        /// Addition up to the integer limit.
        LooseAdd,
        /// Eleven doublings without carrying, then a product.
        LooseDoubling,
        /// Subtraction with a large bias, then a square.
        LooseSub,
        /// Multiplication of inputs with large integer bounds.
        LooseMul,
        /// Storing a value at the integer limit.
        LooseStore,
    }

    const FORMULAS: [Formula; 12] = [
        Formula::Add,
        Formula::Sub,
        Formula::Neg,
        Formula::Double,
        Formula::Mul,
        Formula::Square,
        Formula::Chain,
        Formula::LooseAdd,
        Formula::LooseDoubling,
        Formula::LooseSub,
        Formula::LooseMul,
        Formula::LooseStore,
    ];

    impl Formula {
        /// Returns the integer bounds of the inputs, in units of `p`.
        const fn bounds(self) -> (u64, u64) {
            match self {
                Self::LooseAdd => (LIMIT / 2, LIMIT / 2),
                Self::LooseMul => (LIMIT, 1 << 28),
                Self::LooseStore => (LIMIT, 1),
                _ => (2, 2),
            }
        }

        fn scalar(self, a: Fp, b: Fp) -> Fp {
            match self {
                Self::Add | Self::LooseAdd => a.add(b),
                Self::Sub => a.sub(b),
                Self::Neg => a.neg(),
                Self::Double => a.double(),
                Self::Mul | Self::LooseMul => a.mul(b),
                Self::Square => a.square(),
                Self::Chain => a.add(a).add(a).mul(b.sub(a)).sub(b),
                Self::LooseDoubling => (0..11).fold(a, |a, _| a.double()).mul(b),
                Self::LooseSub => a.sub(b).square(),
                Self::LooseStore => a,
            }
        }

        #[inline(always)]
        fn lanes<S: Simd>(self, simd: S, a: Lanes64<S>, b: Lanes64<S>) -> Lanes64<S> {
            match self {
                Self::Add | Self::LooseAdd => a.add(simd, b),
                Self::Sub => a.sub::<3>(simd, b),
                Self::Neg => a.neg::<3>(simd),
                Self::Double => a.double(simd),
                Self::Mul | Self::LooseMul => a.mul(simd, b),
                Self::Square => a.square(simd),
                Self::Chain => {
                    let three = a.double(simd).add(simd, a).carry(simd);
                    let difference = b.sub::<3>(simd, a).carry(simd);
                    three.mul(simd, difference).sub::<3>(simd, b)
                }
                Self::LooseDoubling => {
                    let mut a = a;
                    for _ in 0..11 {
                        a = a.double(simd);
                    }
                    a.carry(simd).mul(simd, b)
                }
                Self::LooseSub => a.sub::<{ 1 << 20 }>(simd, b).carry(simd).square(simd),
                Self::LooseStore => a,
            }
        }
    }

    /// Returns the representative `a * 2^416 mod p` of an element, in limbs.
    fn to_lanes_form(element: Fp) -> [u64; LIMBS] {
        limbs_from_words(element.mul(Fp(power_of_two(416))).0)
    }

    /// Returns the element whose representative is `limbs`, a carried value below `p`.
    fn from_lanes_form(limbs: [u64; LIMBS]) -> Fp {
        Fp(words_from_limbs(limbs)).mul(Fp(power_of_two(352)))
    }

    /// Returns the representative of `element` plus `(bound - 1) * p`, in carried limbs.
    fn lift(element: Fp, bound: u64) -> [u64; LIMBS] {
        let (value, offset) = (to_lanes_form(element), multiple(bound - 1));
        let mut limbs = [0; LIMBS];
        let mut carry = 0;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let sum = value[i] + offset[i] + carry;
            *limb = sum & MASK;
            carry = sum >> LIMB_BITS;
        }
        assert_eq!(carry, 0);
        assert!(limbs[LIMBS - 1] <= MASK);
        limbs
    }

    /// Loads one element per lane, each lifted by `(bound - 1) * p`.
    fn loose<S: Simd>(simd: S, elements: &[Fp], bound: u64) -> Lanes64<S> {
        let mut lanes = [[0; LIMBS]; MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = lift(*element, bound);
        }
        Lanes64::raw(simd, &lanes, bound)
    }

    /// Returns the element whose representative is `p - 1`, which lifts to `bound * p - 1`.
    fn largest() -> Fp {
        let mut limbs = MODULUS;
        limbs[0] -= 1;
        from_lanes_form(limbs)
    }

    /// Evaluates a formula on every pair of elements, a lane-sized chunk at a time.
    struct Evaluate<'a> {
        formula: Formula,
        a: &'a [Fp; MAX_LANES],
        b: &'a [Fp; MAX_LANES],
    }

    impl<S: Simd> Operation<S> for Evaluate<'_> {
        type Output = [Fp; MAX_LANES];

        fn portable(self, simd: S) -> [Fp; MAX_LANES] {
            let mut output = [Fp::ZERO; MAX_LANES];
            let (a_bound, b_bound) = self.formula.bounds();
            simd.execute(
                #[inline(always)]
                |simd: S| {
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        let a = loose(simd, &self.a[start..], a_bound);
                        let b = loose(simd, &self.b[start..], b_bound);
                        self.formula
                            .lanes(simd, a, b)
                            .store(simd, &mut output[start..]);
                    }
                },
            );
            output
        }
    }

    fn elements(u: &mut Unstructured<'_>) -> arbitrary::Result<[Fp; MAX_LANES]> {
        let mut elements = [Fp::ZERO; MAX_LANES];
        for element in &mut elements {
            *element = match u.int_in_range(0..=9)? {
                0 => Fp::ZERO,
                1 => Fp::ONE,
                2 => Fp::ONE.neg(),
                3 => largest(),
                _ => canonical(u)?,
            };
        }
        Ok(elements)
    }

    #[test]
    fn representatives_round_trip() {
        assert_eq!(to_lanes_form(largest()), {
            let mut limbs = MODULUS;
            limbs[0] -= 1;
            limbs
        });
        assert_eq!(from_lanes_form(to_lanes_form(Fp::ONE.neg())), Fp::ONE.neg());
    }

    #[test]
    fn matches_scalar_field() {
        minifuzz::test(|u| {
            let a = elements(u)?;
            let b = elements(u)?;
            for formula in FORMULAS {
                let expected: Vec<Fp> = a
                    .iter()
                    .zip(&b)
                    .map(|(a, b)| formula.scalar(*a, *b))
                    .collect();
                let actual = test_dispatch(Evaluate {
                    formula,
                    a: &a,
                    b: &b,
                });
                assert_eq!(actual, expected[..actual.len()], "{formula:?}");
                check_consistent(|| Evaluate {
                    formula,
                    a: &a,
                    b: &b,
                });
            }
            Ok(())
        });
    }

    #[test]
    fn round_trip_preserves_elements() {
        minifuzz::test(|u| {
            let a = elements(u)?;
            struct RoundTrip<'a>(&'a [Fp; MAX_LANES]);
            impl<S: Simd> Operation<S> for RoundTrip<'_> {
                type Output = [Fp; MAX_LANES];
                fn portable(self, simd: S) -> [Fp; MAX_LANES] {
                    let mut output = [Fp::ZERO; MAX_LANES];
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        Lanes64::load(simd, &self.0[start..], Fp::ZERO)
                            .store(simd, &mut output[start..]);
                    }
                    output
                }
            }
            assert_eq!(test_dispatch(RoundTrip(&a)), a);
            check_consistent(|| RoundTrip(&a));
            Ok(())
        });
    }

    #[test]
    fn splat_fills_every_lane() {
        minifuzz::test(|u| {
            let element = canonical(u)?;
            struct Splat(Fp);
            impl<S: Simd> Operation<S> for Splat {
                type Output = [Fp; MAX_LANES];
                fn portable(self, simd: S) -> [Fp; MAX_LANES] {
                    let mut output = [Fp::ZERO; MAX_LANES];
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        Lanes64::splat(simd, self.0).store(simd, &mut output[start..]);
                    }
                    output
                }
            }
            assert_eq!(test_dispatch(Splat(element)), [element; MAX_LANES]);
            check_consistent(|| Splat(element));
            Ok(())
        });
    }

    #[test]
    fn rejects_values_beyond_the_limits() {
        if !DebugCounter::live() {
            return;
        }
        let simd = EmulatedScalar;
        let at = |bound| loose(simd, &[largest()], bound);
        assert!(catch_unwind(|| at(LIMIT).add(simd, at(1))).is_err());
        assert!(
            catch_unwind(|| {
                let mut value = at(1);
                for _ in 0..12 {
                    value = value.double(simd);
                }
            })
            .is_err()
        );
        assert!(catch_unwind(|| at(1).double(simd).mul(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(2))).is_ok());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(3))).is_err());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(1).double(simd))).is_err());
        assert!(catch_unwind(|| at(LIMIT).sub::<3>(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(3).neg::<3>(simd)).is_err());
        assert!(catch_unwind(|| at(1).double(simd).neg::<3>(simd)).is_err());
        assert!(catch_unwind(|| at(LIMIT).mul(simd, at(LIMIT))).is_err());
    }
}
