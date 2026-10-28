//! Base field arithmetic on several elements at once, one per vector lane.
//!
//! An [`FpVec`] is a matrix with [`LIMBS`] rows and `S::U64_LANES` columns: row `i` holds limb
//! `i` of every element, so a limb-wise algorithm written for one element runs on every lane at
//! once. Elements use radix `2^52` in Montgomery form with `R = 2^416`, so multiplication
//! accumulates 52-bit products with `u64_madd52lo` and `u64_madd52hi` and nothing crosses
//! lanes. Loading and storing convert from and to the scalar [`Fp`] representation with one
//! multiplication by a constant.
//!
//! This pays off on backends with native 52-bit multipliers (AVX-512 IFMA). Where the
//! instructions are emulated with scalar multiplies, the scalar [`Fp`] arithmetic is faster.
//!
//! # Bounds
//!
//! Every operation accepts and returns elements whose limbs are below `2^52` and whose value
//! is below `2^17 * p`. Products are below `2p`, and a sum of `n` signed products evaluated
//! with one reduction is below `(n / 2 + 1) * p`, so sums or differences of two products are
//! below `2p` as well. An addition's bound is the sum of its inputs' bounds. A subtraction
//! requires its subtrahend below `2^8 * p` and adds `2^9 * p` to the minuend's bound. Formulas
//! may therefore chain several linear operations between multiplications without tracking
//! bounds individually.

use super::{Arithmetic, Fp, WORDS, power_of_two};
use crate::montgomery::negated_inverse;
use commonware_simd::Simd;
use subtle::Choice;

/// Largest lane count a backend may have; wider backends would need larger transposition buffers.
pub(crate) const MAX_LANES: usize = 8;

/// Number of limbs in a field element.
pub const LIMBS: usize = 8;

/// Bits per limb once carries have been propagated.
const LIMB_BITS: u32 = 52;

/// Largest number of terms in one [`FpVec::sum_of_products`].
///
/// Each product adds at most sixteen 52-bit terms to a column, as does the reduction, so up to
/// 254 products fit in the 64-bit accumulators; this smaller limit keeps the result below
/// `33p`, a valid subtrahend.
pub(crate) const MAX_TERMS: usize = 64;

/// The low [`LIMB_BITS`] bits of a limb.
const MASK: u64 = (1 << LIMB_BITS) - 1;

/// The modulus `p` in limbs.
const MODULUS: [u64; LIMBS] = limbs_from_words(super::MODULUS);

/// `-p^(-1) mod 2^52`, the Montgomery reduction constant.
const INV: u64 = negated_inverse(super::MODULUS[0]) & MASK;

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

/// `2^9 * p` with `2^52` moved from each limb into the one below it.
///
/// Subtracting a carried element below `2^8 * p` from these limbs never borrows: the low seven
/// limbs are at least `2^52`, and the top limb exceeds the subtrahend's top limb.
const BIAS: [u64; LIMBS] = {
    let limbs = raised(9);
    // The top limb of 2^8 * p is at most half of the top limb of 2^9 * p.
    assert!(limbs[LIMBS - 1] >= (MODULUS[LIMBS - 1] << 8) + 2);
    limbs
};

/// `2^17 * p` with `2^52` moved from each limb into the one below it, like [`BIAS`].
///
/// Subtracting any element from it never borrows, so `WIDE_BIAS - d` is `-d` as a multiplicand.
const WIDE_BIAS: [u64; LIMBS] = raised(17);

/// `2^k * p` with `2^52` moved from each limb into the one below it.
const fn raised(k: u32) -> [u64; LIMBS] {
    let mut limbs = [0; LIMBS];
    let mut carry = 0u128;
    let mut i = 0;
    while i < LIMBS {
        let wide = ((MODULUS[i] as u128) << k) + carry;
        limbs[i] = wide as u64 & MASK;
        carry = wide >> LIMB_BITS;
        i += 1;
    }
    assert!(carry == 0);
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
pub struct FpVec<S: Simd>([S::U64; LIMBS]);

impl<S: Simd> Clone for FpVec<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd> Copy for FpVec<S> {}

impl<S: Simd> FpVec<S> {
    /// Returns every lane set to `element`.
    #[inline(always)]
    pub fn splat(simd: S, element: Fp) -> Self {
        Self::raw(simd, &[limbs_from_words(element.0); MAX_LANES]).to_lanes(simd)
    }

    /// Loads up to `S::U64_LANES` elements, one per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, elements: &[Fp], fill: Fp) -> Self {
        let mut limbs = [limbs_from_words(fill.0); MAX_LANES];
        for (limbs, element) in limbs.iter_mut().zip(elements) {
            *limbs = limbs_from_words(element.0);
        }
        Self::raw(simd, &limbs).to_lanes(simd)
    }

    /// Stores the canonical value of each lane into `elements`, dropping lanes beyond its length.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [Fp]) {
        let canonical = self
            .mul(simd, Self::raw(simd, &[FROM_LANES; MAX_LANES]))
            .subtract_modulus(simd);
        let mut limbs = [[0; LIMBS]; MAX_LANES];
        canonical.store_raw(simd, &mut limbs);
        for (element, limbs) in elements.iter_mut().zip(limbs) {
            *element = Fp(words_from_limbs(limbs));
        }
    }

    /// Writes each lane's limbs, without any conversion.
    #[inline(always)]
    fn store_raw(self, simd: S, lanes: &mut [[u64; LIMBS]; MAX_LANES]) {
        for (i, row) in self.0.into_iter().enumerate() {
            let mut values = [0; MAX_LANES];
            simd.u64_store(row, &mut values);
            for (lane, value) in lanes.iter_mut().zip(values) {
                lane[i] = value;
            }
        }
    }

    /// Transposes per-lane limbs into limb rows, without any conversion.
    #[inline(always)]
    fn raw(simd: S, lanes: &[[u64; LIMBS]; MAX_LANES]) -> Self {
        const { assert!(S::U64_LANES <= MAX_LANES) };
        let mut rows = [[0; MAX_LANES]; LIMBS];
        for (lane, limbs) in lanes.iter().enumerate() {
            for (row, limb) in rows.iter_mut().zip(limbs) {
                row[lane] = *limb;
            }
        }
        let mut value = [simd.u64_splat(0); LIMBS];
        for (value, row) in value.iter_mut().zip(&rows) {
            *value = simd.u64_load(row);
        }
        Self(value)
    }

    /// Converts the scalar Montgomery form `a * 2^384` into this module's `a * 2^416`.
    #[inline(always)]
    fn to_lanes(self, simd: S) -> Self {
        self.mul(simd, Self::raw(simd, &[TO_LANES; MAX_LANES]))
    }

    /// Returns `self + rhs`.
    #[inline(always)]
    pub fn add(mut self, simd: S, rhs: Self) -> Self {
        for (limb, rhs) in self.0.iter_mut().zip(rhs.0) {
            *limb = simd.u64_add(*limb, rhs);
        }
        self.carry(simd)
    }

    /// Returns `self - rhs`, where `rhs` is below `2^8 * p`.
    #[inline(always)]
    pub fn sub(mut self, simd: S, rhs: Self) -> Self {
        for ((limb, rhs), bias) in self.0.iter_mut().zip(rhs.0).zip(BIAS) {
            *limb = simd.u64_sub(simd.u64_add(*limb, simd.u64_splat(bias)), rhs);
        }
        self.carry(simd)
    }

    /// Returns `-self`, where `self` is below `2^8 * p`.
    #[inline(always)]
    pub fn neg(mut self, simd: S) -> Self {
        for (limb, bias) in self.0.iter_mut().zip(BIAS) {
            *limb = simd.u64_sub(simd.u64_splat(bias), *limb);
        }
        self.carry(simd)
    }

    /// Returns `2 * self`.
    #[inline(always)]
    pub fn double(self, simd: S) -> Self {
        self.add(simd, self)
    }

    /// Returns `self * rhs`.
    ///
    /// Debug builds keep this a call so that deeply inlined formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul(self, simd: S, rhs: Self) -> Self {
        let mut columns = [simd.u64_splat(0); 2 * LIMBS + 1];
        accumulate(simd, &mut columns, self, rhs);
        reduce(simd, columns)
    }

    /// Returns the sum of `a * b` over the terms `(a, b, negate)`, subtracting the product
    /// where `negate` is set, with one reduction.
    ///
    /// A subtracted product is added as `a * (2^17 p - b)`, so the sum never goes negative and
    /// `b` may be any element. Every product of two elements is below `2^34 * p^2`, which
    /// contributes less than `p / 2` to the reduced result because `p < 2^381`, so the result
    /// is below `(n / 2 + 1) * p` for `n` terms.
    ///
    /// # Panics
    ///
    /// Panics if there are more than 64 terms.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn sum_of_products(simd: S, terms: &[(Self, Self, bool)]) -> Self {
        assert!(terms.len() <= MAX_TERMS);
        let mut columns = [simd.u64_splat(0); 2 * LIMBS + 1];
        for (a, b, negate) in terms {
            let b = if *negate { b.wide_neg(simd) } else { *b };
            accumulate(simd, &mut columns, *a, b);
        }
        reduce(simd, columns)
    }

    /// Returns `2^17 * p - self`, which stands in for `-self` as a multiplicand.
    #[inline(always)]
    fn wide_neg(mut self, simd: S) -> Self {
        for (limb, bias) in self.0.iter_mut().zip(WIDE_BIAS) {
            *limb = simd.u64_sub(simd.u64_splat(bias), *limb);
        }
        self.carry(simd)
    }

    /// Returns `self * self`.
    #[inline(always)]
    pub fn square(self, simd: S) -> Self {
        self.mul(simd, self)
    }

    /// Returns `b` in lanes where `choice` is set and `a` elsewhere.
    #[inline(always)]
    pub fn select(simd: S, mut a: Self, b: Self, choice: Choice) -> Self {
        let mask = simd.u64_splat((choice.unwrap_u8() as u64).wrapping_neg());
        for (limb, b) in a.0.iter_mut().zip(b.0) {
            *limb = simd.u64_select(mask, b, *limb);
        }
        a
    }

    /// Propagates carries so every limb is below `2^52`; the value must be below `2^416`.
    #[inline(always)]
    fn carry(mut self, simd: S) -> Self {
        let mask = simd.u64_splat(MASK);
        for i in 0..LIMBS - 1 {
            self.0[i + 1] = simd.u64_add(self.0[i + 1], simd.u64_shr::<LIMB_BITS>(self.0[i]));
            self.0[i] = simd.u64_and(self.0[i], mask);
        }
        self
    }

    /// Returns `self - p` in lanes where `self >= p`; the value must be below `2p`.
    #[inline(always)]
    fn subtract_modulus(self, simd: S) -> Self {
        let mask = simd.u64_splat(MASK);
        let mut reduced = self.0;
        let mut borrow = simd.u64_splat(0);
        for i in 0..LIMBS {
            let diff = simd.u64_sub(simd.u64_sub(self.0[i], simd.u64_splat(MODULUS[i])), borrow);
            reduced[i] = simd.u64_and(diff, mask);
            borrow = simd.u64_shr::<63>(diff);
        }
        // A final borrow means the lane was already below p.
        let keep = simd.u64_sub(simd.u64_splat(0), borrow);
        for (limb, reduced) in reduced.iter_mut().zip(self.0) {
            *limb = simd.u64_select(keep, reduced, *limb);
        }
        Self(reduced)
    }
}

/// Adds the sixteen product columns of `a * b` to `columns` by operand scanning.
///
/// Each product adds at most two 52-bit terms per limb to a column, so a few products fit in
/// the accumulators before reduction.
#[inline(always)]
fn accumulate<S: Simd>(simd: S, columns: &mut [S::U64; 2 * LIMBS + 1], a: FpVec<S>, b: FpVec<S>) {
    for (i, a) in a.0.into_iter().enumerate() {
        for (j, b) in b.0.into_iter().enumerate() {
            columns[i + j] = simd.u64_madd52lo(columns[i + j], a, b);
            columns[i + j + 1] = simd.u64_madd52hi(columns[i + j + 1], a, b);
        }
    }
}

/// Montgomery-reduces accumulated product columns by `2^416`.
///
/// Each step cancels one low column with a multiple of `p` and carries it into the next. For
/// column sums below `2^34 * p^2 * k` with small `k`, the result is below `(k + 1) * p`.
#[inline(always)]
fn reduce<S: Simd>(simd: S, mut columns: [S::U64; 2 * LIMBS + 1]) -> FpVec<S> {
    let zero = simd.u64_splat(0);
    let inv = simd.u64_splat(INV);
    for i in 0..LIMBS {
        let q = simd.u64_madd52lo(zero, columns[i], inv);
        for (j, modulus) in MODULUS.into_iter().enumerate() {
            let modulus = simd.u64_splat(modulus);
            columns[i + j] = simd.u64_madd52lo(columns[i + j], q, modulus);
            columns[i + j + 1] = simd.u64_madd52hi(columns[i + j + 1], q, modulus);
        }
        // The low column is now a multiple of 2^52; carry it into the next one.
        columns[i + 1] = simd.u64_add(columns[i + 1], simd.u64_shr::<LIMB_BITS>(columns[i]));
    }
    let mut result = [zero; LIMBS];
    result.copy_from_slice(&columns[LIMBS..2 * LIMBS]);
    FpVec(result).carry(simd)
}

/// The per-lane field context: `S::U64_LANES` elements at a time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Lanes<S: Simd>(pub S);

impl<S: Simd> Arithmetic for Lanes<S> {
    type Element = FpVec<S>;

    type Scalar = Fp;

    const LANES: usize = S::U64_LANES;

    type Stored = [u64; LIMBS];

    #[inline(always)]
    fn gather<'a>(self, lanes: impl IntoIterator<Item = &'a [u64; LIMBS]>) -> FpVec<S> {
        let mut limbs = [[0; LIMBS]; MAX_LANES];
        for (limbs, lane) in limbs.iter_mut().zip(lanes) {
            *limbs = *lane;
        }
        FpVec::raw(self.0, &limbs)
    }

    #[inline(always)]
    fn scatter<'a>(self, value: FpVec<S>, lanes: impl IntoIterator<Item = &'a mut [u64; LIMBS]>) {
        let mut limbs = [[0; LIMBS]; MAX_LANES];
        value.store_raw(self.0, &mut limbs);
        for (lane, limbs) in lanes.into_iter().zip(limbs) {
            *lane = limbs;
        }
    }

    #[inline(always)]
    fn load(self, elements: &[Fp], fill: Fp) -> FpVec<S> {
        FpVec::load(self.0, elements, fill)
    }

    #[inline(always)]
    fn store(self, value: FpVec<S>, outputs: &mut [Fp]) {
        value.store(self.0, outputs)
    }

    #[inline(always)]
    fn constant(self, value: Fp) -> FpVec<S> {
        FpVec::splat(self.0, value)
    }

    #[inline(always)]
    fn add(self, a: FpVec<S>, b: FpVec<S>) -> FpVec<S> {
        a.add(self.0, b)
    }

    #[inline(always)]
    fn sub(self, a: FpVec<S>, b: FpVec<S>) -> FpVec<S> {
        a.sub(self.0, b)
    }

    #[inline(always)]
    fn neg(self, a: FpVec<S>) -> FpVec<S> {
        a.neg(self.0)
    }

    #[inline(always)]
    fn mul(self, a: FpVec<S>, b: FpVec<S>) -> FpVec<S> {
        a.mul(self.0, b)
    }

    #[inline(always)]
    fn select(self, a: FpVec<S>, b: FpVec<S>, choice: Choice) -> FpVec<S> {
        FpVec::select(self.0, a, b, choice)
    }

    #[inline(always)]
    fn sum_of_products(self, terms: &[(FpVec<S>, FpVec<S>, bool)]) -> FpVec<S> {
        FpVec::sum_of_products(self.0, terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::old::fp::{
        Single,
        tests::{canonical, shaped_terms, sum_of_shapes},
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{Operation, check_consistent, test_dispatch};
    use std::vec::Vec;

    /// A formula evaluated on one pair of elements per lane.
    #[derive(Clone, Copy, Debug)]
    enum Formula {
        Add,
        Sub,
        Neg,
        Mul,
        Square,
        /// `(a + a + a) * (b - a) - b`: linear operations chained around a product.
        Chain,
        /// Selects `b` over `a`.
        Select,
        /// `a * b + b * a`.
        MulAdd,
        /// `a * a - b * b`, then squared to exercise the bound of the result.
        MulSub,
    }

    impl Formula {
        fn scalar(self, a: Fp, b: Fp) -> Fp {
            match self {
                Self::Add => a.add(b),
                Self::Sub => a.sub(b),
                Self::Neg => a.neg(),
                Self::Mul => a.mul(b),
                Self::Square => a.square(),
                Self::Chain => a.add(a).add(a).mul(b.sub(a)).sub(b),
                Self::Select => b,
                Self::MulAdd => a.mul(b).add(b.mul(a)),
                Self::MulSub => a.mul(a).sub(b.mul(b)).square(),
            }
        }

        #[inline(always)]
        fn lanes<S: Simd>(self, simd: S, a: FpVec<S>, b: FpVec<S>) -> FpVec<S> {
            match self {
                Self::Add => a.add(simd, b),
                Self::Sub => a.sub(simd, b),
                Self::Neg => a.neg(simd),
                Self::Mul => a.mul(simd, b),
                Self::Square => a.square(simd),
                Self::Chain => {
                    let three = a.double(simd).add(simd, a);
                    three.mul(simd, b.sub(simd, a)).sub(simd, b)
                }
                Self::Select => FpVec::select(simd, a, b, Choice::from(1)),
                Self::MulAdd => FpVec::sum_of_products(simd, &[(a, b, false), (b, a, false)]),
                Self::MulSub => {
                    FpVec::sum_of_products(simd, &[(a, a, false), (b, b, true)]).square(simd)
                }
            }
        }
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
            simd.execute(
                #[inline(always)]
                |simd: S| {
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        let a = FpVec::load(simd, &self.a[start..], Fp::ZERO);
                        let b = FpVec::load(simd, &self.b[start..], Fp::ZERO);
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
                _ => canonical(u)?,
            };
        }
        Ok(elements)
    }

    #[test]
    fn matches_scalar_field() {
        const FORMULAS: [Formula; 9] = [
            Formula::Add,
            Formula::Sub,
            Formula::Neg,
            Formula::Mul,
            Formula::Square,
            Formula::Chain,
            Formula::Select,
            Formula::MulAdd,
            Formula::MulSub,
        ];
        minifuzz::test(|u| {
            let a = elements(u)?;
            let b = elements(u)?;
            for formula in FORMULAS {
                let expected: Vec<Fp> = a.iter().zip(&b).map(|(a, b)| formula.scalar(*a, *b)).collect();
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
                        FpVec::load(simd, &self.0[start..], Fp::ZERO)
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

    /// Evaluates [`sum_of_shapes`] on every lane.
    #[derive(Clone, Copy)]
    struct Sum<'a> {
        terms: &'a [(u8, u8, bool)],
        values: &'a [[Fp; MAX_LANES]],
    }

    impl<S: Simd> Operation<S> for Sum<'_> {
        type Output = [Fp; MAX_LANES];

        fn portable(self, simd: S) -> [Fp; MAX_LANES] {
            let mut output = [Fp::ZERO; MAX_LANES];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                let values: Vec<FpVec<S>> = self
                    .values
                    .iter()
                    .map(|lanes| FpVec::load(simd, &lanes[start..], Fp::ZERO))
                    .collect();
                // Loaded elements are below 2p, so 15 doublings stay below 2^17 p.
                sum_of_shapes(Lanes(simd), 15, self.terms, &values)
                    .store(simd, &mut output[start..]);
            }
            output
        }
    }

    #[test]
    fn sum_of_products_matches_scalar_field() {
        minifuzz::test(|u| {
            let terms = shaped_terms(u, MAX_TERMS)?;
            let mut values = Vec::new();
            for _ in 0..2 * terms.len().max(1) {
                values.push(elements(u)?);
            }
            let expected: Vec<Fp> = (0..MAX_LANES)
                .map(|lane| {
                    let values: Vec<Fp> = values.iter().map(|lanes| lanes[lane]).collect();
                    sum_of_shapes(Single, 15, &terms, &values)
                })
                .collect();
            let sum = Sum {
                terms: &terms,
                values: &values,
            };
            let actual = test_dispatch(sum);
            assert_eq!(actual, expected[..actual.len()]);
            check_consistent(|| sum);
            Ok(())
        });
    }
}
