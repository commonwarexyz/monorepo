//! Saturated Montgomery arithmetic on several base field elements at once, one per vector lane.
//!
//! A [`Saturated`] is a matrix with [`WORDS`] rows and `S::U64_LANES` columns: row `i` holds
//! word `i` of every element. Elements use the scalar [`Fp`] Montgomery form `a * 2^384`, so
//! loading and storing only transpose. Multiplication interleaves word-by-word products and
//! Montgomery reduction (CIOS) using full 64-bit products.
//!
//! # Bounds
//!
//! Values are lazily reduced: each lane holds an integer below `9p` congruent to its element,
//! which fits six words because `9p < 2^384`. Each value carries a [`DebugCounter`] bounding every
//! lane in units of `p`. For input bounds `A` and `B`:
//!
//! | Operation | Requires | Result bound |
//! |---|---|---|
//! | load, splat, reduce | | `1` |
//! | `a + b` | `A + B <= 9` | `A + B` |
//! | `a - b` with bias `K` | `B <= K`, `A + K <= 9` | `A + K` |
//! | `a * b` | `ceil(A * B / 9) + 1 <= 9` | `ceil(A * B / 9) + 1` |
//!
//! Montgomery multiplication returns below `a * b / 2^384 + p`, and `p / 2^384 < 1 / 9`. Inputs
//! below `2p` therefore give products below `2p`. Debug builds check these rules; release builds
//! do not, and results are unspecified when a formula violates them.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Only tests use this representation so far.")
)]

use crate::{
    debug_counter::DebugCounter,
    fp::{Fp, MODULUS, WORDS, lanes::MAX_LANES},
    montgomery::negated_inverse,
};
use commonware_simd::Simd;

/// Largest bound of any value, in units of `p`.
const LIMIT: u64 = 9;

/// `-p^(-1) mod 2^64`, the Montgomery reduction constant.
const INV: u64 = negated_inverse(MODULUS[0]);

/// Multiples of `p` that [`Saturated::reduce`] conditionally subtracts, largest first.
const REDUCTION_STEPS: [[u64; WORDS]; 4] = [multiple(8), multiple(4), multiple(2), multiple(1)];

/// Returns `k * p`, little-endian.
const fn multiple(k: u64) -> [u64; WORDS] {
    assert!(k <= LIMIT);
    let mut words = [0; WORDS];
    let mut carry = 0u128;
    let mut i = 0;
    while i < WORDS {
        let wide = MODULUS[i] as u128 * k as u128 + carry;
        words[i] = wide as u64;
        carry = wide >> 64;
        i += 1;
    }
    assert!(carry == 0);
    words
}

/// `S::U64_LANES` base field elements in Montgomery form, one per lane.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub(crate) struct Saturated<S: Simd> {
    words: [S::U64; WORDS],
    bound: DebugCounter,
}

impl<S: Simd> Clone for Saturated<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd> Copy for Saturated<S> {}

impl<S: Simd> Saturated<S> {
    /// Returns every lane set to `element`.
    #[inline(always)]
    pub fn splat(simd: S, element: Fp) -> Self {
        Self {
            words: element.0.map(|word| simd.u64_splat(word)),
            bound: DebugCounter::new(1),
        }
    }

    /// Loads up to `S::U64_LANES` elements, one per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, elements: &[Fp], fill: Fp) -> Self {
        let mut lanes = [fill.0; MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = element.0;
        }
        Self::raw(simd, &lanes, 1)
    }

    /// Stores the canonical value of each lane into `elements`, dropping lanes beyond its length.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [Fp]) {
        let lanes = self.reduce(simd).store_raw(simd);
        for (element, lane) in elements.iter_mut().zip(lanes) {
            *element = Fp(lane);
        }
    }

    /// Transposes per-lane words bounded by `bound * p` into word rows.
    #[inline(always)]
    fn raw(simd: S, lanes: &[[u64; WORDS]; MAX_LANES], bound: u64) -> Self {
        const { assert!(S::U64_LANES <= MAX_LANES) };
        let mut rows = [[0; MAX_LANES]; WORDS];
        for (lane, words) in lanes.iter().enumerate() {
            for (row, word) in rows.iter_mut().zip(words) {
                row[lane] = *word;
            }
        }
        Self {
            words: rows.map(|row| simd.u64_load(&row)),
            bound: DebugCounter::new(bound),
        }
    }

    /// Returns each lane's words, without any reduction.
    #[inline(always)]
    fn store_raw(self, simd: S) -> [[u64; WORDS]; MAX_LANES] {
        let mut lanes = [[0; WORDS]; MAX_LANES];
        for (i, row) in self.words.into_iter().enumerate() {
            let mut values = [0; MAX_LANES];
            simd.u64_store(row, &mut values);
            for (lane, value) in lanes.iter_mut().zip(values) {
                lane[i] = value;
            }
        }
        lanes
    }

    /// Returns `self + rhs`.
    #[inline(always)]
    pub fn add(self, simd: S, rhs: Self) -> Self {
        let mut bound = self.bound;
        bound.add(rhs.bound);
        bound.assert_le(LIMIT);
        Self {
            words: add_words(simd, self.words, rhs.words),
            bound,
        }
    }

    /// Returns `self + K * p - rhs`, which is `self - rhs`.
    #[inline(always)]
    pub fn sub<const K: u64>(self, simd: S, rhs: Self) -> Self {
        let mut bound = self.bound;
        bound.sub_with_bias(rhs.bound, K);
        bound.assert_le(LIMIT);
        let bias = const { multiple(K) }.map(|word| simd.u64_splat(word));
        let (words, _) = sub_words(simd, add_words(simd, self.words, bias), rhs.words);
        Self { words, bound }
    }

    /// Returns `K * p - self`, which is `-self`.
    #[inline(always)]
    pub fn neg<const K: u64>(self, simd: S) -> Self {
        let mut bound = DebugCounter::new(0);
        bound.sub_with_bias(self.bound, K);
        bound.assert_le(LIMIT);
        let bias = const { multiple(K) }.map(|word| simd.u64_splat(word));
        let (words, _) = sub_words(simd, bias, self.words);
        Self { words, bound }
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
        let mut bound = self.bound;
        bound.mul(rhs.bound);
        bound.div_ceil(LIMIT);
        bound.add(DebugCounter::new(1));
        bound.assert_le(LIMIT);

        let zero = simd.u64_splat(0);
        let inv = simd.u64_splat(INV);
        // Each iteration starts with t + high * 2^384 below self + p.
        let mut t = [zero; WORDS];
        let mut high = zero;
        for b in rhs.words {
            // t += self * b, which stays below self * 2^64 + p < 2^448, so high cannot overflow.
            let mut carry = zero;
            for (t, a) in t.iter_mut().zip(self.words) {
                (*t, carry) = mul_add(simd, *t, a, b, carry);
            }
            high = simd.u64_add(high, carry);

            // t += m * p, which clears the low word, then shift that word out. The shifted value
            // is below self + p < 2^385, so the new high word is the carry out.
            let m = simd.u64_mul_lo(t[0], inv);
            let (_, mut carry) = mul_add(simd, t[0], m, simd.u64_splat(MODULUS[0]), zero);
            for j in 1..WORDS {
                (t[j - 1], carry) = mul_add(simd, t[j], m, simd.u64_splat(MODULUS[j]), carry);
            }
            (t[WORDS - 1], high) = add_carry(simd, high, carry, zero);
        }
        // The result is below 9p < 2^384, so high is zero.
        Self { words: t, bound }
    }

    /// Returns `self * self`.
    #[inline(always)]
    pub fn square(self, simd: S) -> Self {
        self.mul(simd, self)
    }

    /// Returns the canonical representative of every lane.
    #[inline(always)]
    pub fn reduce(self, simd: S) -> Self {
        // Below 9p, subtracting 8p, 4p, 2p, and p wherever possible leaves each lane below p.
        let zero = simd.u64_splat(0);
        let mut words = self.words;
        for step in REDUCTION_STEPS {
            let (reduced, borrow) = sub_words(simd, words, step.map(|word| simd.u64_splat(word)));
            // A final borrow means the lane was below the step.
            let keep = simd.u64_sub(zero, borrow);
            for (word, reduced) in words.iter_mut().zip(reduced) {
                *word = simd.u64_select(keep, *word, reduced);
            }
        }
        Self {
            words,
            bound: DebugCounter::new(1),
        }
    }
}

/// Returns `a + b + carry` and its carry out, for a carry in of zero or one.
#[inline(always)]
fn add_carry<S: Simd>(simd: S, a: S::U64, b: S::U64, carry: S::U64) -> (S::U64, S::U64) {
    let sum = simd.u64_add(simd.u64_add(a, b), carry);
    // Where the sum's top bit is set, no carry reached it, so both operands' top bits carry out.
    // Elsewhere, either operand's top bit does.
    let out = simd.u64_select(sum, simd.u64_and(a, b), simd.u64_or(a, b));
    (sum, simd.u64_shr::<63>(out))
}

/// Returns `a - b - borrow` and its borrow out, for a borrow in of zero or one.
#[inline(always)]
fn sub_borrow<S: Simd>(simd: S, a: S::U64, b: S::U64, borrow: S::U64) -> (S::U64, S::U64) {
    let difference = simd.u64_sub(simd.u64_sub(a, b), borrow);
    // Where a's top bit is set, borrowing out requires b's top bit and a borrow into it, which
    // leaves the difference's top bit set. Elsewhere, either does.
    let out = simd.u64_select(
        a,
        simd.u64_and(b, difference),
        simd.u64_or(b, difference),
    );
    (difference, simd.u64_shr::<63>(out))
}

/// Returns the low and high words of `acc + a * b + carry`, which is below `2^128`.
#[inline(always)]
fn mul_add<S: Simd>(
    simd: S,
    acc: S::U64,
    a: S::U64,
    b: S::U64,
    carry: S::U64,
) -> (S::U64, S::U64) {
    let zero = simd.u64_splat(0);
    let (low, first) = add_carry(simd, acc, simd.u64_mul_lo(a, b), zero);
    let (low, second) = add_carry(simd, low, carry, zero);
    let high = simd.u64_add(simd.u64_mul_hi(a, b), simd.u64_add(first, second));
    (low, high)
}

/// Returns `a + b`, which must be below `2^384`.
#[inline(always)]
fn add_words<S: Simd>(simd: S, mut a: [S::U64; WORDS], b: [S::U64; WORDS]) -> [S::U64; WORDS] {
    let mut carry = simd.u64_splat(0);
    for (a, b) in a.iter_mut().zip(b) {
        (*a, carry) = add_carry(simd, *a, b, carry);
    }
    a
}

/// Returns `a - b mod 2^384` and a borrow of one in lanes where `a < b`.
#[inline(always)]
fn sub_words<S: Simd>(
    simd: S,
    mut a: [S::U64; WORDS],
    b: [S::U64; WORDS],
) -> ([S::U64; WORDS], S::U64) {
    let mut borrow = simd.u64_splat(0);
    for (a, b) in a.iter_mut().zip(b) {
        (*a, borrow) = sub_borrow(simd, *a, b, borrow);
    }
    (a, borrow)
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
        /// Addition up to the limit.
        LooseAdd,
        /// Subtraction of the largest subtrahend its bias allows, up to the limit.
        LooseSub,
        /// Negation of the largest value.
        LooseNeg,
        /// Multiplication of the largest inputs.
        LooseMul,
        /// Squaring of the largest input.
        LooseSquare,
        /// Reduction of the largest value.
        LooseReduce,
    }

    const FORMULAS: [Formula; 13] = [
        Formula::Add,
        Formula::Sub,
        Formula::Neg,
        Formula::Double,
        Formula::Mul,
        Formula::Square,
        Formula::Chain,
        Formula::LooseAdd,
        Formula::LooseSub,
        Formula::LooseNeg,
        Formula::LooseMul,
        Formula::LooseSquare,
        Formula::LooseReduce,
    ];

    impl Formula {
        /// Returns the bounds of the inputs, in units of `p`.
        const fn bounds(self) -> (u64, u64) {
            match self {
                Self::LooseAdd => (4, 5),
                Self::LooseSub => (5, 4),
                Self::LooseNeg | Self::LooseReduce => (9, 1),
                Self::LooseMul => (9, 8),
                Self::LooseSquare => (8, 1),
                _ => (1, 1),
            }
        }

        fn scalar(self, a: Fp, b: Fp) -> Fp {
            match self {
                Self::Add | Self::LooseAdd => a.add(b),
                Self::Sub | Self::LooseSub => a.sub(b),
                Self::Neg | Self::LooseNeg => a.neg(),
                Self::Double => a.double(),
                Self::Mul | Self::LooseMul => a.mul(b),
                Self::Square | Self::LooseSquare => a.square(),
                Self::Chain => a.add(a).add(a).mul(b.sub(a)).sub(b),
                Self::LooseReduce => a,
            }
        }

        #[inline(always)]
        fn lanes<S: Simd>(self, simd: S, a: Saturated<S>, b: Saturated<S>) -> Saturated<S> {
            match self {
                Self::Add | Self::LooseAdd => a.add(simd, b),
                Self::Sub => a.sub::<1>(simd, b),
                Self::LooseSub => a.sub::<4>(simd, b),
                Self::Neg => a.neg::<1>(simd),
                Self::LooseNeg => a.neg::<9>(simd),
                Self::Double => a.double(simd),
                Self::Mul | Self::LooseMul => a.mul(simd, b),
                Self::Square | Self::LooseSquare => a.square(simd),
                Self::Chain => {
                    let three = a.double(simd).add(simd, a);
                    three.mul(simd, b.sub::<1>(simd, a)).sub::<2>(simd, b)
                }
                Self::LooseReduce => a.reduce(simd),
            }
        }
    }

    /// Returns the representative `element + (bound - 1) * p`, the largest below `bound * p`
    /// for the element `p - 1`.
    fn lift(element: Fp, bound: u64) -> [u64; WORDS] {
        let offset = multiple(bound - 1);
        let mut words = [0; WORDS];
        let mut carry = 0u128;
        for (i, word) in words.iter_mut().enumerate() {
            let wide = element.0[i] as u128 + offset[i] as u128 + carry;
            *word = wide as u64;
            carry = wide >> 64;
        }
        assert_eq!(carry, 0);
        words
    }

    /// Returns `a - b`, which must not be negative.
    fn difference(a: [u64; WORDS], b: [u64; WORDS]) -> [u64; WORDS] {
        let mut words = [0; WORDS];
        let mut borrow = 0;
        for (i, word) in words.iter_mut().enumerate() {
            let (low, first) = a[i].overflowing_sub(b[i]);
            let (low, second) = low.overflowing_sub(borrow);
            *word = low;
            borrow = u64::from(first | second);
        }
        assert_eq!(borrow, 0);
        words
    }

    /// Loads one element per lane, each lifted to the largest representative below `bound * p`.
    fn loose<S: Simd>(simd: S, elements: &[Fp], bound: u64) -> Saturated<S> {
        let mut lanes = [[0; WORDS]; MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = lift(*element, bound);
        }
        Saturated::raw(simd, &lanes, bound)
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
                3 => below_modulus(1),
                _ => canonical(u)?,
            };
        }
        Ok(elements)
    }

    /// Returns the element whose Montgomery representative is `p - k`, for small `k`.
    fn below_modulus(k: u64) -> Fp {
        let mut words = MODULUS;
        words[0] -= k;
        Fp(words)
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
                        Saturated::load(simd, &self.0[start..], Fp::ZERO)
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
                        Saturated::splat(simd, self.0).store(simd, &mut output[start..]);
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
    fn multiplication_carries_into_the_high_word() {
        // Left operands 9p - k for these k, against a right operand whose low five words are
        // 2^64 - 1 once lifted by 7p, carry out of the accumulator while adding m * p.
        let a = [6, 7, 9, 10];
        let a: [Fp; MAX_LANES] = core::array::from_fn(|i| below_modulus(a[i % a.len()]));
        let mut lifted = [u64::MAX; WORDS];
        lifted[WORDS - 1] = multiple(7)[WORDS - 1] + 1;
        let b = [Fp(difference(lifted, multiple(7))); MAX_LANES];
        assert_eq!(lift(b[0], 8), lifted);
        let expected: Vec<Fp> = a.iter().map(|a| a.mul(b[0])).collect();
        let evaluate = || Evaluate {
            formula: Formula::LooseMul,
            a: &a,
            b: &b,
        };
        let actual = test_dispatch(evaluate());
        assert_eq!(actual, expected[..actual.len()]);
        check_consistent(evaluate);
    }

    #[test]
    fn rejects_values_beyond_the_limit() {
        if !DebugCounter::live() {
            return;
        }
        let simd = EmulatedScalar;
        let at = |bound| loose(simd, &[below_modulus(1)], bound);
        assert!(catch_unwind(|| at(5).add(simd, at(5))).is_err());
        assert!(catch_unwind(|| at(5).sub::<5>(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(1).sub::<4>(simd, at(5))).is_err());
        assert!(catch_unwind(|| at(1).neg::<4>(simd)).is_ok());
        assert!(catch_unwind(|| at(5).neg::<4>(simd)).is_err());
        assert!(catch_unwind(|| at(9).mul(simd, at(9))).is_err());
        assert!(catch_unwind(|| at(9).square(simd)).is_err());
    }
}
