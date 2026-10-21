//! Base field arithmetic on several elements at once, one per vector lane.
//!
//! An [`FpVec`] is a matrix with [`LIMBS`] rows and `S::U64_LANES` columns: row `i` holds limb
//! `i` of every element, so a limb-wise algorithm written for one element runs on every lane at
//! once. Multiplication accumulates 52-bit products with `u64_madd52lo` and `u64_madd52hi`,
//! so nothing crosses lanes and the schedule matches the scalar kernel behind [`Fp`].
//!
//! # Bounds
//!
//! Every operation accepts and returns elements whose limbs are below `2^52` and whose value
//! is below `2^17 * p`. Products are below `2p`. An addition's bound is the sum of its inputs'
//! bounds. A subtraction requires its subtrahend below `2^8 * p` and adds `2^9 * p` to the
//! minuend's bound. Formulas may therefore chain several linear operations between
//! multiplications without tracking bounds individually.

use super::{Fp, INV, LIMB_BITS, LIMBS, MASK, MODULUS};
use commonware_simd::Simd;
use subtle::Choice;

/// Largest lane count a backend may have; wider backends would need larger transposition buffers.
const MAX_LANES: usize = 8;

/// `2^9 * p` with `2^52` moved from each limb into the one below it.
///
/// Subtracting a carried element below `2^8 * p` from these limbs never borrows: the low seven
/// limbs are at least `2^52`, and the top limb exceeds the subtrahend's top limb.
const BIAS: [u64; LIMBS] = {
    let mut limbs = MODULUS;
    let mut i = 0;
    while i < LIMBS {
        limbs[i] <<= 9;
        i += 1;
    }
    let mut i = 0;
    while i + 1 < LIMBS {
        limbs[i + 1] += limbs[i] >> LIMB_BITS;
        limbs[i] &= MASK;
        i += 1;
    }
    let mut i = 0;
    while i + 1 < LIMBS {
        assert!(limbs[i + 1] >= 1);
        limbs[i] += 1 << LIMB_BITS;
        limbs[i + 1] -= 1;
        i += 1;
    }
    // The top limb of 2^8 * p is at most half of the top limb of 2^9 * p.
    assert!(limbs[LIMBS - 1] >= (MODULUS[LIMBS - 1] << 8) + 2);
    limbs
};

/// `S::U64_LANES` base field elements in Montgomery form, one per lane.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub struct FpVec<S: Simd>(pub(crate) [S::U64; LIMBS]);

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
        Self(element.0.map(|limb| simd.u64_splat(limb)))
    }

    /// Loads the first `S::U64_LANES` elements, one per lane.
    ///
    /// # Panics
    ///
    /// Panics if fewer elements are supplied.
    #[inline(always)]
    pub fn load(simd: S, elements: &[Fp]) -> Self {
        const { assert!(S::U64_LANES <= MAX_LANES) };
        assert!(elements.len() >= S::U64_LANES);
        Self(core::array::from_fn(|i| {
            let mut row = [0; MAX_LANES];
            for (lane, element) in row.iter_mut().zip(elements) {
                *lane = element.0[i];
            }
            simd.u64_load(&row)
        }))
    }

    /// Stores the canonical value of every lane into the first `S::U64_LANES` elements.
    ///
    /// # Panics
    ///
    /// Panics if fewer elements are supplied.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [Fp]) {
        const { assert!(S::U64_LANES <= MAX_LANES) };
        assert!(elements.len() >= S::U64_LANES);
        let canonical = self.mul(simd, Self::splat(simd, Fp::ONE)).subtract_modulus(simd);
        for (i, row) in canonical.0.into_iter().enumerate() {
            let mut lanes = [0; MAX_LANES];
            simd.u64_store(row, &mut lanes);
            for (element, lane) in elements.iter_mut().zip(lanes) {
                element.0[i] = lane;
            }
        }
    }

    /// Returns `self + rhs`.
    #[inline(always)]
    pub fn add(self, simd: S, rhs: Self) -> Self {
        Self(core::array::from_fn(|i| simd.u64_add(self.0[i], rhs.0[i]))).carry(simd)
    }

    /// Returns `self - rhs`, where `rhs` is below `2^8 * p`.
    #[inline(always)]
    pub fn sub(self, simd: S, rhs: Self) -> Self {
        Self(core::array::from_fn(|i| {
            simd.u64_sub(simd.u64_add(self.0[i], simd.u64_splat(BIAS[i])), rhs.0[i])
        }))
        .carry(simd)
    }

    /// Returns `-self`, where `self` is below `2^8 * p`.
    #[inline(always)]
    pub fn neg(self, simd: S) -> Self {
        Self(core::array::from_fn(|i| simd.u64_sub(simd.u64_splat(BIAS[i]), self.0[i]))).carry(simd)
    }

    /// Returns `2 * self`.
    #[inline(always)]
    pub fn double(self, simd: S) -> Self {
        self.add(simd, self)
    }

    /// Returns `self * rhs`.
    ///
    /// Each outer iteration accumulates one limb of `self` against `rhs`, cancels the low
    /// column with a multiple of `p`, and shifts the columns down by one limb. Column `j`
    /// receives at most four 52-bit terms per iteration, so the accumulators never overflow.
    #[inline(always)]
    pub fn mul(self, simd: S, rhs: Self) -> Self {
        let zero = simd.u64_splat(0);
        let inv = simd.u64_splat(INV);
        let modulus = MODULUS.map(|limb| simd.u64_splat(limb));
        let mut columns = [zero; LIMBS + 1];
        for a in self.0 {
            for j in 0..LIMBS {
                columns[j] = simd.u64_madd52lo(columns[j], a, rhs.0[j]);
                columns[j + 1] = simd.u64_madd52hi(columns[j + 1], a, rhs.0[j]);
            }
            let q = simd.u64_madd52lo(zero, columns[0], inv);
            for j in 0..LIMBS {
                columns[j] = simd.u64_madd52lo(columns[j], q, modulus[j]);
                columns[j + 1] = simd.u64_madd52hi(columns[j + 1], q, modulus[j]);
            }
            columns[1] = simd.u64_add(columns[1], simd.u64_shr::<LIMB_BITS>(columns[0]));
            columns.copy_within(1.., 0);
            columns[LIMBS] = zero;
        }
        let [l0, l1, l2, l3, l4, l5, l6, l7, _] = columns;
        Self([l0, l1, l2, l3, l4, l5, l6, l7]).carry(simd)
    }

    /// Returns `self * self`.
    #[inline(always)]
    pub fn square(self, simd: S) -> Self {
        self.mul(simd, self)
    }

    /// Returns `b` in lanes where `choice` is set and `a` elsewhere.
    #[inline(always)]
    pub fn select(simd: S, a: Self, b: Self, choice: Choice) -> Self {
        let mask = simd.u64_splat((choice.unwrap_u8() as u64).wrapping_neg());
        Self(core::array::from_fn(|i| simd.u64_select(mask, b.0[i], a.0[i])))
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
        Self(core::array::from_fn(|i| simd.u64_select(keep, self.0[i], reduced[i])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fp::tests::canonical;
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
                        let a = FpVec::load(simd, &self.a[start..]);
                        let b = FpVec::load(simd, &self.b[start..]);
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
        const FORMULAS: [Formula; 7] = [
            Formula::Add,
            Formula::Sub,
            Formula::Neg,
            Formula::Mul,
            Formula::Square,
            Formula::Chain,
            Formula::Select,
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
                        FpVec::load(simd, &self.0[start..]).store(simd, &mut output[start..]);
                    }
                    output
                }
            }
            assert_eq!(test_dispatch(RoundTrip(&a)), a);
            check_consistent(|| RoundTrip(&a));
            Ok(())
        });
    }
}
