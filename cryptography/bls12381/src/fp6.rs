//! The cubic extension `Fp6 = Fp2[v] / (v^3 - (1 + i))`.
//!
//! [`Fp6`] is the scalar element. The extension context builds the field over any base field
//! context. Multiplication reduces `v^3` to the non-residue `1 + i` on the multiplicand side, so
//! every coordinate of a product is a single sum of base products with one reduction, as the
//! lazily reduced representations require.

use crate::{
    fp::{Arithmetic, Fp, WORDS, lanes::MAX_LANES},
    fp2::{self, Ext, Fp2, Pair},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The non-residue `1 + i`: `v^3` in this field and `w^6` in the degree-twelve extension.
pub(crate) const NONRESIDUE: Fp2 = Fp2::new(Fp::ONE, Fp::ONE);

/// `(p - 1) / 6`, little-endian.
const SIXTH: [u64; WORDS] = {
    let mut quotient = [0; WORDS];
    let mut remainder = 0u128;
    let mut i = WORDS;
    while i > 0 {
        i -= 1;
        // p - 1 differs from p only in the low word, which is odd.
        let word = if i == 0 {
            crate::fp::MODULUS[0] - 1
        } else {
            crate::fp::MODULUS[i]
        };
        let value = (remainder << 64) | word as u128;
        quotient[i] = (value / 6) as u64;
        remainder = value % 6;
    }
    assert!(remainder == 0);
    quotient
};

/// Returns `base^exponent` for a little-endian exponent.
const fn power(base: Fp2, exponent: &[u64; WORDS]) -> Fp2 {
    let mut result = Fp2::ONE;
    let mut i = WORDS;
    while i > 0 {
        i -= 1;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            result = result.square();
            if (exponent[i] >> bit) & 1 == 1 {
                result = result.mul(base);
            }
        }
    }
    result
}

/// `(1 + i)^(j (p - 1) / 6)` for `j` in `0..6`.
///
/// The Frobenius map sends `a w^j` to `conj(a) w^(j p) = conj(a) * FROBENIUS[j] * w^j`, since
/// `w^(p - 1) = (w^6)^((p - 1) / 6)`; powers of `v = w^2` take the even entries.
pub(crate) const FROBENIUS: [Fp2; 6] = {
    let gamma = power(NONRESIDUE, &SIXTH);
    let mut powers = [Fp2::ONE; 6];
    let mut j = 1;
    while j < 6 {
        powers[j] = powers[j - 1].mul(gamma);
        j += 1;
    }
    powers
};

/// An element `c0 + c1 * v + c2 * v^2` of the cubic extension field.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl Fp6 {
    /// The additive identity.
    pub const ZERO: Self = Self::new(Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(Fp2::ONE, Fp2::ZERO, Fp2::ZERO);

    /// Returns `c0 + c1 * v + c2 * v^2`.
    pub const fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
        Self { c0, c1, c2 }
    }

    /// Returns `self + rhs`.
    pub const fn add(self, rhs: Self) -> Self {
        Self::new(
            self.c0.add(rhs.c0),
            self.c1.add(rhs.c1),
            self.c2.add(rhs.c2),
        )
    }

    /// Returns `self - rhs`.
    pub const fn sub(self, rhs: Self) -> Self {
        Self::new(
            self.c0.sub(rhs.c0),
            self.c1.sub(rhs.c1),
            self.c2.sub(rhs.c2),
        )
    }

    /// Returns `-self`.
    pub const fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg(), self.c2.neg())
    }

    /// Returns `2 * self`.
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Returns `self * rhs`.
    pub const fn mul(self, rhs: Self) -> Self {
        let (a, b) = (self, rhs);
        // v^3 = 1 + i folds the products of degree three and four back down.
        let c0 =
            a.c0.mul(b.c0)
                .add(a.c1.mul(b.c2).add(a.c2.mul(b.c1)).mul_by_nonresidue());
        let c1 =
            a.c0.mul(b.c1)
                .add(a.c1.mul(b.c0))
                .add(a.c2.mul(b.c2).mul_by_nonresidue());
        let c2 = a.c0.mul(b.c2).add(a.c1.mul(b.c1)).add(a.c2.mul(b.c0));
        Self::new(c0, c1, c2)
    }

    /// Returns `self * self`.
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Returns `self * v`.
    pub const fn mul_by_v(self) -> Self {
        Self::new(self.c2.mul_by_nonresidue(), self.c0, self.c1)
    }

    /// Returns the multiplicative inverse, or zero for zero.
    pub const fn invert(self) -> Self {
        // The adjugate t satisfies self * t = d for the norm-like d in Fp2.
        let Self { c0, c1, c2 } = self;
        let t0 = c0.square().sub(c1.mul(c2).mul_by_nonresidue());
        let t1 = c2.square().mul_by_nonresidue().sub(c0.mul(c1));
        let t2 = c1.square().sub(c0.mul(c2));
        let d = c0
            .mul(t0)
            .add(c2.mul(t1).add(c1.mul(t2)).mul_by_nonresidue());
        let d = d.invert();
        Self::new(t0.mul(d), t1.mul(d), t2.mul(d))
    }

    /// Returns the Frobenius image `self^p`.
    pub const fn frobenius(self) -> Self {
        Self::new(
            self.c0.conjugate(),
            self.c1.conjugate().mul(FROBENIUS[2]),
            self.c2.conjugate().mul(FROBENIUS[4]),
        )
    }

    /// Returns whether the element is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }
}

crate::algebra::field_traits!(Fp6);

impl ConstantTimeEq for Fp6 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1) & self.c2.ct_eq(&other.c2)
    }
}

impl ConditionallySelectable for Fp6 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(
            Fp2::conditional_select(&a.c0, &b.c0, choice),
            Fp2::conditional_select(&a.c1, &b.c1, choice),
            Fp2::conditional_select(&a.c2, &b.c2, choice),
        )
    }
}

impl PartialEq for Fp6 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Fp6 {}

/// The coefficients of `1, v, v^2` over any base representation.
pub(crate) type Cubic<E> = [Pair<E>; 3];

/// The cubic extension over a base field context.
///
/// Products of inputs whose coordinates are valid subtrahends have every coordinate a sum of
/// six base products with one reduction: below `4p` under the bounds of [`crate::fp::lanes`]
/// and below `192p` under those of `crate::fp::rns`. Squares sum at most four products.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ext6<F>(pub F);

impl<F: Arithmetic<Scalar = Fp>> Ext6<F> {
    /// Returns `a * b`, or `-(a * b)` when `negate` is set.
    ///
    /// The non-residue multiplies `b1` and `b2`, whose coordinates must be valid subtrahends.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn product(
        self,
        a: Cubic<F::Element>,
        b: Cubic<F::Element>,
        negate: bool,
    ) -> Cubic<F::Element> {
        let f = self.0;
        let xb1 = fp2::mul_by_nonresidue(f, b[1]);
        let xb2 = fp2::mul_by_nonresidue(f, b[2]);
        [
            fp2::sum_of_products(
                f,
                &[
                    (a[0], b[0], negate),
                    (a[1], xb2, negate),
                    (a[2], xb1, negate),
                ],
                &[],
            ),
            fp2::sum_of_products(
                f,
                &[
                    (a[0], b[1], negate),
                    (a[1], b[0], negate),
                    (a[2], xb2, negate),
                ],
                &[],
            ),
            fp2::sum_of_products(
                f,
                &[
                    (a[0], b[2], negate),
                    (a[1], b[1], negate),
                    (a[2], b[0], negate),
                ],
                &[],
            ),
        ]
    }
}

impl<F: Arithmetic<Scalar = Fp>> Arithmetic for Ext6<F> {
    type Element = Cubic<F::Element>;

    type Scalar = Fp6;

    const LANES: usize = F::LANES;

    type Stored = [Pair<F::Stored>; 3];

    #[inline(always)]
    fn gather<'a>(self, lanes: impl IntoIterator<Item = &'a Self::Stored>) -> Self::Element {
        let mut coefficients = [[Pair::default(); MAX_LANES]; 3];
        for (lane, stored) in lanes.into_iter().take(F::LANES).enumerate() {
            for (coefficient, stored) in coefficients.iter_mut().zip(stored) {
                coefficient[lane] = *stored;
            }
        }
        let ext = Ext(self.0);
        [
            ext.gather(&coefficients[0]),
            ext.gather(&coefficients[1]),
            ext.gather(&coefficients[2]),
        ]
    }

    #[inline(always)]
    fn scatter<'a>(
        self,
        value: Self::Element,
        lanes: impl IntoIterator<Item = &'a mut Self::Stored>,
    ) {
        let ext = Ext(self.0);
        let mut coefficients = [[Pair::default(); MAX_LANES]; 3];
        for (coefficient, value) in coefficients.iter_mut().zip(value) {
            ext.scatter(value, coefficient.iter_mut());
        }
        for (lane, stored) in lanes.into_iter().take(F::LANES).enumerate() {
            for (stored, coefficient) in stored.iter_mut().zip(&coefficients) {
                *stored = coefficient[lane];
            }
        }
    }

    #[inline(always)]
    fn load(self, elements: &[Fp6], fill: Fp6) -> Self::Element {
        let mut c0 = [fill.c0; MAX_LANES];
        let mut c1 = [fill.c1; MAX_LANES];
        let mut c2 = [fill.c2; MAX_LANES];
        for (lane, element) in elements.iter().take(F::LANES).enumerate() {
            c0[lane] = element.c0;
            c1[lane] = element.c1;
            c2[lane] = element.c2;
        }
        let ext = Ext(self.0);
        [
            ext.load(&c0, fill.c0),
            ext.load(&c1, fill.c1),
            ext.load(&c2, fill.c2),
        ]
    }

    #[inline(always)]
    fn store(self, value: Self::Element, outputs: &mut [Fp6]) {
        let ext = Ext(self.0);
        let mut coefficients = [[Fp2::ZERO; MAX_LANES]; 3];
        for (coefficient, value) in coefficients.iter_mut().zip(value) {
            ext.store(value, coefficient);
        }
        let [c0, c1, c2] = coefficients;
        for (lane, output) in outputs.iter_mut().take(F::LANES).enumerate() {
            *output = Fp6::new(c0[lane], c1[lane], c2[lane]);
        }
    }

    #[inline(always)]
    fn constant(self, value: Fp6) -> Self::Element {
        let ext = Ext(self.0);
        [
            ext.constant(value.c0),
            ext.constant(value.c1),
            ext.constant(value.c2),
        ]
    }

    #[inline(always)]
    fn add(self, a: Self::Element, b: Self::Element) -> Self::Element {
        let ext = Ext(self.0);
        [
            ext.add(a[0], b[0]),
            ext.add(a[1], b[1]),
            ext.add(a[2], b[2]),
        ]
    }

    #[inline(always)]
    fn sub(self, a: Self::Element, b: Self::Element) -> Self::Element {
        let ext = Ext(self.0);
        [
            ext.sub(a[0], b[0]),
            ext.sub(a[1], b[1]),
            ext.sub(a[2], b[2]),
        ]
    }

    #[inline(always)]
    fn neg(self, a: Self::Element) -> Self::Element {
        let ext = Ext(self.0);
        [ext.neg(a[0]), ext.neg(a[1]), ext.neg(a[2])]
    }

    #[inline(always)]
    fn mul(self, a: Self::Element, b: Self::Element) -> Self::Element {
        self.product(a, b, false)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn square(self, a: Self::Element) -> Self::Element {
        let f = self.0;
        let ext = Ext(f);
        let (d0, d1) = (ext.double(a[0]), ext.double(a[1]));
        let xa2 = fp2::mul_by_nonresidue(f, a[2]);
        [
            fp2::sum_of_products(f, &[(a[0], a[0], false), (d1, xa2, false)], &[]),
            fp2::sum_of_products(f, &[(d0, a[1], false), (a[2], xa2, false)], &[]),
            fp2::sum_of_products(f, &[(a[1], a[1], false), (d0, a[2], false)], &[]),
        ]
    }

    /// Adds the products, each with one reduction per coordinate and its sign folded into
    /// the sum, so `b` needs no negation.
    #[inline(always)]
    fn sum_of_products(self, terms: &[(Self::Element, Self::Element, bool)]) -> Self::Element {
        let Some(((a, b, negate), rest)) = terms.split_first() else {
            return self.constant(Fp6::ZERO);
        };
        let mut sum = self.product(*a, *b, *negate);
        for (a, b, negate) in rest {
            sum = self.add(sum, self.product(*a, *b, *negate));
        }
        sum
    }

    #[inline(always)]
    fn select(self, a: Self::Element, b: Self::Element, choice: Choice) -> Self::Element {
        let ext = Ext(self.0);
        [
            ext.select(a[0], b[0], choice),
            ext.select(a[1], b[1], choice),
            ext.select(a[2], b[2], choice),
        ]
    }

    /// Conjugates each coefficient and multiplies the coefficient of `v^k` by
    /// `FROBENIUS[2k]`, one reduction per coordinate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn frobenius(self, a: Self::Element) -> Self::Element {
        let ext = Ext(self.0);
        let mut result = a;
        for (k, (output, a)) in result.iter_mut().zip(a).enumerate() {
            *output = ext.mul(ext.frobenius(a), ext.constant(FROBENIUS[2 * k]));
        }
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        fp::{MODULUS, Single, lanes::Lanes, rns::Rns},
        fp2::tests::element as fp2_element,
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::Ring;
    use commonware_simd::{
        Operation, Simd, check_consistent, emulated::EmulatedX86V4C, test_dispatch,
    };

    pub(crate) fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<Fp6> {
        Ok(Fp6::new(fp2_element(u)?, fp2_element(u)?, fp2_element(u)?))
    }

    impl<'a> arbitrary::Arbitrary<'a> for Fp6 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            element(u)
        }
    }

    #[test]
    fn algebra_laws() {
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_field::<Fp6>);
    }

    #[test]
    fn frobenius_is_the_p_power() {
        assert_eq!(FROBENIUS[0], Fp2::ONE);
        assert_eq!(
            FROBENIUS[1].pow(&[6]),
            NONRESIDUE.pow(&MODULUS).mul(NONRESIDUE.invert())
        );
        minifuzz::Builder::default()
            .with_search_limit(16)
            .test(|u| {
                let a = element(u)?;
                assert_eq!(a.frobenius(), a.exp(&MODULUS));
                assert_eq!(
                    a.mul_by_v(),
                    a.mul(Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO))
                );
                Ok(())
            });
    }

    /// Evaluates every operation of the extension context, chained so that each output feeds
    /// later operations: `[a * b, (a * b)^2, inverse, frobenius, and a mixed sum]`.
    fn chain<F: Arithmetic<Scalar = Fp>>(
        f: Ext6<F>,
        a: Cubic<F::Element>,
        b: Cubic<F::Element>,
    ) -> [Cubic<F::Element>; 4] {
        let product = f.mul(a, b);
        let square = f.square(product);
        let frobenius = f.frobenius(f.frobenius(square));
        let sum = f.sum_of_products(&[(f.sub(a, product), square, true), (frobenius, b, false)]);
        [product, square, frobenius, sum]
    }

    /// The scalar values of [`chain`].
    fn expected(a: Fp6, b: Fp6) -> [Fp6; 4] {
        let product = a.mul(b);
        let square = product.square();
        let frobenius = square.frobenius().frobenius();
        let sum = frobenius.mul(b).sub(a.sub(product).mul(square));
        [product, square, frobenius, sum]
    }

    /// Runs [`chain`] on every lane.
    #[derive(Clone, Copy)]
    struct Chain<'a> {
        a: &'a [Fp6; MAX_LANES],
        b: &'a [Fp6; MAX_LANES],
    }

    impl<S: Simd> Operation<S> for Chain<'_> {
        type Output = [[Fp6; MAX_LANES]; 4];

        fn portable(self, simd: S) -> Self::Output {
            let f = Ext6(Lanes(simd));
            let mut output = [[Fp6::ZERO; MAX_LANES]; 4];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                let a = f.load(&self.a[start..], Fp6::ZERO);
                let b = f.load(&self.b[start..], Fp6::ZERO);
                for (output, value) in output.iter_mut().zip(chain(f, a, b)) {
                    f.store(value, &mut output[start..]);
                }
            }
            output
        }
    }

    #[test]
    fn contexts_match_scalar_field() {
        minifuzz::Builder::default()
            .with_search_limit(16)
            .test(|u| {
                let mut a = [Fp6::ZERO; MAX_LANES];
                let mut b = [Fp6::ZERO; MAX_LANES];
                for (a, b) in a.iter_mut().zip(&mut b) {
                    *a = element(u)?;
                    *b = element(u)?;
                }
                let expected: [[Fp6; MAX_LANES]; 4] = {
                    let mut out = [[Fp6::ZERO; MAX_LANES]; 4];
                    for lane in 0..MAX_LANES {
                        for (out, value) in out.iter_mut().zip(expected(a[lane], b[lane])) {
                            out[lane] = value;
                        }
                    }
                    out
                };

                let single = Ext6(Single);
                let values = chain(single, single.constant(a[0]), single.constant(b[0]));
                for (value, expected) in values.iter().zip(&expected) {
                    let mut out = [Fp6::ZERO];
                    single.store(*value, &mut out);
                    assert_eq!(out[0], expected[0]);
                }

                assert_eq!(test_dispatch(Chain { a: &a, b: &b }), expected);
                check_consistent(|| Chain { a: &a, b: &b });

                let rns = EmulatedX86V4C.execute(|simd: EmulatedX86V4C| {
                    let f = Ext6(Rns(simd));
                    chain(f, f.constant(a[0]), f.constant(b[0])).map(|value| {
                        let mut out = [Fp6::ZERO];
                        f.store(value, &mut out);
                        out[0]
                    })
                });
                for (actual, expected) in rns.iter().zip(&expected) {
                    assert_eq!(*actual, expected[0]);
                }
                Ok(())
            });
    }
}
