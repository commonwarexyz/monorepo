//! The quadratic extension `Fp2 = Fp[i] / (i^2 + 1)`.
//!
//! [`Fp2`] is the scalar element. The extension context builds the field over any base field
//! context, so one implementation serves scalar arithmetic, one element per lane, and
//! backend-specific representations alike.

use crate::fp::{BYTES as FP_BYTES, Arithmetic, Fp, MODULUS};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Number of bytes in the canonical big-endian encoding: `c1` followed by `c0`.
pub const BYTES: usize = 2 * FP_BYTES;

/// An element `c0 + c1 * i` of the quadratic extension field.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    /// The additive identity.
    pub const ZERO: Self = Self::new(Fp::ZERO, Fp::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(Fp::ONE, Fp::ZERO);

    /// Returns `c0 + c1 * i`.
    pub const fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    /// Parses the canonical big-endian encoding.
    ///
    /// Returns `None` when either coordinate is not below the modulus.
    pub fn from_bytes(bytes: &[u8; BYTES]) -> Option<Self> {
        let (c1, c0) = bytes.split_at(FP_BYTES);
        Some(Self {
            c0: Fp::from_bytes(c0.try_into().expect("half"))?,
            c1: Fp::from_bytes(c1.try_into().expect("half"))?,
        })
    }

    /// Returns the canonical big-endian encoding.
    pub fn to_bytes(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..FP_BYTES].copy_from_slice(&self.c1.to_bytes());
        bytes[FP_BYTES..].copy_from_slice(&self.c0.to_bytes());
        bytes
    }

    /// Returns `self + rhs`.
    pub const fn add(self, rhs: Self) -> Self {
        Self::new(self.c0.add(rhs.c0), self.c1.add(rhs.c1))
    }

    /// Returns `self - rhs`.
    pub const fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0.sub(rhs.c0), self.c1.sub(rhs.c1))
    }

    /// Returns `-self`.
    pub const fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg())
    }

    /// Returns `2 * self`.
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Returns the conjugate `c0 - c1 * i`.
    pub const fn conjugate(self) -> Self {
        Self::new(self.c0, self.c1.neg())
    }

    /// Returns `self * rhs`.
    pub const fn mul(self, rhs: Self) -> Self {
        // Karatsuba: (a0 + a1 i)(b0 + b1 i) = (a0 b0 - a1 b1) + ((a0 + a1)(b0 + b1) - a0 b0 - a1 b1) i.
        let a0b0 = self.c0.mul(rhs.c0);
        let a1b1 = self.c1.mul(rhs.c1);
        let cross = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1));
        Self::new(a0b0.sub(a1b1), cross.sub(a0b0).sub(a1b1))
    }

    /// Returns `self * self`.
    pub const fn square(self) -> Self {
        // (a0 + a1 i)^2 = (a0 + a1)(a0 - a1) + 2 a0 a1 i.
        let c0 = self.c0.add(self.c1).mul(self.c0.sub(self.c1));
        let c1 = self.c0.mul(self.c1).double();
        Self::new(c0, c1)
    }

    /// Returns `self * (c0 + c1 i)` for a base field `c0`.
    pub const fn mul_base(self, rhs: Fp) -> Self {
        Self::new(self.c0.mul(rhs), self.c1.mul(rhs))
    }

    /// Returns `self * i`.
    pub const fn mul_i(self) -> Self {
        Self::new(self.c1.neg(), self.c0)
    }

    /// Returns `self * (1 + i)`, the non-residue that defines the higher extensions.
    pub const fn mul_by_nonresidue(self) -> Self {
        Self::new(self.c0.sub(self.c1), self.c0.add(self.c1))
    }

    /// Returns the multiplicative inverse, or zero for zero.
    pub const fn invert(self) -> Self {
        // 1 / (a0 + a1 i) = (a0 - a1 i) / (a0^2 + a1^2).
        let norm = self.c0.square().add(self.c1.square()).invert();
        self.conjugate().mul_base(norm)
    }

    /// Returns a square root when one exists.
    ///
    /// Uses the `p = 3 mod 4` algorithm of RFC 9380 (Appendix I.2): a candidate is derived from
    /// `self^((p - 3) / 4)` and corrected by `i` when its square has the wrong sign.
    pub fn sqrt(self) -> Option<Self> {
        // (p - 3) / 4 = (p + 1) / 4 - 1.
        let mut exponent = crate::fp::SQRT_EXPONENT;
        exponent[0] -= 1;
        let a1 = self.pow(&exponent);
        let alpha = a1.square().mul(self);
        let x0 = a1.mul(self);
        // alpha = -1 means the root is i * x0; otherwise it is (alpha + 1)^((p - 1) / 2) * x0.
        let minus_one = Self::ONE.neg();
        if bool::from(alpha.ct_eq(&minus_one)) {
            let root = x0.mul_i();
            return Some(root);
        }
        let mut half = [0u64; 6];
        for i in 0..6 {
            half[i] = MODULUS[i] >> 1;
            if i + 1 < 6 {
                half[i] |= MODULUS[i + 1] << 63;
            }
        }
        let root = alpha.add(Self::ONE).pow(&half).mul(x0);
        bool::from(root.square().ct_eq(&self)).then_some(root)
    }

    /// Returns `self^exponent` for a public little-endian exponent.
    pub fn pow(self, exponent: &[u64]) -> Self {
        let mut result = Self::ONE;
        for word in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = result.square();
                if (word >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Returns whether the element is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Returns the sign used by the compressed point encoding: whether `c1` exceeds
    /// `(p - 1) / 2`, or `c0` does when `c1` is zero.
    pub fn is_lexicographically_largest(&self) -> Choice {
        let c1_zero = self.c1.is_zero();
        (self.c1.is_lexicographically_largest() & !c1_zero)
            | (self.c0.is_lexicographically_largest() & c1_zero)
    }
}

crate::algebra::field_traits!(Fp2);

impl ConstantTimeEq for Fp2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl ConditionallySelectable for Fp2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c0: Fp::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

impl PartialEq for Fp2 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Fp2 {}

/// An extension field element `c0 + c1 * i` over any base representation.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Pair<E> {
    pub c0: E,
    pub c1: E,
}

/// Largest number of base field terms one [`sum_of_products`] passes to the base context.
pub(crate) const MAX_TERMS: usize = 16;

/// Returns the sum of `x * y` over the `products` `(x, y, negate)` and of `x * s` over the
/// `scaled` terms `(x, s, negate)` with a base field `s`, subtracting where `negate` is set.
///
/// Each coordinate of the result is one base [`Arithmetic::sum_of_products`] of `2N + M`
/// terms, so formulas built on it keep the bound of a single reduction.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn sum_of_products<F: Arithmetic, const N: usize, const M: usize>(
    f: F,
    products: [(Pair<F::Element>, Pair<F::Element>, bool); N],
    scaled: [(Pair<F::Element>, F::Element, bool); M],
) -> Pair<F::Element> {
    const { assert!(N > 0 && 2 * N + M <= MAX_TERMS) };
    let fill = products[0].0.c0;
    let mut real = [(fill, fill, false); MAX_TERMS];
    let mut imaginary = real;
    let mut len = 0;
    for (x, y, negate) in products {
        // (x0 + x1 i)(y0 + y1 i) = (x0 y0 - x1 y1) + (x0 y1 + x1 y0) i.
        real[len] = (x.c0, y.c0, negate);
        real[len + 1] = (x.c1, y.c1, !negate);
        imaginary[len] = (x.c0, y.c1, negate);
        imaginary[len + 1] = (x.c1, y.c0, negate);
        len += 2;
    }
    for (x, s, negate) in scaled {
        real[len] = (x.c0, s, negate);
        imaginary[len] = (x.c1, s, negate);
        len += 1;
    }
    Pair {
        c0: f.sum_of_products(&real[..len]),
        c1: f.sum_of_products(&imaginary[..len]),
    }
}

/// Returns `(1 + i) * x` as `(x0 - x1) + (x0 + x1) i`.
///
/// This is one subtraction and one addition, so `x1` must be a valid subtrahend. Formulas
/// apply it to multiplicands, which tolerate the larger result.
#[inline(always)]
pub(crate) fn mul_by_nonresidue<F: Arithmetic>(f: F, x: Pair<F::Element>) -> Pair<F::Element> {
    Pair {
        c0: f.sub(x.c0, x.c1),
        c1: f.add(x.c0, x.c1),
    }
}

/// The quadratic extension over a base field context.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ext<F>(pub F);

impl<F: Arithmetic<Scalar = Fp>> Arithmetic for Ext<F> {
    type Element = Pair<F::Element>;

    type Scalar = Fp2;

    const LANES: usize = F::LANES;

    type Stored = Pair<F::Stored>;

    #[inline(always)]
    fn gather<'a>(self, lanes: impl IntoIterator<Item = &'a Pair<F::Stored>>) -> Self::Element {
        let mut c0 = [F::Stored::default(); crate::fp::lanes::MAX_LANES];
        let mut c1 = [F::Stored::default(); crate::fp::lanes::MAX_LANES];
        for (lane, stored) in lanes.into_iter().take(F::LANES).enumerate() {
            c0[lane] = stored.c0;
            c1[lane] = stored.c1;
        }
        Pair {
            c0: self.0.gather(&c0),
            c1: self.0.gather(&c1),
        }
    }

    #[inline(always)]
    fn scatter<'a>(
        self,
        value: Self::Element,
        lanes: impl IntoIterator<Item = &'a mut Pair<F::Stored>>,
    ) {
        let mut c0 = [F::Stored::default(); crate::fp::lanes::MAX_LANES];
        let mut c1 = [F::Stored::default(); crate::fp::lanes::MAX_LANES];
        self.0.scatter(value.c0, c0.iter_mut());
        self.0.scatter(value.c1, c1.iter_mut());
        for (lane, stored) in lanes.into_iter().take(F::LANES).enumerate() {
            stored.c0 = c0[lane];
            stored.c1 = c1[lane];
        }
    }

    #[inline(always)]
    fn load(self, elements: &[Fp2], fill: Fp2) -> Self::Element {
        let mut c0 = [fill.c0; crate::fp::lanes::MAX_LANES];
        let mut c1 = [fill.c1; crate::fp::lanes::MAX_LANES];
        for (lane, element) in elements.iter().take(F::LANES).enumerate() {
            c0[lane] = element.c0;
            c1[lane] = element.c1;
        }
        Pair {
            c0: self.0.load(&c0, fill.c0),
            c1: self.0.load(&c1, fill.c1),
        }
    }

    #[inline(always)]
    fn store(self, value: Self::Element, outputs: &mut [Fp2]) {
        let mut c0 = [Fp::ZERO; crate::fp::lanes::MAX_LANES];
        let mut c1 = [Fp::ZERO; crate::fp::lanes::MAX_LANES];
        self.0.store(value.c0, &mut c0);
        self.0.store(value.c1, &mut c1);
        for (lane, output) in outputs.iter_mut().take(F::LANES).enumerate() {
            *output = Fp2::new(c0[lane], c1[lane]);
        }
    }

    #[inline(always)]
    fn constant(self, value: Fp2) -> Self::Element {
        Pair {
            c0: self.0.constant(value.c0),
            c1: self.0.constant(value.c1),
        }
    }

    #[inline(always)]
    fn add(self, a: Self::Element, b: Self::Element) -> Self::Element {
        Pair {
            c0: self.0.add(a.c0, b.c0),
            c1: self.0.add(a.c1, b.c1),
        }
    }

    #[inline(always)]
    fn sub(self, a: Self::Element, b: Self::Element) -> Self::Element {
        Pair {
            c0: self.0.sub(a.c0, b.c0),
            c1: self.0.sub(a.c1, b.c1),
        }
    }

    #[inline(always)]
    fn neg(self, a: Self::Element) -> Self::Element {
        Pair {
            c0: self.0.neg(a.c0),
            c1: self.0.neg(a.c1),
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn mul(self, a: Self::Element, b: Self::Element) -> Self::Element {
        // Each coordinate is a sum of two products with one reduction, so the result stays as
        // small as a base product, which the lazily reduced representations require.
        let f = self.0;
        Pair {
            c0: f.mul_sub(a.c0, b.c0, a.c1, b.c1),
            c1: f.mul_add(a.c0, b.c1, a.c1, b.c0),
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn square(self, a: Self::Element) -> Self::Element {
        let f = self.0;
        Pair {
            c0: f.mul_sub(a.c0, a.c0, a.c1, a.c1),
            c1: f.mul_add(a.c0, a.c1, a.c1, a.c0),
        }
    }

    // Each coordinate is one base sum of four products.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn mul_add(
        self,
        a: Self::Element,
        b: Self::Element,
        c: Self::Element,
        d: Self::Element,
    ) -> Self::Element {
        sum_of_products(self.0, [(a, b, false), (c, d, false)], [])
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn mul_sub(
        self,
        a: Self::Element,
        b: Self::Element,
        c: Self::Element,
        d: Self::Element,
    ) -> Self::Element {
        sum_of_products(self.0, [(a, b, false), (c, d, true)], [])
    }

    #[inline(always)]
    fn select(self, a: Self::Element, b: Self::Element, choice: Choice) -> Self::Element {
        Pair {
            c0: self.0.select(a.c0, b.c0, choice),
            c1: self.0.select(a.c1, b.c1, choice),
        }
    }

    /// The Frobenius map conjugates: `(c0 + c1 i)^p = c0 - c1 i` since `i^p = -i`.
    #[inline(always)]
    fn frobenius(self, a: Self::Element) -> Self::Element {
        Pair {
            c0: self.0.frobenius(a.c0),
            c1: self.0.neg(self.0.frobenius(a.c1)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fp::{
        Single,
        lanes::{Lanes, MAX_LANES},
        tests::canonical,
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{Operation, Simd, check_consistent, test_dispatch};

    pub(crate) fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<Fp2> {
        Ok(Fp2::new(canonical(u)?, canonical(u)?))
    }

    pub(crate) fn to_blst(value: Fp2) -> blst::blst_fp2 {
        blst::blst_fp2 {
            fp: [crate::fp::tests::to_blst(value.c0), crate::fp::tests::to_blst(value.c1)],
        }
    }

    pub(crate) fn from_blst(value: &blst::blst_fp2) -> Fp2 {
        Fp2::new(
            crate::fp::tests::from_blst(&value.fp[0]),
            crate::fp::tests::from_blst(&value.fp[1]),
        )
    }

    impl<'a> arbitrary::Arbitrary<'a> for Fp2 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            element(u)
        }
    }

    #[test]
    fn algebra_laws() {
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_field::<Fp2>);
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let a = element(u)?;
            let b = element(u)?;
            let (ba, bb) = (to_blst(a), to_blst(b));
            let mut out = blst::blst_fp2::default();
            // SAFETY: all pointers reference valid field elements.
            unsafe {
                blst::blst_fp2_add(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.add(b));
                blst::blst_fp2_sub(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.sub(b));
                blst::blst_fp2_mul(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.mul(b));
                blst::blst_fp2_sqr(&mut out, &ba);
                assert_eq!(from_blst(&out), a.square());
                blst::blst_fp2_cneg(&mut out, &ba, true);
                assert_eq!(from_blst(&out), a.neg());
                blst::blst_fp2_inverse(&mut out, &ba);
                assert_eq!(from_blst(&out), a.invert());
                let exists = blst::blst_fp2_sqrt(&mut out, &ba);
                assert_eq!(exists, a.sqrt().is_some());
            }
            let square = a.square();
            let root = square.sqrt().expect("squares have roots");
            assert!(root == a || root == a.neg());
            assert_eq!(Fp2::from_bytes(&a.to_bytes()), Some(a));
            Ok(())
        });
    }

    /// Evaluates `(a + b) * (a - b) * b + a^2 - a` on every lane.
    #[derive(Clone, Copy)]
    struct Formula<'a> {
        a: &'a [Fp2; MAX_LANES],
        b: &'a [Fp2; MAX_LANES],
    }

    impl Formula<'_> {
        #[inline(always)]
        fn evaluate<F: Arithmetic<Scalar = Fp2>>(self, f: F, a: F::Element, b: F::Element) -> F::Element {
            let product = f.mul(f.mul(f.add(a, b), f.sub(a, b)), b);
            f.sub(f.add(product, f.square(a)), a)
        }
    }

    impl<S: Simd> Operation<S> for Formula<'_> {
        type Output = [Fp2; MAX_LANES];

        fn portable(self, simd: S) -> [Fp2; MAX_LANES] {
            let f = Ext(Lanes(simd));
            let mut output = [Fp2::ZERO; MAX_LANES];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                let a = f.load(&self.a[start..], Fp2::ZERO);
                let b = f.load(&self.b[start..], Fp2::ZERO);
                f.store(self.evaluate(f, a, b), &mut output[start..]);
            }
            output
        }
    }

    #[test]
    fn lanes_match_scalar_extension() {
        minifuzz::test(|u| {
            let mut a = [Fp2::ZERO; MAX_LANES];
            let mut b = [Fp2::ZERO; MAX_LANES];
            for (a, b) in a.iter_mut().zip(&mut b) {
                *a = element(u)?;
                *b = element(u)?;
            }
            let formula = Formula { a: &a, b: &b };
            let scalar = Ext(Single);
            let expected: Vec<Fp2> = a
                .iter()
                .zip(&b)
                .map(|(a, b)| {
                    let (a, b) = (scalar.load(&[*a], Fp2::ZERO), scalar.load(&[*b], Fp2::ZERO));
                    let mut out = [Fp2::ZERO];
                    scalar.store(formula.evaluate(scalar, a, b), &mut out);
                    out[0]
                })
                .collect();
            assert_eq!(test_dispatch(formula).as_slice(), expected);
            check_consistent(|| formula);
            Ok(())
        });
    }
}
