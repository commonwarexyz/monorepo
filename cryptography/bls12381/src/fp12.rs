//! The quadratic extension `Fp12 = Fp6[w] / (w^2 - v)`, which contains the target group.
//!
//! [`Fp12`] is the scalar element. The extension context builds the field over any base field
//! context and represents an element by its coefficients over Fp2 of `1, w, ..., w^5`, where
//! `w^6 = 1 + i`. Multiplication is then a convolution whose wrapped terms carry the non-residue
//! on the multiplicand side, so every coordinate of a product is a single sum of base products
//! with one reduction, as the lazily reduced representations require. The context also
//! provides the operations of the pairing: multiplication by sparse Miller-loop lines,
//! cyclotomic squaring, conjugation, and inversion.

use crate::{
    fp::{self, Arithmetic, BYTES as FP_BYTES, Fp, lanes::MAX_LANES},
    fp2::{self, Ext, Fp2, Pair},
    fp6::{Ext6, FROBENIUS, Fp6},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Number of bytes in the canonical big-endian encoding.
pub const BYTES: usize = 12 * FP_BYTES;

/// An element `c0 + c1 * w` of the degree-twelve extension field.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

impl Fp12 {
    /// The additive identity.
    pub const ZERO: Self = Self::new(Fp6::ZERO, Fp6::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(Fp6::ONE, Fp6::ZERO);

    /// Returns `c0 + c1 * w`.
    pub const fn new(c0: Fp6, c1: Fp6) -> Self {
        Self { c0, c1 }
    }

    /// Returns the coefficients of `1, w, ..., w^5`.
    pub(crate) const fn coefficients(self) -> [Fp2; 6] {
        let Self { c0, c1 } = self;
        [c0.c0, c1.c0, c0.c1, c1.c1, c0.c2, c1.c2]
    }

    /// Builds an element from its coefficients of `1, w, ..., w^5`.
    pub(crate) const fn from_coefficients(a: [Fp2; 6]) -> Self {
        Self::new(Fp6::new(a[0], a[2], a[4]), Fp6::new(a[1], a[3], a[5]))
    }

    /// Parses the canonical big-endian encoding.
    ///
    /// Returns `None` when any coordinate is not below the modulus.
    pub fn from_bytes(bytes: &[u8; BYTES]) -> Option<Self> {
        let mut coefficients = [Fp2::ZERO; 6];
        let (chunks, _) = bytes.as_chunks::<FP_BYTES>();
        for (coefficient, pair) in coefficients.iter_mut().zip(chunks.chunks_exact(2)) {
            *coefficient = Fp2::new(Fp::from_bytes(&pair[0])?, Fp::from_bytes(&pair[1])?);
        }
        Some(Self::from_coefficients(coefficients))
    }

    /// Returns the canonical big-endian encoding.
    ///
    /// For each coefficient of `1, w, ..., w^5` (`c0.c0`, `c1.c0`, `c0.c1`, `c1.c1`, `c0.c2`,
    /// `c1.c2`), the real part precedes the imaginary part. This is the order of blst.
    pub fn to_bytes(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        let (chunks, _) = bytes.as_chunks_mut::<FP_BYTES>();
        for (pair, coefficient) in chunks.chunks_exact_mut(2).zip(self.coefficients()) {
            pair[0] = coefficient.c0.to_bytes();
            pair[1] = coefficient.c1.to_bytes();
        }
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

    /// Returns `self * rhs`.
    pub const fn mul(self, rhs: Self) -> Self {
        // Karatsuba over Fp6 with w^2 = v.
        let t0 = self.c0.mul(rhs.c0);
        let t1 = self.c1.mul(rhs.c1);
        let cross = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1));
        Self::new(t0.add(t1.mul_by_v()), cross.sub(t0).sub(t1))
    }

    /// Returns `self * self`.
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Returns the conjugate `c0 - c1 * w`, which is `self^(p^6)`.
    ///
    /// In the target group this is the inverse.
    pub const fn conjugate(self) -> Self {
        Self::new(self.c0, self.c1.neg())
    }

    /// Returns the multiplicative inverse, or zero for zero.
    pub const fn invert(self) -> Self {
        // 1 / (c0 + c1 w) = (c0 - c1 w) / (c0^2 - v c1^2).
        let t = self.c0.square().sub(self.c1.square().mul_by_v()).invert();
        Self::new(self.c0.mul(t), self.c1.mul(t).neg())
    }

    /// Returns the Frobenius image `self^p`.
    pub const fn frobenius(self) -> Self {
        let mut coefficients = self.coefficients();
        let mut j = 0;
        while j < 6 {
            coefficients[j] = coefficients[j].conjugate().mul(FROBENIUS[j]);
            j += 1;
        }
        Self::from_coefficients(coefficients)
    }

    /// Returns whether the element is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }
}

crate::algebra::field_traits!(Fp12);

impl ConstantTimeEq for Fp12 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl ConditionallySelectable for Fp12 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(
            Fp6::conditional_select(&a.c0, &b.c0, choice),
            Fp6::conditional_select(&a.c1, &b.c1, choice),
        )
    }
}

impl PartialEq for Fp12 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Fp12 {}

/// The coefficients of `1, w, ..., w^5` over any base representation.
pub(crate) type Sextic<E> = [Pair<E>; 6];

/// The degree-twelve extension over a base field context.
///
/// Every operation below accepts elements whose coordinates are valid subtrahends, and each
/// returns coordinates that are sums of at most twelve base products with one reduction:
/// below `7p` under the bounds of [`crate::fp::lanes`] and below `384p` under those of
/// `crate::fp::rns`, both valid subtrahends again. Squares sum at most eight products, sparse
/// line multiplications and Frobenius maps six or fewer, and cyclotomic squares five.
/// Coefficients of a Miller line may be any element where they are not multiplied by the
/// non-residue.
///
/// Every multiplicand stays below the element bound of the representation: the largest are
/// `3a` and `2 (1 + i) a` for an input coordinate `a`, below `1152p` and `1792p` under the
/// bounds of `crate::fp::rns`, whose elements may reach `2048p`.
#[derive(Clone, Copy)]
pub(crate) struct Ext12<F: Arithmetic> {
    pub field: F,
    /// The base field constant one.
    one: F::Element,
    /// The base field constant two.
    two: F::Element,
}

impl<F: Arithmetic<Scalar = Fp>> Ext12<F> {
    /// Returns the context over `field`.
    #[inline(always)]
    pub(crate) fn new(field: F) -> Self {
        Self {
            field,
            one: field.constant(Fp::ONE),
            two: field.constant(Fp::from_u64(2)),
        }
    }

    /// Returns `a * b`, or `-(a * b)` when `negate` is set.
    ///
    /// The coefficient of `w^j` sums `a_m * b_n` over `m + n = j`, and over `m + n = j + 6`
    /// with the non-residue applied to `b_n`, which must have valid subtrahends.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn product(
        self,
        a: Sextic<F::Element>,
        b: Sextic<F::Element>,
        negate: bool,
    ) -> Sextic<F::Element> {
        let f = self.field;
        let mut wrapped = b;
        for (wrapped, b) in wrapped.iter_mut().zip(b).skip(1) {
            *wrapped = fp2::mul_by_nonresidue(f, b);
        }
        let mut result = a;
        for (j, output) in result.iter_mut().enumerate() {
            let mut terms = [(a[0], b[0], negate); 6];
            for (m, term) in terms.iter_mut().enumerate() {
                let factor = if m <= j { b[j - m] } else { wrapped[j + 6 - m] };
                *term = (a[m], factor, negate);
            }
            *output = fp2::sum_of_products(f, terms, []);
        }
        result
    }

    /// Returns `a * (l0 + l2 * w^2 + l3 * w^3)` for the Miller line `[l0, l2, l3]`.
    ///
    /// The non-residue multiplies `l2` and `l3`, which must have valid subtrahends; `l0` may
    /// be any element.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn mul_by_line(
        self,
        a: Sextic<F::Element>,
        [l0, l2, l3]: [Pair<F::Element>; 3],
    ) -> Sextic<F::Element> {
        let f = self.field;
        let x2 = fp2::mul_by_nonresidue(f, l2);
        let x3 = fp2::mul_by_nonresidue(f, l3);
        [
            fp2::sum_of_products(f, [(a[0], l0, false), (a[4], x2, false), (a[3], x3, false)], []),
            fp2::sum_of_products(f, [(a[1], l0, false), (a[5], x2, false), (a[4], x3, false)], []),
            fp2::sum_of_products(f, [(a[2], l0, false), (a[0], l2, false), (a[5], x3, false)], []),
            fp2::sum_of_products(f, [(a[3], l0, false), (a[1], l2, false), (a[0], l3, false)], []),
            fp2::sum_of_products(f, [(a[4], l0, false), (a[2], l2, false), (a[1], l3, false)], []),
            fp2::sum_of_products(f, [(a[5], l0, false), (a[3], l2, false), (a[2], l3, false)], []),
        ]
    }

    /// Returns `a^2` for `a` in the cyclotomic subgroup, where `a^(p^6 + 1) = 1`.
    ///
    /// This is Granger and Scott's squaring ("Faster squaring in the cyclotomic subgroup of
    /// sixth degree extensions", 2010) on the pairs `(a_k, a_(k+3))`, which are elements
    /// `x + y s` of `Fp4 = Fp2[s] / (s^2 - (1 + i))` for `s = w^3`: each output is three times
    /// a square of such a pair plus or minus twice an input coefficient.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn cyclotomic_square(self, a: Sextic<F::Element>) -> Sextic<F::Element> {
        let f = self.field;
        let ext = Ext(f);
        let two = self.two;
        let mut three = a;
        for (three, a) in three.iter_mut().zip(a) {
            *three = ext.add(ext.double(a), a);
        }
        let x3 = fp2::mul_by_nonresidue(f, a[3]);
        let x4 = fp2::mul_by_nonresidue(f, a[4]);
        let x5 = fp2::mul_by_nonresidue(f, a[5]);
        [
            fp2::sum_of_products(
                f,
                [(three[0], a[0], false), (three[3], x3, false)],
                [(a[0], two, true)],
            ),
            fp2::sum_of_products(f, [(three[2], ext.double(x5), false)], [(a[1], two, false)]),
            fp2::sum_of_products(
                f,
                [(three[1], a[1], false), (three[4], x4, false)],
                [(a[2], two, true)],
            ),
            fp2::sum_of_products(f, [(three[0], ext.double(a[3]), false)], [(a[3], two, false)]),
            fp2::sum_of_products(
                f,
                [(three[2], a[2], false), (three[5], x5, false)],
                [(a[4], two, true)],
            ),
            fp2::sum_of_products(f, [(three[1], ext.double(a[4]), false)], [(a[5], two, false)]),
        ]
    }

    /// Returns the conjugate, `a^(p^6)`, which negates the odd coefficients.
    ///
    /// Each negation is a product by one, so the result has the bound of a product rather
    /// than of a negation.
    #[inline(always)]
    pub(crate) fn conjugate(self, a: Sextic<F::Element>) -> Sextic<F::Element> {
        let f = self.field;
        let mut result = a;
        for j in [1, 3, 5] {
            result[j] = Pair {
                c0: f.sum_of_products(&[(a[j].c0, self.one, true)]),
                c1: f.sum_of_products(&[(a[j].c1, self.one, true)]),
            };
        }
        result
    }

    /// Returns the multiplicative inverse, or zero for zero.
    ///
    /// The norm descends to Fp6 as `x^2 - v y^2` for `a = x + y w`, then to Fp2 through the
    /// adjugate, and to the base field, which is inverted by exponentiation.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn invert(self, a: Sextic<F::Element>) -> Sextic<F::Element> {
        let f = self.field;
        let ext = Ext(f);
        let (x, y) = ([a[0], a[2], a[4]], [a[1], a[3], a[5]]);
        let (dx0, dx1) = (ext.double(x[0]), ext.double(x[1]));
        let (dy0, dy1) = (ext.double(y[0]), ext.double(y[1]));
        let xx2 = fp2::mul_by_nonresidue(f, x[2]);
        let xy1 = fp2::mul_by_nonresidue(f, y[1]);
        let xy2 = fp2::mul_by_nonresidue(f, y[2]);
        let t = [
            fp2::sum_of_products(
                f,
                [(x[0], x[0], false), (dx1, xx2, false), (y[1], xy1, true), (dy0, xy2, true)],
                [],
            ),
            fp2::sum_of_products(
                f,
                [(dx0, x[1], false), (x[2], xx2, false), (y[0], y[0], true), (dy1, xy2, true)],
                [],
            ),
            fp2::sum_of_products(
                f,
                [(x[1], x[1], false), (dx0, x[2], false), (dy0, y[1], true), (y[2], xy2, true)],
                [],
            ),
        ];

        // The adjugate c of t satisfies t * c = d in Fp2.
        let xt2 = fp2::mul_by_nonresidue(f, t[2]);
        let c = [
            fp2::sum_of_products(f, [(t[0], t[0], false), (t[1], xt2, true)], []),
            fp2::sum_of_products(f, [(t[2], xt2, false), (t[0], t[1], true)], []),
            fp2::sum_of_products(f, [(t[1], t[1], false), (t[0], t[2], true)], []),
        ];
        let xc1 = fp2::mul_by_nonresidue(f, c[1]);
        let xc2 = fp2::mul_by_nonresidue(f, c[2]);
        let d = fp2::sum_of_products(
            f,
            [(t[0], c[0], false), (t[1], xc2, false), (t[2], xc1, false)],
            [],
        );

        // 1 / d = conj(d) / (d0^2 + d1^2).
        let norm = f.sum_of_products(&[(d.c0, d.c0, false), (d.c1, d.c1, false)]);
        let mut exponent = fp::MODULUS;
        exponent[0] -= 2;
        let inverse = f.pow(norm, &exponent);
        let inverse = Pair {
            c0: f.sum_of_products(&[(d.c0, inverse, false)]),
            c1: f.sum_of_products(&[(d.c1, inverse, true)]),
        };
        let t = [
            ext.mul(c[0], inverse),
            ext.mul(c[1], inverse),
            ext.mul(c[2], inverse),
        ];
        let ext6 = Ext6(f);
        let x = ext6.product(x, t, false);
        let y = ext6.product(y, t, true);
        [x[0], y[0], x[1], y[1], x[2], y[2]]
    }
}

impl<F: Arithmetic<Scalar = Fp>> Arithmetic for Ext12<F> {
    type Element = Sextic<F::Element>;

    type Scalar = Fp12;

    const LANES: usize = F::LANES;

    type Stored = [Pair<F::Stored>; 6];

    #[inline(always)]
    fn gather<'a>(self, lanes: impl IntoIterator<Item = &'a Self::Stored>) -> Self::Element {
        let mut coefficients = [[Pair::default(); MAX_LANES]; 6];
        for (lane, stored) in lanes.into_iter().take(F::LANES).enumerate() {
            for (coefficient, stored) in coefficients.iter_mut().zip(stored) {
                coefficient[lane] = *stored;
            }
        }
        let ext = Ext(self.field);
        let mut result = [ext.gather(&coefficients[0]); 6];
        for (result, coefficient) in result.iter_mut().zip(&coefficients).skip(1) {
            *result = ext.gather(coefficient);
        }
        result
    }

    #[inline(always)]
    fn scatter<'a>(
        self,
        value: Self::Element,
        lanes: impl IntoIterator<Item = &'a mut Self::Stored>,
    ) {
        let ext = Ext(self.field);
        let mut coefficients = [[Pair::default(); MAX_LANES]; 6];
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
    fn load(self, elements: &[Fp12], fill: Fp12) -> Self::Element {
        let fill = fill.coefficients();
        let mut coefficients = [[Fp2::ZERO; MAX_LANES]; 6];
        for (coefficient, fill) in coefficients.iter_mut().zip(fill) {
            *coefficient = [fill; MAX_LANES];
        }
        for (lane, element) in elements.iter().take(F::LANES).enumerate() {
            for (coefficient, value) in coefficients.iter_mut().zip(element.coefficients()) {
                coefficient[lane] = value;
            }
        }
        let ext = Ext(self.field);
        let mut result = [ext.load(&coefficients[0], fill[0]); 6];
        for j in 1..6 {
            result[j] = ext.load(&coefficients[j], fill[j]);
        }
        result
    }

    #[inline(always)]
    fn store(self, value: Self::Element, outputs: &mut [Fp12]) {
        let ext = Ext(self.field);
        let mut coefficients = [[Fp2::ZERO; MAX_LANES]; 6];
        for (coefficient, value) in coefficients.iter_mut().zip(value) {
            ext.store(value, coefficient);
        }
        for (lane, output) in outputs.iter_mut().take(F::LANES).enumerate() {
            let mut lane_coefficients = [Fp2::ZERO; 6];
            for (output, coefficient) in lane_coefficients.iter_mut().zip(&coefficients) {
                *output = coefficient[lane];
            }
            *output = Fp12::from_coefficients(lane_coefficients);
        }
    }

    #[inline(always)]
    fn constant(self, value: Fp12) -> Self::Element {
        let ext = Ext(self.field);
        let value = value.coefficients();
        let mut result = [ext.constant(value[0]); 6];
        for j in 1..6 {
            result[j] = ext.constant(value[j]);
        }
        result
    }

    #[inline(always)]
    fn add(self, mut a: Self::Element, b: Self::Element) -> Self::Element {
        let ext = Ext(self.field);
        for (a, b) in a.iter_mut().zip(b) {
            *a = ext.add(*a, b);
        }
        a
    }

    #[inline(always)]
    fn sub(self, mut a: Self::Element, b: Self::Element) -> Self::Element {
        let ext = Ext(self.field);
        for (a, b) in a.iter_mut().zip(b) {
            *a = ext.sub(*a, b);
        }
        a
    }

    #[inline(always)]
    fn neg(self, mut a: Self::Element) -> Self::Element {
        let ext = Ext(self.field);
        for a in a.iter_mut() {
            *a = ext.neg(*a);
        }
        a
    }

    #[inline(always)]
    fn mul(self, a: Self::Element, b: Self::Element) -> Self::Element {
        self.product(a, b, false)
    }

    /// Sums the products `a_m * a_n` for `m <= n` once, doubling one factor where `m < n`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn square(self, a: Self::Element) -> Self::Element {
        let f = self.field;
        let ext = Ext(f);
        let d = [
            ext.double(a[0]),
            ext.double(a[1]),
            ext.double(a[2]),
            ext.double(a[3]),
            ext.double(a[4]),
        ];
        let x3 = fp2::mul_by_nonresidue(f, a[3]);
        let x4 = fp2::mul_by_nonresidue(f, a[4]);
        let x5 = fp2::mul_by_nonresidue(f, a[5]);
        [
            fp2::sum_of_products(
                f,
                [(a[0], a[0], false), (d[1], x5, false), (d[2], x4, false), (a[3], x3, false)],
                [],
            ),
            fp2::sum_of_products(f, [(d[0], a[1], false), (d[2], x5, false), (d[3], x4, false)], []),
            fp2::sum_of_products(
                f,
                [(d[0], a[2], false), (a[1], a[1], false), (d[3], x5, false), (a[4], x4, false)],
                [],
            ),
            fp2::sum_of_products(f, [(d[0], a[3], false), (d[1], a[2], false), (d[4], x5, false)], []),
            fp2::sum_of_products(
                f,
                [(d[0], a[4], false), (d[1], a[3], false), (a[2], a[2], false), (a[5], x5, false)],
                [],
            ),
            fp2::sum_of_products(f, [(d[0], a[5], false), (d[1], a[4], false), (d[2], a[3], false)], []),
        ]
    }

    /// Adds the products, each with one reduction per coordinate and its sign folded into
    /// the sum, so `b` needs no negation.
    #[inline(always)]
    fn sum_of_products(self, terms: &[(Self::Element, Self::Element, bool)]) -> Self::Element {
        let mut sum: Option<Self::Element> = None;
        for (a, b, negate) in terms {
            let product = self.product(*a, *b, *negate);
            sum = Some(match sum {
                Some(sum) => self.add(sum, product),
                None => product,
            });
        }
        sum.unwrap_or_else(|| self.constant(Fp12::ZERO))
    }

    #[inline(always)]
    fn select(self, mut a: Self::Element, b: Self::Element, choice: Choice) -> Self::Element {
        let ext = Ext(self.field);
        for (a, b) in a.iter_mut().zip(b) {
            *a = ext.select(*a, b, choice);
        }
        a
    }

    /// Conjugates each coefficient and multiplies the coefficient of `w^j` by
    /// `FROBENIUS[j]`, one reduction per coordinate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn frobenius(self, a: Self::Element) -> Self::Element {
        let ext = Ext(self.field);
        let mut result = a;
        for (j, (output, a)) in result.iter_mut().zip(a).enumerate() {
            *output = ext.mul(ext.frobenius(a), ext.constant(FROBENIUS[j]));
        }
        result
    }
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        fp::{MODULUS, Single, lanes::Lanes, rns::Rns},
        fp2::tests as fp2,
        fp6::tests::element as fp6_element,
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::Ring;
    use commonware_simd::{Operation, Simd, check_consistent, emulated::EmulatedX86V4C, test_dispatch};

    pub(crate) fn element(u: &mut Unstructured<'_>) -> arbitrary::Result<Fp12> {
        Ok(Fp12::new(fp6_element(u)?, fp6_element(u)?))
    }

    /// Maps a nonzero element into the cyclotomic subgroup: `a^((p^6 - 1)(p^2 + 1))`.
    pub(crate) fn cyclotomic(a: Fp12) -> Fp12 {
        let a = a.conjugate().mul(a.invert());
        a.frobenius().frobenius().mul(a)
    }

    pub(crate) fn to_blst(value: Fp12) -> blst::blst_fp12 {
        let fp6 = |value: Fp6| blst::blst_fp6 {
            fp2: [fp2::to_blst(value.c0), fp2::to_blst(value.c1), fp2::to_blst(value.c2)],
        };
        blst::blst_fp12 {
            fp6: [fp6(value.c0), fp6(value.c1)],
        }
    }

    pub(crate) fn from_blst(value: &blst::blst_fp12) -> Fp12 {
        let fp6 = |value: &blst::blst_fp6| {
            Fp6::new(
                fp2::from_blst(&value.fp2[0]),
                fp2::from_blst(&value.fp2[1]),
                fp2::from_blst(&value.fp2[2]),
            )
        };
        Fp12::new(fp6(&value.fp6[0]), fp6(&value.fp6[1]))
    }

    impl<'a> arbitrary::Arbitrary<'a> for Fp12 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            element(u)
        }
    }

    #[test]
    fn algebra_laws() {
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_field::<Fp12>);
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let a = element(u)?;
            let b = element(u)?;
            let (ba, bb) = (to_blst(a), to_blst(b));
            let mut out = blst::blst_fp12::default();
            // SAFETY: all pointers reference valid field elements.
            unsafe {
                blst::blst_fp12_mul(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.mul(b));
                blst::blst_fp12_sqr(&mut out, &ba);
                assert_eq!(from_blst(&out), a.square());
                blst::blst_fp12_inverse(&mut out, &ba);
                assert_eq!(from_blst(&out), a.invert());
                for n in 1..=3 {
                    blst::blst_fp12_frobenius_map(&mut out, &ba, n);
                    let mut expected = a;
                    for _ in 0..n {
                        expected = expected.frobenius();
                    }
                    assert_eq!(from_blst(&out), expected);
                }
                let mut conjugate = ba;
                blst::blst_fp12_conjugate(&mut conjugate);
                assert_eq!(from_blst(&conjugate), a.conjugate());

                let mut bytes = [0u8; BYTES];
                blst::blst_bendian_from_fp12(bytes.as_mut_ptr(), &ba);
                assert_eq!(bytes, a.to_bytes());
            }
            assert_eq!(Fp12::from_bytes(&a.to_bytes()), Some(a));
            Ok(())
        });
    }

    #[test]
    fn frobenius_is_the_p_power() {
        minifuzz::Builder::default().with_search_limit(8).test(|u| {
            let a = element(u)?;
            assert_eq!(a.frobenius(), a.exp(&MODULUS));
            Ok(())
        });
    }

    #[test]
    fn cyclotomic_squaring_matches_blst() {
        minifuzz::Builder::default().with_search_limit(32).test(|u| {
            let a = cyclotomic(element(u)?);
            let f = Ext12::new(Single);
            let mut actual = [Fp12::ZERO];
            f.store(f.cyclotomic_square(f.constant(a)), &mut actual);
            let mut out = blst::blst_fp12::default();
            // SAFETY: all pointers reference valid field elements.
            unsafe { blst::blst_fp12_cyclotomic_sqr(&mut out, &to_blst(a)) };
            assert_eq!(from_blst(&out), actual[0]);
            assert_eq!(actual[0], a.square());
            Ok(())
        });
    }

    #[test]
    fn encoding_rejects_non_canonical_coordinates() {
        let mut bytes = Fp12::ONE.to_bytes();
        assert_eq!(Fp12::from_bytes(&bytes), Some(Fp12::ONE));
        bytes[5 * FP_BYTES..6 * FP_BYTES].copy_from_slice(&[0xff; FP_BYTES]);
        assert_eq!(Fp12::from_bytes(&bytes), None);
    }

    /// The inputs of [`chain`] for one lane.
    #[derive(Clone, Copy, Debug)]
    struct Inputs {
        a: Fp12,
        b: Fp12,
        /// An element of the cyclotomic subgroup.
        c: Fp12,
        /// The coefficients of `1, w^2, w^3` of a Miller line.
        line: [Fp2; 3],
    }

    /// Number of outputs of [`chain`].
    const OUTPUTS: usize = 7;

    /// Evaluates every operation of the extension context, chained so that each output feeds
    /// later operations.
    fn chain<F: Arithmetic<Scalar = Fp>>(
        f: Ext12<F>,
        a: Sextic<F::Element>,
        b: Sextic<F::Element>,
        c: Sextic<F::Element>,
        line: [Pair<F::Element>; 3],
    ) -> [Sextic<F::Element>; OUTPUTS] {
        let product = f.mul(a, b);
        let square = f.square(product);
        let lined = f.mul_by_line(square, line);
        let cyclotomic = f.cyclotomic_square(f.cyclotomic_square(c));
        let conjugated = f.mul(f.conjugate(lined), cyclotomic);
        let inverse = f.invert(conjugated);
        let mut frobenius = inverse;
        for _ in 0..3 {
            frobenius = f.frobenius(frobenius);
        }
        let mixed = f.mul(f.sub(square, lined), frobenius);
        [product, square, lined, cyclotomic, conjugated, inverse, mixed]
    }

    /// The scalar values of [`chain`].
    fn expected(inputs: Inputs) -> [Fp12; OUTPUTS] {
        let Inputs { a, b, c, line } = inputs;
        let line = Fp12::from_coefficients([line[0], Fp2::ZERO, line[1], line[2], Fp2::ZERO, Fp2::ZERO]);
        let product = a.mul(b);
        let square = product.square();
        let lined = square.mul(line);
        let cyclotomic = c.square().square();
        let conjugated = lined.conjugate().mul(cyclotomic);
        let inverse = conjugated.invert();
        let frobenius = inverse.frobenius().frobenius().frobenius();
        let mixed = square.sub(lined).mul(frobenius);
        [product, square, lined, cyclotomic, conjugated, inverse, mixed]
    }

    /// Runs [`chain`] on the inputs, one per lane, a lane-sized chunk at a time.
    fn run<F: Arithmetic<Scalar = Fp>>(f: F, inputs: &[Inputs]) -> [[Fp12; MAX_LANES]; OUTPUTS] {
        let tower = Ext12::new(f);
        let ext = Ext(f);
        let mut outputs = [[Fp12::ZERO; MAX_LANES]; OUTPUTS];
        for (start, chunk) in (0..).step_by(F::LANES).zip(inputs.chunks(F::LANES)) {
            let mut a = [Fp12::ZERO; MAX_LANES];
            let mut b = [Fp12::ZERO; MAX_LANES];
            let mut c = [Fp12::ONE; MAX_LANES];
            let mut line = [[Fp2::ZERO; MAX_LANES]; 3];
            for (lane, inputs) in chunk.iter().enumerate() {
                a[lane] = inputs.a;
                b[lane] = inputs.b;
                c[lane] = inputs.c;
                for (line, coefficient) in line.iter_mut().zip(inputs.line) {
                    line[lane] = coefficient;
                }
            }
            let line = [
                ext.load(&line[0], Fp2::ZERO),
                ext.load(&line[1], Fp2::ZERO),
                ext.load(&line[2], Fp2::ZERO),
            ];
            let values = chain(
                tower,
                tower.load(&a, Fp12::ZERO),
                tower.load(&b, Fp12::ZERO),
                tower.load(&c, Fp12::ONE),
                line,
            );
            for (output, value) in outputs.iter_mut().zip(values) {
                tower.store(value, &mut output[start..]);
            }
        }
        outputs
    }

    /// Runs [`chain`] on the lane context, one input per lane.
    #[derive(Clone, Copy)]
    struct Chain<'a>(&'a [Inputs]);

    impl<S: Simd> Operation<S> for Chain<'_> {
        type Output = [[Fp12; MAX_LANES]; OUTPUTS];

        fn portable(self, simd: S) -> Self::Output {
            run(Lanes(simd), self.0)
        }
    }

    fn inputs(u: &mut Unstructured<'_>) -> arbitrary::Result<Inputs> {
        Ok(Inputs {
            a: element(u)?,
            b: element(u)?,
            c: cyclotomic(element(u)?),
            line: [fp2::element(u)?, fp2::element(u)?, fp2::element(u)?],
        })
    }

    #[test]
    fn contexts_match_scalar_field() {
        let mut u = Unstructured::new(&[0x5a; 4096]);
        let mut lanes = [inputs(&mut u).unwrap(); MAX_LANES];
        for (i, lane) in lanes.iter_mut().enumerate() {
            let seed = [i as u8 * 31 + 1; 2048];
            *lane = inputs(&mut Unstructured::new(&seed)).unwrap();
        }
        let expected: [[Fp12; OUTPUTS]; MAX_LANES] = lanes.map(expected);
        let check = |actual: [[Fp12; MAX_LANES]; OUTPUTS], count: usize| {
            for (j, actual) in actual.iter().enumerate() {
                for lane in 0..count {
                    assert_eq!(actual[lane], expected[lane][j], "output {j}, lane {lane}");
                }
            }
        };
        check(run(Single, &lanes), MAX_LANES);
        check(test_dispatch(Chain(&lanes)), MAX_LANES);
        check_consistent(|| Chain(&lanes));
        check(
            EmulatedX86V4C.execute(|simd: EmulatedX86V4C| run(Rns(simd), &lanes)),
            MAX_LANES,
        );
    }
}

