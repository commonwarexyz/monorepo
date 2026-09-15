//! The binary field GF(2^16).

use super::gf8::GF8;
use crate::ocelot::kernel::Kernel;
use commonware_math::algebra::{Additive, Field, Multiplicative, Object, Ring};
use core::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// The constant term in the irreducible polynomial `t^2 + t + DELTA`.
pub const DELTA: GF8 = GF8(0x80);

/// An element of GF(2^16), represented as a quadratic extension of [`GF8`].
///
/// The low byte is `a` and the high byte is `b` in `a + b*t`, where
/// `t^2 + t + DELTA = 0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct GF16(pub u16);

impl GF16 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const fn from_parts(a: GF8, b: GF8) -> Self {
        Self((a.0 as u16) | ((b.0 as u16) << 8))
    }

    const fn parts(self) -> (GF8, GF8) {
        (GF8(self.0 as u8), GF8((self.0 >> 8) as u8))
    }

    const fn add_inner(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    #[inline]
    fn mul_inner(self, rhs: Self) -> Self {
        let (a, b) = self.parts();
        let (c, d) = rhs.parts();
        let ac = a.mul_inner(c);
        let bd = b.mul_inner(d);
        Self::from_parts(ac + DELTA.mul_inner(bd), ac + (a + b).mul_inner(c + d))
    }
}

impl From<u16> for GF16 {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<GF16> for u16 {
    fn from(value: GF16) -> Self {
        value.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for GF16 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

impl Object for GF16 {}

impl Add for GF16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_inner(rhs)
    }
}

impl Add<&Self> for GF16 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl AddAssign<&Self> for GF16 {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + rhs;
    }
}

impl Neg for GF16 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Sub for GF16 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add_inner(rhs)
    }
}

impl Sub<&Self> for GF16 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl SubAssign<&Self> for GF16 {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - rhs;
    }
}

impl Additive for GF16 {
    fn zero() -> Self {
        Self::ZERO
    }
}

impl Mul for GF16 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_inner(rhs)
    }
}

impl Mul<&Self> for GF16 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl MulAssign<&Self> for GF16 {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl Multiplicative for GF16 {}

impl Ring for GF16 {
    fn one() -> Self {
        Self::ONE
    }
}

impl Field for GF16 {
    fn inv(&self) -> Self {
        let (a, b) = self.parts();
        let norm = a.mul_inner(a) + a.mul_inner(b) + DELTA.mul_inner(b.mul_inner(b));
        let norm_inv = norm.inv();
        Self::from_parts((a + b).mul_inner(norm_inv), b.mul_inner(norm_inv))
    }
}

/// A constant prepared for lane-wise multiplication by a [`GF16Vec`].
#[derive(Clone, Copy)]
pub struct GF16Constant<K: Kernel> {
    a: K::Constant,
    delta_b: K::Constant,
    a_plus_b: K::Constant,
}

impl<K: Kernel> GF16Constant<K> {
    /// Prepare `c` for repeated vector multiplication using `kernel`.
    #[inline(always)]
    pub fn new(kernel: K, c: GF16) -> Self {
        let (a, b) = c.parts();
        Self {
            a: kernel.splat(a.0),
            delta_b: kernel.splat(DELTA.mul_inner(b).0),
            a_plus_b: kernel.splat((a + b).0),
        }
    }
}

/// A vector of [`Kernel::LANES`] elements of [`GF16`], operated on in parallel.
///
/// This implements [`Ring`], with every operation applied lane-wise.
#[derive(Clone, Copy)]
pub struct GF16Vec<K: Kernel> {
    kernel: K,
    lo: K::Vector,
    hi: K::Vector,
}

impl<K: Kernel> GF16Vec<K> {
    /// Create a vector with `x` in every lane.
    pub fn splat(x: GF16) -> Self {
        Self::load(&vec![x; K::LANES])
    }

    /// Load a vector from exactly [`Kernel::LANES`] elements.
    ///
    /// # Panics
    ///
    /// - `elements.len() != K::LANES`.
    pub fn load(elements: &[GF16]) -> Self {
        let mut lo = Vec::with_capacity(elements.len());
        let mut hi = Vec::with_capacity(elements.len());
        for element in elements {
            let (a, b) = element.parts();
            lo.push(a.0);
            hi.push(b.0);
        }
        Self::load_planes(K::default(), &lo, &hi)
    }

    /// Load field elements from low and high byte planes using `kernel`.
    ///
    /// # Panics
    ///
    /// - `lo.len() != K::LANES`.
    /// - `hi.len() != K::LANES`.
    #[inline(always)]
    pub fn load_planes(kernel: K, lo: &[u8], hi: &[u8]) -> Self {
        Self {
            kernel,
            lo: kernel.load(lo),
            hi: kernel.load(hi),
        }
    }

    /// Load matching non-empty prefixes of the low and high byte planes.
    #[inline(always)]
    pub fn load_partial_planes(kernel: K, lo: &[u8], hi: &[u8]) -> Self {
        assert_eq!(lo.len(), hi.len(), "plane lengths differ");
        Self {
            kernel,
            lo: kernel.load_partial(lo),
            hi: kernel.load_partial(hi),
        }
    }

    /// Store a vector into exactly [`Kernel::LANES`] elements.
    ///
    /// # Panics
    ///
    /// - `out.len() != K::LANES`.
    pub fn store(self, out: &mut [GF16]) {
        assert_eq!(out.len(), K::LANES, "out.len() != LANES");
        let mut lo = vec![0; K::LANES];
        let mut hi = vec![0; K::LANES];
        self.store_planes(&mut lo, &mut hi);
        for (out, (a, b)) in out.iter_mut().zip(lo.into_iter().zip(hi)) {
            *out = GF16::from_parts(GF8(a), GF8(b));
        }
    }

    /// Store field elements into low and high byte planes.
    ///
    /// # Panics
    ///
    /// - `lo.len() != K::LANES`.
    /// - `hi.len() != K::LANES`.
    #[inline(always)]
    pub fn store_planes(self, lo: &mut [u8], hi: &mut [u8]) {
        self.kernel.store(self.lo, lo);
        self.kernel.store(self.hi, hi);
    }

    /// Store matching non-empty prefixes of the low and high byte planes.
    #[inline(always)]
    pub fn store_partial_planes(self, lo: &mut [u8], hi: &mut [u8]) {
        assert_eq!(lo.len(), hi.len(), "plane lengths differ");
        self.kernel.store_partial(self.lo, lo);
        self.kernel.store_partial(self.hi, hi);
    }

    fn to_vec(self) -> Vec<GF16> {
        let mut out = vec![GF16::ZERO; K::LANES];
        self.store(&mut out);
        out
    }

    /// Multiply every lane by a prepared constant.
    #[inline(always)]
    pub fn mul_prepared(self, c: GF16Constant<K>) -> Self {
        let a = self.kernel.gf8_mul_constant(self.lo, c.a);
        let lo = self
            .kernel
            .xor(a, self.kernel.gf8_mul_constant(self.hi, c.delta_b));
        let hi = self.kernel.xor(
            a,
            self.kernel
                .gf8_mul_constant(self.kernel.xor(self.lo, self.hi), c.a_plus_b),
        );
        Self {
            kernel: self.kernel,
            lo,
            hi,
        }
    }
}

impl<K: Kernel> fmt::Debug for GF16Vec<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GF16Vec").field(&self.to_vec()).finish()
    }
}

impl<K: Kernel> PartialEq for GF16Vec<K> {
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl<K: Kernel> Eq for GF16Vec<K> {}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, K: Kernel> arbitrary::Arbitrary<'a> for GF16Vec<K> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut lo = vec![0; K::LANES];
        let mut hi = vec![0; K::LANES];
        u.fill_buffer(&mut lo)?;
        u.fill_buffer(&mut hi)?;
        Ok(Self::load_planes(K::default(), &lo, &hi))
    }
}

impl<K: Kernel> Object for GF16Vec<K> {}

impl<K: Kernel> Add for GF16Vec<K> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            kernel: self.kernel,
            lo: self.kernel.xor(self.lo, rhs.lo),
            hi: self.kernel.xor(self.hi, rhs.hi),
        }
    }
}

impl<K: Kernel> Add<&Self> for GF16Vec<K> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl<K: Kernel> AddAssign<&Self> for GF16Vec<K> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + rhs;
    }
}

impl<K: Kernel> Neg for GF16Vec<K> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl<K: Kernel> Sub for GF16Vec<K> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            kernel: self.kernel,
            lo: self.kernel.xor(self.lo, rhs.lo),
            hi: self.kernel.xor(self.hi, rhs.hi),
        }
    }
}

impl<K: Kernel> Sub<&Self> for GF16Vec<K> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl<K: Kernel> SubAssign<&Self> for GF16Vec<K> {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - rhs;
    }
}

impl<K: Kernel> Additive for GF16Vec<K> {
    fn zero() -> Self {
        Self::splat(GF16::ZERO)
    }
}

impl<K: Kernel> Mul for GF16Vec<K> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        let kernel = self.kernel;
        let ac = kernel.gf8_mul_vec(self.lo, rhs.lo);
        let bd = kernel.gf8_mul_vec(self.hi, rhs.hi);
        let sums = kernel.gf8_mul_vec(kernel.xor(self.lo, self.hi), kernel.xor(rhs.lo, rhs.hi));
        Self {
            kernel,
            lo: kernel.xor(ac, kernel.gf8_mul_constant(bd, kernel.splat(DELTA.0))),
            hi: kernel.xor(ac, sums),
        }
    }
}

impl<K: Kernel> Mul<&Self> for GF16Vec<K> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl<K: Kernel> Mul<GF16> for GF16Vec<K> {
    type Output = Self;

    fn mul(self, rhs: GF16) -> Self::Output {
        self.mul_prepared(GF16Constant::new(self.kernel, rhs))
    }
}

impl<K: Kernel> MulAssign<&Self> for GF16Vec<K> {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl<K: Kernel> Multiplicative for GF16Vec<K> {}

impl<K: Kernel> Ring for GF16Vec<K> {
    fn one() -> Self {
        Self::splat(GF16::ONE)
    }
}

/// Fuzz plans for GF(2^16) arithmetic.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::ocelot::kernel::portable::Portable;
    use arbitrary::{Arbitrary, Unstructured};

    /// Property checks for GF(2^16) and its portable packed representation.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Check the scalar field laws.
        Field,
        /// Check portable packed-vector operations against scalar operations.
        Vector,
    }

    impl Plan {
        /// Run this property check using bytes from `u`.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Field => commonware_math::algebra::test_suites::fuzz_field::<GF16>(u),
                Self::Vector => fuzz_vec(u),
            }
        }
    }

    fn fuzz_vec(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        commonware_math::algebra::test_suites::fuzz_ring::<GF16Vec<Portable>>(u)?;

        let a: GF16Vec<Portable> = u.arbitrary()?;
        let b: GF16Vec<Portable> = u.arbitrary()?;
        let c: GF16 = u.arbitrary()?;
        let (mut a_elements, mut b_elements) = (
            vec![GF16::ZERO; Portable::LANES],
            vec![GF16::ZERO; Portable::LANES],
        );
        a.store(&mut a_elements);
        b.store(&mut b_elements);

        let product = a_elements
            .iter()
            .zip(&b_elements)
            .map(|(&a, &b)| a * b)
            .collect::<Vec<_>>();
        let constant_product = a_elements.iter().map(|&a| a * c).collect::<Vec<_>>();
        assert_eq!(a * b, GF16Vec::load(&product));
        assert_eq!(a * c, GF16Vec::load(&constant_product));
        Ok(())
    }

    #[test]
    fn minifuzz_field() {
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(100)
            .test(|u| Plan::Field.run(u));
    }

    #[test]
    fn minifuzz_vec() {
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(100)
            .test(|u| Plan::Vector.run(u));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_polynomial_is_irreducible() {
        let mut trace = GF8(0);
        let mut conjugate = DELTA;
        for _ in 0..8 {
            trace += &conjugate;
            conjugate = conjugate * conjugate;
        }
        assert_eq!(trace, GF8(1));
        assert!((0..=u8::MAX).all(|x| {
            let x = GF8(x);
            x.mul_inner(x) + x != DELTA
        }));
    }
}
