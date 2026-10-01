//! The binary field GF(2^8).

use crate::ocelot::kernel::Kernel;
use commonware_math::algebra::{Additive, Field, Multiplicative, Object, Ring};
use core::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// An element of GF(2^8), represented in the AES polynomial basis.
///
/// This implements [`Field`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct GF8(pub u8);

impl GF8 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const fn slice_as_bytes(elements: &[Self]) -> &[u8] {
        // SAFETY: GF8 is repr(transparent) over u8, so the layouts match.
        unsafe { core::slice::from_raw_parts(elements.as_ptr().cast(), elements.len()) }
    }

    const fn slice_as_bytes_mut(elements: &mut [Self]) -> &mut [u8] {
        // SAFETY: GF8 is repr(transparent) over u8, so the layouts match, and
        // every byte is a valid GF8.
        unsafe { core::slice::from_raw_parts_mut(elements.as_mut_ptr().cast(), elements.len()) }
    }

    const fn add_inner(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    pub const fn mul_inner(self, rhs: Self) -> Self {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut product = 0;

        let mut i = 0;
        while i < u8::BITS {
            if b & 1 != 0 {
                product ^= a;
            }

            let high_bit = a & 0x80;
            a <<= 1;
            if high_bit != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
            i += 1;
        }

        Self(product)
    }
}

impl From<u8> for GF8 {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<GF8> for u8 {
    fn from(value: GF8) -> Self {
        value.0
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for GF8 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

impl Object for GF8 {}

impl Add for GF8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_inner(rhs)
    }
}

impl Add<&Self> for GF8 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl AddAssign<&Self> for GF8 {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + rhs;
    }
}

impl Neg for GF8 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Sub for GF8 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add_inner(rhs)
    }
}

impl Sub<&Self> for GF8 {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl SubAssign<&Self> for GF8 {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - rhs;
    }
}

impl Additive for GF8 {
    fn zero() -> Self {
        Self::ZERO
    }
}

impl Mul for GF8 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_inner(rhs)
    }
}

impl Mul<&Self> for GF8 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl MulAssign<&Self> for GF8 {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl Multiplicative for GF8 {}

impl Ring for GF8 {
    fn one() -> Self {
        Self::ONE
    }
}

impl Field for GF8 {
    fn inv(&self) -> Self {
        self.exp(&[254])
    }
}

/// A vector of [`Kernel::LANES`] elements of [`GF8`], operated on in parallel.
///
/// This implements [`Ring`], with every operation applied lane-wise. We stop
/// short of implementing [`Field`], because this structure does not satisfy
/// the properties you would expect. In particular, something like `x 0 0 ...`
/// has no inverse.
#[derive(Clone, Copy)]
pub struct GF8Vec<K: Kernel> {
    kernel: K,
    data: K::Vector,
}

impl<K: Kernel> GF8Vec<K> {
    /// Create a vector with `x` in every lane.
    pub fn splat(x: GF8) -> Self {
        Self::load(&vec![x; K::LANES])
    }

    /// Load a vector from exactly [`Kernel::LANES`] elements.
    ///
    /// # Panics
    ///
    /// - `elements.len() != K::LANES`.
    pub fn load(elements: &[GF8]) -> Self {
        Self::load_bytes(K::default(), GF8::slice_as_bytes(elements))
    }

    /// Load field elements from their byte representations using `kernel`.
    ///
    /// # Panics
    ///
    /// - `bytes.len() != K::LANES`.
    pub fn load_bytes(kernel: K, bytes: &[u8]) -> Self {
        Self {
            kernel,
            data: kernel.load(bytes),
        }
    }

    /// Store a vector into exactly [`Kernel::LANES`] elements.
    ///
    /// # Panics
    ///
    /// - `out.len() != K::LANES`.
    pub fn store(self, out: &mut [GF8]) {
        self.store_bytes(GF8::slice_as_bytes_mut(out));
    }

    /// Store field elements as their byte representations.
    ///
    /// # Panics
    ///
    /// - `out.len() != K::LANES`.
    pub fn store_bytes(self, out: &mut [u8]) {
        self.kernel.store(self.data, out);
    }

    fn to_vec(self) -> Vec<GF8> {
        let mut out = vec![GF8::ZERO; K::LANES];
        self.store(&mut out);
        out
    }

    /// Multiply every lane by the same constant.
    pub fn mul_constant(self, c: GF8) -> Self {
        Self {
            kernel: self.kernel,
            data: self
                .kernel
                .gf8_mul_constant(self.data, self.kernel.splat(c.0)),
        }
    }
}

impl<K: Kernel> fmt::Debug for GF8Vec<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GF8Vec").field(&self.to_vec()).finish()
    }
}

impl<K: Kernel> PartialEq for GF8Vec<K> {
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl<K: Kernel> Eq for GF8Vec<K> {}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, K: Kernel> arbitrary::Arbitrary<'a> for GF8Vec<K> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut elements = vec![GF8::ZERO; K::LANES];
        u.fill_buffer(GF8::slice_as_bytes_mut(&mut elements))?;
        Ok(Self::load(&elements))
    }
}

impl<K: Kernel> Object for GF8Vec<K> {}

impl<K: Kernel> Add for GF8Vec<K> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            kernel: self.kernel,
            data: self.kernel.xor(self.data, rhs.data),
        }
    }
}

impl<K: Kernel> Add<&Self> for GF8Vec<K> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl<K: Kernel> AddAssign<&Self> for GF8Vec<K> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + rhs;
    }
}

impl<K: Kernel> Neg for GF8Vec<K> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl<K: Kernel> Sub for GF8Vec<K> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            kernel: self.kernel,
            data: self.kernel.xor(self.data, rhs.data),
        }
    }
}

impl<K: Kernel> Sub<&Self> for GF8Vec<K> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl<K: Kernel> SubAssign<&Self> for GF8Vec<K> {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - rhs;
    }
}

impl<K: Kernel> Additive for GF8Vec<K> {
    fn zero() -> Self {
        Self::splat(GF8::ZERO)
    }
}

impl<K: Kernel> Mul for GF8Vec<K> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            kernel: self.kernel,
            data: self.kernel.gf8_mul_vec(self.data, rhs.data),
        }
    }
}

impl<K: Kernel> Mul<&Self> for GF8Vec<K> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl<K: Kernel> Mul<GF8> for GF8Vec<K> {
    type Output = Self;

    fn mul(self, rhs: GF8) -> Self::Output {
        self.mul_constant(rhs)
    }
}

impl<K: Kernel> MulAssign<&Self> for GF8Vec<K> {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl<K: Kernel> Multiplicative for GF8Vec<K> {}

impl<K: Kernel> Ring for GF8Vec<K> {
    fn one() -> Self {
        Self::splat(GF8::ONE)
    }
}

/// Fuzz plans for GF(2^8) arithmetic.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::ocelot::kernel::portable::Portable;
    use arbitrary::{Arbitrary, Unstructured};

    /// Property checks for GF(2^8) and its portable packed representation.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Check the scalar field laws.
        Field,
        /// Check the portable packed-vector ring laws.
        VectorRing,
    }

    impl Plan {
        /// Run this property check using bytes from `u`.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Field => commonware_math::algebra::test_suites::fuzz_field::<GF8>(u),
                Self::VectorRing => {
                    commonware_math::algebra::test_suites::fuzz_ring::<GF8Vec<Portable>>(u)
                }
            }
        }
    }

    #[test]
    fn minifuzz_field() {
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(100)
            .test(|u| Plan::Field.run(u));
    }

    #[test]
    fn minifuzz_vec_ring() {
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(100)
            .test(|u| Plan::VectorRing.run(u));
    }
}
