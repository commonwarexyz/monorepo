//! The base field of BLS12-381.
//!
//! [`Fp`] holds one canonical element as six 64-bit words in Montgomery form, and every
//! operation is a `const fn`, so curve constants can be derived at compile time. This is the
//! storage representation, the arithmetic of the portable path, and the reference against which
//! the vectorized representations are tested. [`lanes::FpVec`] carries one element per vector
//! lane in radix `2^52` for backends with 52-bit multipliers, and `rns` spreads one element
//! across the lanes of two registers as residues for x86v4c.

pub mod lanes;
pub(crate) mod rns;

use crate::montgomery;
use commonware_math::algebra::{Additive, Ring};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Number of 64-bit words in a field element.
pub const WORDS: usize = 6;

/// Number of bytes in the canonical big-endian encoding.
pub const BYTES: usize = 48;

/// The modulus `p`, little-endian.
pub const MODULUS: [u64; WORDS] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// `-p^(-1) mod 2^64`, the Montgomery reduction constant.
const INV: u64 = montgomery::negated_inverse(MODULUS[0]);

/// `R mod p` for `R = 2^384`: the Montgomery form of one.
const R: [u64; WORDS] = montgomery::power_of_two(384, &MODULUS);

/// `R^2 mod p`, used to enter Montgomery form.
const R2: [u64; WORDS] = montgomery::power_of_two(768, &MODULUS);

/// `(p + 1) / 4`. Since `p = 3 mod 4`, raising a square to this power yields a square root.
pub(crate) const SQRT_EXPONENT: [u64; WORDS] = {
    // (p + 1) / 4 = (p >> 2) + 1 because p = 3 mod 4.
    let mut exponent = [0; WORDS];
    let mut i = 0;
    while i < WORDS {
        exponent[i] = MODULUS[i] >> 2;
        if i + 1 < WORDS {
            exponent[i] |= MODULUS[i + 1] << 62;
        }
        i += 1;
    }
    exponent[0] += 1;
    exponent
};

/// Computes `2^k mod p`.
pub(crate) const fn power_of_two(k: u32) -> [u64; WORDS] {
    montgomery::power_of_two(k, &MODULUS)
}

/// An element of the base field `GF(p)`.
///
/// The words hold the canonical Montgomery representative `a * R mod p`, little-endian.
#[derive(Clone, Copy, Debug)]
pub struct Fp(pub(crate) [u64; WORDS]);

impl Fp {
    /// The additive identity.
    pub const ZERO: Self = Self([0; WORDS]);

    /// The multiplicative identity.
    pub const ONE: Self = Self(R);

    /// Converts a canonical little-endian integer into the field.
    ///
    /// Returns `None` when the integer is not below the modulus.
    pub const fn from_words(words: [u64; WORDS]) -> Option<Self> {
        if !montgomery::is_below(&words, &MODULUS) {
            return None;
        }
        Some(Self(montgomery::mul(&words, &R2, &MODULUS, INV)))
    }

    /// Reduces a small integer into the field.
    pub const fn from_u64(value: u64) -> Self {
        Self(montgomery::mul(&[value, 0, 0, 0, 0, 0], &R2, &MODULUS, INV))
    }

    /// Returns the canonical integer as little-endian words.
    pub const fn to_words(self) -> [u64; WORDS] {
        montgomery::mul(&self.0, &[1, 0, 0, 0, 0, 0], &MODULUS, INV)
    }

    /// Parses the canonical big-endian encoding.
    ///
    /// Returns `None` when the encoded integer is not below the modulus.
    pub fn from_bytes(bytes: &[u8; BYTES]) -> Option<Self> {
        let mut words = [0; WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter().rev()) {
            *word = u64::from_be_bytes(*chunk);
        }
        Self::from_words(words)
    }

    /// Returns the canonical big-endian encoding.
    pub fn to_bytes(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        let words = self.to_words();
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words.iter().rev()) {
            *chunk = word.to_be_bytes();
        }
        bytes
    }

    /// Returns `self + rhs`.
    pub const fn add(self, rhs: Self) -> Self {
        Self(montgomery::add(&self.0, &rhs.0, &MODULUS))
    }

    /// Returns `self - rhs`.
    pub const fn sub(self, rhs: Self) -> Self {
        self.add(rhs.neg())
    }

    /// Returns `-self`.
    pub const fn neg(self) -> Self {
        Self(montgomery::neg(&self.0, &MODULUS))
    }

    /// Returns `2 * self`.
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Returns `self * rhs`.
    pub const fn mul(self, rhs: Self) -> Self {
        Self(montgomery::mul(&self.0, &rhs.0, &MODULUS, INV))
    }

    /// Returns `self * self`.
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Returns `self^exponent` for a public little-endian exponent.
    ///
    /// Variable-time in the exponent only.
    pub const fn pow(self, exponent: &[u64; WORDS]) -> Self {
        let mut result = Self::ONE;
        let mut i = WORDS;
        while i > 0 {
            i -= 1;
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                result = result.square();
                if (exponent[i] >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Returns the multiplicative inverse, or zero for zero.
    pub const fn invert(self) -> Self {
        // Fermat: a^(p - 2). The modulus is odd, so the low word does not borrow.
        let mut exponent = MODULUS;
        exponent[0] -= 2;
        self.pow(&exponent)
    }

    /// Returns a square root when one exists.
    ///
    /// Since `p = 3 mod 4`, the candidate is `self^((p + 1) / 4)`; it is a root exactly when
    /// its square equals `self`. The chosen root is not canonicalized.
    pub fn sqrt(self) -> Option<Self> {
        let root = self.pow(&SQRT_EXPONENT);
        bool::from(root.square().ct_eq(&self)).then_some(root)
    }

    /// Returns whether the element is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Returns whether the canonical integer is odd.
    pub fn is_odd(&self) -> Choice {
        Choice::from((self.to_words()[0] & 1) as u8)
    }

    /// Returns whether the canonical integer exceeds `(p - 1) / 2`.
    ///
    /// This is the sign bit used by the compressed point encoding.
    pub fn is_lexicographically_largest(&self) -> Choice {
        let words = self.to_words();
        // Compare 2 * value against p: it exceeds p exactly when value > (p - 1) / 2.
        let mut borrow = 0u64;
        let mut carry = 0u64;
        for i in 0..WORDS {
            let doubled = (words[i] << 1) | carry;
            carry = words[i] >> 63;
            let wide = (doubled as u128)
                .wrapping_sub(MODULUS[i] as u128)
                .wrapping_sub(borrow as u128);
            borrow = (wide >> 127) as u64;
        }
        Choice::from(((carry | (1 - borrow)) & 1) as u8)
    }
}

/// Field arithmetic over some representation of field elements.
///
/// Implementations are contexts (a backend token, for vectorized representations) rather than
/// element types, so curve formulas written once against this trait run on the scalar field,
/// on one element per lane, on specialized representations chosen per backend, and on
/// extension fields built over any of those. Bounds on lazily reduced representations follow
/// the rules of the implementing module.
pub(crate) trait Arithmetic: Copy {
    /// One element, or one element per lane.
    type Element: Copy;

    /// The scalar form of one lane's element.
    type Scalar: commonware_math::algebra::Field + Copy;

    /// Number of independent elements in one [`Self::Element`]. At most [`MAX_LANES`].
    const LANES: usize;

    /// The in-memory form of one lane's element, in this context's own representation, so
    /// tables can be kept without converting at every access. The default value is zero.
    type Stored: Copy + Default + 'static;

    /// Loads up to [`Self::LANES`] stored elements, one per lane; remaining lanes are zero.
    fn gather<'a>(self, lanes: impl IntoIterator<Item = &'a Self::Stored>) -> Self::Element;

    /// Stores each lane into the corresponding output, dropping lanes beyond the outputs.
    fn scatter<'a>(self, value: Self::Element, lanes: impl IntoIterator<Item = &'a mut Self::Stored>);

    /// Loads up to [`Self::LANES`] elements, filling the remaining lanes with `fill`.
    fn load(self, elements: &[Self::Scalar], fill: Self::Scalar) -> Self::Element;

    /// Stores the canonical value of each lane into `outputs`, dropping lanes beyond its length.
    fn store(self, value: Self::Element, outputs: &mut [Self::Scalar]);

    /// Returns every element set to `value`.
    fn constant(self, value: Self::Scalar) -> Self::Element;

    /// Returns `a + b`.
    fn add(self, a: Self::Element, b: Self::Element) -> Self::Element;

    /// Returns `a - b`.
    fn sub(self, a: Self::Element, b: Self::Element) -> Self::Element;

    /// Returns `-a`.
    fn neg(self, a: Self::Element) -> Self::Element;

    /// Returns `a * b`.
    fn mul(self, a: Self::Element, b: Self::Element) -> Self::Element;

    /// Returns `2 * a`.
    #[inline(always)]
    fn double(self, a: Self::Element) -> Self::Element {
        self.add(a, a)
    }

    /// Returns `a * a`.
    #[inline(always)]
    fn square(self, a: Self::Element) -> Self::Element {
        self.mul(a, a)
    }

    /// Returns the sum of `a * b` over the terms `(a, b, negate)`, subtracting the product
    /// where `negate` is set.
    ///
    /// Lazily reduced representations evaluate this with one reduction, so extension field
    /// arithmetic keeps its outputs as small as products; their modules bound the number of
    /// terms and the result. The default multiplies each term separately, negating `b` for
    /// subtracted terms, and adds the products.
    #[inline(always)]
    fn sum_of_products(self, terms: &[(Self::Element, Self::Element, bool)]) -> Self::Element {
        let Some(((a, b, negate), rest)) = terms.split_first() else {
            return self.constant(Self::Scalar::zero());
        };
        let b = if *negate { self.neg(*b) } else { *b };
        let mut sum = self.mul(*a, b);
        for (a, b, negate) in rest {
            let b = if *negate { self.neg(*b) } else { *b };
            sum = self.add(sum, self.mul(*a, b));
        }
        sum
    }

    /// Returns `a * b + c * d`, with the bound of a two-term [`Self::sum_of_products`].
    #[inline(always)]
    fn mul_add(
        self,
        a: Self::Element,
        b: Self::Element,
        c: Self::Element,
        d: Self::Element,
    ) -> Self::Element {
        self.sum_of_products(&[(a, b, false), (c, d, false)])
    }

    /// Returns `a * b - c * d`, with the bound of a two-term [`Self::sum_of_products`].
    #[inline(always)]
    fn mul_sub(
        self,
        a: Self::Element,
        b: Self::Element,
        c: Self::Element,
        d: Self::Element,
    ) -> Self::Element {
        self.sum_of_products(&[(a, b, false), (c, d, true)])
    }

    /// Returns `b` where `choice` is set and `a` elsewhere.
    fn select(self, a: Self::Element, b: Self::Element, choice: Choice) -> Self::Element;

    /// Returns `a^p`, the Frobenius map, which is the identity on the base field.
    #[inline(always)]
    fn frobenius(self, a: Self::Element) -> Self::Element {
        a
    }

    /// Returns `a^exponent` for a public little-endian exponent.
    ///
    /// Variable-time in the exponent only.
    #[inline(always)]
    fn pow(self, a: Self::Element, exponent: &[u64]) -> Self::Element {
        let mut result = self.constant(Self::Scalar::one());
        for word in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = self.square(result);
                if (word >> bit) & 1 == 1 {
                    result = self.mul(result, a);
                }
            }
        }
        result
    }
}

/// The scalar context: one canonical element at a time.
///
/// Serves as the reference for the vectorized contexts.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Single;

#[cfg(test)]
impl Arithmetic for Single {
    type Element = Fp;

    type Scalar = Fp;

    const LANES: usize = 1;

    type Stored = Fp;

    #[inline(always)]
    fn gather<'a>(self, lanes: impl IntoIterator<Item = &'a Fp>) -> Fp {
        lanes.into_iter().next().copied().unwrap_or(Fp::ZERO)
    }

    #[inline(always)]
    fn scatter<'a>(self, value: Fp, lanes: impl IntoIterator<Item = &'a mut Fp>) {
        if let Some(lane) = lanes.into_iter().next() {
            *lane = value;
        }
    }

    #[inline(always)]
    fn load(self, elements: &[Fp], fill: Fp) -> Fp {
        elements.first().copied().unwrap_or(fill)
    }

    #[inline(always)]
    fn store(self, value: Fp, outputs: &mut [Fp]) {
        if let Some(output) = outputs.first_mut() {
            *output = value;
        }
    }

    #[inline(always)]
    fn constant(self, value: Fp) -> Fp {
        value
    }

    #[inline(always)]
    fn add(self, a: Fp, b: Fp) -> Fp {
        a.add(b)
    }

    #[inline(always)]
    fn sub(self, a: Fp, b: Fp) -> Fp {
        a.sub(b)
    }

    #[inline(always)]
    fn neg(self, a: Fp) -> Fp {
        a.neg()
    }

    #[inline(always)]
    fn mul(self, a: Fp, b: Fp) -> Fp {
        a.mul(b)
    }

    #[inline(always)]
    fn select(self, a: Fp, b: Fp, choice: Choice) -> Fp {
        Fp::conditional_select(&a, &b, choice)
    }
}

crate::algebra::field_traits!(Fp);

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(core::array::from_fn(|i| {
            u64::conditional_select(&a.0[i], &b.0[i], choice)
        }))
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Fp {}

impl Default for Fp {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use std::vec::Vec;

    /// Draws a canonical field element, biased toward values near the modulus.
    pub(crate) fn canonical(u: &mut Unstructured<'_>) -> arbitrary::Result<Fp> {
        let mut words: [u64; WORDS] = u.arbitrary()?;
        words[WORDS - 1] &= (1 << 61) - 1;
        Ok(Fp::from_words(words).unwrap_or(Fp::ZERO))
    }

    /// Draws terms for [`sum_of_shapes`]: factor shapes and signs, at most `max` of them.
    pub(crate) fn shaped_terms(
        u: &mut Unstructured<'_>,
        max: usize,
    ) -> arbitrary::Result<Vec<(u8, u8, bool)>> {
        let count = if u.ratio(1, 8)? {
            max
        } else {
            u.int_in_range(0..=max)?
        };
        (0..count).map(|_| u.arbitrary()).collect()
    }

    /// Builds a factor from two loaded elements: one of them, their difference, one doubled
    /// `doublings` times, or a negated product.
    fn shape<F: Arithmetic>(
        f: F,
        kind: u8,
        doublings: usize,
        x: F::Element,
        y: F::Element,
    ) -> F::Element {
        match kind % 4 {
            0 => x,
            1 => f.sub(x, y),
            2 => {
                let mut value = x;
                for _ in 0..doublings {
                    value = f.double(value);
                }
                value
            }
            _ => f.sum_of_products(&[(x, y, true)]),
        }
    }

    /// Evaluates a sum of products of shaped factors over `values`, two loaded elements per
    /// term, and then uses the sum as a subtrahend and a multiplicand.
    ///
    /// Doubling a loaded element `doublings` times must stay within the context's bounds.
    pub(crate) fn sum_of_shapes<F: Arithmetic>(
        f: F,
        doublings: usize,
        terms: &[(u8, u8, bool)],
        values: &[F::Element],
    ) -> F::Element {
        let factors: Vec<_> = terms
            .iter()
            .enumerate()
            .map(|(i, (a, b, negate))| {
                let (x, y) = (values[2 * i], values[2 * i + 1]);
                (
                    shape(f, *a, doublings, x, y),
                    shape(f, *b, doublings, y, x),
                    *negate,
                )
            })
            .collect();
        let sum = f.sum_of_products(&factors);
        f.mul(f.sub(values[0], sum), sum)
    }

    pub(crate) fn to_blst(value: Fp) -> blst::blst_fp {
        let mut out = blst::blst_fp::default();
        let bytes = value.to_bytes();
        // SAFETY: both pointers reference valid 48-byte buffers.
        unsafe { blst::blst_fp_from_bendian(&mut out, bytes.as_ptr()) };
        out
    }

    pub(crate) fn from_blst(value: &blst::blst_fp) -> Fp {
        let mut bytes = [0u8; BYTES];
        // SAFETY: both pointers reference valid 48-byte buffers.
        unsafe { blst::blst_bendian_from_fp(bytes.as_mut_ptr(), value) };
        Fp::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn encoding_round_trip() {
        assert_eq!(Fp::from_bytes(&Fp::ONE.to_bytes()), Some(Fp::ONE));
        assert_eq!(Fp::ONE.to_words(), [1, 0, 0, 0, 0, 0]);
        assert!(Fp::from_words(MODULUS).is_none());
        let mut largest = MODULUS;
        largest[0] -= 1;
        assert_eq!(Fp::from_words(largest).unwrap().to_words(), largest);
        minifuzz::test(|u| {
            let a = canonical(u)?;
            assert_eq!(Fp::from_bytes(&a.to_bytes()), Some(a));
            assert_eq!(from_blst(&to_blst(a)), a);
            Ok(())
        });
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let a = canonical(u)?;
            let b = canonical(u)?;
            let (ba, bb) = (to_blst(a), to_blst(b));
            let mut out = blst::blst_fp::default();
            // SAFETY: all pointers reference valid field elements.
            unsafe {
                blst::blst_fp_add(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.add(b));
                blst::blst_fp_sub(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.sub(b));
                blst::blst_fp_mul(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.mul(b));
                blst::blst_fp_sqr(&mut out, &ba);
                assert_eq!(from_blst(&out), a.square());
                blst::blst_fp_cneg(&mut out, &ba, true);
                assert_eq!(from_blst(&out), a.neg());
                blst::blst_fp_inverse(&mut out, &ba);
                assert_eq!(from_blst(&out), a.invert());
            }
            Ok(())
        });
    }

    #[test]
    fn sqrt_and_sign() {
        minifuzz::test(|u| {
            let a = canonical(u)?;
            let square = a.square();
            let root = square.sqrt().expect("squares have roots");
            assert!(root == a || root == a.neg());
            if bool::from(!a.is_zero()) {
                assert_ne!(
                    bool::from(a.is_lexicographically_largest()),
                    bool::from(a.neg().is_lexicographically_largest())
                );
                assert_ne!(bool::from(a.is_odd()), bool::from(a.neg().is_odd()));
            }
            let mut blst_root = blst::blst_fp::default();
            // SAFETY: valid pointers to field elements.
            let exists = unsafe { blst::blst_fp_sqrt(&mut blst_root, &to_blst(a)) };
            assert_eq!(exists, a.sqrt().is_some());
            Ok(())
        });
    }

    impl<'a> arbitrary::Arbitrary<'a> for Fp {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            canonical(u)
        }
    }

    #[test]
    fn algebra_laws() {
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_field::<Fp>);
    }

    #[test]
    fn identities() {
        assert_eq!(Fp::ZERO.neg(), Fp::ZERO);
        assert_eq!(Fp::ZERO.invert(), Fp::ZERO);
        assert_eq!(Fp::ONE.invert(), Fp::ONE);
        assert_eq!(Fp::from_u64(7).mul(Fp::from_u64(7).invert()), Fp::ONE);
        assert_eq!(Fp::from_u64(3).add(Fp::from_u64(4)), Fp::from_u64(7));
    }
}
