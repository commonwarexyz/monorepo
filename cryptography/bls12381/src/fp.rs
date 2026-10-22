//! The base field of BLS12-381.
//!
//! [`Fp`] holds one canonical element as six 64-bit words in Montgomery form, and every
//! operation is a `const fn`, so curve constants can be derived at compile time. This is the
//! storage representation, the arithmetic of the portable path, and the reference against which
//! the vectorized representations are tested. [`lanes::FpVec`] carries one element per vector
//! lane in radix `2^52` for backends with 52-bit multipliers.

pub mod lanes;

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
const INV: u64 = negated_inverse(MODULUS[0]);

/// `R mod p` for `R = 2^384`: the Montgomery form of one.
const R: [u64; WORDS] = power_of_two(384);

/// `R^2 mod p`, used to enter Montgomery form.
const R2: [u64; WORDS] = power_of_two(768);

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

/// Computes `-x^(-1) mod 2^64` for odd `x` by Newton iteration.
pub(crate) const fn negated_inverse(x: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// Computes `2^k mod p` by repeated doubling.
pub(crate) const fn power_of_two(k: u32) -> [u64; WORDS] {
    let mut value = [1, 0, 0, 0, 0, 0];
    let mut i = 0;
    while i < k {
        value = add_words(value, value);
        i += 1;
    }
    value
}

/// Returns `a + b mod p` for canonical inputs.
const fn add_words(a: [u64; WORDS], b: [u64; WORDS]) -> [u64; WORDS] {
    let mut sum = [0; WORDS];
    let mut carry = 0;
    let mut i = 0;
    while i < WORDS {
        let wide = a[i] as u128 + b[i] as u128 + carry as u128;
        sum[i] = wide as u64;
        carry = (wide >> 64) as u64;
        i += 1;
    }
    subtract_modulus(sum, carry)
}

/// Returns `value - p` when `value >= p`, where `carry` extends `value` with a seventh word.
const fn subtract_modulus(value: [u64; WORDS], carry: u64) -> [u64; WORDS] {
    let mut reduced = [0; WORDS];
    let mut borrow = 0;
    let mut i = 0;
    while i < WORDS {
        let wide = (value[i] as u128)
            .wrapping_sub(MODULUS[i] as u128)
            .wrapping_sub(borrow as u128);
        reduced[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        i += 1;
    }
    // Keep the subtraction exactly when it did not underflow the extended value.
    let underflow = carry.wrapping_sub(borrow) >> 63;
    let mask = underflow.wrapping_neg();
    let mut i = 0;
    while i < WORDS {
        reduced[i] = (reduced[i] & !mask) | (value[i] & mask);
        i += 1;
    }
    reduced
}

/// Returns `a * b / R mod p` for canonical inputs (CIOS Montgomery multiplication).
const fn montgomery_mul(a: [u64; WORDS], b: [u64; WORDS]) -> [u64; WORDS] {
    let mut t = [0u64; WORDS + 2];
    let mut i = 0;
    while i < WORDS {
        let mut carry = 0u64;
        let mut j = 0;
        while j < WORDS {
            let wide = t[j] as u128 + a[j] as u128 * b[i] as u128 + carry as u128;
            t[j] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        let wide = t[WORDS] as u128 + carry as u128;
        t[WORDS] = wide as u64;
        t[WORDS + 1] = (wide >> 64) as u64;

        let m = t[0].wrapping_mul(INV);
        let wide = t[0] as u128 + m as u128 * MODULUS[0] as u128;
        let mut carry = (wide >> 64) as u64;
        let mut j = 1;
        while j < WORDS {
            let wide = t[j] as u128 + m as u128 * MODULUS[j] as u128 + carry as u128;
            t[j - 1] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        let wide = t[WORDS] as u128 + carry as u128;
        t[WORDS - 1] = wide as u64;
        t[WORDS] = t[WORDS + 1] + (wide >> 64) as u64;
        i += 1;
    }
    let [w0, w1, w2, w3, w4, w5, carry, _] = t;
    subtract_modulus([w0, w1, w2, w3, w4, w5], carry)
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
        let mut borrow = 0;
        let mut i = 0;
        while i < WORDS {
            let wide = (words[i] as u128)
                .wrapping_sub(MODULUS[i] as u128)
                .wrapping_sub(borrow as u128);
            borrow = (wide >> 127) as u64;
            i += 1;
        }
        if borrow == 0 {
            return None;
        }
        Some(Self(montgomery_mul(words, R2)))
    }

    /// Reduces a small integer into the field.
    pub const fn from_u64(value: u64) -> Self {
        Self(montgomery_mul([value, 0, 0, 0, 0, 0], R2))
    }

    /// Returns the canonical integer as little-endian words.
    pub const fn to_words(self) -> [u64; WORDS] {
        montgomery_mul(self.0, [1, 0, 0, 0, 0, 0])
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
        Self(add_words(self.0, rhs.0))
    }

    /// Returns `self - rhs`.
    pub const fn sub(self, rhs: Self) -> Self {
        self.add(rhs.neg())
    }

    /// Returns `-self`.
    pub const fn neg(self) -> Self {
        let mut value = [0; WORDS];
        let mut borrow = 0;
        let mut i = 0;
        while i < WORDS {
            let wide = (MODULUS[i] as u128)
                .wrapping_sub(self.0[i] as u128)
                .wrapping_sub(borrow as u128);
            value[i] = wide as u64;
            borrow = (wide >> 127) as u64;
            i += 1;
        }
        // The subtraction yields p for a zero input, which maps back to zero.
        let nonzero = self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4] | self.0[5];
        let mask = ((nonzero | nonzero.wrapping_neg()) >> 63).wrapping_neg();
        let mut i = 0;
        while i < WORDS {
            value[i] &= mask;
            i += 1;
        }
        Self(value)
    }

    /// Returns `2 * self`.
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Returns `self * rhs`.
    pub const fn mul(self, rhs: Self) -> Self {
        Self(montgomery_mul(self.0, rhs.0))
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

/// The scalar, canonical form of a field element: the coordinate type of points over it.
pub(crate) trait Coordinate: Copy + core::fmt::Debug {
    /// The additive identity.
    const ZERO: Self;

    /// The multiplicative identity.
    const ONE: Self;
}

impl Coordinate for Fp {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
}

/// Field arithmetic over some representation of field elements.
///
/// Implementations are contexts (a backend token, for vectorized representations) rather than
/// element types, so curve formulas written once against this trait run on the scalar field,
/// on one element per lane, on specialized representations chosen per backend, and on
/// extension fields built over any of those. Bounds on lazily reduced representations follow
/// the rules of the implementing module.
pub(crate) trait Field: Copy {
    /// One element, or one element per lane.
    type Element: Copy;

    /// The scalar form of one lane's element.
    type Scalar: Coordinate;

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

    /// Returns `b` where `choice` is set and `a` elsewhere.
    fn select(self, a: Self::Element, b: Self::Element, choice: Choice) -> Self::Element;

    /// Returns `a^exponent` for a public little-endian exponent.
    ///
    /// Variable-time in the exponent only.
    #[inline(always)]
    fn pow(self, a: Self::Element, exponent: &[u64]) -> Self::Element {
        let mut result = self.constant(Self::Scalar::ONE);
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
/// This is the portable path and the reference for the vectorized contexts.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Single;

impl Field for Single {
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

    /// Draws a canonical field element, biased toward values near the modulus.
    pub(crate) fn canonical(u: &mut Unstructured<'_>) -> arbitrary::Result<Fp> {
        let mut words: [u64; WORDS] = u.arbitrary()?;
        words[WORDS - 1] &= (1 << 61) - 1;
        Ok(Fp::from_words(words).unwrap_or(Fp::ZERO))
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

    #[test]
    fn identities() {
        assert_eq!(Fp::ZERO.neg(), Fp::ZERO);
        assert_eq!(Fp::ZERO.invert(), Fp::ZERO);
        assert_eq!(Fp::ONE.invert(), Fp::ONE);
        assert_eq!(Fp::from_u64(7).mul(Fp::from_u64(7).invert()), Fp::ONE);
        assert_eq!(Fp::from_u64(3).add(Fp::from_u64(4)), Fp::from_u64(7));
    }
}
