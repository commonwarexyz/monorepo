//! The base field of BLS12-381.
//!
//! Elements use radix `2^52` with eight limbs, in Montgomery form with `R = 2^416`. The scalar
//! [`Fp`] holds one canonical element and every operation is a `const fn`, so curve constants
//! can be derived at compile time. Hot paths use [`lanes::FpVec`], which carries one element
//! per vector lane in the same representation; this scalar form is the boundary representation
//! and the reference against which the vector kernels are tested.

pub mod lanes;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Number of limbs in a field element.
pub const LIMBS: usize = 8;

/// Bits per limb once carries have been propagated.
pub const LIMB_BITS: u32 = 52;

/// The low [`LIMB_BITS`] bits of a limb.
pub const MASK: u64 = (1 << LIMB_BITS) - 1;

/// Number of bytes in the canonical big-endian encoding.
pub const BYTES: usize = 48;

/// Number of 64-bit words in the canonical integer.
const WORDS: usize = 6;

/// The modulus `p` as little-endian 64-bit words.
const MODULUS_WORDS: [u64; WORDS] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// The modulus `p` in limbs.
pub const MODULUS: [u64; LIMBS] = limbs_from_words(MODULUS_WORDS);

/// `-p^(-1) mod 2^52`, the Montgomery reduction constant.
pub const INV: u64 = negated_inverse(MODULUS_WORDS[0]) & MASK;

/// `R mod p` for `R = 2^416`: the Montgomery form of one.
const R: [u64; LIMBS] = power_of_two(416);

/// `R^2 mod p`, used to enter Montgomery form.
const R2: [u64; LIMBS] = power_of_two(832);

/// Splits a little-endian 64-bit integer into 52-bit limbs.
pub(crate) const fn limbs_from_words(words: [u64; WORDS]) -> [u64; LIMBS] {
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
pub(crate) const fn words_from_limbs(limbs: [u64; LIMBS]) -> [u64; WORDS] {
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

/// Computes `-x^(-1) mod 2^64` for odd `x` by Newton iteration.
const fn negated_inverse(x: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// Computes `2^k mod p` by repeated doubling.
const fn power_of_two(k: u32) -> [u64; LIMBS] {
    let mut value = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut i = 0;
    while i < k {
        value = add_limbs(value, value);
        i += 1;
    }
    value
}

/// Propagates carries so every limb is below `2^52`; the value must be below `2^416`.
const fn carry(mut limbs: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut i = 0;
    while i + 1 < LIMBS {
        limbs[i + 1] += limbs[i] >> LIMB_BITS;
        limbs[i] &= MASK;
        i += 1;
    }
    limbs
}

/// Returns `value - p` when `value >= p`, for carried limbs with `value < 2p`.
const fn subtract_modulus(value: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut reduced = [0; LIMBS];
    let mut borrow = 0;
    let mut i = 0;
    while i < LIMBS {
        let diff = value[i].wrapping_sub(MODULUS[i]).wrapping_sub(borrow);
        reduced[i] = diff & MASK;
        borrow = diff >> 63;
        i += 1;
    }
    // A final borrow means the value was already below p.
    let mask = borrow.wrapping_neg();
    let mut i = 0;
    while i < LIMBS {
        reduced[i] = (reduced[i] & !mask) | (value[i] & mask);
        i += 1;
    }
    reduced
}

/// Returns `a + b mod p` for canonical inputs.
const fn add_limbs(a: [u64; LIMBS], b: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut sum = [0; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        sum[i] = a[i] + b[i];
        i += 1;
    }
    subtract_modulus(carry(sum))
}

/// Returns `a * b / R mod p` for canonical inputs.
///
/// This is the one-lane form of the vector kernel: each outer iteration accumulates one limb
/// of `a` against `b`, cancels the low column with a multiple of `p`, and shifts the columns
/// down by one limb.
const fn montgomery_mul(a: [u64; LIMBS], b: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut columns = [0u128; LIMBS + 1];
    let mut i = 0;
    while i < LIMBS {
        let mut j = 0;
        while j < LIMBS {
            columns[j] += a[i] as u128 * b[j] as u128;
            j += 1;
        }
        let q = (columns[0] as u64).wrapping_mul(INV) & MASK;
        let mut j = 0;
        while j < LIMBS {
            columns[j] += q as u128 * MODULUS[j] as u128;
            j += 1;
        }
        columns[1] += columns[0] >> LIMB_BITS;
        let mut j = 0;
        while j < LIMBS {
            columns[j] = columns[j + 1];
            j += 1;
        }
        columns[LIMBS] = 0;
        i += 1;
    }

    // The result is below 2p, so one carry pass and one conditional subtraction canonicalize it.
    let mut limbs = [0; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        columns[i + 1] += columns[i] >> LIMB_BITS;
        limbs[i] = columns[i] as u64 & MASK;
        i += 1;
    }
    subtract_modulus(limbs)
}

/// An element of the base field `GF(p)`.
///
/// The limbs hold the canonical Montgomery representative `a * R mod p` in radix `2^52`.
#[derive(Clone, Copy, Debug)]
pub struct Fp(pub(crate) [u64; LIMBS]);

impl Fp {
    /// The additive identity.
    pub const ZERO: Self = Self([0; LIMBS]);

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
                .wrapping_sub(MODULUS_WORDS[i] as u128)
                .wrapping_sub(borrow as u128);
            borrow = (wide >> 127) as u64;
            i += 1;
        }
        if borrow == 0 {
            return None;
        }
        Some(Self(montgomery_mul(limbs_from_words(words), R2)))
    }

    /// Reduces a small integer into the field.
    pub const fn from_u64(value: u64) -> Self {
        Self(montgomery_mul(limbs_from_words([value, 0, 0, 0, 0, 0]), R2))
    }

    /// Returns the canonical integer as little-endian words.
    pub const fn to_words(self) -> [u64; WORDS] {
        words_from_limbs(montgomery_mul(self.0, [1, 0, 0, 0, 0, 0, 0, 0]))
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
        Self(add_limbs(self.0, rhs.0))
    }

    /// Returns `self - rhs`.
    pub const fn sub(self, rhs: Self) -> Self {
        self.add(rhs.neg())
    }

    /// Returns `-self`.
    pub const fn neg(self) -> Self {
        // Canonical inputs never borrow past the top limb. A zero input yields p, which the
        // final subtraction maps back to zero.
        let mut value = [0; LIMBS];
        let mut borrow = 0;
        let mut i = 0;
        while i < LIMBS {
            let diff = MODULUS[i].wrapping_sub(self.0[i]).wrapping_sub(borrow);
            value[i] = diff & MASK;
            borrow = diff >> 63;
            i += 1;
        }
        Self(subtract_modulus(value))
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
        let mut exponent = MODULUS_WORDS;
        exponent[0] -= 2;
        self.pow(&exponent)
    }

    /// Returns a square root when one exists.
    ///
    /// Since `p = 3 mod 4`, the candidate is `self^((p + 1) / 4)`; it is a root exactly when
    /// its square equals `self`. The chosen root is not canonicalized.
    pub fn sqrt(self) -> Option<Self> {
        // (p + 1) / 4 = (p >> 2) + 1 because p = 3 mod 4.
        let mut exponent = [0; WORDS];
        for i in 0..WORDS {
            exponent[i] = MODULUS_WORDS[i] >> 2;
            if i + 1 < WORDS {
                exponent[i] |= MODULUS_WORDS[i + 1] << 62;
            }
        }
        exponent[0] += 1;
        let root = self.pow(&exponent);
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
        // 2 * value exceeds p exactly when value > (p - 1) / 2.
        let mut borrow = 0u64;
        let mut carry = 0u64;
        for i in 0..WORDS {
            let doubled = (words[i] << 1) | carry;
            carry = words[i] >> 63;
            let wide = (doubled as u128)
                .wrapping_sub(MODULUS_WORDS[i] as u128)
                .wrapping_sub(borrow as u128);
            borrow = (wide >> 127) as u64;
        }
        Choice::from(((carry | (1 - borrow)) & 1) as u8)
    }
}

/// Field arithmetic over some representation of base field elements.
///
/// Implementations are contexts (a backend token, for vectorized representations) rather than
/// element types, so curve formulas written once against this trait run on the scalar field,
/// on one element per lane, or on specialized representations chosen per backend. Bounds on
/// lazily reduced representations follow the rules of the implementing module.
pub(crate) trait Field: Copy {
    /// One element, or one element per lane.
    type Element: Copy;

    /// Returns every element set to `value`.
    fn constant(self, value: Fp) -> Self::Element;

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
}

/// The scalar field context: one canonical element at a time.
///
/// Serves as the reference for the vectorized contexts.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Single;

#[cfg(test)]
impl Field for Single {
    type Element = Fp;

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
    fn constants() {
        assert_eq!(words_from_limbs(MODULUS), MODULUS_WORDS);
        assert_eq!(MODULUS[0].wrapping_mul(INV) & MASK, MASK);
        assert!(MODULUS.iter().all(|limb| *limb <= MASK));
        assert!(R.iter().all(|limb| *limb <= MASK));
    }

    #[test]
    fn encoding_round_trip() {
        assert_eq!(Fp::from_bytes(&Fp::ONE.to_bytes()), Some(Fp::ONE));
        assert_eq!(Fp::ONE.to_words(), [1, 0, 0, 0, 0, 0]);
        assert!(Fp::from_words(MODULUS_WORDS).is_none());
        let mut largest = MODULUS_WORDS;
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
