//! The scalar field of BLS12-381: integers modulo the prime order `r` of G1 and G2.

use crate::montgomery;
use alloc::{vec, vec::Vec};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Number of 64-bit words in a scalar.
pub(crate) const WORDS: usize = 4;

/// Number of bytes in the canonical big-endian encoding.
pub const BYTES: usize = 32;

/// The group order `r` as little-endian words.
pub const MODULUS: [u64; WORDS] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

/// `-r^(-1) mod 2^64`, the Montgomery reduction constant.
const INV: u64 = montgomery::negated_inverse(MODULUS[0]);

/// `R mod r` for `R = 2^256`: the Montgomery form of one.
const R: [u64; WORDS] = montgomery::power_of_two(256, &MODULUS);

/// `R^2 mod r`, used to enter Montgomery form.
const R2: [u64; WORDS] = montgomery::power_of_two(512, &MODULUS);

/// `R^3 mod r`, which carries the high half of a 512-bit integer into Montgomery form.
const R3: [u64; WORDS] = montgomery::power_of_two(768, &MODULUS);

/// Number of significant bits in a scalar: `r < 2^255`.
pub(crate) const BITS: usize = 255;

/// Width in bits of the windows [`Digits::window`] exposes.
pub(crate) const WINDOW_BITS: usize = 4;

/// Number of windows in a scalar.
pub(crate) const WINDOWS: usize = WORDS * 64 / WINDOW_BITS;

/// An element of the scalar field, as a canonical Montgomery representative.
#[derive(Clone, Copy, Debug)]
pub struct Scalar([u64; WORDS]);

impl Scalar {
    /// Zero.
    pub const ZERO: Self = Self([0; WORDS]);

    /// One.
    pub const ONE: Self = Self(R);

    /// Converts a canonical little-endian integer into the field.
    ///
    /// Returns `None` when the integer is not below the group order.
    pub const fn from_words(words: [u64; WORDS]) -> Option<Self> {
        if !montgomery::is_below(&words, &MODULUS) {
            return None;
        }
        Some(Self(montgomery::mul(&words, &R2, &MODULUS, INV)))
    }

    /// Reduces a 512-bit little-endian integer into the field.
    ///
    /// The result is statistically close to uniform for uniform input, which makes this the
    /// basis of random sampling and hashing to the field.
    pub fn from_bytes_wide(bytes: &[u8; 2 * BYTES]) -> Self {
        let mut words = [0u64; 2 * WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        let (low, high) = words.split_at(WORDS);
        let (low, high) = (low.try_into().expect("half"), high.try_into().expect("half"));
        // low * R^2 / R + high * R^3 / R = (low + high * 2^256) * R.
        let low = montgomery::mul(&low, &R2, &MODULUS, INV);
        let high = montgomery::mul(&high, &R3, &MODULUS, INV);
        Self(montgomery::add(&low, &high, &MODULUS))
    }

    /// Reduces a small integer into the field.
    pub const fn from_u64(value: u64) -> Self {
        Self(montgomery::mul(&[value, 0, 0, 0], &R2, &MODULUS, INV))
    }

    /// Returns the canonical integer as little-endian words.
    pub const fn to_words(self) -> [u64; WORDS] {
        montgomery::mul(&self.0, &[1, 0, 0, 0], &MODULUS, INV)
    }

    /// Returns the canonical integer for bit-level access.
    pub(crate) const fn digits(self) -> Digits {
        Digits(self.to_words())
    }

    /// Parses the canonical big-endian encoding.
    ///
    /// Returns `None` when the encoded integer is not below the group order.
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

    /// Returns `self * rhs`.
    pub const fn mul(self, rhs: Self) -> Self {
        Self(montgomery::mul(&self.0, &rhs.0, &MODULUS, INV))
    }

    /// Returns `self * self`.
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Returns the multiplicative inverse, or zero for zero.
    pub const fn invert(self) -> Self {
        // Fermat: a^(r - 2). The modulus is odd, so the low word does not borrow.
        let mut exponent = MODULUS;
        exponent[0] -= 2;
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

    /// Returns whether the element is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Inverts every element with one shared inversion; zeros map to zero.
    ///
    /// Montgomery's trick: prefix products of the nonzero elements, one inversion, then peel
    /// each inverse off from the top.
    pub fn invert_many(elements: &[Self]) -> Vec<Self> {
        let mut prefix = Vec::with_capacity(elements.len());
        let mut product = Self::ONE;
        for element in elements {
            prefix.push(product);
            let skip = element.is_zero();
            product = Self::conditional_select(&product.mul(*element), &product, skip);
        }
        let mut inverse = product.invert();
        let mut inverses = vec![Self::ZERO; elements.len()];
        for (i, element) in elements.iter().enumerate().rev() {
            let skip = element.is_zero();
            let value = inverse.mul(prefix[i]);
            inverses[i] = Self::conditional_select(&value, &Self::ZERO, skip);
            inverse = Self::conditional_select(&inverse.mul(*element), &inverse, skip);
        }
        inverses
    }
}

impl commonware_math::algebra::Random for Scalar {
    fn random(mut rng: impl rand_core::CryptoRng) -> Self {
        let mut bytes = [0u8; 2 * BYTES];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes_wide(&bytes)
    }
}

/// The canonical integer of a scalar, for the windowed ladders.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Digits([u64; WORDS]);

impl Digits {
    /// Returns bits `[WINDOW_BITS * index, WINDOW_BITS * (index + 1))` of the integer.
    ///
    /// # Panics
    ///
    /// Panics if `index >= WINDOWS`.
    pub(crate) const fn window(&self, index: usize) -> u8 {
        assert!(index < WINDOWS);
        self.bits(index * WINDOW_BITS, WINDOW_BITS) as u8
    }

    /// Returns `count` bits of the integer starting at bit `start`; bits past the top are zero.
    ///
    /// # Panics
    ///
    /// Panics if `count > 63`.
    pub(crate) const fn bits(&self, start: usize, count: usize) -> u64 {
        assert!(count < 64);
        let mask = (1u64 << count) - 1;
        let (word, shift) = (start / 64, start % 64);
        if word >= WORDS {
            return 0;
        }
        let mut value = self.0[word] >> shift;
        if shift + count > 64 && word + 1 < WORDS {
            value |= self.0[word + 1] << (64 - shift);
        }
        value & mask
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(core::array::from_fn(|i| {
            u64::conditional_select(&a.0[i], &b.0[i], choice)
        }))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Scalar {}

impl Default for Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

crate::algebra::field_traits!(Scalar);

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::{Field, Ring};

    fn canonical(u: &mut Unstructured<'_>) -> arbitrary::Result<Scalar> {
        let mut words: [u64; WORDS] = u.arbitrary()?;
        words[WORDS - 1] &= (1 << 63) - 1;
        Ok(Scalar::from_words(words).unwrap_or(Scalar::ZERO))
    }

    fn to_blst(value: Scalar) -> blst::blst_fr {
        let mut out = blst::blst_fr::default();
        let words = value.to_words();
        // SAFETY: valid pointers; the words hold a canonical scalar.
        unsafe { blst::blst_fr_from_uint64(&mut out, words.as_ptr()) };
        out
    }

    fn from_blst(value: &blst::blst_fr) -> Scalar {
        let mut words = [0u64; WORDS];
        // SAFETY: valid pointers; the output holds four words.
        unsafe { blst::blst_uint64_from_fr(words.as_mut_ptr(), value) };
        Scalar::from_words(words).unwrap()
    }

    #[test]
    fn encoding_round_trip() {
        let mut largest = MODULUS;
        largest[0] -= 1;
        let scalar = Scalar::from_words(largest).unwrap();
        assert_eq!(Scalar::from_bytes(&scalar.to_bytes()), Some(scalar));
        assert_eq!(scalar.to_words(), largest);
        assert!(Scalar::from_words(MODULUS).is_none());
        assert_eq!(Scalar::ONE.to_bytes()[BYTES - 1], 1);
        assert_eq!(Scalar::ONE.to_words(), [1, 0, 0, 0]);
    }

    #[test]
    fn windows_cover_every_bit() {
        let scalar = Digits([0x0123_4567_89ab_cdef, 0, 0, 0]);
        let digits: Vec<u8> = (0..16).map(|i| scalar.window(i)).collect();
        assert_eq!(digits, [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        assert_eq!(scalar.window(WINDOWS - 1), 0);
        let scalar = Digits([u64::MAX, 0x0f, 0, 0]);
        assert_eq!(scalar.bits(60, 8), 0xff);
        assert_eq!(scalar.bits(62, 6), 0x3f);
        assert_eq!(scalar.bits(250, 10), 0);
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let a = canonical(u)?;
            let b = canonical(u)?;
            let (ba, bb) = (to_blst(a), to_blst(b));
            let mut out = blst::blst_fr::default();
            // SAFETY: all pointers reference valid scalars.
            unsafe {
                blst::blst_fr_add(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.add(b));
                blst::blst_fr_sub(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.sub(b));
                blst::blst_fr_mul(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.mul(b));
                blst::blst_fr_cneg(&mut out, &ba, true);
                assert_eq!(from_blst(&out), a.neg());
                blst::blst_fr_inverse(&mut out, &ba);
                assert_eq!(from_blst(&out), a.invert());
            }
            assert_eq!(a.inv(), a.invert());
            assert_eq!(a.exp(&[3]), a.mul(a).mul(a));
            Ok(())
        });
    }

    impl<'a> arbitrary::Arbitrary<'a> for Scalar {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            canonical(u)
        }
    }

    #[test]
    fn wide_reduction_and_batch_inversion() {
        minifuzz::test(|u| {
            let bytes: [u8; 2 * BYTES] = u.arbitrary()?;
            let mut low = [0u8; BYTES];
            let mut high = [0u8; BYTES];
            low.copy_from_slice(&bytes[..BYTES]);
            high.copy_from_slice(&bytes[BYTES..]);
            // Compare against the definition: low + high * 2^256, reduced word by word.
            let mut expected = Scalar::ZERO;
            for byte in bytes.iter().rev() {
                expected = expected.mul(Scalar::from_u64(256)).add(Scalar::from_u64(*byte as u64));
            }
            assert_eq!(Scalar::from_bytes_wide(&bytes), expected);

            let count = u.int_in_range(0..=12)?;
            let mut elements = Vec::with_capacity(count);
            for _ in 0..count {
                elements.push(if u.ratio(1, 6)? { Scalar::ZERO } else { canonical(u)? });
            }
            let inverses = Scalar::invert_many(&elements);
            for (element, inverse) in elements.iter().zip(inverses) {
                assert_eq!(inverse, element.invert());
            }
            Ok(())
        });
    }

    #[test]
    fn algebra_laws() {
        minifuzz::test(commonware_math::algebra::test_suites::fuzz_field::<Scalar>);
    }
}
