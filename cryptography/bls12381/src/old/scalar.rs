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

/// `|z|` for the curve parameter `z = -0xd201000000010000`.
const Z: u64 = 0xd201_0000_0001_0000;

/// `z^2` as little-endian words.
const Z_SQUARED: [u64; 2] = [0x0000_0001_0000_0000, 0xac45_a401_0001_a402];

/// `floor(2^256 / z^2)`, which estimates quotients by `z^2` to within one.
const Z_SQUARED_RECIPROCAL: [u64; 3] = [0x63f6_e522_f6cf_ee2e, 0x7c6b_ecf1_e01f_aadd, 1];

/// `floor(2^128 / |z|)`, which estimates quotients by `|z|` to within one.
const Z_RECIPROCAL: [u64; 2] = [0x3812_04ca_56cd_56b5, 1];

/// Width in bits of the windows [`Digits::window`] exposes.
pub(crate) const WINDOW_BITS: usize = 4;

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

    /// Splits the scalar as `k0 + k1 * z^2` with both parts below `2^128`.
    ///
    /// On G1, `[z^2]P = -phi^2(P)` for the endomorphism `phi`, so a multiplication becomes two
    /// half-length ones.
    pub(crate) fn split_glv(&self) -> [Digits<2>; 2] {
        let words = self.to_words();
        let divisor = [Z_SQUARED[0], Z_SQUARED[1], 0, 0];
        let (quotient, remainder) = divide::<4, 3, 7, 2>(&words, &divisor, &Z_SQUARED_RECIPROCAL);
        [Digits([remainder[0], remainder[1]]), Digits(quotient)]
    }

    /// Widens single-word components to the two-word shape the ladders share.
    pub(crate) const fn widen(digits: Digits<1>) -> Digits<2> {
        Digits([digits.0[0], 0])
    }

    /// Splits the scalar as `k0 + k1 |z| + k2 z^2 + k3 |z|^3` with every part below `2^64`.
    ///
    /// On G2, `psi(P) = [z]P`, so a multiplication becomes four quarter-length ones.
    pub(crate) fn split_gls(&self) -> [Digits<1>; 4] {
        let mut parts = [Digits([0]); 4];
        for (half, parts) in self.split_glv().iter().zip(parts.as_chunks_mut::<2>().0) {
            let (quotient, remainder) = divide::<2, 2, 4, 1>(&half.0, &[Z, 0], &Z_RECIPROCAL);
            parts[0] = Digits([remainder[0]]);
            parts[1] = Digits(quotient);
        }
        parts
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

/// Multiplies little-endian word arrays.
fn multiply_words<const A: usize, const B: usize, const N: usize>(
    a: &[u64; A],
    b: &[u64; B],
) -> [u64; N] {
    const { assert!(N == A + B) };
    let mut result = [0; N];
    for (i, &left) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &right) in b.iter().enumerate() {
            // A word product plus an output word and a carry fits in 128 bits.
            let product = (left as u128 * right as u128) + result[i + j] as u128 + carry;
            result[i + j] = product as u64;
            carry = product >> 64;
        }
        result[i + B] = carry as u64;
    }
    result
}

/// Returns the low `N` words of the product of little-endian word arrays.
fn multiply_low<const N: usize>(a: &[u64], b: &[u64; N]) -> [u64; N] {
    let mut result = [0u64; N];
    for (i, &left) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &right) in b.iter().enumerate().take(N.saturating_sub(i)) {
            let product = (left as u128 * right as u128) + result[i + j] as u128 + carry;
            result[i + j] = product as u64;
            carry = product >> 64;
        }
    }
    result
}

/// Subtracts little-endian word arrays, returning the difference and whether it underflowed.
fn subtract_words<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], Choice) {
    let mut result = [0; N];
    let mut borrow = 0u64;
    for i in 0..N {
        let (difference, first) = a[i].overflowing_sub(b[i]);
        let (difference, second) = difference.overflowing_sub(borrow);
        result[i] = difference;
        borrow = u64::from(first | second);
    }
    (result, Choice::from(borrow as u8))
}

/// Divides `value` by `divisor` given a reciprocal that estimates the quotient to within one,
/// returning the quotient and remainder as fixed-width word arrays.
fn divide<const N: usize, const R: usize, const W: usize, const Q: usize>(
    value: &[u64; N],
    divisor: &[u64; N],
    reciprocal: &[u64; R],
) -> ([u64; Q], [u64; N]) {
    const { assert!(W == N + R && Q <= N) };
    let wide: [u64; W] = multiply_words(value, reciprocal);
    let mut quotient = [0; Q];
    quotient.copy_from_slice(&wide[N..N + Q]);
    let (remainder, _) = subtract_words(value, &multiply_low(&quotient, divisor));
    // The estimate is at most one too small; correct it when the remainder is still too big.
    let (reduced, borrow) = subtract_words(&remainder, divisor);
    let correct = !borrow;
    let mut remainder = remainder;
    for (word, reduced) in remainder.iter_mut().zip(reduced) {
        *word = u64::conditional_select(word, &reduced, correct);
    }
    let mut carry = u64::from(correct.unwrap_u8());
    for word in &mut quotient {
        let (sum, overflow) = word.overflowing_add(carry);
        *word = sum;
        carry = u64::from(overflow);
    }
    (quotient, remainder)
}

/// The canonical integer of a scalar, or part of one, for the windowed ladders.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Digits<const N: usize>([u64; N]);

impl<const N: usize> Default for Digits<N> {
    fn default() -> Self {
        Self([0; N])
    }
}


impl<const N: usize> Digits<N> {
    /// Returns bits `[WINDOW_BITS * index, WINDOW_BITS * (index + 1))` of the integer; windows
    /// past the top are zero.
    pub(crate) const fn window(&self, index: usize) -> u8 {
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
        if word >= N {
            return 0;
        }
        let mut value = self.0[word] >> shift;
        if shift + count > 64 && word + 1 < N {
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

crate::old::algebra::field_traits!(Scalar);

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
        assert_eq!(scalar.window(63), 0);
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
    fn decompositions_recombine() {
        minifuzz::test(|u| {
            let k = canonical(u)?;
            let z = Scalar::from_u64(Z);
            let z2 = z.mul(z);
            let [k0, k1] = k.split_glv();
            let part = |digits: [u64; 2]| {
                Scalar::from_u64(digits[1])
                    .mul(Scalar::from_u64(1).mul(Scalar::from_words([0, 1, 0, 0]).unwrap()))
                    .add(Scalar::from_u64(digits[0]))
            };
            assert_eq!(part(k0.0).add(part(k1.0).mul(z2)), k);
            let [a, b, c, d] = k.split_gls();
            let mut sum = Scalar::ZERO;
            for digit in [d, c, b, a] {
                sum = sum.mul(z).add(Scalar::from_u64(digit.0[0]));
            }
            assert_eq!(sum, k);
            assert!(a.0[0] < Z && b.0[0] < Z && c.0[0] < Z && d.0[0] < Z);
            Ok(())
        });
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
