//! The scalar field of BLS12-381: integers modulo the prime order `r` of G1 and G2.

use crate::montgomery;
use commonware_math::algebra::{Additive, Field, FieldNTT, Multiplicative, Object, Random, Ring};
use core::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand_core::CryptoRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Number of 64-bit words in a scalar.
const WORDS: usize = 4;

/// The group order `r` as little-endian words.
const MODULUS: [u64; WORDS] = [
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

/// The largest `s` such that `2^s` divides `r - 1`.
const TWO_ADICITY: u8 = 32;

/// A generator of the multiplicative group, which is not a square.
const GENERATOR: Scalar = Scalar::from_u64(7);

/// Primitive roots of unity: entry `lg` has order `2^lg`.
///
/// The last entry is `GENERATOR^t` for `r - 1 = t * 2^TWO_ADICITY`; each earlier entry is
/// the square of the next.
const ROOTS_OF_UNITY: [Scalar; TWO_ADICITY as usize + 1] = {
    // The low word of `r - 1` has its low 32 bits clear, so `t = (r - 1) >> 32`.
    let mut odd = [0u64; WORDS];
    let mut i = 0;
    while i < WORDS {
        odd[i] = MODULUS[i] >> TWO_ADICITY;
        if i + 1 < WORDS {
            odd[i] |= MODULUS[i + 1] << (64 - TWO_ADICITY);
        }
        i += 1;
    }
    let mut roots = [Scalar::ONE; TWO_ADICITY as usize + 1];
    let mut lg = TWO_ADICITY as usize;
    roots[lg] = GENERATOR.pow(odd);
    while lg > 0 {
        roots[lg - 1] = roots[lg].square();
        lg -= 1;
    }
    roots
};

/// The inverse of the coset shift [`GENERATOR`].
const GENERATOR_INV: Scalar = GENERATOR.invert();

/// An element of the scalar field.
///
/// Values are kept as canonical Montgomery representatives, and every operation runs in time
/// independent of the operands.
#[derive(Clone, Copy)]
pub struct Scalar([u64; WORDS]);

impl Scalar {
    /// Number of bytes in the canonical big-endian encoding.
    pub const BYTES: usize = 32;

    /// Number of bytes accepted by [`Scalar::from_bytes_wide`].
    pub const WIDE_BYTES: usize = 2 * Self::BYTES;

    /// Zero.
    pub const ZERO: Self = Self([0; WORDS]);

    /// One.
    pub const ONE: Self = Self(R);

    /// Converts a small integer into the field.
    pub const fn from_u64(value: u64) -> Self {
        Self(montgomery::mul(&[value, 0, 0, 0], &R2, &MODULUS, INV))
    }

    /// Converts a canonical little-endian integer into the field.
    ///
    /// Returns `None` when the integer is not below the group order.
    pub const fn from_words(words: [u64; WORDS]) -> Option<Self> {
        if !montgomery::is_below(&words, &MODULUS) {
            return None;
        }
        Some(Self(montgomery::mul(&words, &R2, &MODULUS, INV)))
    }

    /// Returns the canonical integer, below the group order, as little-endian words.
    pub const fn to_words(self) -> [u64; WORDS] {
        montgomery::mul(&self.0, &[1, 0, 0, 0], &MODULUS, INV)
    }

    /// Parses the canonical big-endian encoding.
    ///
    /// Returns `None` when the encoded integer is not below the group order.
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> Option<Self> {
        let mut words = [0; WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter().rev()) {
            *word = u64::from_be_bytes(*chunk);
        }
        Self::from_words(words)
    }

    /// Returns the canonical big-endian encoding.
    pub fn to_bytes(self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        let words = self.to_words();
        for (chunk, word) in bytes
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(words.iter().rev())
        {
            *chunk = word.to_be_bytes();
        }
        bytes
    }

    /// Reduces a 512-bit big-endian integer modulo the group order.
    ///
    /// The result is statistically close to uniform (within `2^-256`) for uniform input.
    pub fn from_bytes_wide(bytes: &[u8; Self::WIDE_BYTES]) -> Self {
        let mut words = [0u64; 2 * WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter().rev()) {
            *word = u64::from_be_bytes(*chunk);
        }
        let (low, high) = words.as_chunks::<WORDS>().0.split_at(1);
        // low * R^2 / R + high * R^3 / R = (low + high * 2^256) * R. Montgomery multiplication
        // accepts a left operand below 2^256 when the right one is below r.
        let low = montgomery::mul(&low[0], &R2, &MODULUS, INV);
        let high = montgomery::mul(&high[0], &R3, &MODULUS, INV);
        Self(montgomery::add(&low, &high, &MODULUS))
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
        // Fermat: a^(r - 2). The low word of r is odd, so subtracting two does not borrow.
        let mut exponent = MODULUS;
        exponent[0] -= 2;
        self.pow(exponent)
    }

    /// Returns `self / 2`.
    pub const fn halve(self) -> Self {
        // Halving commutes with the Montgomery factor: add r when the representative is odd,
        // then shift. The sum is below 2r < 2^256, so it fits in four words.
        let mask = (self.0[0] & 1).wrapping_neg();
        let mut sum = [0u64; WORDS];
        let mut carry = 0u64;
        let mut i = 0;
        while i < WORDS {
            let wide = self.0[i] as u128 + (MODULUS[i] & mask) as u128 + carry as u128;
            sum[i] = wide as u64;
            carry = (wide >> 64) as u64;
            i += 1;
        }
        let mut i = 0;
        while i < WORDS {
            sum[i] >>= 1;
            if i + 1 < WORDS {
                sum[i] |= sum[i + 1] << 63;
            }
            i += 1;
        }
        Self(sum)
    }

    /// Returns `self^exponent` for a little-endian exponent.
    ///
    /// The running time depends on the exponent, which must therefore be public.
    const fn pow(self, exponent: [u64; WORDS]) -> Self {
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
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar(0x")?;
        for word in self.to_words().iter().rev() {
            write!(f, "{word:016x}")?;
        }
        f.write_str(")")
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Representatives are canonical, so equal values have equal words.
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

impl<'a> AddAssign<&'a Self> for Scalar {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = Self::add(*self, *rhs);
    }
}

impl<'a> Add<&'a Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self {
        Self::add(self, *rhs)
    }
}

impl<'a> SubAssign<&'a Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = Self::sub(*self, *rhs);
    }
}

impl<'a> Sub<&'a Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self {
        Self::sub(self, *rhs)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        Self::neg(self)
    }
}

impl<'a> MulAssign<&'a Self> for Scalar {
    fn mul_assign(&mut self, rhs: &'a Self) {
        *self = Self::mul(*self, *rhs);
    }
}

impl<'a> Mul<&'a Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self {
        Self::mul(self, *rhs)
    }
}

impl Object for Scalar {}

impl Additive for Scalar {
    fn zero() -> Self {
        Self::ZERO
    }

    fn double(&mut self) {
        *self = Self::add(*self, *self);
    }
}

impl Multiplicative for Scalar {
    fn square(&mut self) {
        *self = Self::square(*self);
    }
}

impl Ring for Scalar {
    fn one() -> Self {
        Self::ONE
    }
}

impl Field for Scalar {
    fn inv(&self) -> Self {
        self.invert()
    }
}

impl FieldNTT for Scalar {
    const MAX_LG_ROOT_ORDER: u8 = TWO_ADICITY;

    fn root_of_unity(lg: u8) -> Option<Self> {
        ROOTS_OF_UNITY.get(usize::from(lg)).copied()
    }

    /// Returns 7, which generates the multiplicative group.
    fn coset_shift() -> Self {
        GENERATOR
    }

    fn coset_shift_inv() -> Self {
        GENERATOR_INV
    }

    fn div_2(&self) -> Self {
        self.halve()
    }
}

impl Random for Scalar {
    /// Samples a uniform scalar by reducing 512 random bits.
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut bytes = [0u8; Self::WIDE_BYTES];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes_wide(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use blst::{
        blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_from_uint64,
        blst_fr_inverse, blst_fr_mul, blst_fr_rshift, blst_fr_sqr, blst_fr_sub, blst_scalar,
        blst_scalar_fr_check, blst_scalar_from_be_bytes, blst_scalar_from_bendian,
        blst_scalar_from_fr, blst_uint64_from_fr,
    };
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::test_suites;
    use commonware_utils::test_rng;
    use rand_core::Rng as _;

    impl<'a> Arbitrary<'a> for Scalar {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            // Bias towards the edges of the range, where carries and reductions happen.
            Ok(match u.int_in_range(0u8..=3)? {
                0 => Self::from_u64(u.arbitrary()?),
                1 => Self::from_u64(u.arbitrary()?).neg(),
                _ => Self::from_bytes_wide(&u.arbitrary()?),
            })
        }
    }

    fn to_blst(value: Scalar) -> blst_fr {
        let mut out = blst_fr::default();
        let words = value.to_words();
        // SAFETY: both pointers are valid; the input holds four words of a canonical scalar.
        unsafe { blst_fr_from_uint64(&mut out, words.as_ptr()) };
        out
    }

    fn from_blst(value: &blst_fr) -> Scalar {
        let mut words = [0u64; WORDS];
        // SAFETY: both pointers are valid; the output holds four words.
        unsafe { blst_uint64_from_fr(words.as_mut_ptr(), value) };
        Scalar::from_words(words).expect("blst returns canonical scalars")
    }

    /// Returns the Montgomery form blst uses for the canonical big-endian integer.
    fn blst_montgomery(bytes: &[u8; Scalar::BYTES]) -> [u64; WORDS] {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        // SAFETY: all pointers are valid; the input holds 32 bytes of a canonical scalar.
        unsafe {
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
            assert!(blst_scalar_fr_check(&scalar));
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        fr.l
    }

    #[test]
    fn constants_match_blst() {
        // blst uses the same Montgomery radix, so internal representations agree.
        assert_eq!(Scalar::ONE.0, blst_montgomery(&Scalar::ONE.to_bytes()));
        assert_eq!(Scalar::ONE.to_words(), [1, 0, 0, 0]);
        assert_eq!(Scalar::from_u64(7).to_words(), [7, 0, 0, 0]);
        // The Montgomery forms commonware-cryptography uses for its NTT constants.
        assert_eq!(
            Scalar::root_of_unity(TWO_ADICITY).unwrap().0,
            [
                0xb9b5_8d8c_5f0e_466a,
                0x5b1b_4c80_1819_d7ec,
                0x0af5_3ae3_52a3_1e64,
                0x5bf3_adda_19e9_b27b,
            ]
        );
        assert_eq!(
            Scalar::coset_shift().0,
            [
                0x0000_000e_ffff_fff1,
                0x17e3_63d3_0018_9c0f,
                0xff9c_5787_6f84_57b0,
                0x3513_3220_8fc5_a8c4,
            ]
        );
        assert_eq!(
            Scalar::coset_shift_inv().0,
            [
                0xdb6d_b6da_db6d_b6dc,
                0xe6b5_824a_db6c_c6da,
                0xf8b3_56e0_0581_0db9,
                0x66d0_f1e6_60ec_4796,
            ]
        );
    }

    #[test]
    fn roots_of_unity_have_exact_order() {
        assert_eq!(Scalar::root_of_unity(0), Some(Scalar::ONE));
        assert_eq!(Scalar::root_of_unity(1), Some(Scalar::ONE.neg()));
        assert_eq!(Scalar::root_of_unity(TWO_ADICITY + 1), None);
        let mut root = Scalar::root_of_unity(TWO_ADICITY).unwrap();
        for _ in 1..TWO_ADICITY {
            root = root.square();
            assert_ne!(root, Scalar::ONE);
        }
        assert_eq!(root, Scalar::ONE.neg());
        // The coset shift lies outside the 2-Sylow subgroup and is not a square.
        let mut shift = Scalar::coset_shift();
        for _ in 0..TWO_ADICITY {
            shift = shift.square();
        }
        assert_ne!(shift, Scalar::ONE);
        let mut half = MODULUS;
        half[0] -= 1;
        let half =
            core::array::from_fn(|i| (half[i] >> 1) | half.get(i + 1).map_or(0, |next| next << 63));
        assert_eq!(GENERATOR.pow(half), Scalar::ONE.neg());
    }

    #[test]
    fn encoding_edge_cases() {
        let mut largest = MODULUS;
        largest[0] -= 1;
        let scalar = Scalar::from_words(largest).unwrap();
        assert_eq!(scalar, Scalar::ONE.neg());
        assert_eq!(scalar.to_words(), largest);
        assert_eq!(Scalar::from_bytes(&scalar.to_bytes()), Some(scalar));
        assert_eq!(Scalar::ZERO.to_bytes(), [0; Scalar::BYTES]);
        assert_eq!(Scalar::ONE.to_bytes()[Scalar::BYTES - 1], 1);

        // Non-canonical encodings: r itself, r + 1, the top bit, and all ones.
        assert!(Scalar::from_words(MODULUS).is_none());
        let mut above = MODULUS;
        above[0] += 1;
        assert!(Scalar::from_words(above).is_none());
        let modulus = Scalar::ONE.neg().to_bytes();
        let mut bytes = modulus;
        bytes[Scalar::BYTES - 1] += 1;
        assert!(Scalar::from_bytes(&bytes).is_none());
        let mut bytes = [0; Scalar::BYTES];
        bytes[0] = 0x80;
        assert!(Scalar::from_bytes(&bytes).is_none());
        assert!(Scalar::from_bytes(&[0xff; Scalar::BYTES]).is_none());
    }

    #[test]
    fn encoding_matches_blst() {
        minifuzz::test(|u| {
            let a = Scalar::arbitrary(u)?;
            let mut scalar = blst_scalar::default();
            let mut bytes = [0u8; Scalar::BYTES];
            // SAFETY: all pointers are valid; the output holds 32 bytes.
            unsafe {
                blst_scalar_from_fr(&mut scalar, &to_blst(a));
                blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
            }
            assert_eq!(a.to_bytes(), bytes);
            assert_eq!(a.0, blst_montgomery(&bytes));

            // Arbitrary 32-byte strings decode exactly when blst accepts them.
            let bytes: [u8; Scalar::BYTES] = u.arbitrary()?;
            // SAFETY: all pointers are valid; the input holds 32 bytes.
            let canonical = unsafe {
                blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
                blst_scalar_fr_check(&scalar)
            };
            let decoded = Scalar::from_bytes(&bytes);
            assert_eq!(decoded.is_some(), canonical);
            if let Some(decoded) = decoded {
                assert_eq!(decoded.to_bytes(), bytes);
            }
            Ok(())
        });
    }

    fn reduce_wide_blst(bytes: &[u8; Scalar::WIDE_BYTES]) -> Scalar {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        // SAFETY: all pointers are valid; the input holds the given number of bytes.
        unsafe {
            blst_scalar_from_be_bytes(&mut scalar, bytes.as_ptr(), bytes.len());
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        from_blst(&fr)
    }

    #[test]
    fn wide_reduction_matches_blst() {
        assert_eq!(
            Scalar::from_bytes_wide(&[0; Scalar::WIDE_BYTES]),
            Scalar::ZERO
        );
        let ones = [0xff; Scalar::WIDE_BYTES];
        // 2^512 - 1, computed from 2^256 = R mod r.
        let r = Scalar::from_words(R).unwrap();
        let expected = r.square().sub(Scalar::ONE);
        assert_eq!(Scalar::from_bytes_wide(&ones), expected);
        assert_eq!(reduce_wide_blst(&ones), expected);
        minifuzz::test(|u| {
            let bytes: [u8; Scalar::WIDE_BYTES] = u.arbitrary()?;
            assert_eq!(Scalar::from_bytes_wide(&bytes), reduce_wide_blst(&bytes));
            Ok(())
        });
    }

    #[test]
    fn arithmetic_matches_blst() {
        minifuzz::test(|u| {
            let a = Scalar::arbitrary(u)?;
            let b = Scalar::arbitrary(u)?;
            let (ba, bb) = (to_blst(a), to_blst(b));
            let mut out = blst_fr::default();
            // SAFETY: all pointers reference valid scalars.
            unsafe {
                blst_fr_add(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.add(b));
                blst_fr_sub(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.sub(b));
                blst_fr_mul(&mut out, &ba, &bb);
                assert_eq!(from_blst(&out), a.mul(b));
                blst_fr_sqr(&mut out, &ba);
                assert_eq!(from_blst(&out), a.square());
                blst_fr_rshift(&mut out, &ba, 1);
                assert_eq!(from_blst(&out), a.halve());
            }
            if a != Scalar::ZERO {
                // SAFETY: all pointers reference valid scalars, and the input is nonzero.
                unsafe { blst_fr_inverse(&mut out, &ba) };
                assert_eq!(from_blst(&out), a.invert());
            }
            assert_eq!(a.neg().add(a), Scalar::ZERO);
            Ok(())
        });
    }

    #[test]
    fn inversion_edge_cases() {
        assert_eq!(Scalar::ZERO.invert(), Scalar::ZERO);
        assert_eq!(Scalar::ZERO.inv(), Scalar::ZERO);
        assert_eq!(Scalar::ONE.invert(), Scalar::ONE);
        assert_eq!(Scalar::ONE.neg().invert(), Scalar::ONE.neg());
        assert_eq!(Scalar::from_u64(2).invert(), Scalar::ONE.halve());
    }

    #[test]
    fn random_reduces_wide_bytes() {
        let mut rng = test_rng();
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        assert_ne!(a, b);
        let mut rng = test_rng();
        let mut bytes = [0u8; Scalar::WIDE_BYTES];
        rng.fill_bytes(&mut bytes);
        assert_eq!(a, Scalar::from_bytes_wide(&bytes));
    }

    #[test]
    fn debug_shows_canonical_integer() {
        assert_eq!(
            format!("{:?}", Scalar::from_u64(0xabc)),
            "Scalar(0x0000000000000000000000000000000000000000000000000000000000000abc)"
        );
    }

    #[test]
    fn field_laws() {
        minifuzz::test(test_suites::fuzz_field::<Scalar>);
    }

    #[test]
    fn field_ntt_laws() {
        minifuzz::test(test_suites::fuzz_field_ntt::<Scalar>);
    }
}
