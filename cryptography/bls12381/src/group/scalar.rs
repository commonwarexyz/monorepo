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

/// `2^256` as an element of the field, which shifts a word chunk of a wide integer into place.
const SHIFT: Scalar = Scalar(R2);

/// `|x|`, the magnitude of the curve parameter.
pub(crate) const X_ABS: u64 = 0xd201_0000_0001_0000;

/// `t = x^2` as little-endian words, where `r = t^2 - t + 1`.
pub(crate) const X_SQUARED: [u64; 2] = [0x0000_0001_0000_0000, 0xac45_a401_0001_a402];

/// `floor(2^256 / t)`, which [`Scalar::split`] multiplies by to divide by `t`.
const X_SQUARED_RECIPROCAL: [u64; 3] = [0x63f6_e522_f6cf_ee2e, 0x7c6b_ecf1_e01f_aadd, 1];

/// `floor(2^128 / |x|)`, which [`Scalar::split_quarters`] multiplies by to divide by `|x|`.
const X_ABS_RECIPROCAL: [u64; 2] = [0x3812_04ca_56cd_56b5, 1];

/// Returns the product of two little-endian integers, in `N = A + B` words.
const fn mul_words<const A: usize, const B: usize, const N: usize>(
    a: &[u64; A],
    b: &[u64; B],
) -> [u64; N] {
    const { assert!(N == A + B) };
    let mut product = [0; N];
    let mut i = 0;
    while i < A {
        let mut carry = 0u64;
        let mut j = 0;
        while j < B {
            // A product of words plus a word and a carry is below 2^128.
            let wide = product[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry as u128;
            product[i + j] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        product[i + B] = carry;
        i += 1;
    }
    product
}

/// Returns `a - b` modulo `2^(64 N)` and whether it borrowed.
const fn sub_words<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], bool) {
    let mut difference = [0; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let wide = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow as u128);
        difference[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        i += 1;
    }
    (difference, borrow == 1)
}

/// Returns `value / divisor` and `value mod divisor` for a value of `N = 2 D` words whose
/// quotient fits in `D` words, given `reciprocal = floor(2^(64 N) / divisor)` in `R = D + 1`
/// words, without branching on the value.
///
/// The quotient estimated from the reciprocal falls short by at most one, since
/// `value * reciprocal / 2^(64 N)` is at least `value / divisor - value / 2^(64 N)`, so one
/// conditional subtraction of the divisor corrects the remainder.
const fn divide<const N: usize, const D: usize, const R: usize, const W: usize>(
    value: &[u64; N],
    divisor: &[u64; D],
    reciprocal: &[u64; R],
) -> ([u64; D], [u64; D]) {
    const { assert!(N == 2 * D && R == D + 1 && W == N + R) };
    let wide: [u64; W] = mul_words(value, reciprocal);
    let mut quotient = [0; D];
    let mut i = 0;
    while i < D {
        quotient[i] = wide[N + i];
        i += 1;
    }
    let product: [u64; N] = mul_words(&quotient, divisor);
    let (remainder, _) = sub_words(value, &product);
    let mut extended = [0; N];
    let mut i = 0;
    while i < D {
        extended[i] = divisor[i];
        i += 1;
    }
    let (reduced, borrow) = sub_words(&remainder, &extended);
    // Keep the remainder when it is below the divisor, and otherwise take the reduced one and
    // add one to the quotient.
    let keep = (borrow as u64).wrapping_neg();
    let mut corrected = [0; D];
    let mut carry = !keep & 1;
    let mut i = 0;
    while i < D {
        corrected[i] = (remainder[i] & keep) | (reduced[i] & !keep);
        let (sum, overflow) = quotient[i].overflowing_add(carry);
        quotient[i] = sum;
        carry = overflow as u64;
        i += 1;
    }
    (quotient, corrected)
}

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

    /// Reduces a little-endian integer of any length modulo the group order, without branching
    /// on its words.
    pub(crate) fn from_words_wide(words: &[u64]) -> Self {
        // Each chunk of four words enters Montgomery form by one multiplication, which accepts a
        // left operand below 2^256 when the right one is below r, and shifts the sum so far.
        let mut sum = Self::ZERO;
        for chunk in words.chunks(WORDS).rev() {
            let mut padded = [0; WORDS];
            padded[..chunk.len()].copy_from_slice(chunk);
            let chunk = Self(montgomery::mul(&padded, &R2, &MODULUS, INV));
            sum = sum.mul(SHIFT).add(chunk);
        }
        sum
    }

    /// Returns `[a, b]` with `a + b t` the canonical integer and `a, b < t`, for `t = x^2`,
    /// without branching on the value.
    ///
    /// Since `r = t^2 - t + 1`, the quotient by `t` is below `t`, so both halves fit in `128`
    /// bits.
    pub(crate) fn split(self) -> [u128; 2] {
        let (quotient, remainder) =
            divide::<WORDS, 2, 3, 7>(&self.to_words(), &X_SQUARED, &X_SQUARED_RECIPROCAL);
        [remainder, quotient].map(|words| words[0] as u128 | (words[1] as u128) << 64)
    }

    /// Returns `[a0, a1, b0, b1]` with `a = a0 + a1 |x|` and `b = b0 + b1 |x|` for the halves
    /// `[a, b]` of [`Self::split`] and every quarter below `|x|`, without branching on the
    /// value.
    pub(crate) fn split_quarters(self) -> [u64; 4] {
        let [a, b] = self.split();
        let mut quarters = [0; 4];
        for (half, quarters) in [a, b].iter().zip(quarters.as_chunks_mut::<2>().0) {
            let words = [*half as u64, (*half >> 64) as u64];
            let (quotient, remainder) = divide::<2, 1, 2, 4>(&words, &[X_ABS], &X_ABS_RECIPROCAL);
            *quarters = [remainder[0], quotient[0]];
        }
        quarters
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

#[cfg(any(test, feature = "fuzz"))]
impl<'a> arbitrary::Arbitrary<'a> for Scalar {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Bias towards the edges of the range, where carries and reductions happen, and towards
        // runs of zero and one bits, which become runs of zero digits and of carries in the
        // windows of a multiplication.
        Ok(match u.int_in_range(0u8..=7)? {
            0 => Self::from_u64(u.arbitrary()?),
            1 => Self::from_u64(u.arbitrary()?).neg(),
            2 => {
                let mut words = [0; WORDS];
                for word in &mut words {
                    *word = match u.int_in_range(0u8..=3)? {
                        0 => 0,
                        1 => u64::MAX,
                        2 => 1 << u.int_in_range(0u8..=63)?,
                        _ => u.arbitrary()?,
                    };
                }
                Self::from_words_wide(&words)
            }
            _ => Self::from_bytes_wide(&u.arbitrary()?),
        })
    }
}

/// Fuzzing operations for the scalar field.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::algebra::test_suites;
    use std::vec::Vec;

    /// A scalar field fuzzing operation.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks the laws of a field with roots of unity, and that doubling and squaring agree
        /// with addition and multiplication.
        Field,
        /// Checks that scalars round-trip through their encodings, and that exactly the integers
        /// below the order decode.
        Encoding,
        /// Checks that integers of any length reduce to the value of their digits.
        Wide,
        /// Checks that the components of a scalar reconstruct it within their bounds.
        Split,
    }

    /// Returns the big-endian encoding of the order.
    fn order() -> [u8; Scalar::BYTES] {
        let mut bytes = [0; Scalar::BYTES];
        for (chunk, word) in bytes
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(MODULUS.iter().rev())
        {
            *chunk = word.to_be_bytes();
        }
        bytes
    }

    /// Returns the value of big-endian digits in the given base, by Horner's rule.
    fn digits(base: Scalar, digits: impl Iterator<Item = u64>) -> Scalar {
        digits.fold(Scalar::ZERO, |sum, digit| {
            sum * &base + &Scalar::from_u64(digit)
        })
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Field => {
                    test_suites::fuzz_field_ntt::<Scalar>(u)?;
                    let a = Scalar::arbitrary(u)?;
                    let mut doubled = a;
                    Additive::double(&mut doubled);
                    assert_eq!(doubled, a + &a);
                    let mut squared = a;
                    Multiplicative::square(&mut squared);
                    assert_eq!(squared, a * &a);
                }
                Self::Encoding => {
                    let a = Scalar::arbitrary(u)?;
                    assert_eq!(Scalar::from_bytes(&a.to_bytes()), Some(a));
                    assert_eq!(Scalar::from_words(a.to_words()), Some(a));
                    let small: u64 = u.arbitrary()?;
                    assert_eq!(Scalar::from_u64(small).to_words(), [small, 0, 0, 0]);

                    // Strings that share a prefix of any length with the order straddle it.
                    let order = order();
                    let mut bytes: [u8; Scalar::BYTES] = u.arbitrary()?;
                    let shared = u.int_in_range(0..=Scalar::BYTES)?;
                    bytes[..shared].copy_from_slice(&order[..shared]);
                    // Big-endian strings of one length order as their integers do.
                    let canonical = bytes < order;
                    let decoded = Scalar::from_bytes(&bytes);
                    assert_eq!(decoded.is_some(), canonical);
                    if let Some(decoded) = decoded {
                        assert_eq!(decoded.to_bytes(), bytes);
                        let mut wide = [0; Scalar::WIDE_BYTES];
                        wide[Scalar::BYTES..].copy_from_slice(&bytes);
                        assert_eq!(decoded, Scalar::from_bytes_wide(&wide));
                    }
                }
                Self::Wide => {
                    let bytes: [u8; Scalar::WIDE_BYTES] = u.arbitrary()?;
                    assert_eq!(
                        Scalar::from_bytes_wide(&bytes),
                        digits(
                            Scalar::from_u64(1 << 8),
                            bytes.iter().map(|byte| (*byte).into())
                        )
                    );
                    // More words than the reduction handles in one step.
                    let count = u.int_in_range(0..=9)?;
                    let words = (0..count)
                        .map(|_| u.arbitrary())
                        .collect::<arbitrary::Result<Vec<u64>>>()?;
                    assert_eq!(
                        Scalar::from_words_wide(&words),
                        digits(
                            Scalar::from_u64(1 << 32).square(),
                            words.iter().rev().copied()
                        )
                    );
                }
                Self::Split => {
                    let t = Scalar::from_words([X_SQUARED[0], X_SQUARED[1], 0, 0])
                        .expect("below the order");
                    let x = Scalar::from_u64(X_ABS);
                    // Values at which a quotient or a remainder wraps, or arbitrary ones.
                    let value = match u.int_in_range(0u8..=7)? {
                        0 => t,
                        1 => t - &Scalar::ONE,
                        2 => t * &t,
                        3 => t * &t - &Scalar::ONE,
                        4 => x * &x * &x,
                        _ => Scalar::arbitrary(u)?,
                    };
                    let from_u128 = |value: u128| {
                        Scalar::from_words([value as u64, (value >> 64) as u64, 0, 0])
                            .expect("below the order")
                    };
                    let bound = X_SQUARED[0] as u128 | (X_SQUARED[1] as u128) << 64;
                    let [a, b] = value.split();
                    assert!(a < bound && b < bound);
                    assert_eq!(from_u128(a) + &(from_u128(b) * &t), value);
                    let [a0, a1, b0, b1] = value.split_quarters();
                    assert!([a0, a1, b0, b1].iter().all(|quarter| *quarter < X_ABS));
                    assert_eq!(a0 as u128 + a1 as u128 * X_ABS as u128, a);
                    assert_eq!(b0 as u128 + b1 as u128 * X_ABS as u128, b);
                }
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use commonware_invariants::minifuzz;
        use commonware_utils::test_rng;
        use rand_core::Rng as _;

        #[test]
        fn minifuzz_field() {
            minifuzz::test(|u| Plan::Field.run(u));
        }

        #[test]
        fn minifuzz_encoding() {
            minifuzz::test(|u| Plan::Encoding.run(u));
        }

        #[test]
        fn minifuzz_wide() {
            minifuzz::test(|u| Plan::Wide.run(u));
        }

        #[test]
        fn minifuzz_split() {
            minifuzz::test(|u| Plan::Split.run(u));
        }

        #[test]
        fn transform_constants_match_known_answers() {
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
            let half = core::array::from_fn(|i| {
                (half[i] >> 1) | half.get(i + 1).map_or(0, |next| next << 63)
            });
            assert_eq!(GENERATOR.pow(half), Scalar::ONE.neg());
        }

        #[test]
        fn order_bounds_the_encodings() {
            assert_eq!(Scalar::ZERO.to_bytes(), [0; Scalar::BYTES]);
            assert_eq!(Scalar::ONE.to_words(), [1, 0, 0, 0]);
            // The largest scalar is one less than the order.
            let mut largest = MODULUS;
            largest[0] -= 1;
            assert_eq!(Scalar::ONE.neg().to_words(), largest);
            assert_eq!(Scalar::from_words(largest), Some(Scalar::ONE.neg()));
            // The order itself, the next integer, and the largest string do not decode.
            assert!(Scalar::from_words(MODULUS).is_none());
            assert!(Scalar::from_bytes(&order()).is_none());
            let mut above = MODULUS;
            above[0] += 1;
            assert!(Scalar::from_words(above).is_none());
            assert!(Scalar::from_bytes(&[0xff; Scalar::BYTES]).is_none());
            // The order reduces to zero.
            assert_eq!(Scalar::from_words_wide(&MODULUS), Scalar::ZERO);
            let mut wide = [0; Scalar::WIDE_BYTES];
            wide[Scalar::BYTES..].copy_from_slice(&order());
            assert_eq!(Scalar::from_bytes_wide(&wide), Scalar::ZERO);
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
        fn endomorphism_constants() {
            let t: [u64; 2] = mul_words(&[X_ABS], &[X_ABS]);
            assert_eq!(t, X_SQUARED);
            // r = t^2 - t + 1.
            let mut order: [u64; 4] = mul_words(&t, &t);
            (order, _) = sub_words(&order, &[t[0], t[1], 0, 0]);
            order[0] += 1;
            assert_eq!(order, MODULUS);
            // The reciprocals are the floors of 2^256 / t and 2^128 / |x|: the products fall short
            // of the powers of two by less than the divisors.
            let product: [u64; 5] = mul_words(&X_SQUARED_RECIPROCAL, &t);
            assert_eq!(product[4], 0);
            let (short, borrow) = sub_words(&[0, 0, 0, 0], &product[..4].try_into().unwrap());
            assert!(borrow && short[2] == 0 && short[3] == 0);
            assert!(short[1] < t[1] || (short[1] == t[1] && short[0] < t[0]));
            let product: [u64; 3] = mul_words(&X_ABS_RECIPROCAL, &[X_ABS]);
            assert_eq!(product[2], 0);
            let (short, borrow) = sub_words(&[0, 0], &[product[0], product[1]]);
            assert!(borrow && short[1] == 0 && short[0] < X_ABS);
        }
    }
}
