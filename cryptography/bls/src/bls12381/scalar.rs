//! Arithmetic modulo the prime order of the BLS12-381 groups.

use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use commonware_cryptography_vroom::{BlsScalar, Element};
use core::fmt;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
pub(crate) const ORDER: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

const X_ABS: u64 = 0xd201000000010000;
pub(super) const X_SQUARED: [u64; 2] = [0x0000000100000000, 0xac45a4010001a402];

fn multiply_words<const A: usize, const B: usize, const N: usize>(
    a: &[u64; A],
    b: &[u64; B],
) -> Zeroizing<[u64; N]> {
    const { assert!(N == A + B) };
    let mut result = Zeroizing::new([0; N]);
    for (i, &left) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &right) in b.iter().enumerate() {
            // A limb product plus an output limb and carry is at most 2^128 - 1.
            let product = (left as u128 * right as u128)
                .wrapping_add(result[i + j] as u128)
                .wrapping_add(carry);
            result[i + j] = product as u64;
            carry = product >> 64;
        }
        result[i + B] = carry as u64;
        carry.zeroize();
    }
    result
}

fn subtract_words<const N: usize>(a: &[u64; N], b: &[u64; N]) -> (Zeroizing<[u64; N]>, Choice) {
    let mut borrow = 0u64;
    let result = Zeroizing::new(core::array::from_fn(|i| {
        let (difference, first) = a[i].overflowing_sub(b[i]);
        let (difference, second) = difference.overflowing_sub(borrow);
        borrow = u64::from(first | second);
        difference
    }));
    let underflow = Choice::from(borrow as u8);
    borrow.zeroize();
    (result, underflow)
}

/// An integer modulo the prime group order, with a canonical 32-byte big-endian encoding.
///
/// Zero is a valid scalar. Protocols requiring a nonzero secret must enforce that requirement
/// separately. Debug output is redacted; callers can explicitly erase a value with [Zeroize].
#[derive(Clone, Copy, Zeroize)]
pub struct Scalar(pub(crate) Element<BlsScalar>);

impl Scalar {
    /// The additive identity.
    pub const ZERO: Self = Self(Element::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self(Element::ONE);

    /// Constructs a scalar from an unsigned integer.
    pub const fn from_u64(value: u64) -> Self {
        Self(Element::from_u64(value))
    }

    /// Decodes a canonical big-endian integer strictly below the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Element::from_bytes(bytes).map(Self)
    }

    /// Reduces a 512-bit big-endian integer modulo the group order.
    pub fn from_wide_bytes(bytes: &[u8; 64]) -> Self {
        Self(Element::from_bytes_mod_order(bytes))
    }

    /// Returns the canonical big-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    // For t = |x|^2, r = t^2 - t + 1, so k = a + b*t has a,b < t.
    // Multiplication by floor(2^256/t) underestimates k/t by at most one;
    // the full-width remainder is corrected before its high limbs are discarded.
    pub(crate) fn split_glv(&self) -> Zeroizing<[u128; 2]> {
        const RECIPROCAL: [u64; 3] = [0x63f6e522f6cfee2e, 0x7c6becf1e01faadd, 1];
        let bytes = Zeroizing::new(self.to_bytes());
        let words = Zeroizing::new(core::array::from_fn::<_, 4, _>(|i| {
            u64::from_be_bytes(bytes[24 - i * 8..32 - i * 8].try_into().unwrap())
        }));
        let wide = multiply_words::<4, 3, 7>(&words, &RECIPROCAL);
        let quotient = Zeroizing::new([wide[4], wide[5]]);
        let product = multiply_words::<2, 2, 4>(&quotient, &X_SQUARED);
        let (remainder, _) = subtract_words(&words, &product);
        let (reduced, borrow) = subtract_words(&remainder, &[X_SQUARED[0], X_SQUARED[1], 0, 0]);
        let correction = !borrow;
        let remainder = Zeroizing::new(core::array::from_fn::<_, 4, _>(|i| {
            u64::conditional_select(&remainder[i], &reduced[i], correction)
        }));
        Zeroizing::new([
            remainder[0] as u128 | (remainder[1] as u128) << 64,
            (quotient[0] as u128 | (quotient[1] as u128) << 64)
                .wrapping_add(correction.unwrap_u8() as u128),
        ])
    }

    // Each GLV component is below |x|^2. The same reciprocal argument at 128 bits
    // gives two base-|x| digits, retaining the extra bit of the reciprocal.
    pub(crate) fn split_gls(&self) -> Zeroizing<[u64; 4]> {
        const RECIPROCAL: [u64; 2] = [0x381204ca56cd56b5, 1];
        let components = self.split_glv();
        let mut result = Zeroizing::new([0; 4]);
        for (component, digits) in components.iter().zip(result.as_chunks_mut::<2>().0) {
            let words = Zeroizing::new([*component as u64, (*component >> 64) as u64]);
            let wide = multiply_words::<2, 2, 4>(&words, &RECIPROCAL);
            let mut product = wide[2] as u128 * X_ABS as u128;
            let product_words = Zeroizing::new([product as u64, (product >> 64) as u64]);
            product.zeroize();
            let (remainder, _) = subtract_words(&words, &product_words);
            let (reduced, borrow) = subtract_words(&remainder, &[X_ABS, 0]);
            let correction = !borrow;
            let remainder = Zeroizing::new(core::array::from_fn::<_, 2, _>(|i| {
                u64::conditional_select(&remainder[i], &reduced[i], correction)
            }));
            digits[0] = remainder[0];
            digits[1] = wide[2].wrapping_add(correction.unwrap_u8() as u64);
        }
        result
    }

    /// Returns whether this scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Adds two scalars modulo the group order.
    pub fn add(&self, rhs: &Self) -> Self {
        Self(self.0.add(rhs.0))
    }

    /// Subtracts two scalars modulo the group order.
    pub fn sub(&self, rhs: &Self) -> Self {
        Self(self.0.sub(rhs.0))
    }

    /// Returns the additive inverse.
    pub fn neg(&self) -> Self {
        Self(self.0.neg())
    }

    /// Multiplies two scalars modulo the group order.
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(self.0.mul(rhs.0))
    }

    /// Squares this scalar modulo the group order.
    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Returns the multiplicative inverse, or `None` for zero.
    ///
    /// Computation uses a fixed schedule; the returned variant reveals whether the input
    /// is zero.
    pub fn invert(&self) -> Option<Self> {
        self.0.invert().map(Self)
    }

    /// Returns a square root, or `None` for a nonsquare.
    ///
    /// Computation uses a fixed schedule; the returned variant reveals whether the input
    /// is a square.
    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(Self)
    }

    /// Returns whether this value is a square, including zero.
    ///
    /// Computation uses a fixed schedule.
    pub fn is_square(&self) -> bool {
        bool::from(self.0.is_square())
    }

    /// Constructs constant coordinates from canonical little-endian words.
    pub(crate) const fn from_raw(limbs: [u64; 4]) -> Self {
        Self(Element::from_raw(&limbs).expect("canonical field constant"))
    }

    /// Whether this representative is larger than its negation, in constant time.
    pub(crate) fn is_positive(&self) -> Choice {
        self.0.lexicographically_largest()
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar(REDACTED)")
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Scalar {}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Element::conditional_select(&a.0, &b.0, choice))
    }
}

impl Write for Scalar {
    fn write(&self, buf: &mut impl BufMut) {
        self.to_bytes().write(buf);
    }
}

impl FixedSize for Scalar {
    const SIZE: usize = 32;
}

impl Read for Scalar {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Self::from_bytes(&<[u8; 32]>::read_cfg(buf, cfg)?).ok_or(commonware_codec::Error::Invalid(
            "Scalar",
            "noncanonical integer",
        ))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Scalar {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0u8..=3)? {
            0 => Self::ZERO,
            1 => Self::ONE,
            2 => Self::ONE.neg(),
            _ => Self::from_wide_bytes(&u.arbitrary()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;
    use num_bigint::BigUint;
    use rand_core::Rng;

    fn order_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        for (chunk, word) in bytes
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(ORDER.iter().rev())
        {
            *chunk = word.to_be_bytes();
        }
        bytes
    }

    fn modulus() -> BigUint {
        BigUint::from_bytes_be(&order_bytes())
    }

    fn from_big(value: &BigUint) -> Scalar {
        let mut bytes = [0; 32];
        let encoded = value.to_bytes_be();
        bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        Scalar::from_bytes(&bytes).unwrap()
    }

    fn words_big(words: &[u64]) -> BigUint {
        words
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |value, word| (value << 64) + word)
    }

    #[test]
    fn integer_splits_match_biguint() {
        let r = modulus();
        let u = BigUint::from(X_ABS);
        let t = &u * &u;
        assert_eq!(words_big(&X_SQUARED), t);
        let mut values = alloc::vec![BigUint::from(0u8), BigUint::from(1u8), &r - 2u8, &r - 1u8];
        for power in [&u, &t, &(&t * &u)] {
            values.extend([power - 1u8, power.clone(), power + 1u8]);
        }
        let mut rng = test_rng();
        for _ in 0..256 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            values.push(BigUint::from_bytes_be(&bytes) % &r);
        }
        for value in values {
            let scalar = from_big(&value);
            let glv = scalar.split_glv();
            assert_eq!(BigUint::from(glv[0]), &value % &t);
            assert_eq!(BigUint::from(glv[1]), &value / &t);
            let gls = scalar.split_gls();
            assert!(gls.iter().all(|digit| *digit < X_ABS));
            assert_eq!(
                gls.iter()
                    .rev()
                    .fold(BigUint::from(0u8), |sum, digit| sum * &u + digit),
                value
            );
        }

        for _ in 0..64 {
            let a = core::array::from_fn::<_, 4, _>(|_| rng.next_u64());
            let b = core::array::from_fn::<_, 3, _>(|_| rng.next_u64());
            assert_eq!(
                words_big(&*multiply_words::<4, 3, 7>(&a, &b)),
                words_big(&a) * words_big(&b)
            );
        }
        assert_eq!(
            words_big(&*multiply_words::<4, 3, 7>(&[u64::MAX; 4], &[u64::MAX; 3])),
            words_big(&[u64::MAX; 4]) * words_big(&[u64::MAX; 3]),
        );
    }

    #[test]
    fn arithmetic_matches_biguint() {
        let modulus = modulus();
        let mut rng = test_rng();
        let mut values = alloc::vec![BigUint::from(0u8), BigUint::from(1u8), &modulus - 1u8];
        for bit in [63, 64, 127, 128, 191, 192, 254] {
            values.push(BigUint::from(1u8) << bit);
        }
        for _ in 0..64 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            values.push(BigUint::from_bytes_be(&bytes) % &modulus);
        }
        for a in &values {
            let scalar = from_big(a);
            assert_eq!(scalar.neg(), from_big(&((&modulus - a) % &modulus)));
            assert_eq!(scalar.square(), from_big(&((a * a) % &modulus)));
            if a == &BigUint::from(0u8) {
                assert!(scalar.invert().is_none());
            } else {
                assert_eq!(
                    scalar.invert().unwrap(),
                    from_big(&a.modpow(&(&modulus - 2u8), &modulus))
                );
            }
            for b in &values {
                let other = from_big(b);
                assert_eq!(scalar.add(&other), from_big(&((a + b) % &modulus)));
                assert_eq!(
                    scalar.sub(&other),
                    from_big(&((a + &modulus - b) % &modulus))
                );
                assert_eq!(scalar.mul(&other), from_big(&((a * b) % &modulus)));
            }
        }
    }

    #[test]
    fn wide_reduction_matches_biguint() {
        let mut rng = test_rng();
        for i in 0..256 {
            let mut bytes = [0xff; 64];
            if i != 0 {
                rng.fill_bytes(&mut bytes);
            }
            assert_eq!(
                Scalar::from_wide_bytes(&bytes),
                from_big(&(BigUint::from_bytes_be(&bytes) % modulus()))
            );
        }
    }

    #[test]
    fn square_roots_and_sign_match_biguint() {
        let modulus = modulus();
        let exponent = (&modulus - 1u8) >> 1;
        let mut rng = test_rng();
        let mut values = alloc::vec![
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::ONE.neg(),
            Scalar::from_u64(5)
        ];
        for _ in 0..128 {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            values.push(Scalar::from_wide_bytes(&bytes));
        }
        for value in values {
            let integer = BigUint::from_bytes_be(&value.to_bytes());
            let expected =
                value.is_zero() || integer.modpow(&exponent, &modulus) == BigUint::from(1u8);
            assert_eq!(value.is_square(), expected);
            assert_eq!(value.sqrt().is_some(), expected);
            if let Some(root) = value.sqrt() {
                assert_eq!(root.square(), value);
            }
            assert_eq!(value.square().sqrt().unwrap().square(), value.square());
            assert_eq!(
                bool::from(value.is_positive()),
                value.to_bytes() > value.neg().to_bytes()
            );
        }
        assert_eq!(Scalar::from_raw([0; 4]), Scalar::ZERO);
        assert_eq!(Scalar::from_raw([1, 0, 0, 0]), Scalar::ONE);
        assert!(Element::<BlsScalar>::from_raw(&ORDER).is_none());
    }

    #[test]
    fn canonical_codec_and_erasure() {
        for scalar in [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from_u64(u64::MAX),
            Scalar::ONE.neg(),
        ] {
            assert_eq!(Scalar::from_bytes(&scalar.to_bytes()), Some(scalar));
            assert_eq!(Scalar::decode(scalar.encode()).unwrap(), scalar);
            for len in 0..32 {
                assert!(Scalar::decode(scalar.to_bytes()[..len].to_vec()).is_err());
            }
        }
        for bytes in [order_bytes(), [0xff; 32]] {
            assert!(Scalar::from_bytes(&bytes).is_none());
            assert!(Scalar::decode(bytes.to_vec()).is_err());
        }
        let mut secret = Scalar::ONE.neg();
        assert_eq!(alloc::format!("{secret:?}"), "Scalar(REDACTED)");
        secret.zeroize();
        assert_eq!(secret, Scalar::ZERO);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::Scalar;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Scalar> => 1024,
        }
    }
}
