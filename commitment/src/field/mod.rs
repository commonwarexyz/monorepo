//! Binary extension field arithmetic over GF(2^n).
//!
//! Provides field element types and polynomial representations for
//! GF(2^16), GF(2^32), GF(2^64), and GF(2^128). These are the
//! algebraic building blocks for the commitment scheme.

mod elem;
#[allow(dead_code)]
pub(crate) mod fast_inverse;
mod poly;
#[allow(dead_code)]
pub(crate) mod simd;

pub use elem::{BinaryElem128, BinaryElem16, BinaryElem32, BinaryElem64};
pub use poly::{BinaryPoly128, BinaryPoly16, BinaryPoly256, BinaryPoly32, BinaryPoly64};

/// Arithmetic in a binary extension field GF(2^n).
///
/// Elements are represented as polynomials over GF(2) reduced modulo
/// an irreducible polynomial. Addition is XOR; multiplication uses
/// carry-less multiplication with reduction.
pub trait BinaryFieldElement:
    Sized + Copy + Clone + Default + PartialEq + Eq + core::fmt::Debug + Send + Sync
{
    /// The polynomial representation type.
    type Poly: BinaryPolynomial;

    /// The additive identity.
    fn zero() -> Self;

    /// The multiplicative identity.
    fn one() -> Self;

    /// Construct from a polynomial representation.
    fn from_poly(poly: Self::Poly) -> Self;

    /// Extract the polynomial representation.
    fn poly(&self) -> Self::Poly;

    /// Addition (XOR in binary fields).
    fn add(&self, other: &Self) -> Self;

    /// Multiplication with reduction.
    fn mul(&self, other: &Self) -> Self;

    /// Multiplicative inverse (panics on zero).
    fn inv(&self) -> Self;

    /// Exponentiation by squaring.
    fn pow(&self, exp: u64) -> Self;

    /// Construct from a bit pattern interpreted as polynomial coefficients.
    ///
    /// Bit `i` of `bits` sets the coefficient of x^i, where x is the
    /// generator of the field extension.
    fn from_bits(bits: u64) -> Self {
        let mut result = Self::zero();
        let mut power = Self::one();
        let generator = Self::from_poly(Self::Poly::from_value(2));

        for i in 0..64 {
            if (bits >> i) & 1 == 1 {
                result = result.add(&power);
            }
            if i < 63 {
                power = power.mul(&generator);
            }
        }
        result
    }
}

/// Polynomial over GF(2).
pub trait BinaryPolynomial:
    Sized + Copy + Clone + Default + PartialEq + Eq + core::fmt::Debug
{
    /// The underlying value type.
    type Value: Copy + Clone + core::fmt::Debug;

    /// The zero polynomial.
    fn zero() -> Self;

    /// The constant polynomial 1.
    fn one() -> Self;

    /// Construct from a raw integer value.
    fn from_value(val: u64) -> Self;

    /// Extract the raw integer value.
    fn value(&self) -> Self::Value;

    /// Polynomial addition (XOR).
    fn add(&self, other: &Self) -> Self;

    /// Polynomial multiplication (carry-less).
    fn mul(&self, other: &Self) -> Self;

    /// Polynomial division with remainder.
    fn div_rem(&self, other: &Self) -> (Self, Self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_axioms() {
        macro_rules! test_field {
            ($elem:ty, $val1:expr, $val2:expr, $val3:expr) => {
                let a = <$elem>::from_value($val1);
                let b = <$elem>::from_value($val2);
                let c = <$elem>::from_value($val3);

                // Associativity
                assert_eq!(a.add(&b.add(&c)), a.add(&b).add(&c));
                assert_eq!(a.mul(&b.mul(&c)), a.mul(&b).mul(&c));

                // Commutativity
                assert_eq!(a.add(&b), b.add(&a));
                assert_eq!(a.mul(&b), b.mul(&a));

                // Distributivity
                assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));

                // Identities
                assert_eq!(a.add(&<$elem>::zero()), a);
                assert_eq!(a.mul(&<$elem>::one()), a);

                // Self-inverse (char 2)
                assert_eq!(a.add(&a), <$elem>::zero());

                // Multiplicative inverse
                if a != <$elem>::zero() {
                    assert_eq!(a.mul(&a.inv()), <$elem>::one());
                }
            };
        }

        test_field!(BinaryElem16, 0x1234, 0x5678, 0x9ABC);
        test_field!(BinaryElem32, 0x12345678, 0x9ABCDEF0, 0x11111111);
        test_field!(
            BinaryElem128,
            0x123456789ABCDEF0123456789ABCDEF0,
            0xFEDCBA9876543210FEDCBA9876543210,
            0x1111111111111111111111111111111
        );
    }

    #[test]
    fn test_from_bits() {
        let elem = BinaryElem16::from_bits(0b11);
        let expected = BinaryElem16::from_value(1).add(&BinaryElem16::from_value(2));
        assert_eq!(elem, expected);
    }

    #[test]
    #[should_panic(expected = "Cannot invert zero")]
    fn test_zero_inverse_panics() {
        let _ = BinaryElem16::zero().inv();
    }
}
