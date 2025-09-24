//! Utilities for working with `num_rational::BigRational`.

use num_bigint::BigInt;
use num_rational::BigRational;

/// Extension trait adding convenience constructors for [`BigRational`].
pub trait BigRationalExt {
    /// Creates a [`BigRational`] from a `u64` numerator with denominator `1`.
    fn from_u64(value: u64) -> Self;

    /// Creates a [`BigRational`] from a `u128` numerator with denominator `1`.
    fn from_u128(value: u128) -> Self;

    /// Creates a [`BigRational`] from a `usize` numerator with denominator `1`.
    fn from_usize(value: usize) -> Self;
}

impl BigRationalExt for BigRational {
    fn from_u64(value: u64) -> Self {
        BigRational::from_integer(BigInt::from(value))
    }

    fn from_u128(value: u128) -> Self {
        BigRational::from_integer(BigInt::from(value))
    }

    fn from_usize(value: usize) -> Self {
        BigRational::from_integer(BigInt::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::BigRationalExt;
    use num_bigint::BigInt;
    use num_rational::BigRational;

    #[test]
    fn converts_from_u64() {
        let rational = BigRational::from_u64(42);
        assert_eq!(rational.numer(), &BigInt::from(42u64));
        assert_eq!(rational.denom(), &BigInt::from(1u32));
    }

    #[test]
    fn converts_from_u128() {
        let value = (u64::MAX as u128) + 10;
        let rational = BigRational::from_u128(value);
        assert_eq!(rational.numer(), &BigInt::from(value));
        assert_eq!(rational.denom(), &BigInt::from(1u32));
    }

    #[test]
    fn converts_from_usize() {
        let value = usize::MAX;
        let rational = BigRational::from_usize(value);
        assert_eq!(rational.numer(), &BigInt::from(value));
        assert_eq!(rational.denom(), &BigInt::from(1u32));
    }
}
