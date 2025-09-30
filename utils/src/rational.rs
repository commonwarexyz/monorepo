//! Utilities for working with `num_rational::BigRational`.

use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{ToPrimitive, Zero};

/// Extension trait adding convenience constructors for [`BigRational`].
pub trait BigRationalExt {
    /// Creates a [`BigRational`] from a `u64` numerator with denominator `1`.
    fn from_u64(value: u64) -> Self;

    /// Creates a [`BigRational`] from a `u64` numerator and denominator.
    fn from_frac_u64(numerator: u64, denominator: u64) -> Self;

    /// Creates a [`BigRational`] from a `u128` numerator with denominator `1`.
    fn from_u128(value: u128) -> Self;

    /// Creates a [`BigRational`] from a `u128` numerator and denominator.
    fn from_frac_u128(numerator: u128, denominator: u128) -> Self;

    /// Returns the ceiling of the rational value as `u128`, saturating and treating negative values as zero.
    fn ceil_to_u128(&self) -> Option<u128>;

    /// Creates a [`BigRational`] from a `usize` numerator with denominator `1`.
    fn from_usize(value: usize) -> Self;

    /// Creates a [`BigRational`] from a `usize` numerator and denominator.
    fn from_frac_usize(numerator: usize, denominator: usize) -> Self;
}

impl BigRationalExt for BigRational {
    fn from_u64(value: u64) -> Self {
        BigRational::from_integer(BigInt::from(value))
    }

    fn from_frac_u64(numerator: u64, denominator: u64) -> Self {
        BigRational::new(BigInt::from(numerator), BigInt::from(denominator))
    }

    fn from_u128(value: u128) -> Self {
        BigRational::from_integer(BigInt::from(value))
    }

    fn from_frac_u128(numerator: u128, denominator: u128) -> Self {
        BigRational::new(BigInt::from(numerator), BigInt::from(denominator))
    }

    fn ceil_to_u128(&self) -> Option<u128> {
        if self < &BigRational::zero() {
            return Some(0);
        }

        let den = self.denom();
        if den.is_zero() {
            return None;
        }

        let (quot, rem) = self.numer().div_rem(den);
        let mut result = quot.to_u128().unwrap_or(u128::MAX);
        if !rem.is_zero() {
            result = result.saturating_add(1);
        }
        Some(result)
    }

    fn from_usize(value: usize) -> Self {
        BigRational::from_integer(BigInt::from(value))
    }

    fn from_frac_usize(numerator: usize, denominator: usize) -> Self {
        BigRational::new(BigInt::from(numerator), BigInt::from(denominator))
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
    fn converts_from_frac_u64() {
        let rational = BigRational::from_frac_u64(6, 8);
        assert_eq!(rational.numer(), &BigInt::from(3u32));
        assert_eq!(rational.denom(), &BigInt::from(4u32));
    }

    #[test]
    fn converts_from_u128() {
        let value = (u64::MAX as u128) + 10;
        let rational = BigRational::from_u128(value);
        assert_eq!(rational.numer(), &BigInt::from(value));
        assert_eq!(rational.denom(), &BigInt::from(1u32));
    }

    #[test]
    fn converts_from_frac_u128() {
        let rational = BigRational::from_frac_u128(10, 4);
        assert_eq!(rational.numer(), &BigInt::from(5u32));
        assert_eq!(rational.denom(), &BigInt::from(2u32));
    }

    #[test]
    fn converts_from_usize() {
        let value = usize::MAX;
        let rational = BigRational::from_usize(value);
        assert_eq!(rational.numer(), &BigInt::from(value));
        assert_eq!(rational.denom(), &BigInt::from(1u32));
    }

    #[test]
    fn converts_from_frac_usize() {
        let rational = BigRational::from_frac_usize(48, 18);
        assert_eq!(rational.numer(), &BigInt::from(8u32));
        assert_eq!(rational.denom(), &BigInt::from(3u32));
    }

    #[test]
    fn ceiling_handles_positive_fraction() {
        let value = BigRational::new(BigInt::from(5u32), BigInt::from(2u32));
        assert_eq!(value.ceil_to_u128(), Some(3));
    }

    #[test]
    fn ceiling_handles_negative() {
        let value = BigRational::new(BigInt::from(-3i32), BigInt::from(2u32));
        assert_eq!(value.ceil_to_u128(), Some(0));
    }

    #[test]
    fn ceiling_handles_large_values() {
        let value = BigRational::from_u128(u128::MAX - 1);
        assert_eq!(value.ceil_to_u128(), Some(u128::MAX - 1));
    }
}
