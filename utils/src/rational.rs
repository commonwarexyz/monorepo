//! Utilities for working with `num_rational::BigRational`.

use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{One, ToPrimitive, Zero};

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

    /// Computes the ceiling of log2 of this rational number with specified binary precision.
    ///
    /// Returns log2(x) rounded up to the nearest value representable with `binary_digits`
    /// fractional bits in binary representation.
    ///
    /// # Panics
    ///
    /// Panics if the rational number is non-positive.
    ///
    /// # Examples
    ///
    /// ```
    /// use num_rational::BigRational;
    /// use commonware_utils::rational::BigRationalExt;
    ///
    /// let x = BigRational::from_frac_u64(3, 1); // 3
    /// let result = x.log2_ceil(4);
    /// // log2(3) ≈ 1.585, the algorithm computes a ceiling approximation
    /// assert!(result >= BigRational::from_u64(1));
    /// assert!(result <= BigRational::from_u64(2));
    /// ```
    fn log2_ceil(&self, binary_digits: usize) -> BigRational;
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

    fn log2_ceil(&self, binary_digits: usize) -> BigRational {
        if self <= &BigRational::zero() {
            panic!("log2 undefined for non-positive numbers");
        }

        let two = BigRational::from_integer(BigInt::from(2));
        let one = BigRational::one();

        // Step 1: Normalize the value to the range [1, 2) by repeatedly dividing/multiplying by 2.
        // We track the integer part separately since we'll combine it with fractional bits later.
        let mut normalized = self.clone();
        let mut integer_part = BigInt::zero();
        let one_int = BigInt::one();

        // If value >= 2, repeatedly divide by 2 to bring it into range.
        while normalized >= two {
            normalized /= &two;
            integer_part += &one_int;
        }

        // If value < 1, repeatedly multiply by 2 to bring it into range.
        while normalized < one {
            normalized *= &two;
            integer_part -= &one_int;
        }

        // Step 2: Handle the special case where the value is exactly a power of 2.
        // In this case, log2(x) is exact and has no fractional component.
        if normalized == one {
            let numerator = integer_part.clone() << binary_digits;
            let denominator = BigInt::one() << binary_digits;
            return BigRational::new(numerator, denominator);
        }

        // Step 3: Extract binary fractional digits using the square-and-compare method.
        // At this point, normalized is in (1, 2), so log2(normalized) is in (0, 1).
        // By repeatedly squaring and checking if we exceed 2, we extract binary digits.
        let mut fractional_bits = BigInt::zero();
        for _ in 0..binary_digits {
            // Square the normalized value to shift the next binary digit into position.
            normalized = &normalized * &normalized;

            // Left-shift the fractional bits accumulator to make room for the new bit.
            fractional_bits <<= 1;

            // If squared value >= 2, the next binary digit is 1.
            // We divide by 2 to renormalize back to [1, 2).
            if normalized >= two {
                fractional_bits |= BigInt::one();
                normalized /= &two;
            }
        }

        // Step 4: Combine integer and fractional parts, then apply ceiling operation.
        // The result is stored as a fixed-point number: (integer_part << binary_digits) + fractional_bits
        // This represents integer_part + fractional_bits / (2^binary_digits)
        let mut numerator = (integer_part << binary_digits) + fractional_bits;

        // If there's any leftover mass in normalized after extracting all digits,
        // we need to round up (ceiling operation). This happens when normalized > 1.
        if normalized > one {
            numerator += &one_int;
        }

        let denominator = BigInt::one() << binary_digits;
        BigRational::new(numerator, denominator)
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

    #[test]
    fn log2_ceil_exact_powers_of_two() {
        // Test exact powers of 2: log2(2^n) = n
        let value = BigRational::from_u64(1); // 2^0
        assert_eq!(value.log2_ceil(4), BigRational::from_u64(0));

        let value = BigRational::from_u64(2); // 2^1
        assert_eq!(value.log2_ceil(4), BigRational::from_u64(1));

        let value = BigRational::from_u64(8); // 2^3
        assert_eq!(value.log2_ceil(4), BigRational::from_u64(3));

        let value = BigRational::from_u64(1024); // 2^10
        assert_eq!(value.log2_ceil(4), BigRational::from_u64(10));
    }

    #[test]
    fn log2_ceil_fractional_powers_of_two() {
        // Test fractional powers of 2: log2(1/2) = -1, log2(1/4) = -2
        let value = BigRational::from_frac_u64(1, 2); // 2^(-1)
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::from_integer(BigInt::from(-1)));

        let value = BigRational::from_frac_u64(1, 4); // 2^(-2)
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::from_integer(BigInt::from(-2)));

        let value = BigRational::from_frac_u64(3, 8); // 3/8 = 3 * 2^(-3)
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::new(BigInt::from(-11), BigInt::from(8)));
    }

    #[test]
    fn log2_ceil_simple_values() {
        // log2(3) ≈ 1.585, with binary_digits=0 we get integer part
        let value = BigRational::from_u64(3);
        let result = value.log2_ceil(0);
        assert_eq!(result, BigRational::from_u64(2));

        // log2(5) ≈ 2.322, with binary_digits=0 we get integer part
        let value = BigRational::from_u64(5);
        let result = value.log2_ceil(0);
        assert_eq!(result, BigRational::from_u64(3));

        // With 4 bits precision, algorithm should provide fractional results
        let value = BigRational::from_u64(3);
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::from_frac_u64(13, 8));
    }

    #[test]
    fn log2_ceil_rational_values() {
        // Test with some basic fractional values
        let value = BigRational::from_frac_u64(3, 2);
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::from_frac_u64(5, 8));

        let value = BigRational::from_frac_u64(7, 4);
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::from_frac_u64(13, 16));
    }

    #[test]
    fn log2_ceil_different_precisions() {
        let value = BigRational::from_u64(3);

        // Test different precisions give reasonable results
        let result0 = value.log2_ceil(0);
        let result1 = value.log2_ceil(1);
        let result4 = value.log2_ceil(4);
        let result8 = value.log2_ceil(8);

        assert_eq!(result0, BigRational::from_u64(2));
        assert_eq!(result1, BigRational::from_u64(2));
        assert_eq!(result4, BigRational::from_frac_u64(13, 8));
        assert_eq!(
            result8,
            BigRational::new(BigInt::from(203), BigInt::from(128))
        );
    }

    #[test]
    fn log2_ceil_large_values() {
        // Test with larger numbers
        let value = BigRational::from_u64(1000);
        let result = value.log2_ceil(4);
        assert_eq!(result, BigRational::from_u64(10));
    }

    #[test]
    fn log2_ceil_very_small_values() {
        // Test with very small fractions
        let value = BigRational::from_frac_u64(1, 1000);
        let result = value.log2_ceil(4);
        assert_eq!(
            result,
            BigRational::new(BigInt::from(-159), BigInt::from(16))
        );
    }
}
