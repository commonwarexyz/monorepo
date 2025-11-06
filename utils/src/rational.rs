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

        // Step 1: Extract numerator and denominator as unsigned integers for efficient computation.
        let numer = self.numer().to_biguint().expect("positive");
        let denom = self.denom().to_biguint().expect("positive");

        // Step 2: Compute the integer part of log2(numer/denom) by comparing bit lengths.
        // Since log2(numer/denom) = log2(numer) - log2(denom), and bits() gives us
        // floor(log2(x)) + 1, we can compute the integer part directly.
        let numer_bits = numer.bits();
        let denom_bits = denom.bits();
        let mut integer_part = numer_bits as i128 - denom_bits as i128;

        // Step 3: Align the most significant bits of numerator and denominator to bring
        // the ratio into the range [1, 2). By shifting both values to have the same bit
        // length, we normalize the ratio in a single operation.
        let mut normalized_numer = numer;
        if denom_bits > numer_bits {
            normalized_numer <<= denom_bits - numer_bits;
        }
        let mut normalized_denom = denom;
        if numer_bits > denom_bits {
            normalized_denom <<= numer_bits - denom_bits;
        }

        // After alignment, we may need one additional shift to ensure normalized value is in [1, 2).
        if normalized_numer < normalized_denom {
            normalized_numer <<= 1;
            integer_part -= 1;
        }
        assert!(
            normalized_numer >= normalized_denom && normalized_numer < (&normalized_denom << 1)
        );

        // Step 4: Handle the special case where the value is exactly a power of 2.
        // In this case, log2(x) is exact and has no fractional component.
        if normalized_numer == normalized_denom {
            let numerator = BigInt::from(integer_part) << binary_digits;
            let denominator = BigInt::one() << binary_digits;
            return BigRational::new(numerator, denominator);
        }

        // Step 5: Extract binary fractional digits using the square-and-compare method.
        // At this point, normalized is in (1, 2), so log2(normalized) is in (0, 1).
        // We use integer-only arithmetic to avoid BigRational division overhead:
        // Instead of squaring the rational and comparing to 2, we square the numerator
        // and denominator separately and check if numer^2 >= 2 * denom^2.
        let mut fractional_bits = BigInt::zero();
        let one = BigInt::one();

        for _ in 0..binary_digits {
            // Square both numerator and denominator to shift the next binary digit into position.
            let numer_squared = &normalized_numer * &normalized_numer;
            let denom_squared = &normalized_denom * &normalized_denom;

            // Left-shift the fractional bits accumulator to make room for the new bit.
            fractional_bits <<= 1;

            // If squared value >= 2, the next binary digit is 1.
            // We renormalize by dividing by 2, which is equivalent to multiplying the denominator by 2.
            let two_denom_squared = &denom_squared << 1;
            if numer_squared >= two_denom_squared {
                fractional_bits |= &one;
                normalized_numer = numer_squared;
                normalized_denom = two_denom_squared;
            } else {
                normalized_numer = numer_squared;
                normalized_denom = denom_squared;
            }
        }

        // Step 6: Combine integer and fractional parts, then apply ceiling operation.
        // We need to return a single rational number with denominator 2^binary_digits.
        // By left-shifting the integer part, we convert it to the same "units" as fractional_bits,
        // allowing us to add them: numerator = (integer_part * 2^binary_digits) + fractional_bits.
        // This represents: integer_part + fractional_bits / (2^binary_digits)
        let mut numerator = (BigInt::from(integer_part) << binary_digits) + fractional_bits;

        // If there's any leftover mass in the normalized value after extracting all digits,
        // we need to round up (ceiling operation). This happens when normalized_numer > normalized_denom.
        if normalized_numer > normalized_denom {
            numerator += &one;
        }

        let denominator = one << binary_digits;
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
    #[should_panic(expected = "log2 undefined for non-positive numbers")]
    fn log2_ceil_negative_panics() {
        <BigRational as num_traits::FromPrimitive>::from_i64(-1)
            .unwrap()
            .log2_ceil(8);
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

    #[test]
    fn log2_ceil_edge_cases() {
        // -- Just above a power of two (small positive, should round up to a tiny dyadic)
        // log2(17/16) ≈ 0.087462, k=8 → 0.087462 * 256 ≈ 22.39 ⇒ ceil = 23 → 23/256
        let x = BigRational::from_frac_u64(17, 16);
        assert_eq!(x.log2_ceil(8), BigRational::from_frac_u64(23, 256));

        // log2(129/128) ≈ 0.011227, k=8 → 0.011227 * 256 ≈ 2.874 ⇒ ceil = 3 → 3/256
        let x = BigRational::from_frac_u64(129, 128);
        assert_eq!(x.log2_ceil(8), BigRational::from_frac_u64(3, 256));

        // log2(33/32) ≈ 0.044394, k=10 → 0.044394 * 1024 ≈ 45.45 ⇒ ceil = 46 → 46/1024
        let x = BigRational::from_frac_u64(33, 32);
        assert_eq!(x.log2_ceil(10), BigRational::from_frac_u64(46, 1024));

        // -- Just below a power of two (negative, but tiny in magnitude)
        // log2(255/256) ≈ −0.00565, k=8 → −0.00565 * 256 ≈ −1.44 ⇒ ceil = −1 → −1/256
        let x = BigRational::from_frac_u64(255, 256);
        assert_eq!(x.log2_ceil(8), BigRational::new((-1).into(), 256u32.into()));

        // log2(1023/1024) ≈ −0.00141, k=9 → −0.00141 * 512 ≈ −0.72 ⇒ ceil = 0 → 0/512
        let x = BigRational::from_frac_u64(1023, 1024);
        assert_eq!(x.log2_ceil(9), BigRational::new(0.into(), 512u32.into()));

        // -- k = 0 (integer ceiling of log2)
        // log2(3/2) ≈ 0.585 ⇒ ceil = 1
        let x = BigRational::from_frac_u64(3, 2);
        assert_eq!(x.log2_ceil(0), BigRational::from_integer(1.into()));

        // log2(3/4) ≈ −0.415 ⇒ ceil = 0
        let x = BigRational::from_frac_u64(3, 4);
        assert_eq!(x.log2_ceil(0), BigRational::from_integer(0.into()));

        // -- x < 1 with fractional bits (negative dyadic output)
        // log2(3/4) ≈ −0.415, k=4 → −0.415 * 16 ≈ −6.64 => ceil = −6 → −6/16
        let x = BigRational::from_frac_u64(3, 4);
        assert_eq!(x.log2_ceil(4), BigRational::new((-6).into(), 16u32.into()));

        // -- Monotonic with k: increasing k refines the dyadic upwards
        // For 257/256: k=8 → 0.00563*256 ≈ 1.44 ⇒ ceil=2 → 2/256
        //              k=9 → 0.00563*512 ≈ 2.88 ⇒ ceil=3 → 3/512
        let x = BigRational::from_frac_u64(257, 256);
        assert_eq!(x.log2_ceil(8), BigRational::new(2.into(), 256u32.into()));
        assert_eq!(x.log2_ceil(9), BigRational::new(3.into(), 512u32.into()));

        // -- Scale invariance (multiply numerator and denominator by same factor, result unchanged)
        // (17/16) * (2^30 / 2^30) has the same log2, the dyadic result should match 23/256 at k=8.
        let num = BigInt::from(17u32) << 30;
        let den = BigInt::from(16u32) << 30;
        let x = BigRational::new(num, den);
        assert_eq!(x.log2_ceil(8), BigRational::from_frac_u64(23, 256));
    }
}
