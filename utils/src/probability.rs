//! A platform-independent probability value and sampler.

use rand::Rng;

// Number of possible `u64` samples and denominator of the threshold grid.
const SCALE: u128 = 1u128 << u64::BITS;

// Biased `f64` exponent where scaling by 2^64 leaves the 53-bit significand unshifted.
const SCALED_EXPONENT: u64 = 1023 + 52 - 64;

/// Error returned when an `f64` cannot be represented as a probability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "probability must be finite, within [0, 1], and exactly representable as a 64-bit threshold"
)]
pub struct InvalidProbability;

/// A probability represented as a threshold over all possible `u64` samples.
///
/// Ratios are rounded down to the nearest multiple of 2^-64. Sampling consumes one `u64` for
/// probabilities strictly between zero and one, and consumes no randomness for either endpoint.
/// Given the same sequence of `u64` samples, decisions are identical on every platform.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Probability(u64);

impl Probability {
    /// Creates a probability from `numerator / denominator`.
    ///
    /// Returns [`None`] if the denominator is zero or the numerator exceeds the denominator.
    pub const fn new(numerator: u64, denominator: u64) -> Option<Self> {
        if denominator == 0 || numerator > denominator {
            return None;
        }

        if numerator == denominator {
            return Some(Self(u64::MAX));
        }

        let threshold = ((numerator as u128) << u64::BITS) / denominator as u128;

        // A proper fraction with a `u64` denominator is at least 2^-64 below one, so its rounded
        // threshold cannot collide with the sentinel reserved for probability one.
        assert!(threshold < u64::MAX as u128);
        Some(Self(threshold as u64))
    }

    /// Creates a probability from an `f64` that maps exactly to a 64-bit threshold.
    ///
    /// Returns [`None`] if `value` is not finite, is outside `[0, 1]`, or would require rounding.
    /// The exact IEEE-754 value is preserved rather than interpreting its source spelling as a
    /// decimal ratio. Use [`TryFrom`] when const evaluation is not required.
    pub const fn from_f64(value: f64) -> Option<Self> {
        let bits = value.to_bits();
        let magnitude = bits & (u64::MAX >> 1);

        if magnitude == 0 {
            return Some(Self(0));
        }
        if bits != magnitude || magnitude > 1.0f64.to_bits() {
            return None;
        }

        let exponent = magnitude >> 52;
        if exponent == 0 {
            return None;
        }
        let significand = (1u64 << 52) | (magnitude & ((1u64 << 52) - 1));
        if exponent < SCALED_EXPONENT {
            let shift = (SCALED_EXPONENT - exponent) as u32;
            if significand.trailing_zeros() < shift {
                return None;
            }
            return Some(Self(significand >> shift));
        }

        let threshold = (significand as u128) << (exponent - SCALED_EXPONENT);
        if threshold == SCALE {
            return Some(Self(u64::MAX));
        }

        // Exact one is handled above, so the narrowed threshold cannot use its reserved sentinel.
        assert!(threshold < u64::MAX as u128);
        Some(Self(threshold as u64))
    }

    /// Returns whether this probability never occurs.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns whether this probability always occurs.
    pub const fn is_one(self) -> bool {
        self.0 == u64::MAX
    }

    /// Converts this probability to an `f64` in the inclusive range `[0, 1]`.
    ///
    /// This conversion is intended for APIs that require floating-point probabilities. Interior
    /// probabilities remain strictly below one even when rounding to `f64`.
    pub fn as_f64(self) -> f64 {
        if self.is_one() {
            return 1.0;
        }

        let value = self.0 as f64 / SCALE as f64;
        if value == 1.0 {
            f64::from_bits(1.0f64.to_bits() - 1)
        } else {
            value
        }
    }

    /// Samples this probability using the next `u64` from `rng`.
    pub fn sample<R: Rng + ?Sized>(self, rng: &mut R) -> bool {
        match self.0 {
            0 => false,
            u64::MAX => true,
            threshold => rng.next_u64() < threshold,
        }
    }
}

impl TryFrom<f64> for Probability {
    type Error = InvalidProbability;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::from_f64(value).ok_or(InvalidProbability)
    }
}

/// Creates a [`Probability`] from an integer ratio or an exactly representable `f64`.
///
/// The two-argument form preserves the exact ratio. The one-argument form preserves the exact
/// IEEE-754 value and accepts only a literal that maps exactly to a 64-bit threshold. Ratio
/// literals are validated at compile time; ratio expressions are validated at runtime.
///
/// # Panics
///
/// The ratio expression form panics if its denominator is zero or its numerator exceeds the
/// denominator. Use [`Probability::new`] or [`Probability::try_from`] to validate untrusted values
/// without panicking.
///
/// # Examples
///
/// ```
/// use commonware_utils::Probability;
///
/// const HALF: Probability = Probability!(1, 2);
/// const NINETY_EIGHT_PERCENT: Probability = Probability!(0.98);
/// assert_eq!(HALF.as_f64(), 0.5);
/// assert_eq!(NINETY_EIGHT_PERCENT.as_f64(), 0.98);
/// ```
///
/// ```compile_fail
/// use commonware_utils::Probability;
///
/// const INVALID: Probability = Probability!(2, 1);
/// ```
///
/// ```compile_fail
/// use commonware_utils::Probability;
///
/// const REQUIRES_ROUNDING: Probability = Probability!(1e-20);
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! Probability {
    ($value:literal) => {
        const {
            $crate::Probability::from_f64($value).expect(
                "probability requires a value in [0, 1] exactly representable as a 64-bit threshold",
            )
        }
    };
    ($numerator:literal, $denominator:literal) => {
        const {
            $crate::Probability::new($numerator, $denominator)
                .expect("probability requires a non-zero denominator and numerator <= denominator")
        }
    };
    ($numerator:expr, $denominator:expr) => {
        $crate::Probability::new($numerator, $denominator)
            .expect("probability requires a non-zero denominator and numerator <= denominator")
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand::TryRng;

    struct CountingRng {
        value: u64,
        calls: usize,
    }

    impl TryRng for CountingRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.calls += 1;
            Ok(self.value as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.calls += 1;
            Ok(self.value)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            dst.fill(0);
            Ok(())
        }
    }

    #[test]
    fn construction() {
        assert_eq!(Probability::new(0, u64::MAX), Some(Probability!(0.0)));
        assert_eq!(
            Probability::new(u64::MAX, u64::MAX),
            Some(Probability!(1.0))
        );
        assert_eq!(Probability!(1, 2), Probability!(2, 4));
        assert_eq!(Probability!(1, 2).as_f64(), 0.5);
        assert!(Probability::new(1, 0).is_none());
        assert!(Probability::new(2, 1).is_none());
    }

    #[test]
    fn f64_construction_preserves_clean_binary_value() {
        const FROM_LITERAL: Probability = Probability!(0.98);
        const MINIMUM_INTERIOR: f64 = f64::from_bits(959u64 << 52);

        assert_eq!(FROM_LITERAL.0, 18_077_809_192_235_360_256);
        assert_eq!(FROM_LITERAL.as_f64(), 0.98);
        assert_ne!(FROM_LITERAL, Probability!(49, 50));
        assert_eq!(Probability!(0.5), Probability!(1, 2));
        assert_eq!(Probability::try_from(0.5), Ok(Probability!(0.5)));
        assert_eq!(Probability::from_f64(0.0), Some(Probability!(0.0)));
        assert_eq!(Probability::from_f64(-0.0), Some(Probability!(0.0)));
        assert_eq!(Probability::from_f64(1.0), Some(Probability!(1.0)));
        assert_eq!(
            Probability::from_f64(MINIMUM_INTERIOR),
            Some(Probability(1))
        );

        let below_one = f64::from_bits(1.0f64.to_bits() - 1);
        assert_eq!(
            Probability::from_f64(below_one).unwrap().as_f64(),
            below_one
        );
    }

    #[test]
    fn f64_construction_rejects_lossy_or_invalid_values() {
        const BELOW_MINIMUM: f64 = f64::from_bits(958u64 << 52);
        const MINIMUM_INTERIOR_BITS: u64 = 959u64 << 52;

        for value in [
            BELOW_MINIMUM,
            f64::from_bits(MINIMUM_INTERIOR_BITS + 1),
            f64::from_bits(1),
            -0.1,
            1.1,
            f64::from_bits(1.0f64.to_bits() + 1),
            f64::NAN,
            f64::from_bits(f64::NAN.to_bits() | (1u64 << 63)),
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            assert!(Probability::from_f64(value).is_none());
            assert_eq!(Probability::try_from(value), Err(InvalidProbability));
        }
    }

    #[test]
    fn representation_matches_a_raw_rate() {
        assert_eq!(core::mem::size_of::<Probability>(), size_of::<u64>());
    }

    #[test]
    fn ratios_use_platform_independent_thresholds() {
        assert_eq!(Probability!(1, 3).0 as u128, SCALE / 3);
        assert_eq!(Probability!(2, 3).0 as u128, (2 * SCALE) / 3);

        let below_one = Probability::new(u64::MAX - 1, u64::MAX).unwrap();
        assert_eq!(below_one.0, u64::MAX - 1);
        assert!(below_one.as_f64() < 1.0);
    }

    #[test]
    fn sampling_uses_threshold_and_skips_endpoints() {
        let mut rng = CountingRng { value: 0, calls: 0 };
        assert!(!Probability!(0.0).sample(&mut rng));
        assert!(Probability!(1.0).sample(&mut rng));
        assert_eq!(rng.calls, 0);

        rng.value = (1u64 << 63) - 1;
        assert!(Probability!(1, 2).sample(&mut rng));
        assert_eq!(rng.calls, 1);

        rng.value = 1u64 << 63;
        assert!(!Probability!(1, 2).sample(&mut rng));
        assert_eq!(rng.calls, 2);
    }

    #[test]
    #[should_panic(
        expected = "probability requires a non-zero denominator and numerator <= denominator"
    )]
    fn expression_macro_rejects_invalid_probability() {
        let numerator = 2;
        let denominator = 1;
        let _ = Probability!(numerator, denominator);
    }
}
