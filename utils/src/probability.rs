//! A platform-independent probability value and sampler.

use rand::Rng;

const SCALE: u128 = 1u128 << u64::BITS;

/// A probability represented as a threshold over all possible `u64` samples.
///
/// Ratios are rounded down to the nearest multiple of 2^-64. Sampling consumes one `u64` for
/// probabilities strictly between zero and one, and consumes no randomness for either endpoint.
/// Given the same sequence of `u64` samples, decisions are identical on every platform.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Probability(u64);

impl Probability {
    /// A probability that never occurs.
    pub const ZERO: Self = Self(0);

    /// A probability that always occurs.
    pub const ONE: Self = Self(u64::MAX);

    /// Creates a probability from `numerator / denominator`.
    ///
    /// Returns [`None`] if the denominator is zero or the numerator exceeds the denominator.
    pub const fn new(numerator: u64, denominator: u64) -> Option<Self> {
        if denominator == 0 || numerator > denominator {
            return None;
        }

        if numerator == denominator {
            return Some(Self::ONE);
        }

        let threshold = ((numerator as u128) << u64::BITS) / denominator as u128;

        // A proper fraction with a `u64` denominator is at least 2^-64 below one, so its rounded
        // threshold cannot collide with the sentinel reserved for `ONE`.
        debug_assert!(threshold < u64::MAX as u128);
        Some(Self(threshold as u64))
    }

    /// Returns whether this probability never occurs.
    pub const fn is_zero(self) -> bool {
        self.0 == Self::ZERO.0
    }

    /// Returns whether this probability always occurs.
    pub const fn is_one(self) -> bool {
        self.0 == Self::ONE.0
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
    pub fn sample(self, rng: &mut (impl Rng + ?Sized)) -> bool {
        match self.0 {
            0 => false,
            u64::MAX => true,
            threshold => rng.next_u64() < threshold,
        }
    }
}

/// Creates a [`Probability`] from an integer numerator and denominator.
///
/// Literal arguments are validated at compile time. Expression arguments are validated at
/// runtime.
///
/// # Panics
///
/// The expression form panics if the denominator is zero or the numerator exceeds the
/// denominator. Use [`Probability::new`] to validate untrusted values without panicking.
///
/// # Examples
///
/// ```
/// use commonware_utils::Probability;
///
/// const HALF: Probability = Probability!(1, 2);
/// assert_eq!(HALF.as_f64(), 0.5);
/// ```
///
/// ```compile_fail
/// use commonware_utils::Probability;
///
/// const INVALID: Probability = Probability!(2, 1);
/// ```
#[cfg(not(any(
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))] // BETA
#[macro_export]
macro_rules! Probability {
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
        assert_eq!(Probability::new(0, u64::MAX), Some(Probability::ZERO));
        assert_eq!(Probability::new(u64::MAX, u64::MAX), Some(Probability::ONE));
        assert_eq!(Probability!(1, 2), Probability!(2, 4));
        assert_eq!(Probability!(1, 2).as_f64(), 0.5);
        assert!(Probability::new(1, 0).is_none());
        assert!(Probability::new(2, 1).is_none());
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
        assert!(!Probability::ZERO.sample(&mut rng));
        assert!(Probability::ONE.sample(&mut rng));
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
