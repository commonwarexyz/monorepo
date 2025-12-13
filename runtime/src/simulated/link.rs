//! Network link configuration for simulated connections.

use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::time::Duration;

/// Describes network conditions for a simulated link between two endpoints.
///
/// Links are unidirectional - to simulate bidirectional communication with
/// different characteristics in each direction, configure two separate links.
///
/// # Fields
///
/// - `latency`: Mean delay for message delivery
/// - `jitter`: Standard deviation of the latency (sampled from normal distribution)
/// - `success_rate`: Probability that a message is delivered (0.0 to 1.0)
///
/// # Example
///
/// ```
/// use commonware_runtime::simulated::Link;
/// use std::time::Duration;
///
/// // High-quality link: 10ms latency, 2ms jitter, 99.9% delivery
/// let good_link = Link::new(
///     Duration::from_millis(10),
///     Duration::from_millis(2),
///     0.999,
/// );
///
/// // Lossy link: 100ms latency, 50ms jitter, 80% delivery
/// let lossy_link = Link::new(
///     Duration::from_millis(100),
///     Duration::from_millis(50),
///     0.80,
/// );
/// ```
#[derive(Clone, Debug)]
pub struct Link {
    /// Mean latency for message delivery.
    pub latency: Duration,

    /// Standard deviation of the latency (jitter).
    ///
    /// The actual latency is sampled from a normal distribution with
    /// mean `latency` and standard deviation `jitter`. Negative samples
    /// are clamped to zero.
    pub jitter: Duration,

    /// Probability of successful delivery (in range \[0,1\]).
    ///
    /// A value of 1.0 means all messages are delivered, 0.0 means none are.
    /// Values outside this range will cause panics when sampling.
    pub success_rate: f64,
}

impl Default for Link {
    fn default() -> Self {
        Self {
            latency: Duration::ZERO,
            jitter: Duration::ZERO,
            success_rate: 1.0,
        }
    }
}

impl Link {
    /// Create a new link with the given parameters.
    ///
    /// # Panics
    ///
    /// Panics if `success_rate` is not in the range \[0, 1\].
    pub fn new(latency: Duration, jitter: Duration, success_rate: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&success_rate),
            "success_rate must be in range [0, 1], got {success_rate}"
        );
        Self {
            latency,
            jitter,
            success_rate,
        }
    }

    /// Sample the actual latency based on the configured latency and jitter.
    ///
    /// Returns a duration sampled from a normal distribution with mean `latency`
    /// and standard deviation `jitter`. The result is clamped to be non-negative.
    pub fn sample_latency<R: Rng>(&self, rng: &mut R) -> Duration {
        if self.jitter.is_zero() {
            return self.latency;
        }

        let latency_ms = self.latency.as_secs_f64() * 1000.0;
        let jitter_ms = self.jitter.as_secs_f64() * 1000.0;

        // Create normal distribution centered at latency with std dev of jitter
        let sampler = Normal::new(latency_ms, jitter_ms).unwrap();
        let sampled_ms = sampler.sample(rng).max(0.0);
        Duration::from_secs_f64(sampled_ms / 1000.0)
    }

    /// Determine if a message should be delivered based on success_rate.
    ///
    /// Returns `true` if the message should be delivered, `false` if it should be dropped.
    pub fn should_deliver<R: Rng>(&self, rng: &mut R) -> bool {
        if self.success_rate >= 1.0 {
            return true;
        }
        if self.success_rate <= 0.0 {
            return false;
        }
        rng.gen_bool(self.success_rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn default_link_is_perfect() {
        let link = Link::default();
        assert_eq!(link.latency, Duration::ZERO);
        assert_eq!(link.jitter, Duration::ZERO);
        assert!((link.success_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sample_latency_without_jitter() {
        let link = Link::new(Duration::from_millis(50), Duration::ZERO, 1.0);
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        for _ in 0..100 {
            let latency = link.sample_latency(&mut rng);
            assert_eq!(latency, Duration::from_millis(50));
        }
    }

    #[test]
    fn sample_latency_with_jitter() {
        let link = Link::new(Duration::from_millis(100), Duration::from_millis(20), 1.0);
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let mut sum_ms = 0.0;
        let samples = 1000;

        for _ in 0..samples {
            let latency = link.sample_latency(&mut rng);
            sum_ms += latency.as_secs_f64() * 1000.0;
        }

        // Mean should be close to 100ms
        let mean = sum_ms / samples as f64;
        assert!(
            (mean - 100.0).abs() < 5.0,
            "mean latency {mean}ms should be close to 100ms"
        );
    }

    #[test]
    fn should_deliver_always_with_full_success() {
        let link = Link::new(Duration::ZERO, Duration::ZERO, 1.0);
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        for _ in 0..100 {
            assert!(link.should_deliver(&mut rng));
        }
    }

    #[test]
    fn should_deliver_never_with_zero_success() {
        let link = Link::new(Duration::ZERO, Duration::ZERO, 0.0);
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        for _ in 0..100 {
            assert!(!link.should_deliver(&mut rng));
        }
    }

    #[test]
    fn should_deliver_probabilistic() {
        let link = Link::new(Duration::ZERO, Duration::ZERO, 0.5);
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let mut delivered = 0;
        let samples = 1000;

        for _ in 0..samples {
            if link.should_deliver(&mut rng) {
                delivered += 1;
            }
        }

        // Should be roughly 50% with some tolerance
        let rate = delivered as f64 / samples as f64;
        assert!(
            (rate - 0.5).abs() < 0.1,
            "delivery rate {rate} should be close to 0.5"
        );
    }

    #[test]
    #[should_panic(expected = "success_rate must be in range")]
    fn panics_on_invalid_success_rate_high() {
        Link::new(Duration::ZERO, Duration::ZERO, 1.5);
    }

    #[test]
    #[should_panic(expected = "success_rate must be in range")]
    fn panics_on_invalid_success_rate_negative() {
        Link::new(Duration::ZERO, Duration::ZERO, -0.1);
    }
}
