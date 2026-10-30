use std::time::Duration;

const PROBABILITY_SCALE: u64 = 1 << 32;
const WEIGHT_SCALE: u128 = 1 << 40;

/// Exponentially weighted success probability and successful response latency.
///
/// For success probability `p`, successful latency `L`, and failure cost `F`, the service
/// rate is `p / (p * L + (1 - p) * F)`. Both estimates use half-weight updates. Failures
/// leave `L` unchanged; only observed service can improve the estimates.
#[derive(Clone, Copy, Debug)]
pub(super) struct Score {
    /// Success probability in units of 2^-32, including both zero and one.
    probability: u64,
    latency_ns: Option<u128>,
}

impl Default for Score {
    fn default() -> Self {
        Self {
            probability: PROBABILITY_SCALE,
            latency_ns: None,
        }
    }
}

impl Score {
    /// Moves success probability halfway toward one and averages successful response latency.
    /// The first successful response initializes latency; averages round down.
    pub(super) fn record_success(&mut self, elapsed: Duration) {
        self.probability = (self.probability + PROBABILITY_SCALE) / 2;
        let elapsed_ns = elapsed.as_nanos().max(1);
        self.latency_ns = Some(
            self.latency_ns
                .map_or(elapsed_ns, |latency_ns| (latency_ns + elapsed_ns) / 2),
        );
    }

    /// Halves success probability, rounding down, without changing successful latency.
    pub(super) const fn record_failure(&mut self) {
        self.probability /= 2;
    }

    /// Returns a positive sampling weight for successful responses per charged nanosecond.
    ///
    /// Unobserved latency uses the failure cost. Both durations are at least one nanosecond.
    pub(super) fn weight(&self, failure_cost: Duration) -> u64 {
        let failure_ns = failure_cost.as_nanos().max(1);
        let latency_ns = self.latency_ns.unwrap_or(failure_ns);
        let probability = u128::from(self.probability);
        let failure_probability = u128::from(PROBABILITY_SCALE - self.probability);

        // Duration nanoseconds are below 2^94. The coefficients sum to 2^32, so the
        // denominator is below 2^126 and at least 2^32. The numerator is at most 2^72,
        // making the weight at most 1 + 2^40.
        let denominator = probability * latency_ns + failure_probability * failure_ns;
        (1 + WEIGHT_SCALE * probability / denominator) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILURE_COST: Duration = Duration::from_millis(100);

    #[test]
    fn first_success_sets_latency() {
        let mut score = Score::default();
        assert_eq!(score.probability, PROBABILITY_SCALE);
        assert_eq!(score.latency_ns, None);
        assert_eq!(score.weight(FAILURE_COST), 10_996);

        score.record_success(Duration::from_millis(1));
        assert_eq!(score.probability, PROBABILITY_SCALE);
        assert_eq!(score.latency_ns, Some(1_000_000));
        assert_eq!(score.weight(FAILURE_COST), 1_099_512);
    }

    #[test]
    fn faster_successes_increase_weight() {
        let mut score = Score::default();
        score.record_success(Duration::from_millis(32));
        let initial = score.weight(FAILURE_COST);
        score.record_success(Duration::from_millis(8));
        let faster = score.weight(FAILURE_COST);
        assert_eq!(score.latency_ns, Some(20_000_000));
        assert!(faster > initial);

        score.record_success(Duration::from_millis(8));
        assert_eq!(score.latency_ns, Some(14_000_000));
        assert!(score.weight(FAILURE_COST) > faster);
    }

    #[test]
    fn failure_charges_cost_and_preserves_successful_latency() {
        let mut score = Score::default();
        score.record_success(Duration::from_millis(1));

        // A timeout or missing response supplies the same failure observation.
        score.record_failure();
        assert_eq!(score.probability, PROBABILITY_SCALE / 2);
        assert_eq!(score.latency_ns, Some(1_000_000));
        assert_eq!(score.weight(FAILURE_COST), 10_887);

        score.record_success(Duration::from_millis(1));
        assert_eq!(score.probability, 3 * PROBABILITY_SCALE / 4);
        assert_eq!(score.weight(FAILURE_COST), 32_025);
    }

    #[test]
    fn first_success_after_failure_sets_latency() {
        let mut score = Score::default();
        score.record_failure();
        assert_eq!(score.latency_ns, None);
        assert_eq!(score.weight(FAILURE_COST), 5_498);

        score.record_success(Duration::from_millis(1));
        assert_eq!(score.probability, 3 * PROBABILITY_SCALE / 4);
        assert_eq!(score.latency_ns, Some(1_000_000));
        assert_eq!(score.weight(FAILURE_COST), 32_025);
    }

    #[test]
    fn repeated_failures_reach_floor_and_success_recovers() {
        let mut score = Score::default();
        score.record_success(Duration::from_nanos(1));
        let mut previous = score.weight(FAILURE_COST);
        assert_eq!(previous, (1 << 40) + 1);

        for _ in 0..33 {
            score.record_failure();
            let weight = score.weight(FAILURE_COST);
            assert!(weight <= previous);
            previous = weight;
        }
        assert_eq!(score.probability, 0);
        assert_eq!(score.latency_ns, Some(1));
        assert_eq!(previous, 1);
        score.record_failure();
        assert_eq!(score.probability, 0);

        score.record_success(Duration::from_nanos(1));
        assert_eq!(score.probability, PROBABILITY_SCALE / 2);
        assert_eq!(score.weight(FAILURE_COST), 10_996);
    }

    #[test]
    fn successful_latency_averages_with_integer_rounding() {
        let mut score = Score::default();
        for (sample, expected) in [(10, 10), (30, 20), (6, 13), (2, 7)] {
            score.record_success(Duration::from_nanos(sample));
            assert_eq!(score.latency_ns, Some(expected));
        }
        assert_eq!(score.probability, PROBABILITY_SCALE);
        assert_eq!(score.weight(FAILURE_COST), 157_073_089_683);
    }

    #[test]
    fn zero_durations_use_one_nanosecond() {
        let mut score = Score::default();
        assert_eq!(score.weight(Duration::ZERO), (1 << 40) + 1);
        score.record_success(Duration::ZERO);
        assert_eq!(score.latency_ns, Some(1));
        assert_eq!(score.weight(Duration::ZERO), (1 << 40) + 1);

        for _ in 0..32 {
            score.record_failure();
        }
        assert_eq!(score.probability, 1);
        assert_eq!(score.weight(Duration::ZERO), 257);
        score.record_failure();
        assert_eq!(score.weight(Duration::ZERO), 1);
    }

    #[test]
    fn maximum_durations_and_probability_endpoints() {
        let mut score = Score::default();
        assert_eq!(score.weight(Duration::MAX), 1);
        score.record_success(Duration::MAX);
        score.record_success(Duration::MAX);
        assert_eq!(score.latency_ns, Some(Duration::MAX.as_nanos()));
        assert_eq!(score.weight(Duration::ZERO), 1);

        score.record_failure();
        assert_eq!(score.weight(Duration::MAX), 1);
        score.record_success(Duration::ZERO);
        assert_eq!(score.latency_ns, Some(Duration::MAX.as_nanos().div_ceil(2)));
        assert_eq!(score.weight(Duration::MAX), 1);

        for _ in 0..33 {
            score.record_failure();
        }
        assert_eq!(score.probability, 0);
        assert_eq!(score.weight(Duration::MAX), 1);
        assert_eq!(score.weight(Duration::ZERO), 1);
        score.record_success(Duration::MAX);
        assert_eq!(score.probability, PROBABILITY_SCALE / 2);
        assert_eq!(score.weight(Duration::MAX), 1);
    }
}
