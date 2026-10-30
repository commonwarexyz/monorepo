use commonware_utils::time::NANOS_PER_SEC;
use std::time::Duration;

/// Keeps 32 fractional bits in byte averages so even one-byte responses can rebuild
/// a score after repeated failures.
const BYTE_SCALE: u128 = 1 << 32;

/// Exponentially weighted estimate of useful bytes per charged second.
///
/// Each observation moves the byte and duration averages halfway toward its samples, and the
/// weight divides one average by the other. The averages do not decay between observations. A
/// zero-byte observation never raises the weight, and an observation with bytes can lower it when
/// its byte rate is below the current estimate.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Score {
    /// Mean bytes in units of 2^-32 and mean charged nanoseconds, initialized together.
    averages: Option<(u128, u128)>,
}

impl Score {
    /// Records useful bytes and their charged duration, floored at one nanosecond.
    /// The first observation initializes both estimates. Later averages round down.
    pub(super) fn record(&mut self, elapsed: Duration, bytes: usize) {
        let bytes = (bytes as u128) * BYTE_SCALE;
        let elapsed_ns = elapsed.as_nanos().max(1);
        self.averages = Some(match self.averages {
            Some((mean_bytes, mean_ns)) => ((mean_bytes + bytes) / 2, (mean_ns + elapsed_ns) / 2),
            None => (bytes, elapsed_ns),
        });
    }

    /// Returns estimated bytes per second plus one, saturating at `u64::MAX`. The minimum weight
    /// of one keeps every peer selectable by weighted sampling, including peers without
    /// observations.
    pub(super) fn weight(&self) -> u64 {
        let Some((bytes, elapsed_ns)) = self.averages else {
            return 1;
        };

        // Payload lengths use at most 64 bits, so scaled bytes stay below 2^96. Duration
        // nanoseconds stay below 2^94. Both products fit below 2^126, and the denominator is
        // nonzero because each recorded duration is at least one nanosecond.
        let rate = bytes * NANOS_PER_SEC / (elapsed_ns * BYTE_SCALE);
        u64::try_from(rate).unwrap_or(u64::MAX).saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILURE_COST: Duration = Duration::from_secs(2);

    #[test]
    fn throughput_accounts_for_bytes_and_duration() {
        // Equal durations reward larger responses. Equal byte rates earn equal weights.
        for (bytes, elapsed_ms, expected) in [
            (1, 1, 1_001),
            (1_024, 1, 1_024_001),
            (1_024, 2, 512_001),
            (10_240, 20, 512_001),
            (10 * 1024 * 1024, 10, 1_048_576_001),
            (10 * 1024 * 1024, 5, 2_097_152_001),
        ] {
            let mut score = Score::default();
            assert_eq!(score.weight(), 1);
            score.record(Duration::from_millis(elapsed_ms), bytes);
            assert_eq!(score.weight(), expected);
        }
    }

    #[test]
    fn throughput_averages_bytes_and_time_before_dividing() {
        let mut score = Score::default();
        score.record(Duration::from_millis(1), 1_000);
        score.record(Duration::from_millis(999), 1);

        // These equally weighted observations deliver 1,001 bytes over one second.
        // Averaging their individual rates would overvalue the fast response.
        assert_eq!(score.weight(), 1_002);
    }

    #[test]
    fn failures_charge_timeout_and_service_recovers() {
        let mut score = Score::default();
        score.record(Duration::from_millis(100), 1_000_000);
        assert_eq!(score.weight(), 10_000_001);

        // A failed attempt adds its full cost while contributing no useful bytes.
        score.record(FAILURE_COST, 0);
        assert_eq!(score.weight(), 476_191);

        // Successful service rebuilds the estimate without erasing the failure.
        score.record(Duration::from_millis(100), 1_000_000);
        assert_eq!(score.weight(), 1_304_348);
    }

    #[test]
    fn empty_responses_cannot_restore_old_byte_credit() {
        let mut score = Score::default();
        score.record(Duration::from_millis(100), 1_000_000);
        for _ in 0..10 {
            let previous = score.weight();
            score.record(FAILURE_COST, 0);
            assert!(score.weight() < previous);
        }

        // Fast empty responses must not revive credit from the old large response.
        for elapsed in [
            Duration::from_millis(100),
            Duration::from_nanos(1),
            Duration::ZERO,
        ] {
            let previous = score.weight();
            score.record(elapsed, 0);
            assert!(score.weight() <= previous);
            assert!(score.weight() < 1_000);
        }
    }

    #[test]
    fn small_responses_recover_after_repeated_failures() {
        let mut score = Score::default();
        score.record(Duration::from_nanos(1), usize::MAX);
        let mut previous = score.weight();
        for _ in 0..128 {
            score.record(FAILURE_COST, 0);
            assert!(score.weight() <= previous);
            previous = score.weight();
        }
        assert_eq!(previous, 1);

        // Keeping fractional bytes lets even one-byte successes rebuild the score.
        for _ in 0..16 {
            score.record(Duration::from_millis(1), 1);
            assert!(score.weight() >= previous);
            previous = score.weight();
        }
        assert!(previous > 900);
        assert!(previous < 1_001);
    }

    #[test]
    fn failure_before_first_success_is_retained() {
        let mut score = Score::default();
        score.record(FAILURE_COST, 0);
        assert_eq!(score.weight(), 1);
        score.record(Duration::from_millis(100), 1_000_000);
        assert_eq!(score.weight(), 476_191);
    }

    #[test]
    fn zero_and_maximum_inputs_remain_bounded() {
        for bytes in [0, 1, usize::MAX] {
            for elapsed in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
                let mut score = Score::default();
                let rate = (bytes as u128) * NANOS_PER_SEC / elapsed.as_nanos().max(1);
                let expected = u64::try_from(rate + 1).unwrap_or(u64::MAX);

                // Repeating the extremes also exercises the averaging additions.
                for _ in 0..2 {
                    score.record(elapsed, bytes);
                    assert_eq!(score.weight(), expected);
                }
                score.record(Duration::MAX, 0);
                assert!(score.weight() <= expected);
                score.record(Duration::ZERO, usize::MAX);
                assert!(score.weight() >= 1);
            }
        }
    }
}
