//! Utility functions for `std::time`.

use rand::Rng;
use std::time::{Duration, SystemTime};

/// Extension trait to add methods to `std::time::SystemTime`
pub trait SystemTimeExt {
    /// Returns the duration since the Unix epoch.
    ///
    /// Panics if the system time is before the Unix epoch.
    fn epoch(&self) -> Duration;

    /// Returns the number of milliseconds (rounded down) since the Unix epoch.
    ///
    /// Panics if the system time is before the Unix epoch.
    /// Saturates at `u64::MAX`.
    fn epoch_millis(&self) -> u64;

    /// Adds a random `Duration` to the current time between `0` and `jitter * 2` and returns the
    /// resulting `SystemTime`. The random duration is generated using the provided `context`.
    fn add_jittered(&self, rng: &mut impl Rng, jitter: Duration) -> SystemTime;
}

impl SystemTimeExt for SystemTime {
    fn epoch(&self) -> Duration {
        self.duration_since(std::time::UNIX_EPOCH)
            .expect("failed to get epoch time")
    }

    fn epoch_millis(&self) -> u64 {
        self.epoch().as_millis().min(u64::MAX as u128) as u64
    }

    fn add_jittered(&self, rng: &mut impl Rng, jitter: Duration) -> SystemTime {
        *self + rng.gen_range(Duration::default()..=jitter * 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch() {
        let time = SystemTime::UNIX_EPOCH;
        assert_eq!(time.epoch(), Duration::from_secs(0));

        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1) + Duration::from_millis(1);
        assert_eq!(time.epoch(), Duration::from_millis(1_001));
    }

    #[test]
    #[should_panic(expected = "failed to get epoch time")]
    fn test_epoch_panics() {
        let time = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        time.epoch();
    }

    #[test]
    fn test_epoch_millis() {
        let time = SystemTime::UNIX_EPOCH;
        assert_eq!(time.epoch_millis(), 0);

        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1) + Duration::from_millis(1);
        assert_eq!(time.epoch_millis(), 1_001);

        // Rounds nanoseconds down
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1) + Duration::from_nanos(999_999);
        assert_eq!(time.epoch_millis(), 1_000);

        // Add 5 minutes
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(300);
        assert_eq!(time.epoch_millis(), 300_000);
    }

    #[test]
    #[should_panic(expected = "failed to get epoch time")]
    fn test_epoch_millis_panics() {
        let time = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        time.epoch_millis();
    }

    #[test]
    fn test_add_jittered() {
        let mut rng = rand::thread_rng();
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let jitter = Duration::from_secs(2);

        // Ensure we generate values both below and above the average time.
        let (mut below, mut above) = (false, false);
        let avg = time + jitter;
        for _ in 0..100 {
            let new_time = time.add_jittered(&mut rng, jitter);

            // Record values higher or lower than the average
            below |= new_time < avg;
            above |= new_time > avg;

            // Check bounds
            assert!(new_time >= time);
            assert!(new_time <= time + (jitter * 2));
        }
        assert!(below && above);
    }
}
