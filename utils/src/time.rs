//! Utility functions for `std::time`.

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
}

impl SystemTimeExt for SystemTime {
    fn epoch(&self) -> Duration {
        self.duration_since(std::time::UNIX_EPOCH)
            .expect("failed to get epoch time")
    }

    fn epoch_millis(&self) -> u64 {
        self.epoch().as_millis().min(u64::MAX as u128) as u64
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

        // Saturates at u64::MAX
        let time = SystemTime::UNIX_EPOCH + Duration::from_millis(u64::MAX);
        assert_eq!(time.epoch_millis(), u64::MAX);
        let time = time + Duration::from_millis(1);
        assert_eq!(time.epoch_millis(), u64::MAX);
    }

    #[test]
    #[should_panic(expected = "failed to get epoch time")]
    fn test_epoch_millis_panics() {
        let time = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        time.epoch_millis();
    }
}
