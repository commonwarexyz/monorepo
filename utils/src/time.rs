//! Utility functions for `std::time`.

use std::time::{Duration, SystemTime};

/// Extension trait to add methods to `std::time::Duration`
pub trait DurationExt {
    /// Convert the duration to milliseconds as a `u64`.
    ///
    /// Saturates at `u64::MAX`.
    fn as_millis_u64(&self) -> u64;
}

impl DurationExt for Duration {
    fn as_millis_u64(&self) -> u64 {
        self.as_millis().min(u64::MAX as u128) as u64
    }
}

/// Extension trait to add methods to `std::time::SystemTime`
pub trait SystemTimeExt {
    /// Returns the duration since the Unix epoch.
    fn epoch(&self) -> Duration;

    /// Returns the number of milliseconds since the Unix epoch.
    ///
    /// Saturates at `u64::MAX`.
    fn epoch_millis(&self) -> u64;
}

impl SystemTimeExt for SystemTime {
    fn epoch(&self) -> Duration {
        self.duration_since(std::time::UNIX_EPOCH)
            .expect("failed to get epoch time")
    }
    fn epoch_millis(&self) -> u64 {
        self.epoch().as_millis_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_millis() {
        assert_eq!(Duration::from_secs(1).as_millis_u64(), 1_000);
        assert_eq!(Duration::from_millis(1).as_millis_u64(), 1);
        assert_eq!(Duration::from_secs(u64::MAX).as_millis_u64(), u64::MAX);
    }
}
