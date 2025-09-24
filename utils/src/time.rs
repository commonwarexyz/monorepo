//! Utility functions for `std::time`.

use rand::Rng;
use std::time::{Duration, SystemTime};

/// Number of nanoseconds in a second.
pub const NANOS_PER_SEC: u128 = 1_000_000_000;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        /// Maximum duration that can be safely added to [`SystemTime::UNIX_EPOCH`] without overflow on the
        /// current platform.
        ///
        /// Source: [`FILETIME` range](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
        /// uses unsigned 64-bit ticks (100ns) since 1601-01-01; converting to the Unix epoch offset of
        /// 11_644_473_600 seconds yields the remaining representable span.
        pub const MAX_DURATION_SINCE_UNIX_EPOCH: Duration = Duration::new(910_692_730_085, 477_580_700);

        /// The precision of [`SystemTime`] on Windows.
        pub const SYSTEM_TIME_PRECISION: Duration = Duration::from_nanos(100);
    } else { // We default to Unix-like behavior on all other platforms
        /// Maximum duration that can be safely added to [`SystemTime::UNIX_EPOCH`] without overflow on the
        /// current platform.
        ///
        /// Source: `SystemTime` on Unix stores seconds in a signed 64-bit integer; see
        /// [`std::sys::pal::unix::time`](https://github.com/rust-lang/rust/blob/master/library/std/src/sys/pal/unix/time.rs),
        /// which bounds additions at `i64::MAX` seconds plus 999_999_999 nanoseconds.
        #[cfg(not(windows))]
        pub const MAX_DURATION_SINCE_UNIX_EPOCH: Duration = Duration::new(i64::MAX as u64, 999_999_999);

        /// The precision of [`SystemTime`] on Unix.
        pub const SYSTEM_TIME_PRECISION: Duration = Duration::from_nanos(1);
    }
}

/// Extension trait providing additional functionality for [`Duration`].
pub trait DurationExt {
    /// Creates a duration from nanoseconds represented as a `u128`. Saturates anything beyond the
    /// representable range.
    fn from_nanos_saturating(ns: u128) -> Duration;

    /// Parse a duration string with time unit suffixes.
    ///
    /// This function accepts duration strings with the following suffixes:
    /// - `ms`: Milliseconds (e.g., "500ms", "1000ms")
    /// - `s`: Seconds (e.g., "30s", "5s")
    /// - `m`: Minutes (e.g., "2m", "30m")
    /// - `h`: Hours (e.g., "1h", "24h")
    ///
    /// A suffix is required - strings without suffixes will return an error.
    ///
    /// # Overflow Protection
    ///
    /// The function includes overflow protection for time unit conversions:
    /// - Hours are safely converted to seconds (hours * 3600) with overflow checking
    /// - Minutes are safely converted to seconds (minutes * 60) with overflow checking
    /// - Values that would cause integer overflow return an error
    ///
    /// # Arguments
    ///
    /// * `s` - A string slice containing the duration with required suffix
    ///
    /// # Returns
    ///
    /// * `Ok(Duration)` - Successfully parsed duration
    /// * `Err(String)` - Error message describing what went wrong (invalid format, overflow, etc.)
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_utils::DurationExt;
    /// # use std::time::Duration;
    ///
    /// // Different time units
    /// assert_eq!(Duration::parse("500ms").unwrap(), Duration::from_millis(500));
    /// assert_eq!(Duration::parse("30s").unwrap(), Duration::from_secs(30));
    /// assert_eq!(Duration::parse("5m").unwrap(), Duration::from_secs(300));
    /// assert_eq!(Duration::parse("2h").unwrap(), Duration::from_secs(7200));
    ///
    /// // Error cases
    /// assert!(Duration::parse("invalid").is_err());
    /// assert!(Duration::parse("10x").is_err());
    /// assert!(Duration::parse("5minutes").is_err()); // Long forms not supported
    /// assert!(Duration::parse("60").is_err()); // No suffix required
    ///
    /// // Overflow protection
    /// let max_hours = u64::MAX / 3600;
    /// assert!(Duration::parse(&format!("{}h", max_hours)).is_ok());      // At limit
    /// assert!(Duration::parse(&format!("{}h", max_hours + 1)).is_err()); // Overflow
    /// ```
    fn parse(s: &str) -> Result<Duration, String>;
}

impl DurationExt for Duration {
    fn from_nanos_saturating(ns: u128) -> Duration {
        // Clamp anything beyond the representable range
        if ns > Duration::MAX.as_nanos() {
            return Duration::MAX;
        }

        // Convert to `Duration`
        let secs = (ns / NANOS_PER_SEC) as u64;
        let nanos = (ns % NANOS_PER_SEC) as u32;
        Duration::new(secs, nanos)
    }

    fn parse(s: &str) -> Result<Duration, String> {
        let s = s.trim();

        // Handle milliseconds
        if let Some(num_str) = s.strip_suffix("ms") {
            let millis: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid milliseconds value: '{num_str}'"))?;
            return Ok(Duration::from_millis(millis));
        }

        // Handle hours
        if let Some(num_str) = s.strip_suffix("h") {
            let hours: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid hours value: '{num_str}'"))?;
            let seconds = hours
                .checked_mul(3600)
                .ok_or_else(|| format!("Hours value too large (would overflow): '{hours}'"))?;
            return Ok(Duration::from_secs(seconds));
        }

        // Handle minutes
        if let Some(num_str) = s.strip_suffix("m") {
            let minutes: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid minutes value: '{num_str}'"))?;
            let seconds = minutes
                .checked_mul(60)
                .ok_or_else(|| format!("Minutes value too large (would overflow): '{minutes}'"))?;
            return Ok(Duration::from_secs(seconds));
        }

        // Handle seconds
        if let Some(num_str) = s.strip_suffix("s") {
            let secs: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid seconds value: '{num_str}'"))?;
            return Ok(Duration::from_secs(secs));
        }

        // No suffix - return error
        Err(format!(
            "Invalid duration format: '{s}'. A suffix is required. \
         Supported formats: '123ms', '30s', '5m', '2h'"
        ))
    }
}

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

    /// Returns the maximum representable [SystemTime] on this platform.
    fn limit() -> SystemTime;

    /// Adds `delta` to the current time, saturating at the platform maximum instead of overflowing.
    fn saturating_add(&self, delta: Duration) -> SystemTime;
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

    fn limit() -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(MAX_DURATION_SINCE_UNIX_EPOCH)
            .expect("maximum system time must be representable")
    }

    fn saturating_add(&self, delta: Duration) -> SystemTime {
        if delta.is_zero() {
            return *self;
        }

        // When adding less than SYSTEM_TIME_PRECISION, this may actually not fail but simply
        // round down to the nearest representable value
        self.checked_add(delta).unwrap_or_else(Self::limit)
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
    fn test_from_nanos_saturating() {
        // Support simple cases
        assert_eq!(Duration::from_nanos_saturating(0), Duration::new(0, 0));
        assert_eq!(
            Duration::from_nanos_saturating(NANOS_PER_SEC - 1),
            Duration::new(0, (NANOS_PER_SEC - 1) as u32)
        );
        assert_eq!(
            Duration::from_nanos_saturating(NANOS_PER_SEC + 1),
            Duration::new(1, 1)
        );

        // Support larger values than `Duration::from_nanos`
        let std = Duration::from_nanos(u64::MAX);
        let beyond_std = Duration::from_nanos_saturating(u64::MAX as u128 + 1);
        assert!(beyond_std > std);

        // Test very large values
        assert_eq!(
            Duration::from_nanos_saturating(Duration::MAX.as_nanos()),
            Duration::MAX
        );

        // Clamp anything beyond the representable range
        assert_eq!(
            Duration::from_nanos_saturating(Duration::MAX.as_nanos() + 1),
            Duration::MAX
        );
        assert_eq!(Duration::from_nanos_saturating(u128::MAX), Duration::MAX);
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

    #[test]
    fn check_duration_limit() {
        // Rollback to limit
        let result = SystemTime::limit()
            .checked_add(SYSTEM_TIME_PRECISION - Duration::from_nanos(1))
            .expect("addition within precision should round down");
        assert_eq!(result, SystemTime::limit(), "unexpected precision");

        // Exceed limit
        let result = SystemTime::limit().checked_add(SYSTEM_TIME_PRECISION);
        assert!(result.is_none(), "able to exceed max duration");
    }

    #[test]
    fn system_time_saturating_add() {
        let max = SystemTime::limit();
        assert_eq!(max.saturating_add(Duration::from_nanos(1)), max);
        assert_eq!(max.saturating_add(Duration::from_secs(1)), max);
    }

    #[test]
    fn test_duration_parse_milliseconds() {
        assert_eq!(
            Duration::parse("500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(Duration::parse("0ms").unwrap(), Duration::from_millis(0));
        assert_eq!(Duration::parse("1ms").unwrap(), Duration::from_millis(1));
        assert_eq!(
            Duration::parse("1000ms").unwrap(),
            Duration::from_millis(1000)
        );
        assert_eq!(
            Duration::parse("250ms").unwrap(),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn test_duration_parse_seconds() {
        assert_eq!(Duration::parse("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(Duration::parse("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(Duration::parse("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(Duration::parse("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(Duration::parse("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(Duration::parse("3600s").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_duration_parse_minutes() {
        assert_eq!(Duration::parse("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(Duration::parse("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(Duration::parse("0m").unwrap(), Duration::from_secs(0));
        assert_eq!(Duration::parse("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(Duration::parse("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(Duration::parse("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(Duration::parse("60m").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_duration_parse_hours() {
        assert_eq!(Duration::parse("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(Duration::parse("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(Duration::parse("0h").unwrap(), Duration::from_secs(0));
        assert_eq!(Duration::parse("3h").unwrap(), Duration::from_secs(10800));
        assert_eq!(Duration::parse("4h").unwrap(), Duration::from_secs(14400));
        assert_eq!(Duration::parse("12h").unwrap(), Duration::from_secs(43200));
        assert_eq!(Duration::parse("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(
            Duration::parse("168h").unwrap(),
            Duration::from_secs(604800)
        );
        // 1 week
    }

    #[test]
    fn test_duration_parse_whitespace() {
        // Should handle whitespace around the input
        assert_eq!(Duration::parse("  30s  ").unwrap(), Duration::from_secs(30));
        assert_eq!(
            Duration::parse("\t500ms\n").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(Duration::parse(" 2h ").unwrap(), Duration::from_secs(7200));

        // Should handle whitespace between number and suffix
        assert_eq!(Duration::parse("30 s").unwrap(), Duration::from_secs(30));
        assert_eq!(
            Duration::parse("500 ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(Duration::parse("2 h").unwrap(), Duration::from_secs(7200));
        assert_eq!(Duration::parse("5 m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_duration_parse_error_cases() {
        // Invalid number
        assert!(Duration::parse("invalid").is_err());
        assert!(Duration::parse("abc123ms").is_err());
        assert!(Duration::parse("12.5s").is_err()); // Decimal not supported

        // Invalid suffix
        assert!(Duration::parse("10x").is_err());
        assert!(Duration::parse("30days").is_err());
        assert!(Duration::parse("5y").is_err());

        // Long forms not supported
        assert!(Duration::parse("5minutes").is_err());
        assert!(Duration::parse("10seconds").is_err());
        assert!(Duration::parse("2hours").is_err());
        assert!(Duration::parse("500millis").is_err());
        assert!(Duration::parse("30sec").is_err());
        assert!(Duration::parse("5min").is_err());
        assert!(Duration::parse("2hr").is_err());

        // No suffix
        assert!(Duration::parse("60").is_err());
        assert!(Duration::parse("0").is_err());
        assert!(Duration::parse("3600").is_err());
        assert!(Duration::parse("1").is_err());

        // Empty or whitespace only
        assert!(Duration::parse("").is_err());
        assert!(Duration::parse("   ").is_err());

        // Negative numbers (should fail because we use u64)
        assert!(Duration::parse("-5s").is_err());
        assert!(Duration::parse("-100ms").is_err());

        // Mixed case should not work (we only support lowercase)
        assert!(Duration::parse("30S").is_err());
        assert!(Duration::parse("500MS").is_err());
        assert!(Duration::parse("2H").is_err());
    }

    #[test]
    fn test_duration_parse_large_values() {
        // Large values that don't overflow
        assert_eq!(
            Duration::parse("999999999ms").unwrap(),
            Duration::from_millis(999999999)
        );
        assert_eq!(
            Duration::parse("99999999s").unwrap(),
            Duration::from_secs(99999999)
        );
    }

    #[test]
    fn test_duration_parse_overflow_cases() {
        // Test hours overflow
        let max_safe_hours = u64::MAX / 3600;
        let overflow_hours = max_safe_hours + 1;
        assert!(Duration::parse(&format!("{max_safe_hours}h")).is_ok());
        match Duration::parse(&format!("{overflow_hours}h")) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for large hours value"),
        }
        match Duration::parse(&format!("{}h", u64::MAX)) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for u64::MAX hours"),
        }

        // Test minutes overflow
        let max_safe_minutes = u64::MAX / 60;
        let overflow_minutes = max_safe_minutes + 1;
        assert!(Duration::parse(&format!("{max_safe_minutes}m")).is_ok());
        match Duration::parse(&format!("{overflow_minutes}m")) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for large minutes value"),
        }
        match Duration::parse(&format!("{}m", u64::MAX)) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for u64::MAX minutes"),
        }
    }
}
