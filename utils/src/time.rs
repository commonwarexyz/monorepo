//! Utility functions for `std::time`.

use rand::Rng;
use std::time::{Duration, SystemTime};

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
/// # use commonware_utils::parse_duration;
/// # use std::time::Duration;
///
/// // Different time units
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
/// assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
///
/// // Error cases
/// assert!(parse_duration("invalid").is_err());
/// assert!(parse_duration("10x").is_err());
/// assert!(parse_duration("5minutes").is_err()); // Long forms not supported
/// assert!(parse_duration("60").is_err()); // No suffix required
///
/// // Overflow protection
/// let max_hours = u64::MAX / 3600;
/// assert!(parse_duration(&format!("{}h", max_hours)).is_ok());     // At limit
/// assert!(parse_duration(&format!("{}h", max_hours + 1)).is_err()); // Overflow
/// ```
pub fn parse_duration(s: &str) -> Result<Duration, String> {
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

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("0ms").unwrap(), Duration::from_millis(0));
        assert_eq!(parse_duration("1ms").unwrap(), Duration::from_millis(1));
        assert_eq!(
            parse_duration("1000ms").unwrap(),
            Duration::from_millis(1000)
        );
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("3600s").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("0m").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("60m").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("0h").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("3h").unwrap(), Duration::from_secs(10800));
        assert_eq!(parse_duration("4h").unwrap(), Duration::from_secs(14400));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43200));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("168h").unwrap(), Duration::from_secs(604800));
        // 1 week
    }

    #[test]
    fn test_parse_duration_whitespace() {
        // Should handle whitespace around the input
        assert_eq!(parse_duration("  30s  ").unwrap(), Duration::from_secs(30));
        assert_eq!(
            parse_duration("\t500ms\n").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(parse_duration(" 2h ").unwrap(), Duration::from_secs(7200));

        // Should handle whitespace between number and suffix
        assert_eq!(parse_duration("30 s").unwrap(), Duration::from_secs(30));
        assert_eq!(
            parse_duration("500 ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(parse_duration("2 h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("5 m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_error_cases() {
        // Invalid number
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("abc123ms").is_err());
        assert!(parse_duration("12.5s").is_err()); // Decimal not supported

        // Invalid suffix
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("30days").is_err());
        assert!(parse_duration("5y").is_err());

        // Long forms not supported
        assert!(parse_duration("5minutes").is_err());
        assert!(parse_duration("10seconds").is_err());
        assert!(parse_duration("2hours").is_err());
        assert!(parse_duration("500millis").is_err());
        assert!(parse_duration("30sec").is_err());
        assert!(parse_duration("5min").is_err());
        assert!(parse_duration("2hr").is_err());

        // No suffix
        assert!(parse_duration("60").is_err());
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("3600").is_err());
        assert!(parse_duration("1").is_err());

        // Empty or whitespace only
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());

        // Negative numbers (should fail because we use u64)
        assert!(parse_duration("-5s").is_err());
        assert!(parse_duration("-100ms").is_err());

        // Mixed case should not work (we only support lowercase)
        assert!(parse_duration("30S").is_err());
        assert!(parse_duration("500MS").is_err());
        assert!(parse_duration("2H").is_err());
    }

    #[test]
    fn test_parse_duration_large_values() {
        // Large values that don't overflow
        assert_eq!(
            parse_duration("999999999ms").unwrap(),
            Duration::from_millis(999999999)
        );
        assert_eq!(
            parse_duration("99999999s").unwrap(),
            Duration::from_secs(99999999)
        );
    }

    #[test]
    fn test_parse_duration_overflow_cases() {
        // Test hours overflow
        let max_safe_hours = u64::MAX / 3600;
        let overflow_hours = max_safe_hours + 1;
        assert!(parse_duration(&format!("{max_safe_hours}h")).is_ok());
        match parse_duration(&format!("{overflow_hours}h")) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for large hours value"),
        }
        match parse_duration(&format!("{}h", u64::MAX)) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for u64::MAX hours"),
        }

        // Test minutes overflow
        let max_safe_minutes = u64::MAX / 60;
        let overflow_minutes = max_safe_minutes + 1;
        assert!(parse_duration(&format!("{max_safe_minutes}m")).is_ok());
        match parse_duration(&format!("{overflow_minutes}m")) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for large minutes value"),
        }
        match parse_duration(&format!("{}m", u64::MAX)) {
            Err(msg) => assert!(msg.contains("too large (would overflow)")),
            Ok(_) => panic!("Expected overflow error for u64::MAX minutes"),
        }
    }
}
