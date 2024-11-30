use std::time::Duration;

/// Convert a `Duration` to epoch milliseconds.
/// If the duration is too large, it will be clamped to the maximum value of `u64`.
pub fn to_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_millis() {
        assert_eq!(to_millis(Duration::from_secs(1)), 1_000);
        assert_eq!(to_millis(Duration::from_millis(1)), 1);
        assert_eq!(to_millis(Duration::from_secs(u64::MAX)), u64::MAX);
    }
}
