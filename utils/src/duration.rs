use std::time::Duration;

/// Extension trait to add methods to `Duration`
pub trait Utils {
    /// Convert the duration to milliseconds as a `u64`.
    /// Saturates at `u64::MAX`.
    fn as_millis_u64(&self) -> u64;
}

impl Utils for Duration {
    fn as_millis_u64(&self) -> u64 {
        self.as_millis().min(u64::MAX as u128) as u64
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
