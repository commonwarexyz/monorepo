//! Utilities for a DKG/Resharing procedure.

use commonware_utils::max_faults;

/// Assuming that `n = 3f + 1`, compute the maximum threshold `f + 1`
/// that can be supported.
///
/// If the value of `n` is too small to tolerate any faults, this function returns `None`.
pub fn threshold(n: u32) -> Option<u32> {
    let f = max_faults(n)?;
    Some(f + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_small() {
        assert_eq!(threshold(0), None);
    }

    #[test]
    fn test_still_too_small() {
        assert_eq!(threshold(1), None);
    }

    #[test]
    fn test_minimal() {
        assert_eq!(threshold(4), Some(2));
    }

    #[test]
    fn test_floor() {
        assert_eq!(threshold(5), Some(2));
    }

    #[test]
    fn test_many() {
        assert_eq!(threshold(100), Some(34));
    }
}
