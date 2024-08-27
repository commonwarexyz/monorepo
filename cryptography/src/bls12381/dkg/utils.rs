//! Utilities for a DKG/Resharing procedure.

/// Assuming that `n = 3f + 1`, compute the minimum required threshold to satisfy `t = 2f + 1`.
pub fn threshold(n: u32) -> Option<u32> {
    let f = (n - 1) / 3;
    if f == 0 {
        return None;
    }
    Some((2 * f) + 1)
}

/// Assuming that `t = 2f + 1`, compute the maximum number of shares that can be revealed
/// without allowing an adversary of size `f` to reconstruct the secret.
pub fn max_reveals(t: u32) -> u32 {
    (t - 1) / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold() {
        // Test case 0: n = 3 (3*0 + 1)
        assert_eq!(threshold(3), None);

        // Test case 1: n = 4 (3*1 + 1)
        assert_eq!(threshold(4), Some(3));

        // Test case 2: n = 7 (3*2 + 1)
        assert_eq!(threshold(7), Some(5));

        // Test case 3: n = 10 (3*3 + 1)
        assert_eq!(threshold(10), Some(7));
    }

    #[test]
    fn test_max_reveals() {
        // Test case 0: t = 2 (2*0 + 1)
        assert_eq!(max_reveals(2), 0);

        // Test case 1: t = 3 (2*1 + 1)
        assert_eq!(max_reveals(3), 1);

        // Test case 2: t = 5 (2*2 + 1)
        assert_eq!(max_reveals(5), 2);

        // Test case 3: t = 7 (2*3 + 1)
        assert_eq!(max_reveals(7), 3);
    }
}
