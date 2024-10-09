//! Utilities for a DKG/Resharing procedure.

/// Assuming that `t >= 2f + 1`, compute the maximum number of shares that can be revealed
/// without allowing an adversary of size `f` to reconstruct the secret.
pub fn max_reveals(t: u32) -> u32 {
    (t - 1) / 2
}

#[cfg(test)]
mod tests {
    use super::*;

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
