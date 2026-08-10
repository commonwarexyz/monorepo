//! Hardcoded quorum values as a "root of trust" for BFT calculations.
//!
//! These values serve as regression protection - if the upstream `N3f1`
//! implementation is accidentally modified, assertions here will catch it.

/// Hardcoded max_faults values for n=1..=21.
///
/// Formula: f = (n-1) / 3
const MAX_FAULTS: [u32; 21] = [
    0, // n=1:  f=0
    0, // n=2:  f=0
    0, // n=3:  f=0
    1, // n=4:  f=1
    1, // n=5:  f=1
    1, // n=6:  f=1
    2, // n=7:  f=2
    2, // n=8:  f=2
    2, // n=9:  f=2
    3, // n=10: f=3
    3, // n=11: f=3
    3, // n=12: f=3
    4, // n=13: f=4
    4, // n=14: f=4
    4, // n=15: f=4
    5, // n=16: f=5
    5, // n=17: f=5
    5, // n=18: f=5
    6, // n=19: f=6
    6, // n=20: f=6
    6, // n=21: f=6
];

/// Hardcoded quorum values for n=1..=21.
///
/// Formula: q = n - f = n - (n-1)/3
const QUORUM: [u32; 21] = [
    1,  // n=1:  q=1
    2,  // n=2:  q=2
    3,  // n=3:  q=3
    3,  // n=4:  q=3
    4,  // n=5:  q=4
    5,  // n=6:  q=5
    5,  // n=7:  q=5
    6,  // n=8:  q=6
    7,  // n=9:  q=7
    7,  // n=10: q=7
    8,  // n=11: q=8
    9,  // n=12: q=9
    9,  // n=13: q=9
    10, // n=14: q=10
    11, // n=15: q=11
    11, // n=16: q=11
    12, // n=17: q=12
    13, // n=18: q=13
    13, // n=19: q=13
    14, // n=20: q=14
    15, // n=21: q=15
];

/// Returns the maximum faults for n participants using hardcoded values.
///
/// Panics if n is 0 or > 21.
pub fn max_faults(n: u32) -> u32 {
    assert!(n > 0 && n <= 21, "n must be in range 1..=21");
    MAX_FAULTS[(n - 1) as usize]
}

/// Returns the quorum size for n participants using hardcoded values.
///
/// Panics if n is 0 or > 21.
pub fn quorum(n: u32) -> u32 {
    assert!(n > 0 && n <= 21, "n must be in range 1..=21");
    QUORUM[(n - 1) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{Faults, N3f1};

    #[test]
    fn test_hardcoded_values_match_upstream() {
        for n in 1..=21u32 {
            let expected_f = max_faults(n);
            let expected_q = quorum(n);
            let actual_f = N3f1::max_faults(n);
            let actual_q = N3f1::quorum(n);

            assert_eq!(
                actual_f, expected_f,
                "N3f1::max_faults({n}) = {actual_f}, expected {expected_f}"
            );
            assert_eq!(
                actual_q, expected_q,
                "N3f1::quorum({n}) = {actual_q}, expected {expected_q}"
            );

            // Verify invariant: n = f + q
            assert_eq!(
                n,
                expected_f + expected_q,
                "Invariant n = f + q violated for n={n}"
            );

            // Verify BFT safety property: 2q > n + f
            assert!(
                2 * expected_q > n + expected_f,
                "BFT safety violated for n={n}: 2*{expected_q} <= {n} + {expected_f}"
            );
        }
    }

    #[test]
    fn test_specific_configurations() {
        // N4F1C3: 4 nodes, 1 faulty, 3 correct
        assert_eq!(max_faults(4), 1);
        assert_eq!(quorum(4), 3);

        // Standard BFT configurations
        assert_eq!(max_faults(3), 0); // 3f+1 = 1, so f=0
        assert_eq!(max_faults(4), 1); // 3f+1 = 4, so f=1
        assert_eq!(max_faults(7), 2); // 3f+1 = 7, so f=2
        assert_eq!(max_faults(10), 3); // 3f+1 = 10, so f=3
    }

    #[test]
    fn test_can_finalize_logic() {
        use crate::{Configuration, N4F1C3, N4F3C1};

        // N4F1C3: 4 nodes, 1 faulty - can finalize (1 <= 1)
        assert!(N4F1C3.can_finalize());

        // N4F3C1: 4 nodes, 3 faulty - cannot finalize (3 > 1)
        assert!(!N4F3C1.can_finalize());

        // Edge cases
        let zero_faults = Configuration::new(4, 0, 4);
        assert!(zero_faults.can_finalize()); // 0 <= 1

        let exact_max = Configuration::new(4, 1, 3);
        assert!(exact_max.can_finalize()); // 1 <= 1

        let over_max = Configuration::new(4, 2, 2);
        assert!(!over_max.can_finalize()); // 2 > 1
    }
}
