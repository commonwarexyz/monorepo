//! Multimmit quorum thresholds for the `n >= 5f + 1` fault model.

use commonware_utils::{Faults, N5f1};
use num_traits::ToPrimitive;

/// Protocol thresholds extending the [`N5f1`] fault model.
pub trait MultimmitFaults: Faults {
    /// Compute `f + 1`, the number of votes that must endorse a position for it to be a
    /// safe-to-extend tip of a V-QC.
    ///
    /// Any set of this size contains at least one correct participant.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    fn safe_rank(n: impl ToPrimitive) -> u32;

    /// Compute `2f + 1`, the number of nullify messages in a nullification.
    ///
    /// Any set of this size shares at least one correct participant with every set of `n - f`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    fn nullification_quorum(n: impl ToPrimitive) -> u32;

    /// Compute `3f + 1`, the number of votes that must endorse a position for it to be a
    /// finalized tip of an L-QC.
    ///
    /// Any set of this size contains at least `2f + 1` correct participants.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    fn final_rank(n: impl ToPrimitive) -> u32;

    /// Compute `n - 2f`, the number of DA-votes in a DA-certificate.
    ///
    /// Any two sets of this size share at least `n - 4f >= f + 1` participants, so at least one
    /// correct participant.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    fn da_quorum(n: impl ToPrimitive) -> u32;
}

impl MultimmitFaults for N5f1 {
    fn safe_rank(n: impl ToPrimitive) -> u32 {
        Self::max_faults(n) + 1
    }

    fn nullification_quorum(n: impl ToPrimitive) -> u32 {
        2 * Self::max_faults(n) + 1
    }

    fn final_rank(n: impl ToPrimitive) -> u32 {
        3 * Self::max_faults(n) + 1
    }

    fn da_quorum(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        n - 2 * Self::max_faults(n)
    }
}

/// Fault model requiring `n >= 5f + 1` participants, whose quorum is the `2f + 1` nullification
/// quorum of [`N5f1`].
///
/// Tolerates up to `f = (n-1)/5` faults. Every quorum contains at least `f + 1` correct
/// participants, but two quorums need not share one, so this model suits only a protocol whose
/// correct participants agree without intersecting quorums, such as certifying a deterministic
/// digest.
///
/// # Example
///
/// | n  | f  | quorum (2f+1) |
/// |----|----|---------------|
/// | 6  | 1  | 3             |
/// | 11 | 2  | 5             |
/// | 16 | 3  | 7             |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct N5f1Nullification;

impl Faults for N5f1Nullification {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        N5f1::max_faults(n)
    }

    fn quorum(n: impl ToPrimitive) -> u32 {
        N5f1::nullification_quorum(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;
    use std::panic::{UnwindSafe, catch_unwind};

    #[test]
    fn test_n5f1_nullification_quorum() {
        for (n, faults, quorum) in [(1, 0, 1), (6, 1, 3), (11, 2, 5), (16, 3, 7), (50, 9, 19)] {
            assert_eq!(N5f1Nullification::max_faults(n), faults);
            assert_eq!(N5f1Nullification::quorum(n), quorum);
            // A quorum outnumbers twice the faults and can form without them.
            assert!(2 * faults < quorum && quorum <= n - faults);
        }
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_nullification_quorum_zero_panics() {
        N5f1::nullification_quorum(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_safe_rank_zero_panics() {
        N5f1::safe_rank(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_final_rank_zero_panics() {
        N5f1::final_rank(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_da_quorum_zero_panics() {
        N5f1::da_quorum(0);
    }

    #[rstest]
    // n=1 to n=5: f=0
    #[case(1, 0, 1, 1, 1, 1, 1)]
    #[case(2, 0, 2, 1, 1, 1, 2)]
    #[case(3, 0, 3, 1, 1, 1, 3)]
    #[case(4, 0, 4, 1, 1, 1, 4)]
    #[case(5, 0, 5, 1, 1, 1, 5)]
    // n=6 to n=10: f=1
    #[case(6, 1, 5, 3, 2, 4, 4)]
    #[case(7, 1, 6, 3, 2, 4, 5)]
    #[case(8, 1, 7, 3, 2, 4, 6)]
    #[case(9, 1, 8, 3, 2, 4, 7)]
    #[case(10, 1, 9, 3, 2, 4, 8)]
    // n=11 to n=15: f=2
    #[case(11, 2, 9, 5, 3, 7, 7)]
    #[case(12, 2, 10, 5, 3, 7, 8)]
    #[case(13, 2, 11, 5, 3, 7, 9)]
    #[case(14, 2, 12, 5, 3, 7, 10)]
    #[case(15, 2, 13, 5, 3, 7, 11)]
    // n=16 to n=20: f=3
    #[case(16, 3, 13, 7, 4, 10, 10)]
    #[case(17, 3, 14, 7, 4, 10, 11)]
    #[case(18, 3, 15, 7, 4, 10, 12)]
    #[case(19, 3, 16, 7, 4, 10, 13)]
    #[case(20, 3, 17, 7, 4, 10, 14)]
    // n=21: f=4
    #[case(21, 4, 17, 9, 5, 13, 13)]
    #[case(100, 19, 81, 39, 20, 58, 62)]
    #[case(
        u32::MAX,
        858_993_458,
        3_435_973_837,
        1_717_986_917,
        858_993_459,
        2_576_980_375,
        2_576_980_379
    )]
    fn test_bft5f1_quorums(
        #[case] n: u32,
        #[case] expected_f: u32,
        #[case] expected_quorum: u32,
        #[case] expected_nullification_quorum: u32,
        #[case] expected_safe_rank: u32,
        #[case] expected_final_rank: u32,
        #[case] expected_da_quorum: u32,
    ) {
        assert_eq!(N5f1::max_faults(n), expected_f);
        assert_eq!(N5f1::quorum(n), expected_quorum);
        assert_eq!(N5f1::nullification_quorum(n), expected_nullification_quorum);
        assert_eq!(N5f1::safe_rank(n), expected_safe_rank);
        assert_eq!(N5f1::final_rank(n), expected_final_rank);
        assert_eq!(N5f1::da_quorum(n), expected_da_quorum);

        // Verify invariants
        assert_eq!(n, expected_f + expected_quorum); // n = f + q
        assert_eq!(expected_nullification_quorum, 2 * expected_f + 1);
        assert_eq!(expected_safe_rank, expected_f + 1);
        assert_eq!(expected_final_rank, 3 * expected_f + 1);
        assert_eq!(expected_da_quorum, n - 2 * expected_f);
    }

    #[test]
    fn test_generic_integer_types() {
        // Test with various integer types

        assert_eq!(N5f1::max_faults(10u64), 1);
        assert_eq!(N5f1::quorum(10usize), 9);
        assert_eq!(N5f1::nullification_quorum(10i32), 3);
        assert_eq!(N5f1::safe_rank(10u8), 2);
        assert_eq!(N5f1::final_rank(10u16), 4);
        assert_eq!(N5f1::da_quorum(10u64), 8);
    }

    #[test]
    fn test_bft5f1_helpers_reject_invalid_integers() {
        fn assert_panics(f: impl FnOnce() -> u32 + UnwindSafe) {
            assert!(catch_unwind(f).is_err());
        }

        assert_panics(|| N5f1::safe_rank(-1i32));
        assert_panics(|| N5f1::final_rank(-1i32));
        assert_panics(|| N5f1::da_quorum(-1i32));
        assert_panics(|| N5f1::safe_rank(u64::MAX));
        assert_panics(|| N5f1::final_rank(u64::MAX));
        assert_panics(|| N5f1::da_quorum(u64::MAX));
    }

    proptest! {
        /// N5f1 quorum relationships must hold for all valid participant counts.
        ///
        /// For n >= 6 (where f >= 1):
        /// - every helper equals its defining formula; and
        /// - `f+1 <= 2f+1 <= 3f+1 <= n-2f <= n-f <= n`.
        #[test]
        fn test_n5f1_quorum_relationships(n in 6u32..10_000) {
            let f = N5f1::max_faults(n);
            let safe = N5f1::safe_rank(n);
            let nullification = N5f1::nullification_quorum(n);
            let finalized = N5f1::final_rank(n);
            let da = N5f1::da_quorum(n);
            let quorum = N5f1::quorum(n);

            prop_assert_eq!(safe, f + 1);
            prop_assert_eq!(nullification, 2 * f + 1);
            prop_assert_eq!(finalized, 3 * f + 1);
            prop_assert_eq!(da, n - 2 * f);
            prop_assert_eq!(quorum, n - f);
            prop_assert!(safe <= nullification);
            prop_assert!(nullification <= finalized);
            prop_assert!(finalized <= da);
            prop_assert!(da <= quorum);
            prop_assert!(quorum <= n);
        }

    }
}
