//! Byzantine fault tolerance models for consensus protocols.
//!
//! This module provides abstractions over quorum calculations for different BFT
//! fault models. The two primary models are:
//!
//! - [`N3f1`]: Fault model requiring `n >= 3f + 1` participants
//! - [`N5f1`]: Fault model requiring `n >= 5f + 1` participants
//!
//! _`f` denotes the maximum number of faults that can be tolerated._
//!
//! # Example
//!
//! ```
//! use commonware_utils::{Faults, N3f1, N5f1};
//!
//! // n >= 3f+1
//! let n = 10;
//! assert_eq!(N3f1::max_faults(n), 3);  // f = (n-1)/3 = 3
//! assert_eq!(N3f1::quorum(n), 7);       // q = n - f = 7
//!
//! // n >= 5f+1
//! assert_eq!(N5f1::max_faults(n), 1);  // f = (n-1)/5 = 1
//! assert_eq!(N5f1::quorum(n), 9);       // q = n - f = 9
//!
//! // Works with any integer type
//! let n_i32: i32 = 10;
//! assert_eq!(N3f1::max_faults(n_i32), 3);
//! assert_eq!(N3f1::quorum(n_i32), 7);
//! ```

use num_traits::ToPrimitive;

/// A Byzantine fault tolerance model that defines quorum calculations.
///
/// Different consensus protocols require different fault tolerance guarantees.
/// This trait abstracts over those requirements, allowing protocols to be
/// parameterized by their fault model.
///
/// All methods accept any integer type that implements [`ToPrimitive`], allowing
/// callers to use `u32`, `u64`, `i32`, `usize`, etc. without explicit conversion.
/// Output is always `u32`.
pub trait Faults {
    /// Compute the maximum number of faults that can be tolerated for `n` participants.
    ///
    /// This is the maximum integer `f` such that the protocol's safety and liveness
    /// properties hold when up to `f` participants are Byzantine.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    fn max_faults(n: impl ToPrimitive) -> u32;

    /// Compute the quorum size for `n` participants.
    ///
    /// This is the minimum number of participants that must agree for the protocol
    /// to make progress. It equals `n - max_faults(n)`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    fn quorum(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        n - Self::max_faults(n)
    }
}

/// Fault model requiring `n >= 3f + 1` participants.
///
/// Tolerates up to `f = (n-1)/3` faults with quorum size `q = n - f`.
///
/// For any two quorums Q1 and Q2, there exists at least one honest participant
/// in their intersection (since `|Q1| + |Q2| > n + f`).
///
/// # Example
///
/// | n  | f  | quorum |
/// |----|----| -------|
/// | 4  | 1  | 3      |
/// | 7  | 2  | 5      |
/// | 10 | 3  | 7      |
/// | 13 | 4  | 9      |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct N3f1;

impl Faults for N3f1 {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        (n - 1) / 3
    }
}

/// Fault model requiring `n >= 5f + 1` participants.
///
/// Tolerates up to `f = (n-1)/5` faults with quorum size `q = n - f`, the size of a Multimmit
/// L-QC or V-QC.
///
/// Also provides the other thresholds named in the
/// [Multimmit specification](https://arxiv.org/abs/2607.21021v5):
/// [`safe_rank`](Self::safe_rank) (`f + 1`),
/// [`nullification_quorum`](Self::nullification_quorum) (`2f + 1`),
/// [`final_rank`](Self::final_rank) (`3f + 1`), and [`da_quorum`](Self::da_quorum) (`n - 2f`).
///
/// # Example
///
/// | n  | f  | quorum (n-f) | nullification quorum (2f+1) |
/// |----|----|--------------|-----------------------------|
/// | 6  | 1  | 5            | 3                           |
/// | 11 | 2  | 9            | 5                           |
/// | 16 | 3  | 13           | 7                           |
/// | 21 | 4  | 17           | 9                           |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct N5f1;

impl Faults for N5f1 {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        Self::faults(n)
    }
}

impl N5f1 {
    /// Computes `f` for a validated, non-zero `n`.
    const fn faults(n: u32) -> u32 {
        (n - 1) / 5
    }

    /// Compute `f + 1`, the number of votes that must endorse a position for it to be a
    /// safe-to-extend tip of a V-QC.
    ///
    /// Any set of this size contains at least one correct participant.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    #[commonware_macros::stability(ALPHA)]
    pub fn safe_rank(n: impl ToPrimitive) -> u32 {
        Self::max_faults(n) + 1
    }

    /// Compute `2f + 1`, the number of nullify messages in a nullification.
    ///
    /// Any set of this size shares at least one correct participant with every set of `n - f`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    #[commonware_macros::stability(ALPHA)]
    pub fn nullification_quorum(n: impl ToPrimitive) -> u32 {
        2 * Self::max_faults(n) + 1
    }

    /// Compute `3f + 1`, the number of votes that must endorse a position for it to be a
    /// finalized tip of an L-QC.
    ///
    /// Any set of this size contains at least `2f + 1` correct participants.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    #[commonware_macros::stability(ALPHA)]
    pub fn final_rank(n: impl ToPrimitive) -> u32 {
        3 * Self::max_faults(n) + 1
    }

    /// Compute `n - 2f`, the number of DA-votes in a DA-certificate.
    ///
    /// Any two sets of this size share at least `n - 4f >= f + 1` participants, so at least one
    /// correct participant.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    #[commonware_macros::stability(ALPHA)]
    pub fn da_quorum(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        n - 2 * Self::faults(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;
    use std::panic::{UnwindSafe, catch_unwind};

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft3f1_max_faults_zero_panics() {
        N3f1::max_faults(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft3f1_quorum_zero_panics() {
        N3f1::quorum(0);
    }

    #[rstest]
    #[case(1, 0, 1)]
    #[case(2, 0, 2)]
    #[case(3, 0, 3)]
    #[case(4, 1, 3)]
    #[case(5, 1, 4)]
    #[case(6, 1, 5)]
    #[case(7, 2, 5)]
    #[case(8, 2, 6)]
    #[case(9, 2, 7)]
    #[case(10, 3, 7)]
    #[case(11, 3, 8)]
    #[case(12, 3, 9)]
    #[case(13, 4, 9)]
    #[case(14, 4, 10)]
    #[case(15, 4, 11)]
    #[case(16, 5, 11)]
    #[case(17, 5, 12)]
    #[case(18, 5, 13)]
    #[case(19, 6, 13)]
    #[case(20, 6, 14)]
    #[case(21, 6, 15)]
    fn test_bft3f1_quorum_and_max_faults(
        #[case] n: u32,
        #[case] expected_f: u32,
        #[case] expected_q: u32,
    ) {
        assert_eq!(N3f1::max_faults(n), expected_f);
        assert_eq!(N3f1::quorum(n), expected_q);
        // Verify the invariant: n = f + q
        assert_eq!(n, expected_f + expected_q);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_max_faults_zero_panics() {
        N5f1::max_faults(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_quorum_zero_panics() {
        N5f1::quorum(0);
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
        assert_eq!(N3f1::max_faults(10u8), 3);
        assert_eq!(N3f1::max_faults(10u16), 3);
        assert_eq!(N3f1::max_faults(10u32), 3);
        assert_eq!(N3f1::max_faults(10u64), 3);
        assert_eq!(N3f1::max_faults(10usize), 3);
        assert_eq!(N3f1::max_faults(10i32), 3);
        assert_eq!(N3f1::max_faults(10i64), 3);

        assert_eq!(N3f1::quorum(10u8), 7);
        assert_eq!(N3f1::quorum(10u16), 7);
        assert_eq!(N3f1::quorum(10u64), 7);
        assert_eq!(N3f1::quorum(10usize), 7);
        assert_eq!(N3f1::quorum(10i32), 7);
        assert_eq!(N3f1::quorum(10i64), 7);

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

    #[test]
    #[should_panic(expected = "n must be a non-negative integer that fits in u32")]
    fn test_max_faults_negative_panics() {
        N3f1::max_faults(-1i32);
    }

    #[test]
    #[should_panic(expected = "n must be a non-negative integer that fits in u32")]
    fn test_max_faults_overflow_panics() {
        N3f1::max_faults(u64::MAX);
    }

    #[test]
    #[should_panic(expected = "n must be a non-negative integer that fits in u32")]
    fn test_quorum_negative_panics() {
        N3f1::quorum(-1i32);
    }

    #[test]
    #[should_panic(expected = "n must be a non-negative integer that fits in u32")]
    fn test_quorum_overflow_panics() {
        N3f1::quorum(u64::MAX);
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

        /// BFT safety property: two quorums must intersect in at least one honest node.
        ///
        /// Mathematically: 2q - n > f, or equivalently: 2q > n + f
        ///
        /// This ensures that any two quorums share at least one honest participant,
        /// which is fundamental for BFT consensus safety.
        #[test]
        fn test_bft_model_safety_property(n in 1u32..10_000) {
            // N3f1 safety
            let f_3f1 = N3f1::max_faults(n);
            let q_3f1 = N3f1::quorum(n);
            prop_assert!(
                2 * q_3f1 > n + f_3f1,
                "N3f1 safety violated for n={}: 2*{} <= {} + {}",
                n, q_3f1, n, f_3f1
            );

            // N5f1 safety
            let f_5f1 = N5f1::max_faults(n);
            let q_5f1 = N5f1::quorum(n);
            prop_assert!(
                2 * q_5f1 > n + f_5f1,
                "N5f1 safety violated for n={}: 2*{} <= {} + {}",
                n, q_5f1, n, f_5f1
            );
        }
    }
}
