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
    /// to make progress. It defaults to `n - max_faults(n)`. A model for a protocol that
    /// only needs every quorum to contain a correct participant may choose a smaller quorum,
    /// but never one of `max_faults(n)` or fewer.
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
/// Tolerates up to `f = (n-1)/5` faults with quorum size `q = n - f`.
///
/// # Example
///
/// | n  | f  | quorum |
/// |----|----|--------|
/// | 6  | 1  | 5      |
/// | 11 | 2  | 9      |
/// | 16 | 3  | 13     |
/// | 21 | 4  | 17     |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct N5f1;

impl Faults for N5f1 {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        (n - 1) / 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;

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

    #[rstest]
    // n=1 to n=5: f=0
    #[case(1, 0, 1)]
    #[case(2, 0, 2)]
    #[case(3, 0, 3)]
    #[case(4, 0, 4)]
    #[case(5, 0, 5)]
    // n=6 to n=10: f=1
    #[case(6, 1, 5)]
    #[case(7, 1, 6)]
    #[case(8, 1, 7)]
    #[case(9, 1, 8)]
    #[case(10, 1, 9)]
    // n=11 to n=15: f=2
    #[case(11, 2, 9)]
    #[case(12, 2, 10)]
    #[case(13, 2, 11)]
    #[case(14, 2, 12)]
    #[case(15, 2, 13)]
    // n=16 to n=20: f=3
    #[case(16, 3, 13)]
    #[case(17, 3, 14)]
    #[case(18, 3, 15)]
    #[case(19, 3, 16)]
    #[case(20, 3, 17)]
    // n=21: f=4
    #[case(21, 4, 17)]
    #[case(100, 19, 81)]
    #[case(u32::MAX, 858_993_458, 3_435_973_837)]
    fn test_bft5f1_quorums(#[case] n: u32, #[case] expected_f: u32, #[case] expected_quorum: u32) {
        assert_eq!(N5f1::max_faults(n), expected_f);
        assert_eq!(N5f1::quorum(n), expected_quorum);

        // Verify invariants
        assert_eq!(n, expected_f + expected_quorum); // n = f + q
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
