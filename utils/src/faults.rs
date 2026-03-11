//! Byzantine fault tolerance models for consensus protocols.
//!
//! This module provides abstractions over quorum calculations for different BFT
//! fault models. The primary models are:
//!
//! - [`N3f1`]: Fault model requiring `n >= 3f + 1` participants
//! - [`N5f1`]: Fault model requiring `n >= 5f + 1` participants (L-quorum: `n - f`)
//! - [`M5f1`]: M-quorum variant of `N5f1` (M-quorum: `2f + 1`)
//!
//! _`f` denotes the maximum number of faults that can be tolerated._
//!
//! # Example
//!
//! ```
//! use commonware_utils::{Faults, N3f1, N5f1, M5f1};
//!
//! // n >= 3f+1
//! let n = 10;
//! assert_eq!(N3f1::max_faults(n), 3);  // f = (n-1)/3 = 3
//! assert_eq!(N3f1::quorum(n), 7);       // q = n - f = 7
//!
//! // n >= 5f+1 (L-quorum)
//! assert_eq!(N5f1::max_faults(n), 1);  // f = (n-1)/5 = 1
//! assert_eq!(N5f1::quorum(n), 9);       // L-quorum = n - f = 9
//!
//! // n >= 5f+1 (M-quorum)
//! assert_eq!(M5f1::max_faults(n), 1);  // f = (n-1)/5 = 1
//! assert_eq!(M5f1::quorum(n), 3);       // M-quorum = 2f + 1 = 3
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
    /// to make progress.
    ///
    /// The default implementation returns `n - max_faults(n)`, but specific models
    /// may override this. For example, [`M5f1`] uses M-quorum (`2f + 1`) while
    /// preserving [`Faults::max_faults`] from [`N5f1`].
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
/// Tolerates up to `f = (n-1)/5` faults with quorum size `q = n - f` (also
/// provided as [`l_quorum`](Self::l_quorum)).
///
/// Also provides [`m_quorum`](Self::m_quorum) which computes `2f + 1`.
///
/// # Example
///
/// | n  | f  | quorum (n-f) | m-quorum (2f+1) |
/// |----|----| -------------|-----------------|
/// | 6  | 1  | 5            | 3               |
/// | 11 | 2  | 9            | 5               |
/// | 16 | 3  | 13           | 7               |
/// | 21 | 4  | 17           | 9               |
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

impl N5f1 {
    /// Compute `2f + 1`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    pub fn m_quorum(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        assert!(n > 0, "n must not be zero");
        2 * Self::max_faults(n) + 1
    }

    /// Compute `n - f`.
    ///
    /// This is equivalent to [`Self::quorum`].
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, negative, or exceeds `u32::MAX`.
    pub fn l_quorum(n: impl ToPrimitive) -> u32 {
        Self::quorum(n)
    }
}

/// M-quorum variant of the `n >= 5f + 1` fault model.
///
/// This type uses the same fault tolerance as [`N5f1`] but returns `2f + 1`
/// (M-quorum) from [`Faults::quorum`] instead of `n - f` (L-quorum).
///
/// This is useful for protocols like Minimmit that require different quorum
/// thresholds for different certificate types:
/// - M-notarization and Nullification use M-quorum (`2f + 1`)
/// - Finalization uses L-quorum (`n - f`)
///
/// # Example
///
/// | n  | f  | M-quorum (2f+1) | L-quorum (n-f) |
/// |----|----| ----------------|----------------|
/// | 6  | 1  | 3               | 5              |
/// | 11 | 2  | 5               | 9              |
/// | 16 | 3  | 7               | 13             |
/// | 21 | 4  | 9               | 17             |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct M5f1;

impl Faults for M5f1 {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        N5f1::max_faults(n)
    }

    fn quorum(n: impl ToPrimitive) -> u32 {
        N5f1::m_quorum(n)
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

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_m_quorum_zero_panics() {
        N5f1::m_quorum(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_bft5f1_l_quorum_zero_panics() {
        N5f1::l_quorum(0);
    }

    #[rstest]
    // n=1 to n=5: f=0
    #[case(1, 0, 1, 1)]
    #[case(2, 0, 2, 1)]
    #[case(3, 0, 3, 1)]
    #[case(4, 0, 4, 1)]
    #[case(5, 0, 5, 1)]
    // n=6 to n=10: f=1
    #[case(6, 1, 5, 3)]
    #[case(7, 1, 6, 3)]
    #[case(8, 1, 7, 3)]
    #[case(9, 1, 8, 3)]
    #[case(10, 1, 9, 3)]
    // n=11 to n=15: f=2
    #[case(11, 2, 9, 5)]
    #[case(12, 2, 10, 5)]
    #[case(13, 2, 11, 5)]
    #[case(14, 2, 12, 5)]
    #[case(15, 2, 13, 5)]
    // n=16 to n=20: f=3
    #[case(16, 3, 13, 7)]
    #[case(17, 3, 14, 7)]
    #[case(18, 3, 15, 7)]
    #[case(19, 3, 16, 7)]
    #[case(20, 3, 17, 7)]
    // n=21: f=4
    #[case(21, 4, 17, 9)]
    fn test_bft5f1_quorums(
        #[case] n: u32,
        #[case] expected_f: u32,
        #[case] expected_l_quorum: u32,
        #[case] expected_m_quorum: u32,
    ) {
        assert_eq!(N5f1::max_faults(n), expected_f);
        assert_eq!(N5f1::quorum(n), expected_l_quorum);
        assert_eq!(N5f1::l_quorum(n), expected_l_quorum);
        assert_eq!(N5f1::m_quorum(n), expected_m_quorum);

        // Verify invariants
        assert_eq!(n, expected_f + expected_l_quorum); // n = f + q
        assert_eq!(expected_m_quorum, 2 * expected_f + 1); // m = 2f + 1
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_m5f1_max_faults_zero_panics() {
        M5f1::max_faults(0);
    }

    #[test]
    #[should_panic(expected = "n must not be zero")]
    fn test_m5f1_quorum_zero_panics() {
        M5f1::quorum(0);
    }

    #[rstest]
    // n=1 to n=5: f=0, M-quorum=1
    #[case(1, 0, 1)]
    #[case(2, 0, 1)]
    #[case(3, 0, 1)]
    #[case(4, 0, 1)]
    #[case(5, 0, 1)]
    // n=6 to n=10: f=1, M-quorum=3
    #[case(6, 1, 3)]
    #[case(7, 1, 3)]
    #[case(8, 1, 3)]
    #[case(9, 1, 3)]
    #[case(10, 1, 3)]
    // n=11 to n=15: f=2, M-quorum=5
    #[case(11, 2, 5)]
    #[case(12, 2, 5)]
    #[case(13, 2, 5)]
    #[case(14, 2, 5)]
    #[case(15, 2, 5)]
    // n=16 to n=20: f=3, M-quorum=7
    #[case(16, 3, 7)]
    #[case(17, 3, 7)]
    #[case(18, 3, 7)]
    #[case(19, 3, 7)]
    #[case(20, 3, 7)]
    // n=21: f=4, M-quorum=9
    #[case(21, 4, 9)]
    fn test_m5f1_quorums(#[case] n: u32, #[case] expected_f: u32, #[case] expected_m_quorum: u32) {
        assert_eq!(M5f1::max_faults(n), expected_f);
        assert_eq!(M5f1::quorum(n), expected_m_quorum);

        // Verify M5f1 matches N5f1's m_quorum
        assert_eq!(M5f1::quorum(n), N5f1::m_quorum(n));
        assert_eq!(M5f1::max_faults(n), N5f1::max_faults(n));

        // Verify invariant: m = 2f + 1
        assert_eq!(expected_m_quorum, 2 * expected_f + 1);
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
        assert_eq!(N5f1::m_quorum(10i32), 3);
        assert_eq!(N5f1::l_quorum(10i64), 9);

        // M5f1 integer type tests
        assert_eq!(M5f1::max_faults(10u64), 1);
        assert_eq!(M5f1::max_faults(10usize), 1);
        assert_eq!(M5f1::max_faults(10i32), 1);
        assert_eq!(M5f1::quorum(10u64), 3);
        assert_eq!(M5f1::quorum(10usize), 3);
        assert_eq!(M5f1::quorum(10i32), 3);
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
        /// - M-quorum (2f+1) < L-quorum (n-f)
        /// - Both quorums must be achievable (<= n)
        #[test]
        fn test_n5f1_quorum_relationships(n in 6u32..10_000) {
            let m = N5f1::m_quorum(n);
            let l = N5f1::l_quorum(n);

            // M-quorum must be strictly less than L-quorum
            prop_assert!(
                m < l,
                "M-quorum ({}) should be less than L-quorum ({}) for n={}",
                m, l, n
            );

            // Both quorums must be achievable
            prop_assert!(m <= n, "M-quorum ({}) should be <= n ({})", m, n);
            prop_assert!(l <= n, "L-quorum ({}) should be <= n ({})", l, n);
        }

        /// M5f1 must be consistent with N5f1's m_quorum.
        ///
        /// M5f1::quorum(n) == N5f1::m_quorum(n) for all valid n.
        #[test]
        fn test_m5f1_consistency_with_n5f1(n in 1u32..10_000) {
            // M5f1::quorum must equal N5f1::m_quorum
            prop_assert_eq!(
                M5f1::quorum(n),
                N5f1::m_quorum(n),
                "M5f1::quorum({}) != N5f1::m_quorum({})",
                n, n
            );

            // M5f1::max_faults must equal N5f1::max_faults
            prop_assert_eq!(
                M5f1::max_faults(n),
                N5f1::max_faults(n),
                "M5f1::max_faults({}) != N5f1::max_faults({})",
                n, n
            );
        }

        /// Minimmit safety boundary: M-quorum and L-quorum must intersect in
        /// more than `f` participants, guaranteeing at least one honest overlap.
        ///
        /// Mathematically: `m + l > n + f` where:
        /// - `m = 2f + 1` (M-quorum)
        /// - `l = n - f` (L-quorum)
        #[test]
        fn test_n5f1_m_l_intersection_exceeds_faults(n in 1u32..10_000) {
            let f = N5f1::max_faults(n);
            let m = M5f1::quorum(n);
            let l = N5f1::l_quorum(n);

            prop_assert!(
                m + l > n + f,
                "N5f1/M5f1 intersection violated for n={}: {} + {} <= {} + {}",
                n,
                m,
                l,
                n,
                f
            );
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
