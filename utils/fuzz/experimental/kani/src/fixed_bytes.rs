//! `FixedBytes<N>` orders exactly as its byte array does.
//!
//! `FixedBytes<N>` is a key type: its order decides the order of maps and of sorted lists.
//! Its `Ord` takes one of three paths by width: the array compare for `N <= 16` and `N > 64`;
//! for the widths between, a compare of 8-byte big-endian words, and when `N` is not a
//! multiple of 8, a last compare of the final 8 bytes, which overlap the last whole word.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! The documentation of `FixedBytes` does not state its order. The crate's own test does:
//!
//! 1. The order of two values is the order of their byte arrays, both ways, and
//!    `partial_cmp` agrees. utils/src/sequence/fixed_bytes.rs, the test helper
//!    `assert_matches`: "assert_eq!(left.cmp(&right), a.cmp(b));",
//!    "assert_eq!(right.cmp(&left), b.cmp(a));" and
//!    "assert_eq!(left.partial_cmp(&right), Some(a.cmp(b)));".
//! 2. This holds at every width. utils/src/sequence/fixed_bytes.rs, the doc of the test
//!    `test_ord_matches_byte_order`: "Checks `FixedBytes` ordering against `[u8; N]` at every
//!    first-difference position, on both sides of each size cutoff and at every remainder
//!    length."
//!
//! The order of `[u8; N]` is lexicographic: the first index where the arrays differ decides,
//! and arrays with no such index are equal. The proof compares with a plain loop that states
//! this rule, not with the array compare, so it does not depend on how the compiler lowers a
//! slice compare.
//!
//! # What is proven
//!
//! `kani_fixed_bytes_cmp_<N>`: for EVERY pair of arrays `a`, `b` of `N` bytes,
//! `FixedBytes::new(a).cmp(&FixedBytes::new(b))` is the lexicographic order of `a` and `b`,
//! the reversed compare is its reverse, and `partial_cmp` is `Some` of it.
//!
//! # Bounds
//!
//! No bound on the content: every byte of both arrays is any value. The widths are
//! 16, 17, 18, 19, 20, 21, 22, 23, 24, 63, 64 and 65, one harness each (`N` is a constant of
//! the type). They hold both sides of both cutoffs (16 and 17, 64 and 65) and every remainder
//! of `N` modulo 8 inside the word path (17 to 24), as the crate's test does. Other widths are
//! not proven: they share a path and a remainder with a proven width, which is an argument,
//! not a proof. Loops unwind `N + 2` times. `usize` is 64 bits.

use commonware_utils::sequence::FixedBytes;
use core::cmp::Ordering;

/// The lexicographic order of two arrays and the first index where they differ.
fn byte_order<const N: usize>(a: &[u8; N], b: &[u8; N]) -> (Ordering, Option<usize>) {
    let mut i = 0;
    while i < N {
        if a[i] != b[i] {
            let order = if a[i] < b[i] {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            return (order, Some(i));
        }
        i += 1;
    }
    (Ordering::Equal, None)
}

/// Asserts the contract for any two arrays of `N` bytes and returns their order and the first
/// index where they differ, for the cover checks of the caller.
fn check<const N: usize>() -> (Ordering, Option<usize>) {
    let a: [u8; N] = kani::any();
    let b: [u8; N] = kani::any();
    let (left, right) = (FixedBytes::new(a), FixedBytes::new(b));
    let (order, first) = byte_order(&a, &b);

    assert!(left.cmp(&right) == order);
    assert!(right.cmp(&left) == order.reverse());
    assert!(left.partial_cmp(&right) == Some(order));

    kani::cover!(order == Ordering::Less, "orders a smaller array first");
    kani::cover!(order == Ordering::Greater, "orders a larger array last");
    kani::cover!(order == Ordering::Equal, "equal arrays are equal");
    kani::cover!(first == Some(0), "the first byte decides");
    kani::cover!(first == Some(N - 1), "the last byte decides");
    (order, first)
}

/// One harness per width. The last argument names the path of `cmp` for that width, so that
/// each harness holds only the cover checks its width can satisfy:
///
/// - `array`: `N <= 16` or `N > 64`, the array compare. No further check.
/// - `words`: `N` is a multiple of 8 between 17 and 64. A whole word decides.
/// - `words_tail`: any other `N` between 17 and 64. A whole word decides, or the bytes after
///   the last whole word do (the overlapping last compare).
macro_rules! cmp_harness {
    ($name:ident, $n:literal, $unwind:literal, array) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            check::<$n>();
        }
    };
    ($name:ident, $n:literal, $unwind:literal, words) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            let (_, first) = check::<$n>();
            kani::cover!(matches!(first, Some(k) if k >= 8), "a later whole word decides");
        }
    };
    ($name:ident, $n:literal, $unwind:literal, words_tail) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            let (_, first) = check::<$n>();
            kani::cover!(
                matches!(first, Some(k) if k >= 8 && k < $n / 8 * 8),
                "a later whole word decides"
            );
            kani::cover!(
                matches!(first, Some(k) if k >= $n / 8 * 8),
                "the bytes after the last whole word decide"
            );
        }
    };
}

cmp_harness!(kani_fixed_bytes_cmp_16, 16, 18, array);
cmp_harness!(kani_fixed_bytes_cmp_17, 17, 19, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_18, 18, 20, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_19, 19, 21, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_20, 20, 22, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_21, 21, 23, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_22, 22, 24, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_23, 23, 25, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_24, 24, 26, words);
cmp_harness!(kani_fixed_bytes_cmp_63, 63, 65, words_tail);
cmp_harness!(kani_fixed_bytes_cmp_64, 64, 66, words);
cmp_harness!(kani_fixed_bytes_cmp_65, 65, 67, array);
