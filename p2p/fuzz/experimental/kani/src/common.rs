//! Helpers shared by the proofs.

/// An implementation-consistency check: an assertion that is STRONGER than the documented
/// contract.
///
/// It is compiled into the proof only with `--features consistency`. The default build (the
/// contract gate) does not assert it, so a valid change of the implementation cannot fail the
/// gate through one of these.
macro_rules! consistency {
    ($($arg:tt)*) => {
        if cfg!(feature = "consistency") {
            assert!($($arg)*);
        }
    };
}
pub(crate) use consistency;

/// Returns `true` when `a` and `b` have the same length and hold the same bytes.
///
/// A plain loop, so that a proof does not depend on how the compiler lowers a slice
/// comparison. A harness that calls it needs an unwind bound above the slice length.
pub fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
