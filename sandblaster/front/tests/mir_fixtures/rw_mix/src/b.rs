//! A file of the crate that `a.rs` calls into (not lifted itself).

/// The low byte of `x`, as a `u64`.
pub fn low(x: u64) -> u64 {
    x & 0xff
}
