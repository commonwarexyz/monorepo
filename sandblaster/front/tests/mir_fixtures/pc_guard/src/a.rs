/// Half of `x`.
///
/// # Panics
///
/// Panics if `x` exceeds 1000.
pub fn halve_capped(x: u64) -> u64 {
    assert!(x <= 1000, "x exceeds 1000");
    x / 2
}

/// The successor of `x`.
///
/// # Panics
///
/// Panics if `x` is `u64::MAX` (the sum overflows).
pub fn succ(x: u64) -> u64 {
    x + 1
}

/// Half of the value in `x`.
///
/// # Panics
///
/// Panics if `x` is `None`.
pub fn half_of(x: Option<u64>) -> u64 {
    x.unwrap() / 2
}
