/// The smaller of `a` and `b`, without a branch: `mask` is all ones when
/// `a < b` and zero otherwise, so `b ^ ((a ^ b) & mask)` is `a` or `b`.
pub fn min_u64(a: u64, b: u64) -> u64 {
    let mask = ((a < b) as u64).wrapping_neg();
    b ^ ((a ^ b) & mask)
}
