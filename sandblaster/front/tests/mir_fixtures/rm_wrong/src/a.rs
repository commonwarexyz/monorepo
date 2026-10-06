/// The smaller of `a` and `b`, without a branch, with a classic slip: the
/// comparison bit is the mask without being negated to all ones, so only
/// the lowest bit of `a ^ b` is ever selected.
pub fn min_u64(a: u64, b: u64) -> u64 {
    let mask = (a < b) as u64;
    b ^ ((a ^ b) & mask)
}
