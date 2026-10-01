//! Faster alternatives, each tied to a source function by a `#[rewrite]`
//! lemma in PROOF.rs.

/// `x` has at most one bit set: clearing its lowest set bit leaves zero.
pub fn at_most_one_bit_fast(x: u8) -> bool {
    x & x.wrapping_sub(1) == 0
}

/// Slower than the source (a multiply, a mask and a remainder).
pub fn ones_plus_one_slow(x: u8) -> u32 {
    let v = ((x as u64) * 0x0804_0201 >> 3) & 0x1111_1111;
    (v % 15) as u32 + 1
}
