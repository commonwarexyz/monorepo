//! Faster alternatives, each tied to a source function by a `#[rewrite]`
//! lemma in PROOF.rs.

/// `x` has at most one bit set: clearing its lowest set bit leaves zero.
pub fn at_most_one_bit_fast(x: u8) -> bool {
    x & x.wrapping_sub(1) == 0
}
