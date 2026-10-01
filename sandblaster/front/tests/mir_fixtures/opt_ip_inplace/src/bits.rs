//! Bit tests of a byte, the obvious way.

/// Whether at most one bit of `x` is set.
pub fn at_most_one_bit(x: u8) -> bool {
    x.count_ones() <= 1
}

/// The number of set bits, plus one.
pub fn ones_plus_one(x: u8) -> u32 {
    x.count_ones() + 1
}
