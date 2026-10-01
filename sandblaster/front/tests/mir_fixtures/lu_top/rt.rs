//! Bit tests of a byte, the obvious way.
//!
//! (A second paragraph of docs.)

/// Whether at most one bit of `x` is set.
pub fn at_most_one_bit(x: u8) -> bool {
    x.count_ones() <= 1
}

/// The number of set bits, plus one.
pub fn ones_plus_one(x: u8) -> u32 {
    x.count_ones() + 1
}

/// A byte. (`Byte::new` is not a candidate: its signature names `Self`,
/// a reason that mentions the round trip without being its rejection.)
pub struct Byte(pub u8);

impl Byte {
    /// Wraps `x`.
    pub fn new(x: u8) -> Self {
        Byte(x)
    }
}

fn __sandblaster_check__at_most_one_bit(x: u8) -> bool {
    __sandblaster_opt_at_most_one_bit_fast(x)
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

/// `x` has at most one bit set: clearing its lowest set bit leaves zero.
fn __sandblaster_opt_at_most_one_bit_fast(x: u8) -> bool {
    x & x.wrapping_sub(1) == 0
}
