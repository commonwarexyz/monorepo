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

#[cfg(test)]
mod tests {
    #[test]
    fn l() {
        assert!(line!() > 0);
    }
}
