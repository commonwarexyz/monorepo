//! Bits of a byte, the obvious way.

/// The low three bits of `x`, clamped to 7.
pub fn clamp7(x: u8) -> u8 {
    x & 7
}

/// The low byte of `x`.
pub fn low_byte(x: u32) -> u8 {
    x as u8
}
