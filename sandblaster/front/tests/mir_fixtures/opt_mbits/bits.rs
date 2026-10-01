//! Bits of a byte, the obvious way.

/// The low three bits of `x`, clamped to 7.
pub fn clamp7(x: u8) -> u8 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// The low byte of `x`.
pub fn low_byte(x: u32) -> u8 {
    x as u8
}
