//! Arithmetic written the obvious way, with nothing to rule out its panics.

/// Two quotients of the same operands, added: it panics when `b == 0` and
/// when the sum overflows (the second division is the first one again).
pub fn twice_quot(a: u32, b: u32) -> u32 {
    (a / b) + (a / b)
}

/// The ceiling of `a / b`: it panics when `b == 0`.
pub fn ceil_div(a: u32, b: u32) -> u32 {
    let q = a / b;
    if a % b != 0 { q + 1 } else { q }
}

/// `x + 1`: it panics at `u8::MAX`.
pub fn inc(x: u8) -> u8 {
    x + 1
}

/// The low three bits of `x`, clamped to 7 (which they never exceed), in a
/// `const fn`.
pub const fn clamp7c(x: u32) -> u32 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}
