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

fn __sandblaster_check__clamp7(x: u8) -> u8 {
    __sandblaster_opt_clamp7(x)
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_clamp7(l0_x: u8) -> u8 {
    l0_x & 7u8
}
