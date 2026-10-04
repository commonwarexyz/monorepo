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

fn __sandblaster_check__twice_quot(a: u32, b: u32) -> u32 {
    __sandblaster_opt_twice_quot(a, b)
}

fn __sandblaster_check__clamp7c(x: u32) -> u32 {
    __sandblaster_opt_clamp7c(x)
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_twice_quot(l0_a: u32, l1_b: u32) -> u32 {
    {
        let l10_s10: u32 = l0_a / l1_b;
        {
            let l9_value_9: u32 = l10_s10 + l10_s10;
            l9_value_9
        }
    }
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
const fn __sandblaster_opt_clamp7c(l0_x: u32) -> u32 {
    l0_x & 7u32
}
