//! Buffer reads, the obvious way.
use bytes::Buf;

/// The low three bits, clamped to 7.
fn low3(x: u8) -> u8 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// One byte's low three bits, clamped to 7, or `None` at the end of the
/// buffer.
pub fn get_low3(buf: &mut impl Buf) -> Option<u8> {
    match buf.try_get_u8() {
        Ok(b) => {
            let y = b & 7;
            Some(if y > 7 { 7 } else { y })
        }
        Err(_) => None,
    }
}

/// Two bytes' low three bits added (`None` when fewer are left).
pub fn get_two(buf: &mut impl Buf) -> Option<u8> {
    let a = match buf.try_get_u8() {
        Ok(a) => low3(a),
        Err(_) => return None,
    };
    let b = match buf.try_get_u8() {
        Ok(b) => low3(b),
        Err(_) => return None,
    };
    Some(a + b)
}

/// A byte as it is (nothing cheaper).
pub fn get_raw(buf: &mut impl Buf) -> Option<u8> {
    match buf.try_get_u8() {
        Ok(b) => Some(b),
        Err(_) => None,
    }
}

fn __sandblaster_check__low3(x: u8) -> u8 {
    __sandblaster_opt_low3(x)
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_low3(l0_x: u8) -> u8 {
    l0_x & 7u8
}
