//! Small functions whose cheaper residuals rustc compiles to MIR of another
//! shape than the residuals' own (temporaries bound by `let`, a checked
//! operation's `Option` tested with `is_none`, sub-slices of a slice).

/// The smallest power of two that is `>= n` (`1` for `0` and `1`), or
/// `None` when it does not fit in a `u64`.
pub fn pow2_ceil(n: u64) -> Option<u64> {
    if n <= 1 {
        return Some(1);
    }
    let mut v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v.checked_add(1)
}

/// The big-endian `u16` at `at`, or `None` past the end of `data`.
pub fn read_u16_be(data: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let b = data.get(at..end)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// A multiply-xorshift mixer of a `u32`.
pub const fn mix32(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^ (x >> 16)
}

fn __sandblaster_check__pow2_ceil(n: u64) -> Option<u64> {
    __sandblaster_opt_pow2_ceil(n)
}

fn __sandblaster_check__read_u16_be(data: &[u8], at: usize) -> Option<u16> {
    __sandblaster_opt_read_u16_be(data, at)
}

fn __sandblaster_check__mix32(x: u32) -> u32 {
    __sandblaster_opt_mix32(x)
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_pow2_ceil(l0_n: u64) -> Option<u64> {
    if l0_n <= 1u64 {
        Some(1u64)
    } else {
        let l17_s17: u64 = l0_n - 1u64;
        let l18_s18: u64 = l17_s17 >> 1u32;
        let l19_s19: u64 = l17_s17 | l18_s18;
        let l20_s20: u64 = l19_s19 >> 2u32;
        let l21_s21: u64 = l19_s19 | l20_s20;
        let l22_s22: u64 = l21_s21 >> 4u32;
        let l23_s23: u64 = l21_s21 | l22_s22;
        let l24_s24: u64 = l23_s23 >> 8u32;
        let l25_s25: u64 = l23_s23 | l24_s24;
        let l26_s26: u64 = l25_s25 >> 16u32;
        let l27_s27: u64 = l25_s25 | l26_s26;
        let l28_s28: u64 = l27_s27 >> 32u32;
        let l29_s29: u64 = l27_s27 | l28_s28;
        match l29_s29.checked_add(1u64) {
            None => {
                None
            },
            Some(l16_value_16) => {
                Some(l29_s29 + 1u64)
            },
        }
    }
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_read_u16_be(l0_data: &[u8], l1_at: usize) -> Option<u16> {
    match l1_at.checked_add(2usize) {
        None => {
            None
        },
        Some(l8_value_8) => {
            let l9_s9: usize = l1_at + 2usize;
            if l1_at <= l9_s9 {
                if l9_s9 <= l0_data.len() {
                    let l10_s10: &[u8] = &l0_data[l1_at..];
                    let l11_s11: &[u8] = &l10_s10[..(l9_s9 - l1_at)];
                    let l12_s12: u16 = u16::from_le_bytes([l11_s11[0usize], l11_s11[1usize]]);
                    Some(l12_s12.wrapping_shl(8u32) | l12_s12.wrapping_shr(8u32))
                } else {
                    None
                }
            } else {
                None
            }
        },
    }
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
const fn __sandblaster_opt_mix32(mut l0_x: u32) -> u32 {
    let l8_s8: u32 = (l0_x ^ (l0_x >> 16u32)).wrapping_mul(2146121005u32);
    let l9_s9: u32 = (l8_s8 ^ (l8_s8 >> 15u32)).wrapping_mul(2221713035u32);
    l9_s9 ^ (l9_s9 >> 16u32)
}
