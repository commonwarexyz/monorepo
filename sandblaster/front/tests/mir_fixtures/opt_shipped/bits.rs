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
