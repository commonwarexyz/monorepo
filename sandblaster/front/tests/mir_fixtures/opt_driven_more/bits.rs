//! Bit tests, written the obvious way.

/// `n + 1` (wrapping) when the low three bits of `k` are zero, else `n`; the
/// bits are clamped to 7 on the way (which they never exceed).
pub fn bump_low(n: u32, k: u32) -> u32 {
    let m = k & 7;
    let m = if m > 7 { 7 } else { m };
    let m = if m > 7 { 7 } else { m };
    if m < 1 { n.wrapping_add(1) } else { n }
}

/// The low three bits of `x`, clamped to 7 (which they never exceed).
pub fn clamp7(x: u32) -> u32 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// Already as cheap as it gets.
pub fn low_byte(x: u64) -> u8 {
    x as u8
}

mod sealed {
    pub trait Prim: Copy {
        fn low(self) -> u8;
    }
    impl Prim for u16 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u32 {
        fn low(self) -> u8 { self as u8 }
    }
}
pub use sealed::Prim;

/// Generic: one instance per impl type.
pub fn clamp_generic<T: Prim>(x: T) -> u8 {
    let b = x.low() & 7;
    if b > 7 { 7 } else { b }
}

use bytes::BufMut;

/// A state and a result: not lowered yet.
pub fn put_counted(x: u8, buf: &mut impl BufMut) -> u32 {
    buf.put_u8(x & 7);
    1
}
