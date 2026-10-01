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
    /// sandblaster: the per-type dispatch of the optimized generic functions over `Prim` (DESIGN.md §2.1).
    #[doc(hidden)]
    #[allow(non_camel_case_types)]
    pub trait __sandblaster_dispatch_Prim: Sized {
        fn __sandblaster_opt_clamp_generic(self) -> u8;
    }

    pub trait Prim: Copy + __sandblaster_dispatch_Prim {
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

fn __sandblaster_check__clamp7(x: u32) -> u32 {
    __sandblaster_opt_clamp7(x)
}

fn __sandblaster_check__clamp_generic<T: Prim>(x: T) -> u8 {
    x.__sandblaster_opt_clamp_generic()
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_clamp7(l0_x: u32) -> u32 {
    l0_x & 7u32
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_clamp_generic_for_u16(l0_x: u16) -> u8 {
    (l0_x as u8) & 7u8
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_clamp_generic_for_u32(l0_x: u32) -> u8 {
    (l0_x as u8) & 7u8
}

impl sealed::__sandblaster_dispatch_Prim for u16 {
    #[inline(always)]
    fn __sandblaster_opt_clamp_generic(self) -> u8 {
        __sandblaster_opt_clamp_generic_for_u16(self)
    }
}

impl sealed::__sandblaster_dispatch_Prim for u32 {
    #[inline(always)]
    fn __sandblaster_opt_clamp_generic(self) -> u8 {
        __sandblaster_opt_clamp_generic_for_u32(self)
    }
}
