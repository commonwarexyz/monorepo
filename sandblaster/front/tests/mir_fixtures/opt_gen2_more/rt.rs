//! Generic bit masks over a sealed trait.
mod sealed {
    /// sandblaster: the per-type dispatch of the optimized generic functions over `Prim` (DESIGN.md §2.1).
    #[doc(hidden)]
    #[allow(non_camel_case_types)]
    pub trait __sandblaster_dispatch_Prim: Sized {
        fn __sandblaster_opt_clamp_low(self) -> u8;
    }

    /// The primitive types the masks take.
    pub trait Prim: Copy + __sandblaster_dispatch_Prim {
        fn low(self) -> u8;
    }
    impl Prim for u16 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u32 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u64 {
        fn low(self) -> u8 { self as u8 }
    }
}
pub use sealed::Prim;

/// The low three bits of the low byte, clamped to 7 (which they never exceed).
pub fn clamp_low<T: Prim>(x: T) -> u8 {
    let b = x.low() & 7;
    if b > 7 { 7 } else { b }
}

/// The same, clamped twice, plus `k` (wrapping).
pub fn clamp_low_plus<T: Prim>(x: T, k: u8) -> u8 {
    let b = x.low() & 7;
    let b = if b > 7 { 7 } else { b };
    let b = if b > 7 { 7 } else { b };
    b.wrapping_add(k)
}

use bytes::BufMut;

/// A generic writer.
pub fn put_low<T: Prim>(x: T, buf: &mut impl BufMut) {
    buf.put_u8(x.low());
}

/// Already cheap at every instance.
pub fn low_byte<T: Prim>(x: T) -> u8 {
    x.low()
}

fn __sandblaster_check__clamp_low<T: Prim>(x: T) -> u8 {
    x.__sandblaster_opt_clamp_low()
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_clamp_low_for_u16(l0_x: u16) -> u8 {
    (l0_x as u8) & 7u8
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_clamp_low_for_u32(l0_x: u32) -> u8 {
    (l0_x as u8) & 7u8
}

impl sealed::__sandblaster_dispatch_Prim for u16 {
    #[inline(always)]
    fn __sandblaster_opt_clamp_low(self) -> u8 {
        __sandblaster_opt_clamp_low_for_u16(self)
    }
}

impl sealed::__sandblaster_dispatch_Prim for u32 {
    #[inline(always)]
    fn __sandblaster_opt_clamp_low(self) -> u8 {
        __sandblaster_opt_clamp_low_for_u32(self)
    }
}

impl sealed::__sandblaster_dispatch_Prim for u64 {
    #[inline(always)]
    fn __sandblaster_opt_clamp_low(self) -> u8 {
        __sandblaster_orig_clamp_low::<u64>(self)
    }
}

#[allow(dead_code)]
fn __sandblaster_orig_clamp_low<T: Prim>(x: T) -> u8 {
    let b = x.low() & 7;
    if b > 7 { 7 } else { b }
}
