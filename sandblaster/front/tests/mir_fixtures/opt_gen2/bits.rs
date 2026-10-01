//! Generic bit masks over a sealed trait.
mod sealed {
    /// The primitive types the masks take.
    pub trait Prim: Copy {
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
