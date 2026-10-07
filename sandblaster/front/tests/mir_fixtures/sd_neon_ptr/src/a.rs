//! A NEON load through a raw pointer: it needs `unsafe`, which verified code
//! never contains (refused, with the pointer load named).
use core::arch::aarch64::*;

/// The sixteen bytes of `a` as a vector.
pub fn load(a: &[u8; 16]) -> uint8x16_t {
    unsafe { vld1q_u8(a.as_ptr()) }
}
