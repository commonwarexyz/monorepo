//! aarch64 (NEON) load/store helpers (DESIGN.md §9.2).
//!
//! Each helper wraps exactly one unaligned `vld1`/`vst1` intrinsic behind a
//! fixed-size array reference; see the parent module for the contract. NEON
//! typed vectors are modelled as `Array(T, N)` of lanes with lane 0 at the
//! lowest address, which is exactly what `ld1`/`st1` do on little-endian
//! targets.

use core::arch::aarch64::{
    uint8x8_t, uint8x16_t, uint32x4_t, uint64x2_t, vld1_u8, vld1q_u8, vld1q_u32, vld1q_u64,
    vst1q_u8, vst1q_u32, vst1q_u64,
};

/// Load 16 bytes as a `uint8x16_t` (lane `i` = `a[i]`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn load_u8x16(a: &[u8; 16]) -> uint8x16_t {
    // SAFETY: `a` is a valid, readable 16-byte array; `vld1q_u8` performs an
    // unaligned 16-byte load; `neon` is enabled on this function.
    unsafe { vld1q_u8(a.as_ptr()) }
}

/// Load 8 bytes as a `uint8x8_t` (lane `i` = `a[i]`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn load_u8x8(a: &[u8; 8]) -> uint8x8_t {
    // SAFETY: `a` is a valid, readable 8-byte array; `vld1_u8` performs an
    // unaligned 8-byte load; `neon` is enabled on this function.
    unsafe { vld1_u8(a.as_ptr()) }
}

/// Load four 32-bit words as a `uint32x4_t` (lane `i` = `a[i]`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn load_u32x4(a: &[u32; 4]) -> uint32x4_t {
    // SAFETY: `a` is a valid, readable `[u32; 4]` (16 bytes, 4-byte aligned,
    // and `vld1q_u32` only needs element alignment); `neon` is enabled.
    unsafe { vld1q_u32(a.as_ptr()) }
}

/// Load two 64-bit words as a `uint64x2_t` (lane `i` = `a[i]`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn load_u64x2(a: &[u64; 2]) -> uint64x2_t {
    // SAFETY: `a` is a valid, readable `[u64; 2]`; `vld1q_u64` needs only
    // element alignment; `neon` is enabled on this function.
    unsafe { vld1q_u64(a.as_ptr()) }
}

/// Store a `uint8x16_t` into a fresh 16-byte array (`out[i]` = lane `i`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn store_u8x16(v: uint8x16_t) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: `out` is a valid, writable 16-byte array; `vst1q_u8` performs an
    // unaligned 16-byte store; `neon` is enabled on this function.
    unsafe { vst1q_u8(out.as_mut_ptr(), v) };
    out
}

/// Store a `uint32x4_t` into a fresh `[u32; 4]` (`out[i]` = lane `i`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn store_u32x4(v: uint32x4_t) -> [u32; 4] {
    let mut out = [0u32; 4];
    // SAFETY: `out` is a valid, writable `[u32; 4]`; `vst1q_u32` needs only
    // element alignment; `neon` is enabled on this function.
    unsafe { vst1q_u32(out.as_mut_ptr(), v) };
    out
}

/// Store a `uint64x2_t` into a fresh `[u64; 2]` (`out[i]` = lane `i`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `neon`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements NEON.
#[target_feature(enable = "neon")]
#[inline]
pub fn store_u64x2(v: uint64x2_t) -> [u64; 2] {
    let mut out = [0u64; 2];
    // SAFETY: `out` is a valid, writable `[u64; 2]`; `vst1q_u64` needs only
    // element alignment; `neon` is enabled on this function.
    unsafe { vst1q_u64(out.as_mut_ptr(), v) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        let bytes: [u8; 16] = core::array::from_fn(|i| i as u8 * 17);
        let words = [0x0123_4567, 0x89ab_cdef, 0xdead_beef, 0x0bad_f00d];
        // SAFETY: NEON was detected above.
        unsafe {
            assert_eq!(store_u8x16(load_u8x16(&bytes)), bytes);
            assert_eq!(store_u32x4(load_u32x4(&words)), words);
            assert_eq!(store_u64x2(load_u64x2(&[1, u64::MAX])), [1, u64::MAX]);
            let half: [u8; 8] = core::array::from_fn(|i| i as u8 + 1);
            let wide = core::arch::aarch64::vcombine_u8(load_u8x8(&half), load_u8x8(&half));
            assert_eq!(store_u8x16(wide)[..8], half);
        }
    }
}
