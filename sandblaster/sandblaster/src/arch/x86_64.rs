//! x86_64 (SSE2) load/store helpers (DESIGN.md §9.2).
//!
//! Each helper wraps exactly one unaligned `_mm_loadu_si128` /
//! `_mm_storeu_si128` behind a fixed-size array reference; see the parent
//! module for the contract. `__m128i` is canonically `Array(U8, 16)`,
//! little-endian, lane 0 at the lowest address, so a `[u32; 4]` loaded here
//! has 32-bit view `[a[0], a[1], a[2], a[3]]`.

use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

/// Load 16 bytes as an `__m128i` (byte `i` = `a[i]`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `sse2`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements SSE2.
#[target_feature(enable = "sse2")]
#[inline]
pub fn load_u8x16(a: &[u8; 16]) -> __m128i {
    // SAFETY: `a` is a valid, readable 16-byte array and `_mm_loadu_si128`
    // has no alignment requirement; `sse2` is enabled on this function.
    unsafe { _mm_loadu_si128(a.as_ptr().cast::<__m128i>()) }
}

/// Load four 32-bit words as an `__m128i` (32-bit lane `i` = `a[i]`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `sse2`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements SSE2.
#[target_feature(enable = "sse2")]
#[inline]
pub fn load_u32x4(a: &[u32; 4]) -> __m128i {
    // SAFETY: `a` is a valid, readable 16-byte array and `_mm_loadu_si128`
    // has no alignment requirement; `sse2` is enabled on this function.
    unsafe { _mm_loadu_si128(a.as_ptr().cast::<__m128i>()) }
}

/// A vector constant from four 32-bit words, passed by value
/// (`m128i_from_u32x4([w0, w1, w2, w3])` has 32-bit view `[w0, w1, w2, w3]`).
/// This is the unsigned replacement for `_mm_set_epi32`, whose arguments are
/// signed (§9.2).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `sse2`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements SSE2.
#[target_feature(enable = "sse2")]
#[inline]
pub fn m128i_from_u32x4(a: [u32; 4]) -> __m128i {
    // SAFETY: `a` is a valid, readable 16-byte local and `_mm_loadu_si128`
    // has no alignment requirement; `sse2` is enabled on this function.
    unsafe { _mm_loadu_si128(a.as_ptr().cast::<__m128i>()) }
}

/// Store an `__m128i` into a fresh 16-byte array (`out[i]` = byte `i`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `sse2`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements SSE2.
#[target_feature(enable = "sse2")]
#[inline]
pub fn store_u8x16(v: __m128i) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: `out` is a valid, writable 16-byte array and
    // `_mm_storeu_si128` has no alignment requirement; `sse2` is enabled.
    unsafe { _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), v) };
    out
}

/// Store an `__m128i` into a fresh `[u32; 4]` (`out[i]` = 32-bit lane `i`).
///
/// # Safety
///
/// Safe to call from a function whose feature set includes `sse2`.
/// Elsewhere `rustc` requires `unsafe`, and the caller must guarantee that
/// the CPU implements SSE2.
#[target_feature(enable = "sse2")]
#[inline]
pub fn store_u32x4(v: __m128i) -> [u32; 4] {
    let mut out = [0u32; 4];
    // SAFETY: `out` is a valid, writable 16-byte array and
    // `_mm_storeu_si128` has no alignment requirement; `sse2` is enabled.
    unsafe { _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), v) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes: [u8; 16] = core::array::from_fn(|i| i as u8 * 17);
        let words = [0x0123_4567, 0x89ab_cdef, 0xdead_beef, 0x0bad_f00d];
        // SAFETY: SSE2 is part of the x86_64 baseline.
        unsafe {
            assert_eq!(store_u8x16(load_u8x16(&bytes)), bytes);
            assert_eq!(store_u32x4(load_u32x4(&words)), words);
            assert_eq!(store_u32x4(m128i_from_u32x4(words)), words);
            assert_eq!(store_u8x16(load_u32x4(&words))[..4], 0x0123_4567u32.to_le_bytes());
        }
    }
}
