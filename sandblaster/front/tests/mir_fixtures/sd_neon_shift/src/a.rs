//! A negative twin of `sd_neon`: the high nibble taken with a shift by 3, not 4.
//!
//! Sixteen bytes through nibble tables with NEON: the shape of Reed–Solomon's
//! NEON `mul_128` on one vector, in safe Rust (value intrinsics only, in
//! `#[target_feature(enable = "neon")]` functions).
use core::arch::aarch64::*;

/// Each byte `b` of `x` through the nibble tables: `lo[b & 15] ^ hi[b >> 4]`.
#[target_feature(enable = "neon")]
pub fn mul_nibbles(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) -> uint8x16_t {
    let mask = vdupq_n_u8(0x0f);
    let l = vqtbl1q_u8(lo, vandq_u8(x, mask));
    let h = vqtbl1q_u8(hi, vshrq_n_u8::<3>(x));
    veorq_u8(l, h)
}

/// Each byte `k` of `idx` looked up in `table`: `table[k]`, or 0 past it.
#[target_feature(enable = "neon")]
pub fn lookup(table: uint8x16_t, idx: uint8x16_t) -> uint8x16_t {
    vqtbl1q_u8(table, idx)
}

/// `mul_nibbles` twice: a `#[target_feature]` function calling another.
#[target_feature(enable = "neon")]
pub fn mul_twice(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) -> uint8x16_t {
    mul_nibbles(mul_nibbles(x, lo, hi), lo, hi)
}

/// Whether the CPU has NEON: every aarch64 target enables it, so the
/// detection is the constant `true`.
pub fn has_neon() -> bool {
    std::arch::is_aarch64_feature_detected!("neon")
}
