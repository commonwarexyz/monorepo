//! A NEON intrinsic the target library has no validated model of (`vaddq_u8`):
//! refused by both readings, never read as anything.
use core::arch::aarch64::*;

/// The lane-wise sum of `x` and `y`.
#[target_feature(enable = "neon")]
pub fn add_bytes(x: uint8x16_t, y: uint8x16_t) -> uint8x16_t {
    vaddq_u8(x, y)
}
