//! tests/simd.rs: a negative twin of `sd_neon_mul128` (the high nibble of the
//! low bytes taken with a shift by 3), refused by the same laws.
#[cfg(target_arch = "aarch64")]
pub mod a;
