//! tests/simd.rs: a negative twin of `sd_neon_mul128` (the low product
//! bytes' third and fourth rows swapped), refused by the same laws.
#[cfg(target_arch = "aarch64")]
pub mod a;
