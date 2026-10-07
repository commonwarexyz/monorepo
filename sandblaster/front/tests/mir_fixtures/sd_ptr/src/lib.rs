//! tests/unsafe_simd.rs: `unsafe` NEON code read through the narrow reading
//! of raw-pointer loads and stores (docs/DESIGN-UNSAFE-SIMD.md), verified in
//! place against a scalar reference.
#[cfg(target_arch = "aarch64")]
pub mod a;
