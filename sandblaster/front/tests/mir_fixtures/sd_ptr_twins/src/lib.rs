//! tests/unsafe_simd.rs: `unsafe` code outside the narrow reading of raw
//! pointers, or inside it but undefined: each function is refused, named.
#[cfg(target_arch = "aarch64")]
pub mod a;
