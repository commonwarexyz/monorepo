//! tests/simd.rs: a host crate whose `src/a.rs` (NEON, value intrinsics
//! only) is verified in place against scalar reference laws.
#[cfg(target_arch = "aarch64")]
pub mod a;
