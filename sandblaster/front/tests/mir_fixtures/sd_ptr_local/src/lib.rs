//! tests/unsafe_simd.rs: pointers whose base lives in a local of the forming
//! function, and the window rule's other siblings (stage soundness-fixes):
//! each function is read as rustc computes it or refused, named.
#[cfg(target_arch = "aarch64")]
pub mod a;
