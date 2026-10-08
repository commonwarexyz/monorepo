//! tests/unsafe_simd.rs: bodies that differ by the codegen configuration, for
//! a window extraction made under other rustflags than the main extraction
//! (stage soundness-fixes, the review's F2): the window extraction must be
//! refused.
#[cfg(target_arch = "aarch64")]
pub mod a;
