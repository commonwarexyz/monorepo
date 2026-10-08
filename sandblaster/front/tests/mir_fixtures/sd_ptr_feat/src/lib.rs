//! tests/unsafe_simd.rs: a body that differs by a Cargo feature (stage
//! leftovers): a window extraction, or a build, under other features than
//! the main extraction's must be refused.
#[cfg(target_arch = "aarch64")]
pub mod a;
