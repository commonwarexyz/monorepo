//! tests/simd.rs: Reed–Solomon's NEON `mul_128` as written (its table rows as
//! byte arrays), verified in place against the scalar reference: the
//! split-table lookups proven lane by lane.
#[cfg(target_arch = "aarch64")]
pub mod a;
