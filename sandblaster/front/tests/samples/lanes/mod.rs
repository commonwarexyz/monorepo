//! Lane sites (plan O10): arrays of independent SHA-256 compressions and
//! 64-byte hashes, which the lane functor lifts to AVX-512 ×16, AVX2 ×8 and
//! NEON ×4 kernels. `tools/gates/g7.sh` emits this crate for x86_64 with
//! `SANDBLASTER_LANES_COMPILE_ONLY=1` (the kernels printed although no host has
//! run them) and compiles it for both x86_64 triples.
#![forbid(unsafe_code)]

pub mod sha256;
pub mod sites;
