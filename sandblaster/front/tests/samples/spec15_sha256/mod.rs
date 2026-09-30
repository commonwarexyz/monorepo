//! Worked example of DESIGN.md §15 (S1): a SHA-256 compression function
//! and a big-endian reader, each refining a readable reference
//! specification; the specification itself is validated by known answers
//! (`#[example]`) and an independent CAVP-format vector file.
#![forbid(unsafe_code)]
use sandblaster::prelude::*;

mod codec;
mod sha;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/mod.rs"]
mod spec;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;

pub use codec::read_u32_be;
pub use sha::compress;
