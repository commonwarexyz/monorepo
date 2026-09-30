//! The source of `lemmas/nat.core`: the facts of the ghost prelude's
//! `pow2`, `log2` and `popcount`, proved in the DSL. The kernel terms the
//! front end produces for them are the proofs in `lemmas/nat.core`;
//! `spec15_s5_gaps::nat_lemmas_match_their_source` checks that this crate
//! still proves exactly the statements of that file.
#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[cfg(sandblaster)]
#[path = "nat.rs"]
mod nat;

pub fn api(x: u8) -> u8 { x }
