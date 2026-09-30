//! A recursive spec type in use (§15 S5): hash trees and the generic
//! binding law of the QMDB design (docs/qmdb-spec-design.md §2.4), over a
//! toy digest so the sample stays small.
#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/mod.rs"]
mod spec;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;

pub fn api(x: u8) -> u8 { x }
