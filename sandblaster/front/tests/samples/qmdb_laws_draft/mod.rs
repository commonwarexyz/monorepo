//! Fixture of the §15.1 law-rule tests (`tests/spec15_law_rules.rs`): the draft `LAWS.rs` of
//! docs/qmdb-spec-design.md §2.2, copied verbatim from the design document by the test, over stub
//! spec items (`spec/`) that give every name the laws use its type and shape. The draft's own
//! spec files need front-end features that are not implemented yet (a recursive spec enum,
//! `?` in spec functions, `#[example]` on constants, vector files), so only the laws are the
//! draft's; the stubs are recursive where the real definitions are, so that no law follows from
//! one unfolding of a stub.
#![forbid(unsafe_code)]
use sandblaster::prelude::*;

mod verifier;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/mod.rs"]
mod spec;

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

pub use verifier::{verify, verify_fixed};
