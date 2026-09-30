//! Ghost-item attributes (DESIGN.md §4.5, §15), including `#[proof]`.
//!
//! Ghost files (`LAWS.rs`, `PROOF.rs`) are declared behind
//! `#[cfg(sandblaster)]`, so `rustc` never loads them and the checker reads
//! their annotations by name. This module exists for ghost code that should
//! nevertheless compile under `rustc` (e.g. a scratch file): `use
//! sandblaster::ghost::*;` brings every ghost-item attribute into scope, each of
//! which erases its item. It deliberately does not export the `proof!`
//! statement macro, which shares the name `proof` with the attribute (see
//! [`crate::prelude`]).

pub use sandblaster_macros::{
    assumption, corollary, definitional, example, examples, fuel_sufficient, induction, law,
    lemma, mirrors_impl, opaque, proof, reduces_to, rewrite, spec,
};
