//! commonware-storage's MMR position and peak arithmetic, verified in
//! place: `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` are lifted as
//! written from the host's own files (SEMANTICS.md §19), at the one
//! verified instance of the open `Family` traits (the MMR). `LAWS.rs`
//! states what they guarantee; `PROOF.rs` proves it.
#![forbid(unsafe_code)]

mod merkle;

// optimization alternatives: faster code for source functions, each tied to
// its function by a proven `#[rewrite]` lemma in PROOF.rs; lowered into the
// host's files only where cheaper (DESIGN.md §2.1)
#[lift(opt, instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family")]
mod opt;

// the toolchain's domain-free proof library (its `bridges` are prover rules)
#[cfg(sandblaster)]
#[path = "../../../sandblaster/front/stdlib/mod.rs"]
mod stdlib;

// word facts the prover applies by itself
#[cfg(sandblaster)]
#[bridges]
#[path = "WORDS.rs"]
mod words;

#[cfg(sandblaster)]
#[lift]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

// the boundary: the lifted types and their methods (laws may mention them),
// and the lift prelude's models of core types in their signatures
pub use merkle::{Error, Location, Position};
pub use merkle::mmr::Family;
pub use merkle::mmr::iterator::PeakIterator;
pub use crate::__lift::{Once, Ordering, PhantomData, RangeInclusiveU32, Result};
