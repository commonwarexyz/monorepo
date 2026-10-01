//! commonware-storage's Merkle proof verifier, verified in place (first
//! set): the hashing of `src/merkle/hasher.rs` at QMDB's hasher
//! (`Standard<Sha256>`) and the subtree reconstruction of
//! `src/merkle/proof.rs` (`Subtree::reconstruct_digest`, the core of every
//! range-proof verification), lifted as written from the host's own files
//! (SEMANTICS.md §19) at the MMR family, together with the position
//! arithmetic they call (`position.rs`, `location.rs`, `mmr/mod.rs`,
//! `mmr/iterator.rs`, as in `sandblaster/mmr`). SHA-256 is the standard
//! library's FIPS 180-4 specification. `LAWS.rs` states what the lifted
//! code guarantees; `PROOF.rs` proves it.
//!
//! The function bodies are read from rustc's MIR, `verifier.sbmir`
//! (`sandblaster/docs/mir-lift.md` §20; extracted by
//! `sandblaster/mirx/extract.sh` at the instances of `instances.rs`, see its
//! README), not from the surface syntax. A changed source refuses the stale
//! MIR until it is extracted again.
#![forbid(unsafe_code)]

mod merkle;

// the toolchain's domain-free proof library (its `bridges` are prover rules)
#[cfg(sandblaster)]
#[path = "../../../sandblaster/front/stdlib/mod.rs"]
mod stdlib;

// FIPS 180-4 SHA-256 and what a collision is (an optional part of the
// standard library: only crates that hash mount it)
#[cfg(sandblaster)]
#[path = "../../../sandblaster/front/stdlib/sha256.rs"]
mod sha256;

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
mod proofs;

// the boundary: the lifted types and their methods (laws may mention them),
// and the lift prelude's models of core types in their signatures
pub use merkle::{Bagging, Error, Location, Position};
pub use merkle::hasher::Standard;
pub use merkle::mmr::Family;
pub use crate::__lift::{Once, Ordering, PhantomData, RangeInclusiveU32, Result};
