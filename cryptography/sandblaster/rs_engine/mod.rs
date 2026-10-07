//! commonware-cryptography's Reed–Solomon engine multiply, verified in
//! place: `src/reed_solomon/engine/engine_neon.rs` (`<Neon as Engine>::mul`
//! and the `mul_neon` and `mul_128` it runs, `unsafe` NEON code with raw
//! pointer loads and stores) and `src/reed_solomon/engine/engine_scalar.rs`
//! (`<Scalar as Engine>::mul`, the reference), lifted as written from the
//! host's own files (SEMANTICS.md §19), with the types they name from
//! `engine.rs` and `tables.rs`. `LAWS.rs` states what they guarantee;
//! `PROOF.rs` proves it.
//!
//! The function bodies are read from rustc's MIR, `rs_engine.sbmir`
//! (`sandblaster/docs/mir-lift.md` §20; extracted by
//! `sandblaster/mirx/extract.sh`, see `sandblaster/mirx/README.md`), not from
//! the surface syntax; the raw-pointer loads and stores through the narrow
//! reading of existing `unsafe` (§20.10), with the window rule run on the
//! unoptimized extraction `rs_engine.window.sbmir`. A changed source refuses
//! the stale MIR until it is extracted again.
#![forbid(unsafe_code)]

mod reed_solomon;

// the toolchain's domain-free proof library (its `bridges` are prover rules)
#[cfg(sandblaster)]
#[path = "../../../sandblaster/front/stdlib/mod.rs"]
mod stdlib;

#[cfg(sandblaster)]
#[lift]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

// the boundary: the lifted types and their methods (laws may mention them)
pub use reed_solomon::engine::engine_neon::Neon;
pub use reed_solomon::engine::engine_scalar::Scalar;
pub use reed_solomon::engine::tables::Multiply128lutT;
