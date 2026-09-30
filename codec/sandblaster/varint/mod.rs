//! The varint pilot: commonware-codec's `varint.rs`, lifted as-is.
//!
//! `varint.rs` is a byte-for-byte copy of `codec/src/varint.rs`. `error.rs`
//! models the host items it uses (`crate::Error`). The laws are in `LAWS.rs`,
//! their proofs in `PROOF.rs`.
#![forbid(unsafe_code)]

// FRICTION: the kernel has no 128-bit machine words, so the `u128` and
// `i128` instances are declared unverified here: the lift reports them and
// does not check them. (Signed integers are read as their two's complement
// bits, SEMANTICS.md §19.3.)
//
// The bodies are read from rustc's MIR (`varint.sbmir`, written by
// `sandblaster/mirx/extract.sh` with the nightly of the stable release this
// crate builds with; `docs/mir-lift.md` §20), not from the surface syntax: the
// lift keeps only the items' names and signatures. A changed `varint.rs`
// refuses the stale MIR until it is extracted again.
#[lift(mir = "varint.sbmir", unverified = "u128, i128")]
mod varint;

// a model of the host's `crate::Error` (the variants varint builds): proven
// against, never emitted; the emitted module checks each variant against the
// host
#[lift(host)]
mod error;

#[cfg(sandblaster)]
#[lift]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

pub use error::Error;
// the lift's model of core's `Result` (feed's return type reaches the boundary)
pub use crate::__lift::Result;
// the lift's models of the signed integers (their two's complement bits;
// `SInt`'s field reaches the boundary)
pub use crate::__lift::{I16, I32, I64};
pub use varint::{SInt, UInt, MAX_U16_VARINT_SIZE, MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE, MAX_U128_VARINT_SIZE};
