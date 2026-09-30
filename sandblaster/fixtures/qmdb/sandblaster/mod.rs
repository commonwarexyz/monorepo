//! QMDB current-membership verifier in sandblaster: the DSL crate root of the
//! production instance, N = 32 activity chunks (DESIGN.md §2, §11, §15).
//!
//! [`verify`] and [`verify_fixed`] decide whether a Commonware QMDB
//! `current::unordered` operation proof shows `key ↦ value` as an active
//! update under a trusted root (MMR, SHA-256, locations and leaf counts up
//! to 2^62). Each carries `#[refines(spec::proof::verify)]`: on every input
//! it returns the verdict of the specification in `spec/`, which is written
//! from FIPS 180-4 and Commonware's source (6e15fe7c), not from this code.
//! `LAWS.rs` says what that verdict guarantees; `PROOF.rs` proves both.
//!
//! `n1.rs` is the N = 1 instance: the same files, with `config_n1.rs` and
//! `spec/config_n1.rs` as its configuration.
//!
//! | Module | Contents |
//! | --- | --- |
//! | `config` | the chunk size N and the two hash kernels it selects |
//! | `sha256` | `compress`, the fixed-size hashes, the hardware variants |
//! | `codec` | canonical varint and byte readers |
//! | `merkle` | peak search, branch reconstruction, grafting, bagging |
//! | `verifier` | proof decoding, the activity bit, the canonical root, `verify` |
//! | `spec`, `spec_config` (ghost) | the specification (`spec/`) |
//! | `laws`, `proof` (ghost) | `LAWS.rs`, `PROOF.rs` |
//!
//! The boundary is the `pub use` list below (§15.8). The files are written in
//! the exec subset (§3); `qmdb/baseline` compiles the same files with `rustc`,
//! every annotation erased. Sibling modules are named through `super::`, so
//! the files compile unchanged wherever they are mounted.
#![forbid(unsafe_code)]

mod codec;
mod config;
mod merkle;
mod sha256;
mod verifier;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/mod.rs"]
mod spec;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/config.rs"]
mod spec_config;

#[cfg(sandblaster)]
#[path = "../../../front/stdlib/mod.rs"]
mod stdlib;

#[cfg(sandblaster)]
#[model]
#[path = "MODEL.rs"]
mod model;

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;

pub use sha256::Digest;
pub use verifier::{verify, verify_fixed};
