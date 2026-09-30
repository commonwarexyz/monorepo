//! QMDB current-membership verifier, N = 1 instance: the second DSL crate
//! root over the same files as `mod.rs` (DESIGN.md §2, §11, §14.2, §15).
//!
//! `mod.rs` is the production instance (N = 32). This root mounts the same
//! `codec`, `merkle`, `sha256` and `verifier` files, the same specification,
//! laws and proofs, with `config_n1.rs` and `spec/config_n1.rs` (N = 1, the
//! Bend configuration) as their configuration: every N-dependent item is read
//! through `super::config::…`. It is verified as its own crate (`qmdb/n1`,
//! package `qmdb-n1`) and has its own lock, `SPEC.n1.lock`.
#![forbid(unsafe_code)]

mod codec;
mod config_n1;
mod merkle;
mod sha256;
mod verifier;

/// The shared modules' `super::config`: this instance's configuration.
use self::config_n1 as config;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/mod.rs"]
mod spec;

#[cfg(sandblaster)]
#[spec]
#[path = "spec/config_n1.rs"]
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
