//! The QMDB specification: what a Current root commits to (`db`), which proofs verify (`proof`)
//! and how they are written (`codec`), and why that is secure (`tree`), over SHA-256 (`sha256`,
//! FIPS 180-4). Written from the standard and from Commonware's source at 6e15fe7c, never from
//! this crate's code (spec closure, DESIGN §15.1). `LAWS.rs` says what it guarantees.
//! `Nat`, `Seq`, `pow2`, `log2`, `popcount`, `min` and `max` come from the ghost prelude.

pub mod codec;
pub mod db;
pub mod proof;
pub mod sha256;
pub mod tree;

/// The instance: `mod.rs` mounts `spec/config.rs` here (N = 32), `n1.rs` `spec/config_n1.rs` (N = 1).
pub use super::spec_config as config;
