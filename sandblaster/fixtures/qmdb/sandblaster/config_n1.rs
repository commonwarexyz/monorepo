//! Instance configuration of the N = 1 root `n1.rs`: one-byte activity chunks,
//! the configuration of the Bend program `qmdb-bend2`, its corpora and the
//! pinned fixtures in `qmdb/fixtures` (DESIGN.md §14.2 `Config`).
//!
//! Same items as `config.rs` (see there); `n1.rs` mounts this file as
//! `config`. N = 1 is a valid proof configuration for Commonware's verifier,
//! but no production database uses it (they require N to be a multiple of
//! the digest size).

pub use super::sha256::{hash_1 as hash_chunk, hash_33 as hash_graft};

/// Bytes per activity chunk (Commonware `N`).
pub const CHUNK_BYTES: usize = 1;

/// Operations per activity chunk, `8N` = 8: the graft width `2^G` (G = 3)
/// and the modulus of the activity bit and of the partial-chunk length.
pub const CHUNK_BITS: u64 = 8 * CHUNK_BYTES as u64;

/// Length of the graft preimage `chunk ‖ subtree digest` (33 bytes).
pub const GRAFT_BYTES: usize = CHUNK_BYTES + 32;

/// One activity chunk.
pub type Chunk = [u8; CHUNK_BYTES];
