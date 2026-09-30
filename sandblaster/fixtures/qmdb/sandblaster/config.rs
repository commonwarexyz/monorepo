//! Instance configuration of the production root `mod.rs`: Commonware's
//! activity-chunk size **N = 32** (DESIGN.md §14.2 `Config`, fixed per crate
//! until const generics land, §14.3(1)).
//!
//! Commonware stores the activity bitmap in chunks of N bytes; a production
//! database requires N to be a power of two and a multiple of the digest size
//! (storage/src/qmdb/current/mod.rs:431-442 at 6e15fe7c), so with SHA-256 the
//! smallest and the only deployed value is 32. The N = 1 instance (`n1.rs`,
//! the Bend configuration) reads `config_n1.rs` instead; every other module
//! reads its configuration through `super::config::…`, so both instances are
//! the same source text.
//!
//! What N fixes (docs/prod-domain-commonware-spec.md §1, §3.3):
//!
//! | item | value | where |
//! | --- | --- | --- |
//! | chunk carried by a proof | `N` raw bytes after `location` | `verifier::parse` |
//! | activity bit | bit `location % 8N` of the chunk, LSB first | `verifier::active` |
//! | graft | `H(chunk ‖ subtree)` at width `8N` (height `log2 8N`) | `merkle::path_node` |
//! | partial-chunk digest | `H(chunk)`, `N`-byte preimage | `verifier::canonical` |
//!
//! Both hashes are fixed-length kernels, so a chunk/kernel length mismatch is
//! a type error: an instance without the right kernel cannot build.

pub use super::sha256::{hash_32 as hash_chunk, hash_64 as hash_graft};

/// Bytes per activity chunk (Commonware `N`).
pub const CHUNK_BYTES: usize = 32;

/// Operations per activity chunk, `8N` = 256: the graft width `2^G` (G = 8)
/// and the modulus of the activity bit and of the partial-chunk length.
pub const CHUNK_BITS: u64 = 8 * CHUNK_BYTES as u64;

/// Length of the graft preimage `chunk ‖ subtree digest` (64 bytes).
pub const GRAFT_BYTES: usize = CHUNK_BYTES + 32;

/// One activity chunk.
pub type Chunk = [u8; CHUNK_BYTES];
