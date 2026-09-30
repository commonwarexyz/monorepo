//! The N = 1 instance: one-byte activity chunks, the configuration of the Bend program and its
//! corpora. N = 1 is valid for Commonware's proofs, but no production database uses it (they
//! need N to be a multiple of the digest size). `config.rs` is the production instance (N = 32).

use super::spec::db::Db;
use super::spec::proof::verify;

/// Bytes per activity chunk. A chunk holds the flags of C = 8N operations and is grafted onto the
/// nodes of height G, which are C leaves wide.
#[example(N as Nat + 32 != 72)] // a graft's preimage is never as long as an inner node's (tree.rs `fits`)
pub const N: usize = 1;
/// Operations per chunk.
pub const C: Nat = 8 * N as Nat;
/// The height of the nodes a chunk is grafted onto.
#[example(pow2(G) == C)] // 8N is a power of two (proof/mod.rs:55-64)
pub const G: Nat = 3;

/// Known answers from Commonware itself (§15.7; exported by `qmdb/oracle`): its verdict on a
/// curated set of pinned proofs, accepted or rejected, malformed bytes included, and the roots of
/// databases its own code built. They catch what no law can: a spec wrong the same way on both
/// sides (bits read from the wrong end, peaks folded in the wrong order).
#[examples(file = "../../fixtures-n1/known-answers.json", format = "json", provenance = production)]
#[example(!commonware_verdicts(seq![], seq![], seq![], seq![], true))] // an empty key never verifies
fn commonware_verdicts(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>, expected: bool) -> bool {
    verify(root, key, value, proof) == expected
}

/// See [`commonware_verdicts`].
#[examples(file = "../../fixtures-n1/databases.json", format = "json", provenance = production)]
fn commonware_roots(db: Db, root: Seq<u8>) -> bool { db.root() == root }
