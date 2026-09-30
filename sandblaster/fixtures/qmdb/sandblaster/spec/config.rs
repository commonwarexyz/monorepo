//! The instance: Commonware's chunk size N = 32, the one production databases use
//! (current/mod.rs:431-442), and this instance's known answers. `config_n1.rs` is the N = 1
//! instance: the same text with N = 1, G = 3 and the files in `qmdb/fixtures-n1`.

use super::spec::db::Db;
use super::spec::proof::verify;

/// Bytes per activity chunk. A chunk holds the flags of C = 8N operations and is grafted onto the
/// nodes of height G, which are C leaves wide.
#[example(N as Nat + 32 != 72)] // a graft's preimage is never as long as an inner node's (tree.rs `fits`)
pub const N: usize = 32;
/// Operations per chunk.
pub const C: Nat = 8 * N as Nat;
/// The height of the nodes a chunk is grafted onto.
#[example(pow2(G) == C)] // 8N is a power of two (proof/mod.rs:55-64)
pub const G: Nat = 8;

/// Known answers from Commonware itself (§15.7; exported by `qmdb/oracle`): its verdict on a
/// curated set of pinned proofs, accepted or rejected, malformed bytes included, and the roots of
/// databases its own code built. They catch what no law can: a spec wrong the same way on both
/// sides (bits read from the wrong end, peaks folded in the wrong order).
#[examples(file = "../../fixtures-n32/known-answers.json", format = "json", provenance = production)]
#[example(!commonware_verdicts(seq![], seq![], seq![], seq![], true))] // an empty key never verifies
fn commonware_verdicts(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>, expected: bool) -> bool {
    verify(root, key, value, proof) == expected
}

/// See [`commonware_verdicts`].
#[examples(file = "../../fixtures-n32/databases.json", format = "json", provenance = production)]
fn commonware_roots(db: Db, root: Seq<u8>) -> bool { db.root() == root }
