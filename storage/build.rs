//! Verifies the MMR position and peak arithmetic in place: sandblaster reads
//! `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` as written,
//! proves `sandblaster/mmr/LAWS.rs` about them (and that they never panic
//! within their stated preconditions); a failing proof fails this crate's
//! build. Their function bodies are read from rustc's MIR
//! (`sandblaster/mmr/mmr.sbmir`, checked in; after editing one of those
//! files, re-extract it with `sandblaster/mirx/extract.sh`, see its README). The proven optimizer then writes the lowered copy of each of
//! those files (`OUT_DIR/mmr-lowered__<path>`, index `mmr-lowered.txt`):
//! the file with its proven rewrites, checked by the lifted round trip.
//! rustc compiles `position.rs`, `location.rs` and `mmr/mod.rs` as
//! written, and `mmr/iterator.rs` from its lowered copy (the faster
//! `PeakIterator::to_nearest_size`): `mmr/mod.rs` declares `iterator` by
//! its lowered declaration (sandblaster DESIGN.md §2.1, "Compiling the
//! optimized output"); a rewrite the round trip rejects, or any failed
//! proof, fails the build. The specification lock is not accepted yet, so this uses
//! the development aid `compile_lifted_pending_gates` (to be removed before
//! landing): the §15 gates are reported, not enforced, and it issues no
//! verdict — it writes `OUT_DIR/mmr-pending.txt` (`NOT VERIFIED —
//! DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING`) and a `NOT
//! VERIFIED` stub as `OUT_DIR/mmr-verified.txt`. Once the lock is accepted
//! this becomes `compile_lifted` (which also runs the lift conformance
//! check of the in-place modules: it passes for the MMR; for the verifier
//! below it finds no value mismatch but 16 `reconstruct_digest` inputs run
//! out of the kernel's step budget, so it does not pass yet, see
//! sandblaster `docs/mir-lift.md` §5).
//!
//! It also verifies the first set of the Merkle proof verifier in place
//! (`sandblaster/verifier`: the hashing of `src/merkle/hasher.rs` at
//! `Standard<Sha256>` and the subtree reconstruction of `src/merkle/proof.rs`),
//! its bodies read from rustc's MIR too (`sandblaster/verifier/verifier.sbmir`;
//! re-extract it after editing `hasher.rs`, `proof.rs` or the position
//! files), with the same development aid: `OUT_DIR/verifier-pending.txt`.
fn main() {
    sandblaster::build::compile_lifted_pending_gates("sandblaster/mmr/mod.rs", "mmr");
    sandblaster::build::compile_lifted_pending_gates("sandblaster/verifier/mod.rs", "verifier");
}
