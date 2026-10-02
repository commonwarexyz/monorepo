//! Verifies the MMR position and peak arithmetic in place: sandblaster reads
//! `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` as written,
//! proves `sandblaster/mmr/LAWS.rs` about them (and that they never panic
//! within their stated preconditions); a failing proof fails this crate's
//! build. Their function bodies are read from rustc's MIR
//! (`sandblaster/mmr/mmr.sbmir`, checked in; after editing one of those
//! files, re-extract it with `sandblaster/mirx/extract.sh`, see its README). The proven optimizer
//! (which always runs) then writes the lowered copy of each of those files
//! (`OUT_DIR/mmr-lowered__<path>`, index `mmr-lowered.txt`): the file with
//! every function the optimizer found a cheaper, kernel-checked replacement
//! for rewritten, checked by the lifted round trip. Today it finds none, so
//! every lowered copy is its source (after a generated header and without
//! the leading `//!` lines, which the declaration carries) and rustc compiles all four files
//! as written: `position.rs`, `location.rs` and `mmr/mod.rs` directly, and
//! `mmr/iterator.rs` through its lowered copy, because `mmr/mod.rs`
//! declares `iterator` by its lowered declaration (sandblaster DESIGN.md
//! §2.1, "Compiling the optimized output"), so a future optimizer rewrite
//! is compiled with no change here. A rewrite the round trip rejects, or
//! any failed proof, fails the build. The MMR's specification lock is accepted
//! (`sandblaster/mmr/SPEC.lock`), so this is `compile_lifted`: every §15 gate
//! (including spec mutation), every per-function MIR theorem and the lift
//! conformance check of the in-place modules must pass, and a passing build
//! writes the verdict to `OUT_DIR/mmr-verified.txt`. An unchanged rebuild
//! takes the cached verdict; a changed law needs `sandblaster spec --accept`.
//!
//! It also verifies the first set of the Merkle proof verifier in place
//! (`sandblaster/verifier`: the hashing of `src/merkle/hasher.rs` at
//! `Standard<Sha256>` and the subtree reconstruction of `src/merkle/proof.rs`),
//! its bodies read from rustc's MIR too (`sandblaster/verifier/verifier.sbmir`;
//! re-extract it after editing `hasher.rs`, `proof.rs` or the position
//! files). Its §15 gates are not complete yet (examples, sections and its
//! lock), so it uses the development aid `compile_lifted_pending_gates` (to
//! be removed before landing): proofs and MIR theorems are checked, the gates
//! are reported, not enforced, and it issues no verdict
//! (`OUT_DIR/verifier-pending.txt`, `NOT VERIFIED — DEVELOPMENT BUILD: PROOFS
//! CHECKED, §15 GATES PENDING`).
fn main() {
    sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr");
    sandblaster::build::compile_lifted_pending_gates("sandblaster/verifier/mod.rs", "verifier");
}
