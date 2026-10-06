//! Verifies the MMR position and peak arithmetic in place: sandblaster reads
//! `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` as written and
//! proves `sandblaster/mmr/LAWS.rs` about them (within their stated
//! preconditions they panic exactly where the laws' panic contracts say,
//! and nowhere else); a failing proof fails this crate's build. Their
//! function bodies are read from rustc's MIR (`sandblaster/mmr/mmr.sbmir`,
//! checked in; after editing one of those files, re-extract it with
//! `sandblaster/mirx/extract.sh`, see its README). rustc compiles all four
//! files as written. The MMR's specification lock is accepted
//! (`sandblaster/mmr/SPEC.lock`), so this is `compile_lifted`: every §15
//! gate, every per-function MIR theorem (and panic theorem) and the lift
//! conformance check of the in-place modules must pass, and a passing build
//! writes the verdict to `OUT_DIR/mmr-verified.txt`. An unchanged rebuild
//! takes the cached verdict; a changed law needs `sandblaster spec
//! --accept`. The overflow and underflow panic contracts assume overflow
//! checks on, which every profile of this workspace sets (DESIGN.md §16.5).
//!
//! It also verifies the first set of the Merkle proof verifier in place
//! (`sandblaster/verifier`: the hashing of `src/merkle/hasher.rs` at
//! `Standard<Sha256>` and the subtree reconstruction of `src/merkle/proof.rs`),
//! its bodies read from rustc's MIR too (`sandblaster/verifier/verifier.sbmir`;
//! re-extract it after editing `hasher.rs`, `proof.rs` or the position
//! files). Its specification lock is accepted
//! (`sandblaster/verifier/SPEC.lock`), so it is `compile_lifted` as well: every
//! §15 gate, every per-function MIR theorem (and panic theorem) and the lift
//! conformance check must pass, and a passing build writes the verdict to
//! `OUT_DIR/verifier-verified.txt`.
fn main() {
    sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr");
    sandblaster::build::compile_lifted("sandblaster/verifier/mod.rs", "verifier");
}
