//! Verifies the MMR position and peak arithmetic in place: sandblaster reads
//! `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` as written,
//! proves `sandblaster/mmr/LAWS.rs` about them (and that they never panic
//! within their stated preconditions), and runs every §15 gate against
//! `sandblaster/mmr/SPEC.lock` (determinacy, examples, law rules, spec
//! mutation) and the lift conformance check (the lifted model against a
//! rustc build of a copy of this crate, on generated inputs). rustc compiles
//! the same files; a failing proof, gate or conformance case fails this
//! crate's build. The verdict is `OUT_DIR/mmr-verified.txt` (with
//! `mmr-report.json` and `mmr-timing.json`); an unchanged crate reuses it.
fn main() {
    sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr");
}
