//! Verifies the MMR position and peak arithmetic in place: rustoleum reads
//! `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` as written,
//! proves `rustoleum/mmr/LAWS.rs` about them (and that they never panic
//! within their stated preconditions) and writes the record
//! `OUT_DIR/mmr-verified.txt`. rustc compiles the same files; a failing
//! proof fails this crate's build. The specification lock is not accepted
//! yet, so the §15 gates are reported, not enforced (the record says
//! `PROOFS CHECKED, §15 GATES PENDING`); once it is, this becomes
//! `compile_lifted`.
fn main() {
    rustoleum::build::compile_lifted_pending_gates("rustoleum/mmr/mod.rs", "mmr");
}
