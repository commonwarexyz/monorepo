//! Verifies the MMR position and peak arithmetic in place: sandblaster reads
//! `src/merkle/position.rs`, `src/merkle/location.rs`,
//! `src/merkle/mmr/mod.rs` and `src/merkle/mmr/iterator.rs` as written,
//! proves `sandblaster/mmr/LAWS.rs` about them (and that they never panic
//! within their stated preconditions). rustc compiles the same files; a
//! failing proof fails this crate's build. The proven optimizer then writes
//! lowered copies of the files it can make faster beside the record
//! (`OUT_DIR/mmr-lowered__<path>`, index `mmr-lowered.txt`); rustc does not
//! compile them. The specification lock is not accepted yet, so this uses
//! the development aid `compile_lifted_pending_gates` (to be removed before
//! landing): the §15 gates are reported, not enforced, and it issues no
//! verdict — it writes `OUT_DIR/mmr-pending.txt` (`NOT VERIFIED —
//! DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING`) and a `NOT
//! VERIFIED` stub as `OUT_DIR/mmr-verified.txt`. Once the lock is accepted
//! this becomes `compile_lifted` (which also runs the lift conformance
//! check; with the current sandblaster toolchain that check does not support
//! in-place modules yet, so `compile_lifted` issues no verdict for this
//! crate until it does).
fn main() {
    sandblaster::build::compile_lifted_pending_gates("sandblaster/mmr/mod.rs", "mmr");
}
