//! The QMDB laws through the verified pipeline (DESIGN.md §4.5, §11.3), and
//! the script machinery their proofs rely on.
//!
//! * `sandblaster/fixtures/qmdb/sandblaster` verifies with its ghost modules: all 13 laws of
//!   `LAWS.rs` (the nine of `LAWS.bend` and four for Commonware's domain)
//!   proven by `PROOF.rs`, no open claim, every obligation discharged (the
//!   build's standard prover chain).
//! * Negative tests: in-memory copies of `sandblaster/fixtures/qmdb/sandblaster` with one mutation
//!   each — an exec function made wrong (the activity check of
//!   `verify_decoded` weakened, the trailing-bytes check of `codec::exact`
//!   removed) or a law made false — must fail, with a diagnostic naming the
//!   broken law.
//! * Small programs for the proof features the QMDB proofs use: prelude
//!   lemma paths (`sandblaster::lemmas::..`, glob imports), refinement of a
//!   slice variable, term-level `unfold`/`rewrite(a == b)`, a `match` on a
//!   non-variable scrutinee that occurs in the goal, codec readers opaque in
//!   proofs.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::Severity;
use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::elab::DefStatus;
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::explain;

/// The production root `mod.rs` (N = 32) and the files it mounts.
const QMDB_FILES: &[&str] = &["mod.rs", "config.rs", "codec.rs", "merkle.rs", "sha256.rs", "verifier.rs", "LAWS.rs", "PROOF.rs"];

/// The sources of `sandblaster/fixtures/qmdb/sandblaster`, keyed by file name.
fn qmdb_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster");
    QMDB_FILES.iter().map(|f| (f.to_string(), std::fs::read_to_string(dir.join(f)).unwrap_or_else(|e| panic!("{f}: {e}")))).collect()
}

/// Checks and verifies (ghost items included, standard provers) an
/// in-memory copy of `sandblaster/fixtures/qmdb/sandblaster` with `edit` applied to `file`.
fn qmdb_with(file: &str, from: &str, to: &str) -> (Checked, Verification) {
    let mut files = qmdb_sources();
    if !file.is_empty() {
        let (_, text) = files.iter_mut().find(|(f, _)| f == file).unwrap();
        assert!(text.contains(from), "mutation site not found in {file}: {from}");
        *text = text.replacen(from, to, 1);
    }
    let owned: Vec<(String, String)> = files.into_iter().map(|(f, t)| (format!("q/{f}"), t)).collect();
    let fs = MemFs::from_files(owned.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let c = driver::check(Path::new("q/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front end rejected the (mutated) QMDB sources:\n{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    (c, v)
}

fn law_status<'v>(v: &'v Verification, name: &str) -> &'v DefStatus {
    &v.laws.iter().find(|l| l.name == name).unwrap_or_else(|| panic!("no law {name}: {:?}", v.laws)).status
}

/// The rendered error diagnostics.
fn errors(c: &Checked, v: &Verification) -> String {
    v.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.render(&c.sm)).collect::<Vec<_>>().join("\n")
}

#[test]
fn qmdb_laws_are_proven() {
    let (c, v) = qmdb_with("", "", "");
    let names: Vec<&str> = v.laws.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(v.laws.len(), 13, "{names:?}");
    for law in [
        "crate::laws::digest_equal_sound",
        "crate::laws::bag_prefix_partition",
        "crate::laws::bag_prefix_order",
        "crate::laws::merkle_digest_count",
        "crate::laws::merkle_wrong_count_rejected",
        "crate::laws::verify_acceptance",
        "crate::laws::inactive_decoded_rejected",
        "crate::laws::inactive_rejected",
        "crate::laws::trailing_bytes_rejected",
        "crate::laws::location_bounded",
        "crate::laws::leaves_above_max_rejected",
        "crate::laws::shape_bounds",
        "crate::laws::partial_chunk_bound",
    ] {
        assert_eq!(law_status(&v, law), &DefStatus::Checked, "{law}:\n{}", explain(&c, &v));
    }
    assert!(v.laws.iter().all(|l| l.proof != "missing"), "open claims: {:?}", v.laws);
    let st = v.stats();
    assert_eq!(st.failed + st.todo, 0, "{}", explain(&c, &v));
    assert!(v.proofs_ok, "not verified:\n{}", explain(&c, &v));
    println!("QMDB laws: {} proven, {} obligations, {:.2}s", v.laws.len(), st.total, v.elapsed.as_secs_f64());
}

#[test]
fn weakened_activity_check_breaks_the_activity_laws() {
    // `verify_decoded` accepts an inactive operation whose root matches
    let (c, v) = qmdb_with(
        "verifier.rs",
        "active(proof) && root_matches(root, reconstruct(proof, key, value))",
        "active(proof) || root_matches(root, reconstruct(proof, key, value))",
    );
    assert!(!v.proofs_ok);
    assert_ne!(law_status(&v, "crate::laws::inactive_decoded_rejected"), &DefStatus::Checked);
    assert_ne!(law_status(&v, "crate::laws::inactive_rejected"), &DefStatus::Checked);
    // unaffected laws still hold
    assert_eq!(law_status(&v, "crate::laws::merkle_wrong_count_rejected"), &DefStatus::Checked);
    let e = errors(&c, &v);
    assert!(e.contains("crate::laws::inactive_decoded_rejected"), "{e}");
    assert!(e.contains("verify_decoded"), "the diagnostic shows the goal:\n{e}");
}

#[test]
fn dropped_trailing_bytes_check_breaks_the_suffix_laws() {
    // `exact` keeps a decoded value whatever follows it
    let (c, v) = qmdb_with("codec.rs", "Some((_, [_, ..])) => None,", "Some((value, [_, ..])) => Some(value),");
    assert!(!v.proofs_ok);
    assert_ne!(law_status(&v, "crate::laws::trailing_bytes_rejected"), &DefStatus::Checked);
    assert_ne!(law_status(&v, "crate::laws::verify_acceptance"), &DefStatus::Checked);
    assert_eq!(law_status(&v, "crate::laws::inactive_decoded_rejected"), &DefStatus::Checked);
    let e = errors(&c, &v);
    assert!(e.contains("trailing_bytes_rejected") || e.contains("exact_proof_suffix"), "{e}");
}

#[test]
fn dropped_partial_chunk_binding_breaks_partial_chunk_bound() {
    // `canonical` no longer checks `H(chunk)` against the partial digest
    let (c, v) = qmdb_with(
        "verifier.rs",
        "location / CHUNK_BITS != leaves / CHUNK_BITS || equal(&hash_chunk(chunk), &partial_digest)",
        "location / CHUNK_BITS != leaves / CHUNK_BITS || true",
    );
    assert!(!v.proofs_ok);
    assert_ne!(law_status(&v, "crate::laws::partial_chunk_bound"), &DefStatus::Checked);
    assert_eq!(law_status(&v, "crate::laws::shape_bounds"), &DefStatus::Checked);
    let e = errors(&c, &v);
    assert!(e.contains("partial_chunk_bound") || e.contains("partial_digest_bound"), "{e}");
}

#[test]
fn a_false_law_is_not_proven() {
    // an active proof is not rejected by `verify`
    let (c, v) = qmdb_with(
        "LAWS.rs",
        "requires(verifier::active(&decoded) == false);\n    ensures(verifier::verify(root, key, value, bytes) == false);",
        "requires(verifier::active(&decoded) == true);\n    ensures(verifier::verify(root, key, value, bytes) == false);",
    );
    assert!(!v.proofs_ok);
    assert_ne!(law_status(&v, "crate::laws::inactive_rejected"), &DefStatus::Checked);
    assert_eq!(law_status(&v, "crate::laws::trailing_bytes_rejected"), &DefStatus::Checked);
    let e = errors(&c, &v);
    assert!(e.contains("inactive_rejected") || e.contains("inactive_inputs"), "{e}");
}

// ---------------------------------------------------------------------------
// the proof features, on small programs
// ---------------------------------------------------------------------------

fn full(files: &[(&str, &str)]) -> (Checked, Verification) {
    let c = util::check_files(files);
    assert!(c.ok(), "front end rejected:\n{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    (c, v)
}

#[track_caller]
fn assert_all_verified(c: &Checked, v: &Verification) {
    assert!(v.proofs_ok, "not verified:\n{}", explain(c, v));
}

#[test]
fn prelude_lemmas_by_path_and_glob_import() {
    let root = "pub fn same(a: [u8; 4], b: [u8; 4]) -> bool { a == b }\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n#[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n";
    let laws = "use sandblaster::prelude::*;\nuse super::same;\n#[law] fn same_sound(a: [u8; 4], b: [u8; 4]) { requires(same(a, b)); ensures(a == b); }\n#[law] fn same_sound2(a: [u8; 4], b: [u8; 4]) { requires(same(a, b)); ensures(b == a); }\n";
    let proofs = "use sandblaster::prelude::*;\nuse sandblaster::lemmas::array::*;\n#[proof] fn same_sound(a: [u8; 4], b: [u8; 4]) { sandblaster::lemmas::array::eq_sound_u8(4, a, b); }\n#[proof] fn same_sound2(a: [u8; 4], b: [u8; 4]) { eq_sound_u8(4, a, b); }\n";
    let (c, v) = full(&[("r/mod.rs", root), ("r/LAWS.rs", laws), ("r/PROOF.rs", proofs)]);
    assert_all_verified(&c, &v);
    assert!(v.laws.iter().all(|l| l.status == DefStatus::Checked), "{:?}", v.laws);
}

#[test]
fn slice_refinement_in_lemmas() {
    let src = r#"
pub fn first_or_zero(xs: &[u8]) -> u8 {
    match xs {
        [] => 0,
        [h, ..] => *h,
    }
}
#[cfg(sandblaster)]
#[lemma]
fn empty_is_zero(xs: &[u8]) {
    requires(xs.len() == 0);
    ensures(first_or_zero(xs) == 0);
    match xs {
        [] => {}
        [h, t @ ..] => {}
    }
}
#[cfg(sandblaster)]
#[lemma]
fn cons_is_head(h: u8, t: &[u8]) {
    requires((t.len() as Int) < ISIZE_MAX);
    ensures(first_or_zero(seq::cons(h, t)) == h);
}
"#;
    let (c, v) = full(&[("r/mod.rs", src)]);
    assert_all_verified(&c, &v);
}

#[test]
fn term_level_unfold_rewrite_and_match() {
    // `wrap` is transparent; its goal is handled on the term: `unfold`
    // exposes the match on `pick(x)`, `rewrite(pick(x) == None)` replaces
    // it, and a `match pick(x)` generalizes its occurrence in the goal
    let src = r#"
pub fn pick(x: u32) -> Option<u32> {
    if x > 10 { Some(x - 10) } else { None }
}
pub fn wrap(x: u32) -> bool {
    match pick(x) {
        None => false,
        Some(v) => v > 3,
    }
}
#[cfg(sandblaster)]
#[lemma]
fn wrap_none(x: u32) {
    requires(pick(x) == None);
    ensures(wrap(x) == false);
    unfold(wrap);
    rewrite(pick(x) == None);
}
#[cfg(sandblaster)]
#[lemma]
fn pick_small(x: u32, v: u32) {
    requires(x <= 13);
    requires(pick(x) == Some(v));
    ensures(v <= 3);
    if x > 10 {
    } else {
    }
}
#[cfg(sandblaster)]
#[lemma]
fn wrap_small(x: u32) {
    requires(x <= 13);
    ensures(wrap(x) == false);
    unfold(wrap);
    match pick(x) {
        None => {}
        Some(v) => {
            pick_small(x, v);
        }
    }
}
"#;
    let (c, v) = full(&[("r/mod.rs", src)]);
    assert_all_verified(&c, &v);
}

#[test]
fn codec_readers_are_opaque_in_proofs() {
    let src = r#"
pub fn byte(xs: &[u8]) -> Option<(u8, &[u8])> {
    match xs {
        [] => None,
        [h, t @ ..] => Some((*h, t)),
    }
}
pub fn head_or(xs: &[u8], d: u8) -> u8 {
    match byte(xs) {
        None => d,
        Some((b, _)) => b,
    }
}
"#;
    let c = util::accepted(src);
    let k = c.krate.as_ref().unwrap();
    let opaque = driver::stage::with_elaboration(k, &VerifyOptions { provers: ProverSet::Basic, exec_only: true }, |out| {
        let g = |n: &str| out.env.global_opaque(out.env.lookup_global(n).unwrap_or_else(|| panic!("no {n}"))).unwrap();
        (g("crate::byte"), g("crate::head_or"))
    });
    assert_eq!(opaque, (true, false), "`byte` is a reader (opaque), `head_or` is not");
}
