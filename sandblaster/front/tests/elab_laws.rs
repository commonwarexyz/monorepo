//! The QMDB laws through the verified pipeline (DESIGN.md §4.5, §11.3), and
//! the script machinery their proofs rely on.
//!
//! * `sandblaster/fixtures/qmdb/sandblaster` verifies with its ghost modules
//!   (the fully specified QMDB of §15 S5): the five laws of `LAWS.rs`, all
//!   over `spec::` items, proven by `PROOF.rs`, and `verify` and
//!   `verify_fixed` refining `spec::proof::verify`; no open claim, every
//!   obligation discharged (the build's standard prover chain).
//! * Negative tests: in-memory copies of `sandblaster/fixtures/qmdb/sandblaster` with one mutation
//!   each — an exec function made wrong (the activity check of
//!   `verify_decoded` weakened, the trailing-bytes check of `codec::exact`
//!   removed, the partial-chunk binding of `canonical` dropped) or a law made
//!   false — must fail, with a diagnostic naming what broke: a wrong exec
//!   function breaks the refinement of `verify` (no law names exec code),
//!   a false law is not proven. Each elaborates only what the verdict it
//!   checks reaches (the mutation gate's item filter): the whole of QMDB
//!   takes about ten minutes, and `qmdb_laws_are_proven` elaborates it.
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
use sandblaster_front::elab::{self, DefStatus, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::explain;

#[path = "common/qmdb.rs"]
mod qmdb;

/// The refinement proofs of the boundary (`PROOF.rs`, R12): `verify` and
/// `verify_fixed` refine `spec::proof::verify`.
const REFINEMENTS: [&str; 2] = ["crate::proof::verify_fixed", "crate::proof::verify"];

/// The laws of the crate: the two tree laws of `spec/tree.rs` (why one
/// root binds, docs/qmdb-spec-design.md §2.4) and the five of `LAWS.rs`.
const ALL_LAWS: [&str; 7] = [
    "crate::spec::tree::agreeing_trees_have_one_root",
    "crate::spec::tree::equal_roots_agree",
    "crate::laws::current_updates_have_proofs",
    "crate::laws::verified_updates_are_current",
    "crate::laws::one_proof_per_location",
    "crate::laws::proofs_have_one_encoding",
    "crate::laws::verified_proofs_are_small",
];

/// The five laws of `LAWS.rs`.
const LAWS: [&str; 5] = [
    "crate::laws::current_updates_have_proofs",
    "crate::laws::verified_updates_are_current",
    "crate::laws::one_proof_per_location",
    "crate::laws::proofs_have_one_encoding",
    "crate::laws::verified_proofs_are_small",
];

/// Serializes the QMDB elaborations of this binary. Each holds the whole
/// production QMDB crate and its kernel environment; run side by side under
/// the default test threads they exceed the memory cap
/// (`SANDBLASTER_MEM_LIMIT_GB`, 6 GB by default). The small programs below
/// do not take it. A poisoned lock (a failed QMDB test) is taken anyway:
/// one failure must not fail the others.
static QMDB_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Checks and verifies (ghost items included, standard provers) an
/// in-memory copy of the production root `mod.rs` (N = 32) and every file
/// it mounts (`qmdb::crate_files`), with `edit` applied to `file`. With
/// `seeds`, only the items they reach are elaborated (the mutation gate's
/// item filter, `elab::order::filter_closure`; never a verification of the
/// crate, so `proofs_ok` is false); `None` verifies the whole crate.
fn qmdb_with(file: &str, from: &str, to: &str, seeds: Option<&[&str]>) -> (Checked, Verification, Refinements) {
    let _serial = QMDB_SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut files = qmdb::crate_files("mod.rs");
    if !file.is_empty() {
        let text = qmdb::entry(&mut files, file);
        assert!(text.contains(from), "mutation site not found in {file}: {from}");
        *text = text.replacen(from, to, 1);
    }
    let fs = MemFs::from_files(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let c = driver::check(Path::new(&files[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front end rejected the (mutated) QMDB sources:\n{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (v, refinements) = match seeds {
        None => {
            let v = driver::stage::verify(k, &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
            // a refinement lemma `f::refines` is a definition once checked
            let r = v.defs.iter().filter(|d| d.name.ends_with("::refines")).map(|d| (d.name.clone(), d.status.clone())).collect();
            (v, r)
        }
        Some(seeds) => {
            let items = elab::order::filter_closure(k, seeds.iter().map(|p| k.find(p).unwrap_or_else(|| panic!("no item {p}"))));
            let opts = elab::Options { items: Some(std::sync::Arc::new(items)), ..elab::Options::default() };
            elab::with_big_stack(|| {
                let t = std::time::Instant::now();
                let out = elab::elaborate(k, &mut ProverChain::standard(), &opts);
                let r = out.refinements.iter().map(|r| (format!("{}::refines", k.item(r.item).path), r.status.clone())).collect();
                (Verification { defs: out.defs, obligations: out.obligations, laws: out.laws, diags: out.diags, deferred: out.deferred, proofs_ok: false, elapsed: t.elapsed(), provers: vec![], exec_only: false }, r)
            })
        }
    };
    (c, v, refinements)
}

/// The refinements of an elaboration: `(f::refines, status)`.
type Refinements = Vec<(String, DefStatus)>;

fn refinement<'r>(r: &'r Refinements, name: &str) -> Option<&'r DefStatus> {
    r.iter().find(|(n, _)| n == name).map(|(_, s)| s)
}

fn law_status<'v>(v: &'v Verification, name: &str) -> &'v DefStatus {
    &v.laws.iter().find(|l| l.name == name).unwrap_or_else(|| panic!("no law {name}: {:?}", v.laws)).status
}

/// The rendered error diagnostics.
fn errors(c: &Checked, v: &Verification) -> String {
    v.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.render(&c.sm)).collect::<Vec<_>>().join("\n")
}

/// No law's statement reaches `f`: the laws state guarantees over `spec::`
/// items, never over exec code, so a wrong exec function cannot make one
/// false (what a statement reaches: `elab::order::statement_refs`, closed).
fn no_law_reaches(c: &Checked, f: &str) {
    let k = c.krate.as_ref().unwrap();
    let id = k.find(f).unwrap_or_else(|| panic!("no item {f}"));
    for law in LAWS {
        let mut reach = std::collections::BTreeSet::new();
        let mut work = vec![k.find(law).unwrap()];
        while let Some(x) = work.pop() {
            if reach.insert(x) {
                work.extend(elab::order::statement_refs(k, x));
            }
        }
        assert!(!reach.contains(&id), "{law} reaches the exec function {f}");
    }
}

/// An exec mutation: the refinement of `verify_fixed` (and so `verify`'s,
/// which calls it) is not proven, the diagnostics name it and `site` (a
/// definition or obligation of the refinement proof's that states the
/// mutated code), and no law reaches the mutated function.
fn breaks_the_refinement(c: &Checked, v: &Verification, r: &Refinements, mutated: &str, site: &str) {
    assert!(!v.proofs_ok);
    let e = errors(c, v);
    for f in ["crate::verifier::verify_fixed::refines", "crate::verifier::verify::refines"] {
        assert!(refinement(r, f) != Some(&DefStatus::Checked), "{f} checked: {r:?}\n{e}");
    }
    assert!(e.contains("verify_fixed"), "the diagnostics name the refinement of `verify_fixed`:\n{e}");
    assert!(e.contains(site), "the diagnostics name `{site}`:\n{e}");
    no_law_reaches(c, mutated);
    println!("{mutated}: refinement not proven ({:.1} s)", v.elapsed.as_secs_f64());
}

#[test]
fn qmdb_laws_are_proven() {
    let (c, v, r) = qmdb_with("", "", "", None);
    let names: Vec<&str> = v.laws.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(v.laws.len(), ALL_LAWS.len(), "{names:?}");
    for law in ALL_LAWS {
        assert_eq!(law_status(&v, law), &DefStatus::Checked, "{law}:\n{}", explain(&c, &v));
    }
    assert!(v.laws.iter().all(|l| l.proof != "missing"), "open claims: {:?}", v.laws);
    for f in ["crate::verifier::verify_fixed::refines", "crate::verifier::verify::refines"] {
        assert_eq!(refinement(&r, f), Some(&DefStatus::Checked), "{f}: {r:?}\n{}", explain(&c, &v));
    }
    let st = v.stats();
    assert_eq!(st.failed + st.todo, 0, "{}", explain(&c, &v));
    assert!(v.proofs_ok, "not verified:\n{}", explain(&c, &v));
    println!("QMDB laws: {} proven, {} obligations, {:.2}s", v.laws.len(), st.total, v.elapsed.as_secs_f64());
}

#[test]
fn weakened_activity_check_breaks_the_refinement() {
    // `verify_decoded` accepts an inactive operation whose root matches
    let (c, v, r) = qmdb_with(
        "verifier.rs",
        "active(proof) && root_matches(root, reconstruct(proof, key, value))",
        "active(proof) || root_matches(root, reconstruct(proof, key, value))",
        Some(&REFINEMENTS),
    );
    // `decoded_parts` states the code's verdict on a decoded proof
    breaks_the_refinement(&c, &v, &r, "crate::verifier::verify_decoded", "decoded_parts");
}

#[test]
fn dropped_trailing_bytes_check_breaks_the_refinement() {
    // `exact` keeps a decoded value whatever follows it
    let (c, v, r) = qmdb_with("codec.rs", "Some((_, [_, ..])) => None,", "Some((value, [_, ..])) => Some(value),", Some(&REFINEMENTS));
    // `exact_left` states that a reading with bytes left is refused
    breaks_the_refinement(&c, &v, &r, "crate::codec::exact", "exact_left");
}

#[test]
fn dropped_partial_chunk_binding_breaks_the_refinement() {
    // `canonical` no longer checks `H(chunk)` against the partial digest
    let (c, v, r) = qmdb_with(
        "verifier.rs",
        "location / CHUNK_BITS != leaves / CHUNK_BITS || equal(&hash_chunk(chunk), &partial_digest)",
        "location / CHUNK_BITS != leaves / CHUNK_BITS || true",
        Some(&REFINEMENTS),
    );
    // `canonical_partial_bad` states that a partial chunk whose digest
    // differs gives no root
    breaks_the_refinement(&c, &v, &r, "crate::verifier::canonical", "canonical_partial_bad");
}

#[test]
fn a_false_law_is_not_proven() {
    // a verifying proof is not at most 32 bytes long (its operations root
    // alone is 32 bytes)
    const LAW: &str = "crate::laws::verified_proofs_are_small";
    let (c, v, _) = qmdb_with("LAWS.rs", "ensures(proof.len() <= 3989 + N as Nat);", "ensures(proof.len() <= 32);", Some(&[LAW]));
    assert!(!v.proofs_ok);
    assert_ne!(law_status(&v, LAW), &DefStatus::Checked, "{}", explain(&c, &v));
    let e = errors(&c, &v);
    assert!(e.contains("verified_proofs_are_small"), "{e}");
    println!("{LAW}: not proven ({:.1} s)", v.elapsed.as_secs_f64());
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
