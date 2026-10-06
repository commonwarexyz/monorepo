//! §15 S1 `SPEC.lock` (DESIGN.md §15.6): the specification surface, the
//! Merkle lock (canon, `Hdep`, the header, exact-set comparison), its
//! enforcement (the lock gate of every build: a missing, malformed or
//! mismatched lock fails the crate), acceptance (`sandblaster spec --accept`;
//! the lock text through `lock::preview_accept` here), the kernel
//! classification of changes (`--diff`, `--equivalent-only`).
//!
//! The fixture is a small crate with a spec helper, a spec with examples,
//! a refinement, a vector file, two laws over an exec function and a
//! private exec constant; each test edits it and checks which lock keys
//! the change names.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use sandblaster_front::diag::{Diagnostics, Severity};
use sandblaster_front::driver::{self, Checked, stage::SpecBaseline, stage::SpecRun, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::lock::{self, Lock, LockEntry, LockState, Selection, What};
use sandblaster_front::specdiff::{self, Class};
use sandblaster_front::surface::{self, SurfaceOptions};
use sandblaster_front::target::TargetInfo;

const ROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

const LIMIT: u32 = 100;

pub fn clamp(x: u32) -> u32 {
    if x > LIMIT { LIMIT } else { x }
}

#[cfg(sandblaster)]
#[spec]
fn twice(x: Nat) -> Nat { x + x }

#[cfg(sandblaster)]
#[spec]
#[example(double(2) == 4)]
#[example(double(5) == 10)]
fn double(x: Nat) -> Nat { twice(x) }

#[cfg(sandblaster)]
#[spec]
fn total(xs: Seq<u8>) -> Nat { xs.len() }

#[refines(double)]
pub fn dbl(x: u32) -> u64 { (x as u64) * 2 }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "dbl.rsp", format = "cavp", provenance = independent)]
fn dbl_kat(x: Nat, y: Nat) -> bool { double(x) == y }

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const LAWS: &str = r#"use sandblaster::prelude::*;
use super::{clamp, LIMIT};

#[law]
fn clamp_bounded(x: u32) {
    requires(x < 1000);
    ensures(clamp(x) <= LIMIT);
}

#[law]
fn clamp_small(x: u32) {
    requires(x < 50);
    ensures(clamp(x) == x);
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
use super::clamp;

#[proof]
fn clamp_bounded(x: u32) {}

#[proof]
fn clamp_small(x: u32) {}
"#;

const RSP: &str = "# double, known answers\nX = 1\nY = 2\n\nX = 7\nY = 14\n";

type Files = Vec<(String, String)>;

fn fixture() -> Files {
    vec![("r/mod.rs".into(), ROOT.into()), ("r/LAWS.rs".into(), LAWS.into()), ("r/PROOF.rs".into(), PROOF.into()), ("r/dbl.rsp".into(), RSP.into())]
}

/// `files` with `from` replaced by `to` in `file` (the site must exist).
fn edit(files: &Files, file: &str, from: &str, to: &str) -> Files {
    let mut out = files.clone();
    let (_, text) = out.iter_mut().find(|(p, _)| p == file).unwrap_or_else(|| panic!("no file {file}"));
    assert!(text.contains(from), "edit site not found in {file}: {from}");
    *text = text.replacen(from, to, 1);
    out
}

fn with_lock(files: &Files, lock: &str) -> Files {
    let mut out: Files = files.iter().filter(|(p, _)| p != "r/SPEC.lock").cloned().collect();
    out.push(("r/SPEC.lock".into(), lock.into()));
    out
}

fn check(files: &Files) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front end rejected the fixture:\n{}", c.render());
    c
}

/// `sandblaster spec` on `files` (the lock, if any, is `r/SPEC.lock`).
fn spec(files: &Files) -> SpecRun {
    let c = check(files);
    let r = driver::stage::spec_run(&c, &SpecBaseline::Lock, true);
    assert!(r.v.proofs_ok, "the fixture does not verify:\n{}", r.v.diags.render(&c.sm));
    r
}

/// The lock `sandblaster spec --accept` writes for `files`.
fn accepted(files: &Files) -> String {
    let r = spec(files);
    let (l, _) = lock::preview_accept(None, r.surface.as_ref().unwrap(), &Selection::All).expect("accept");
    l.render()
}

fn keys(r: &SpecRun) -> BTreeSet<String> {
    r.surface.as_ref().unwrap().items.iter().map(|i| i.key.clone()).collect()
}

fn mismatches(r: &SpecRun) -> BTreeMap<String, What> {
    r.status.mismatches.iter().map(|m| (m.key.clone(), m.what)).collect()
}

#[track_caller]
fn assert_changed(r: &SpecRun, expected: &[(&str, What)]) {
    let got = mismatches(r);
    let want: BTreeMap<String, What> = expected.iter().map(|(k, w)| (k.to_string(), *w)).collect();
    assert_eq!(got, want, "status: {}\n{:#?}", r.status.summary(), r.status.mismatches);
    assert_eq!(r.status.state, LockState::Mismatch);
}

// ---------------------------------------------------------------------
// the surface
// ---------------------------------------------------------------------

#[test]
fn the_surface_is_exactly_the_reviewable_items() {
    let r = spec(&fixture());
    let want: BTreeSet<String> = [
        "boundary-fn:crate::clamp",
        "boundary-fn:crate::dbl",
        "constant:crate::LIMIT",
        "example:crate::double#0",
        "example:crate::double#1",
        "law:crate::laws::clamp_bounded",
        "law:crate::laws::clamp_small",
        // the computed section of `clamp` (§15.5, S3; its laws do not
        // determine it — recorded, enforced by the section gate)
        "section:crate::clamp",
        "spec-fn:crate::dbl_kat",
        "spec-fn:crate::double",
        "spec-fn:crate::twice",
        "vector-file:crate::dbl_kat#0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(keys(&r), want);
    let s = r.surface.as_ref().unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    // `total` is used by no statement: a proof internal, computed and
    // checked but never locked (crate::surface, *What is locked*)
    assert_eq!(s.internal, vec!["spec-fn:crate::total".to_string()]);
    assert_eq!(r.status.internal, 1);
    // Merkle dependencies: the law names the function it constrains and the
    // constant it reads; the refinement names its spec; the example its spec
    let deps = |k: &str| s.get(k).unwrap().deps.iter().map(|d| d.name.clone()).collect::<Vec<_>>();
    assert!(deps("law:crate::laws::clamp_bounded").contains(&"boundary-fn:crate::clamp".to_string()), "{:?}", deps("law:crate::laws::clamp_bounded"));
    assert!(deps("law:crate::laws::clamp_bounded").contains(&"constant:crate::LIMIT".to_string()));
    assert!(!deps("law:crate::laws::clamp_small").contains(&"constant:crate::LIMIT".to_string()));
    assert!(deps("boundary-fn:crate::dbl").contains(&"spec-fn:crate::double".to_string()));
    assert!(deps("example:crate::double#1").contains(&"spec-fn:crate::double".to_string()));
    // the de-elaborated statement: fully parenthesized, literals typed,
    // implicit coercions explicit
    let law = s.get("law:crate::laws::clamp_bounded").unwrap();
    let st = law.statement.join("\n");
    assert!(st.contains("requires ((x < 1000u32) == true)"), "{st}");
    assert!(st.contains("ensures ((crate::clamp(x) <= crate::LIMIT) == true)"), "{st}");
    let dbl = s.get("boundary-fn:crate::dbl").unwrap().statement.join("\n");
    assert!(dbl.contains("refines crate::double((x as Nat))"), "{dbl}");
    // the kernel statement is stored in core text for kernel comparison
    assert!(law.kernel.iter().any(|(p, t)| p == "type" && t.contains("crate::clamp")), "{:?}", law.kernel);
    // no exec body is part of the surface
    let clamp = s.get("boundary-fn:crate::clamp").unwrap();
    assert!(!clamp.source.contains("if x"), "{}", clamp.source);
}

#[test]
fn a_spec_that_calls_the_implementation_cannot_be_locked() {
    let files = edit(&fixture(), "r/mod.rs", "fn total(xs: Seq<u8>) -> Nat { xs.len() }", "fn total(xs: Seq<u8>) -> Nat { xs.len() }\n#[cfg(sandblaster)] #[spec] fn via_impl(x: u32) -> u32 { clamp(x) }");
    // negative twin: a spec function no statement uses is a proof internal:
    // not locked, so no lock error (its spec closure is the examples gate's
    // `error[spec-depends-on-impl]`, which runs on every spec item)
    let r = spec(&files);
    assert_ne!(r.status.state, LockState::SurfaceErrors, "{}", r.status.summary());
    assert!(r.surface.as_ref().unwrap().internal.contains(&"spec-fn:crate::via_impl".to_string()));
    // used by a law, it is vocabulary: on the surface, and it cannot be locked
    let files = edit(&files, "r/LAWS.rs", "use super::{clamp, LIMIT};", "use super::{clamp, via_impl, LIMIT};\n\n#[law]\nfn via_bounded(x: u32) {\n    ensures(via_impl(x) <= 100u32);\n}");
    let files = edit(&files, "r/PROOF.rs", "#[proof]\nfn clamp_small(x: u32) {}", "#[proof]\nfn clamp_small(x: u32) {}\n\n#[proof]\nfn via_bounded(x: u32) {}");
    let r = spec(&files);
    assert_eq!(r.status.state, LockState::SurfaceErrors, "{}", r.status.summary());
    let s = r.surface.as_ref().unwrap();
    assert!(s.errors.iter().any(|e| e.key == "spec-fn:crate::via_impl" && e.msg.contains("exec function `crate::clamp`")), "{:?}", s.errors);
    assert!(lock::preview_accept(None, s, &Selection::All).is_err(), "a surface with §15.6 errors is never accepted");
    let mut d = Diagnostics::new();
    lock::enforce(&r.status, &BTreeMap::new(), &mut d);
    assert!(d.list.iter().any(|x| x.severity == Severity::Error && x.msg.contains("crate::clamp")), "{:?}", d.list);
}

// ---------------------------------------------------------------------
// the lock: accept, unchanged, exec-only changes
// ---------------------------------------------------------------------

#[test]
fn accept_then_rebuild_matches_and_an_exec_body_change_keeps_the_lock() {
    let base = fixture();
    let r0 = spec(&base);
    assert_eq!(r0.status.state, LockState::Missing);
    assert_eq!(r0.status.root, [0; 32], "no lock: the exported root is zero");
    let text = accepted(&base);
    let parsed = Lock::parse(&text).expect("the rendered lock parses");
    assert_eq!(parsed.render(), text, "render ∘ parse is the identity");
    assert_eq!(parsed.root, parsed.compute_root());
    // the unchanged surface matches (the driver reads r/SPEC.lock through the
    // file provider)
    let r1 = spec(&with_lock(&base, &text));
    assert!(r1.status.matches(), "{} {:#?}", r1.status.summary(), r1.status.mismatches);
    assert_eq!(r1.status.root, parsed.root);
    assert_eq!(r1.status.computed_root, parsed.root);
    // exec bodies are not part of the surface
    let exec_only = edit(&base, "r/mod.rs", "if x > LIMIT { LIMIT } else { x }", "if x >= LIMIT { LIMIT } else { x }");
    let exec_only = edit(&exec_only, "r/mod.rs", "(x as u64) * 2", "(x as u64) + (x as u64)");
    let r2 = spec(&with_lock(&exec_only, &text));
    assert!(r2.status.matches(), "an implementation change leaves the lock unchanged: {} {:#?}", r2.status.summary(), r2.status.mismatches);
}

#[test]
fn a_changed_law_requires_is_detected_and_enforced() {
    let text = accepted(&fixture());
    let files = edit(&with_lock(&fixture(), &text), "r/LAWS.rs", "requires(x < 1000);", "requires(x < 2000);");
    let r = spec(&files);
    // the section of `clamp` has the law among its hypotheses (S3)
    assert_changed(&r, &[("law:crate::laws::clamp_bounded", What::Changed), ("section:crate::clamp", What::Changed)]);
    assert_eq!(r.status.root, [0; 32], "a mismatched lock exports a zero root");
    let mut d = Diagnostics::new();
    lock::enforce(&r.status, &specdiff::classes(&r.changes), &mut d);
    let e: Vec<String> = d.list.iter().filter(|x| x.severity == Severity::Error).map(|x| format!("{} [{}]", x.msg, x.notes.iter().map(|n| n.1.clone()).collect::<Vec<_>>().join(" | "))).filter(|m| !m.contains("section:crate::clamp")).collect();
    assert_eq!(e.len(), 1, "{e:?}");
    // a wider domain: the new law implies the old one
    assert!(e[0].contains("`law:crate::laws::clamp_bounded` changed (strengthened)"), "{e:?}");
    assert!(e[0].contains("locked:") && e[0].contains("1000u32") && e[0].contains("2000u32"), "{e:?}");
    assert!(d.list.iter().all(|x| x.kind.code() == "spec-lock"));
}

#[test]
fn a_changed_constant_used_by_a_law_is_a_merkle_dependency() {
    let text = accepted(&fixture());
    let files = edit(&with_lock(&fixture(), &text), "r/mod.rs", "const LIMIT: u32 = 100;", "const LIMIT: u32 = 200;");
    let r = spec(&files);
    // the law's own text did not change: its hash covers LIMIT's
    assert_changed(&r, &[("constant:crate::LIMIT", What::Changed), ("law:crate::laws::clamp_bounded", What::Changed), ("section:crate::clamp", What::Changed)]);
    let m = r.status.mismatches.iter().find(|m| m.key == "law:crate::laws::clamp_bounded").unwrap();
    assert_eq!(m.via, vec!["constant:crate::LIMIT".to_string()]);
    assert_eq!(m.old, m.new, "the rendered statement is the same; the dependency changed");
}

#[test]
fn a_changed_spec_helper_body_is_detected_through_every_dependent() {
    let text = accepted(&fixture());
    let files = edit(&with_lock(&fixture(), &text), "r/mod.rs", "fn twice(x: Nat) -> Nat { x + x }", "fn twice(x: Nat) -> Nat { 2 * x }");
    let r = spec(&files);
    assert_changed(
        &r,
        &[
            ("boundary-fn:crate::dbl", What::Changed),
            ("example:crate::double#0", What::Changed),
            ("example:crate::double#1", What::Changed),
            ("spec-fn:crate::dbl_kat", What::Changed),
            ("spec-fn:crate::double", What::Changed),
            ("spec-fn:crate::twice", What::Changed),
            ("vector-file:crate::dbl_kat#0", What::Changed),
        ],
    );
    // the helper itself is kernel-proven extensionally equal to the old one
    let c = r.changes.iter().find(|c| c.key == "spec-fn:crate::twice").unwrap();
    assert_eq!(c.class, Some(Class::Equivalent), "{c:?}");
}

#[test]
fn a_vector_file_edit_or_deletion_is_detected() {
    let text = accepted(&fixture());
    let edited = edit(&with_lock(&fixture(), &text), "r/dbl.rsp", "X = 7\nY = 14", "X = 8\nY = 16");
    assert_changed(&spec(&edited), &[("vector-file:crate::dbl_kat#0", What::Changed)]);
    let deleted: Files = edit(&with_lock(&fixture(), &text), "r/mod.rs", "#[examples(file = \"dbl.rsp\", format = \"cavp\", provenance = independent)]\n", "").into_iter().filter(|(p, _)| p != "r/dbl.rsp").collect();
    // without its vector file the checker is used by nothing: it leaves the
    // lock with it (a proof internal)
    assert_changed(&spec(&deleted), &[("spec-fn:crate::dbl_kat", What::Removed), ("vector-file:crate::dbl_kat#0", What::Removed)]);
}

#[test]
fn a_removed_example_is_detected() {
    let text = accepted(&fixture());
    let files = edit(&with_lock(&fixture(), &text), "r/mod.rs", "#[example(double(5) == 10)]\n", "");
    assert_changed(&spec(&files), &[("example:crate::double#1", What::Removed)]);
}

#[test]
fn a_prelude_change_is_detected_in_the_header_and_its_dependents() {
    // `total` (a `list.core` user) made vocabulary by a law
    let files = edit(&fixture(), "r/LAWS.rs", "use super::{clamp, LIMIT};", "use super::{clamp, total, LIMIT};\n\n#[law]\nfn total_counts(xs: Seq<u8>) {\n    ensures(total(xs) == xs.len());\n}");
    let files = edit(&files, "r/PROOF.rs", "#[proof]\nfn clamp_small(x: u32) {}", "#[proof]\nfn clamp_small(x: u32) {}\n\n#[proof]\nfn total_counts(xs: Seq<u8>) {}");
    let c = check(&files);
    let k = c.krate.as_ref().unwrap();
    let (before, after) = driver::stage::with_elaboration(k, &VerifyOptions::default(), |out| {
        let before = surface::compute(out, k, &c.sm, &SurfaceOptions::default());
        let mut tc = surface::Toolchain::current().clone();
        tc.prelude_files.insert("list.core".into(), [7; 32]);
        tc.prelude = [8; 32];
        let after = surface::compute(out, k, &c.sm, &SurfaceOptions { toolchain: Some(tc), ..Default::default() });
        (before, after)
    });
    let text = lock::preview_accept(None, &before, &Selection::All).unwrap().0.render();
    let st = lock::compare(Some(&text), &after, "r/SPEC.lock");
    assert_eq!(st.state, LockState::Mismatch);
    assert!(st.header.iter().any(|h| h.starts_with("prelude:")), "{:?}", st.header);
    let changed: Vec<&str> = st.mismatches.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(changed, vec!["law:crate::laws::total_counts", "spec-fn:crate::total"], "only the items that use a list.core global");
    assert!(before.get("spec-fn:crate::total").unwrap().deps.iter().any(|d| d.name == "prelude:list.core"), "a prelude global is a file dependency");
}

#[test]
fn a_crate_written_in_the_dsl_has_no_lift_prelude_line() {
    // the lift prelude is pinned only for a lifted crate (`lock_surface.rs`,
    // `a_lifted_crate_pins_the_lift_prelude`): this crate does not load it,
    // so its lock has no `lift` line and a changed prelude does not touch it
    let files = fixture();
    let c = check(&files);
    let k = c.krate.as_ref().unwrap();
    let (before, after) = driver::stage::with_elaboration(k, &VerifyOptions::default(), |out| {
        let before = surface::compute(out, k, &c.sm, &SurfaceOptions::default());
        let mut tc = surface::Toolchain::current().clone();
        tc.lift = [9; 32];
        let after = surface::compute(out, k, &c.sm, &SurfaceOptions { toolchain: Some(tc), ..Default::default() });
        (before, after)
    });
    assert_eq!(before.lift, None);
    let text = lock::preview_accept(None, &before, &Selection::All).unwrap().0.render();
    assert!(!text.lines().any(|l| l.starts_with("lift ")), "{}", &text[..400]);
    assert_eq!(lock::compare(Some(&text), &after, "r/SPEC.lock").state, LockState::Matches);
}

// ---------------------------------------------------------------------
// --diff and --equivalent-only
// ---------------------------------------------------------------------

/// The entries of the surface of `files` (the old side of `--diff`).
fn old_entries(files: &Files) -> Vec<LockEntry> {
    let r = spec(files);
    let s = r.surface.unwrap();
    s.items.iter().map(|i| LockEntry::of(i, &s.target)).collect()
}

fn diff(old: &Files, new: &Files) -> HashMap<String, (What, Option<Class>, String)> {
    let entries = old_entries(old);
    let c = check(new);
    let r = driver::stage::spec_run(&c, &SpecBaseline::Old(entries), true);
    assert!(r.v.proofs_ok, "{}", r.v.diags.render(&c.sm));
    r.changes.into_iter().map(|ch| (ch.key, (ch.what, ch.class, ch.reason))).collect()
}

#[test]
fn diff_classifies_an_added_requires_as_weakened_and_a_dropped_one_as_strengthened() {
    let base = fixture();
    let more = edit(&base, "r/LAWS.rs", "requires(x < 50);", "requires(x < 50);\n    requires(x > 3);");
    let d = diff(&base, &more);
    let (what, class, why) = &d["law:crate::laws::clamp_small"];
    assert_eq!((*what, *class), (What::Changed, Some(Class::Weakened)), "{why}");
    // and the section of `clamp`, whose hypotheses changed (S3)
    assert_eq!(d.len(), 2, "{d:?}");
    assert_eq!(d["section:crate::clamp"].1, Some(Class::Unrelated), "{d:?}");
    let d = diff(&more, &base);
    let (what, class, why) = &d["law:crate::laws::clamp_small"];
    assert_eq!((*what, *class), (What::Changed, Some(Class::Strengthened)), "{why}");
}

#[test]
fn diff_proves_a_restated_requires_equivalent_and_reports_unrelated_changes() {
    let base = fixture();
    let restated = edit(&base, "r/LAWS.rs", "requires(x < 1000);", "requires(x <= 999);");
    let d = diff(&base, &restated);
    let (_, class, why) = &d["law:crate::laws::clamp_bounded"];
    assert_eq!(*class, Some(Class::Equivalent), "{why}");
    // a different conclusion over a different bound: neither implies the other
    let other = edit(&base, "r/LAWS.rs", "requires(x < 50);\n    ensures(clamp(x) == x);", "requires(x > 200);\n    ensures(clamp(x) == 100);");
    let d = diff(&base, &other);
    let (_, class, why) = &d["law:crate::laws::clamp_small"];
    assert_eq!(*class, Some(Class::Unrelated), "{why}");
}

#[test]
fn equivalent_only_accepts_only_kernel_proven_equivalents() {
    let base = fixture();
    let text = accepted(&base);
    let old = Lock::parse(&text).unwrap();
    let files = edit(&with_lock(&base, &text), "r/LAWS.rs", "requires(x < 1000);", "requires(x <= 999);");
    let files = edit(&files, "r/LAWS.rs", "requires(x < 50);", "requires(x < 50);\n    requires(x > 3);");
    let r = spec(&files);
    assert_changed(&r, &[("law:crate::laws::clamp_bounded", What::Changed), ("law:crate::laws::clamp_small", What::Changed), ("section:crate::clamp", What::Changed)]);
    let keys = specdiff::equivalent_keys(&r.changes);
    assert_eq!(keys, vec!["law:crate::laws::clamp_bounded".to_string()], "{:#?}", r.changes);
    let mut sel = keys.clone();
    sel.push("toolchain".into());
    let (new_lock, acc) = lock::preview_accept(Some(&old), r.surface.as_ref().unwrap(), &Selection::Items(sel)).unwrap();
    assert_eq!(acc.changed, vec!["law:crate::laws::clamp_bounded".to_string()]);
    let r2 = spec(&with_lock(&files, &new_lock.render()));
    assert_changed(&r2, &[("law:crate::laws::clamp_small", What::Changed), ("section:crate::clamp", What::Changed)]);
}

// ---------------------------------------------------------------------
// the lock file and enforcement
// ---------------------------------------------------------------------

#[test]
fn a_hand_edited_lock_is_malformed_and_a_missing_lock_is_an_error_when_enforced() {
    let base = fixture();
    let text = accepted(&base);
    // change one hash without recomputing the root
    let line = text.lines().find(|l| l.starts_with("  hash ")).unwrap();
    let forged = text.replacen(line, &format!("  hash {}", "0".repeat(64)), 1);
    let r = spec(&with_lock(&base, &forged));
    assert!(matches!(r.status.state, LockState::Malformed(ref m) if m.contains("root")), "{:?}", r.status.state);
    // an entry line edited consistently with the root: its hash no longer
    // covers its fields
    let mut l = Lock::parse(&text).unwrap();
    l.entries[0].canon = [1; 32];
    l.root = l.compute_root();
    let r = spec(&with_lock(&base, &l.render()));
    assert!(matches!(r.status.state, LockState::Malformed(ref m) if m.contains("does not hash to its `hash` line")), "{:?}", r.status.state);
    // enforcement: a missing lock is an error naming the file
    let r = spec(&base);
    let mut d = Diagnostics::new();
    lock::enforce(&r.status, &BTreeMap::new(), &mut d);
    assert_eq!(d.list.len(), 1);
    assert!(d.list[0].msg.contains("no SPEC.lock at `r/SPEC.lock`"), "{}", d.list[0].msg);
    assert!(d.list[0].notes.iter().any(|n| n.1.contains("only `sandblaster spec --accept` writes SPEC.lock")));
}

#[test]
fn accepting_single_items_updates_only_those_entries() {
    let base = fixture();
    let text = accepted(&base);
    let old = Lock::parse(&text).unwrap();
    let files = edit(&base, "r/LAWS.rs", "requires(x < 1000);", "requires(x < 2000);");
    let files = edit(&files, "r/mod.rs", "#[example(double(5) == 10)]\n", "");
    let r = spec(&with_lock(&files, &text));
    let (l, acc) = lock::preview_accept(Some(&old), r.surface.as_ref().unwrap(), &Selection::Items(vec!["example:crate::double#1".into()])).unwrap();
    assert_eq!(acc.removed, vec!["example:crate::double#1".to_string()]);
    assert!(acc.changed.is_empty() && !acc.header);
    let r2 = spec(&with_lock(&files, &l.render()));
    assert_changed(&r2, &[("law:crate::laws::clamp_bounded", What::Changed), ("section:crate::clamp", What::Changed)]);
    assert!(lock::preview_accept(Some(&old), r.surface.as_ref().unwrap(), &Selection::Items(vec!["law:crate::nope".into()])).is_err());
}

#[test]
fn a_lock_for_another_target_keeps_its_entries() {
    // the lock of one target records only that target; accepting on a
    // second target keeps the first target's entries and header line
    let base = fixture();
    let r = spec(&base);
    let s = r.surface.unwrap();
    let (l, _) = lock::preview_accept(None, &s, &Selection::All).unwrap();
    let mut other = s.clone();
    other.target = "x86_64".into();
    other.target_model = [9; 32];
    let st = lock::compare(Some(&l.render()), &other, "SPEC.lock");
    assert!(st.header.iter().any(|h| h.contains("target x86_64: not accepted")), "{:?}", st.header);
    let (l2, _) = lock::preview_accept(Some(&l), &other, &Selection::All).unwrap();
    let both = l2.render();
    assert!(lock::compare(Some(&both), &s, "SPEC.lock").matches(), "aarch64 still matches");
    assert!(lock::compare(Some(&both), &other, "SPEC.lock").matches(), "x86_64 matches");
    assert_eq!(Lock::parse(&both).unwrap().entries.len(), s.items.len(), "identical entries are shared, not duplicated");
}

#[test]
fn the_kernel_source_list_is_the_kernel_crate() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kernel/src");
    fn walk(d: &Path, base: &Path, out: &mut BTreeSet<String>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, base, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.insert(p.strip_prefix(base).unwrap().display().to_string());
            }
        }
    }
    let mut files = BTreeSet::new();
    walk(&dir, &dir, &mut files);
    let listed: BTreeSet<String> = lock::KERNEL_SOURCES.iter().map(|(n, _)| n.to_string()).collect();
    assert_eq!(files, listed, "lock::KERNEL_SOURCES must list every kernel source file (the `kernel` hash of SPEC.lock)");
}

// ---------------------------------------------------------------------
// the build: enforced by the lock gate
// ---------------------------------------------------------------------

#[test]
fn the_build_fails_without_a_matching_lock() {
    // the crate path's lock gate (the build entry points run it unchanged)
    let gate = |files: &Files| {
        let c = check(files);
        let b = driver::build_crate(&c, driver::LockUse::Enforce, "r/mod.rs");
        (b.gates.diags.render(&c.sm), b.report.clone(), b.verdict.is_some())
    };
    // (the fixture also fails other gates — exec functions at the root,
    // laws over exec functions — which is not what this test is about)
    // no lock: the lock gate fails the build
    let (d, report, verdict) = gate(&fixture());
    assert!(!verdict);
    assert!(d.contains("error[spec-lock]: no SPEC.lock at"), "{d}");
    assert!(report.contains("\"status\": \"missing\""), "{report}");
    // an accepted lock: the lock gate passes
    let text = accepted(&fixture());
    let (d, report, _) = gate(&with_lock(&fixture(), &text));
    assert!(!d.contains("error[spec-lock]"), "{d}");
    assert!(report.contains("\"status\": \"matches\""), "{report}");
    // a mismatch is an error naming the item
    let (d, report, verdict) = gate(&edit(&with_lock(&fixture(), &text), "r/LAWS.rs", "requires(x < 1000);", "requires(x < 2000);"));
    assert!(!verdict);
    assert!(d.contains("error[spec-lock]: SPEC.lock: `law:crate::laws::clamp_bounded` changed"), "{d}");
    assert!(report.contains("\"status\": \"mismatch\""), "{report}");
}

#[test]
fn cyclic_entries_are_verified_as_one_component() {
    // mutually referring contracts are mutual recursion (rejected by the
    // validator), so the surface graph has no cycle today; the lock format
    // still supports one: each member's hash covers every member's content
    use sandblaster_front::lock::{DepKind, LockDep};
    use sandblaster_front::surface::{item_l, item_local, scc_member_hash};
    let base = fixture();
    let text = accepted(&base);
    let mut l = Lock::parse(&text).unwrap();
    let t: BTreeSet<String> = l.targets.keys().cloned().collect();
    let entry = |key: &str, other: &str| LockEntry {
        key: key.into(),
        kind: sandblaster_front::surface::SurfaceKind::Contract,
        targets: t.clone(),
        hash: [0; 32],
        canon: [3; 32],
        src: [4; 32],
        deps: vec![LockDep { kind: DepKind::Cycle, name: other.into(), hash: None }],
        statement: vec![],
        kernel: vec![],
        kernel_omitted: vec![],
    };
    let (mut a, mut b) = (entry("contract:crate::a", "contract:crate::b"), entry("contract:crate::b", "contract:crate::a"));
    let l_of = |e: &LockEntry, other: &str| item_l(&item_local(e.kind, &e.key, &e.canon, &e.src), &[], &[(other, None)]);
    let members = vec![("contract:crate::a".to_string(), l_of(&a, "contract:crate::b")), ("contract:crate::b".to_string(), l_of(&b, "contract:crate::a"))];
    a.hash = scc_member_hash(&members[0].1, &members);
    b.hash = scc_member_hash(&members[1].1, &members);
    l.entries.push(a);
    l.entries.push(b.clone());
    lock::verify_entries(&l).expect("a consistent component");
    // editing one member breaks both hashes
    let n = l.entries.len();
    l.entries[n - 1].canon = [5; 32];
    assert!(lock::verify_entries(&l).is_err());
}

// ---------------------------------------------------------------------
// review fixes: comparisons never use an implementation's body; the
// statements show what a refinement really claims
// ---------------------------------------------------------------------

/// A crate with one boundary function `f` whose contract (or law) is
/// `CONTRACT`, and whose body is `BODY`.
fn weak_files(contract: &str, law: Option<&str>, body: &str) -> Files {
    let mut root = format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n{contract}\npub fn f(x: u32) -> u32 {{ {body} }}\n");
    let mut files = Vec::new();
    if let Some(l) = law {
        root.push_str("\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
        files.push(("r/LAWS.rs".to_string(), format!("use sandblaster::prelude::*;\nuse super::f;\n\n#[law]\nfn f_law(x: u32) {{\n    {l}\n}}\n")));
        files.push(("r/PROOF.rs".to_string(), "use sandblaster::prelude::*;\nuse super::f;\n\n#[proof]\nfn f_law(x: u32) {}\n".to_string()));
    }
    files.insert(0, ("r/mod.rs".to_string(), root));
    files
}

#[test]
fn a_weakened_contract_or_law_is_never_equivalent_through_the_body() {
    // both statements hold of `f = 7`; compared for every implementation of
    // `f`, the weaker one does not imply the stronger
    let old = weak_files("#[ensures(|r| r == 7)]", None, "7");
    for weaker in ["#[ensures(|r| r < 100)]", "#[ensures(|r| true)]"] {
        let d = diff(&old, &weak_files(weaker, None, "7"));
        let (what, class, why) = &d["boundary-fn:crate::f"];
        assert_eq!((*what, *class), (What::Changed, Some(Class::Weakened)), "{weaker}: {why}");
        assert!(why.contains("compared for every implementation of `crate::f`"), "{why}");
    }
    let old = weak_files("", Some("ensures(f(x) == 7);"), "7");
    let d = diff(&old, &weak_files("", Some("ensures(f(x) < 100);"), "7"));
    let (_, class, why) = &d["law:crate::laws::f_law"];
    assert_eq!(*class, Some(Class::Weakened), "{why}");
    // a restatement that holds for every implementation stays equivalent
    let d = diff(&weak_files("", Some("ensures(f(x) <= 7);"), "7"), &weak_files("", Some("ensures(f(x) < 8);"), "7"));
    let (_, class, why) = &d["law:crate::laws::f_law"];
    assert_eq!(*class, Some(Class::Equivalent), "{why}");
}

#[test]
fn equivalent_only_does_not_accept_a_weakened_contract() {
    // the end-to-end attack: accept `r == 7`, weaken to `r < 100`, re-accept
    // "equivalent" items only, then change the body: the lock must not match
    let base = weak_files("#[ensures(|r| r == 7)]", None, "7");
    let text = accepted(&base);
    let weak = with_lock(&weak_files("#[ensures(|r| r < 100)]", None, "7"), &text);
    let r = spec(&weak);
    // `f`'s section has its `ensures` among its hypotheses (S3)
    assert_changed(&r, &[("boundary-fn:crate::f", What::Changed), ("section:crate::f", What::Changed)]);
    assert!(specdiff::equivalent_keys(&r.changes).is_empty(), "{:#?}", r.changes);
}

const REPR: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[cfg(sandblaster)]
#[spec]
#[path = "spec.rs"]
mod spec;

/// A counter represented by its count (the relation can never hold).
#[derive(Clone, Copy)]
#[represents(|s: &Ctr, a: Nat| s.count as Nat == a && s.count as Nat != a)]
pub struct Ctr { count: u16 }

impl Ctr {
    #[refines(spec::get)]
    pub fn get(&self) -> u16 { 7 }
}

/// A pair viewed through its low half only. Internal and not `Abstract`
/// (its derived `PartialEq` compares `hi`): the view stays lossy (S2).
#[derive(Clone, Copy, PartialEq)]
#[view(|p| p.lo as Nat)]
struct Pair { lo: u32, hi: u32 }

#[refines(spec::inc)]
fn bump(x: u32) -> Pair { Pair { lo: x, hi: 0xdead } }

pub fn low(x: u32) -> u32 { bump(x).lo }
"#;

#[test]
fn simulation_and_lossy_refinements_show_their_real_statement() {
    let files: Files = vec![("r/mod.rs".into(), REPR.into()), ("r/spec.rs".into(), "pub fn get(a: Nat) -> Nat { a }\npub fn inc(x: Nat) -> Nat { x }\n".into())];
    let r = spec(&files);
    let s = r.surface.as_ref().unwrap();
    let get = s.get("boundary-fn:crate::Ctr::get").unwrap().statement.join("\n");
    assert!(get.contains("refines crate::spec::get(a) through the representation relation crate::Ctr::represents"), "{get}");
    assert!(get.contains("meaning: for all a: Nat, (crate::Ctr::represents(self, a) => ((crate::Ctr::get(self) as Nat) == crate::spec::get(a)))"), "{get}");
    assert!(get.contains("NOT DETERMINING") && get.contains("Abstract(T)"), "{get}");
    assert!(!get.contains("view::<Nat>(self)"), "no view of a type without one: {get}");
    let bump = s.get("contract:crate::bump").unwrap().statement.join("\n");
    assert!(bump.contains("meaning: (view::<Nat>(crate::bump(x)) == crate::spec::inc((x as Nat)))"), "{bump}");
    assert!(bump.contains("NOT DETERMINING: refines `crate::spec::inc` up to view("), "{bump}");
    // the lock's rendered lines are these statements
    let (l, _) = lock::preview_accept(None, s, &Selection::All).unwrap();
    assert!(l.render().contains("NOT DETERMINING: refines `crate::spec::inc` up to view("));
    // the report records every refinement with its form and determinacy
    let c = check(&files);
    let built = driver::stage::verify_checked(&c, &VerifyOptions::default());
    assert!(built.v.proofs_ok, "{}", built.v.diags.render(&c.sm));
    let json = driver::stage::report_json(&c, &built.v, &built.law_audit, "r/mod.rs", Some(&built.spec), Some(&built.spec15));
    let j = sandblaster_front::elab::value::J::parse(&json).expect("report JSON");
    let text = j.render();
    assert!(text.contains("\"function\":\"crate::bump\"") && text.contains("\"determines\":false") && text.contains("up to view("), "{text}");
    assert!(text.contains("\"form\":\"represents-observer\""), "{text}");
}

#[test]
fn a_vector_file_entry_records_how_many_records_were_checked() {
    let r = spec(&fixture());
    let s = r.surface.as_ref().unwrap();
    let v = s.get("vector-file:crate::dbl_kat#0").unwrap();
    assert!(v.statement.iter().any(|l| l.contains("2 record(s) checked")), "{:?}", v.statement);
}
