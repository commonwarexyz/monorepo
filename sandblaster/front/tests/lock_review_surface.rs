//! `SPEC.lock` holds the review surface only (DESIGN.md §15.6;
//! `sandblaster_front::surface`, *What is locked*): the laws, the vocabulary
//! they use, the boundary signatures, trusted items, sections and the
//! known answers of the vocabulary — never proof internals (helper spec
//! functions only proofs use, their examples, invariants of types no
//! statement mentions, lemmas).
//!
//! * the fixture's helper spec function, its examples, its lemma and the
//!   invariant of an internal type are computed but not locked;
//! * a proof refactor (renaming a helper, changing or adding its examples,
//!   rewriting a lemma, changing the internal invariant, reordering
//!   PROOF.rs) leaves the lock byte for byte unchanged;
//! * negative twins: a changed law, vocabulary body or vocabulary example,
//!   a helper that a law starts to use, and an internal type that becomes a
//!   boundary type all change the lock;
//! * the kept set is closed under dependencies (so no kept hash moves) and
//!   the rule is deterministic.

use std::collections::BTreeSet;
use std::path::Path;

use sandblaster_front::driver::{self, stage::SpecBaseline, stage::SpecRun, Checked};
use sandblaster_front::loader::MemFs;
use sandblaster_front::lock::{self, LockState, Selection};
use sandblaster_front::target::TargetInfo;

const ROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[derive(Clone, Copy)]
#[invariant(self.v < 2000)]
struct Small { v: u32 }

fn small(x: u32) -> Small {
    if x < 1000 { Small { v: x } } else { Small { v: 1000 } }
}

pub fn inc(x: u32) -> u32 {
    let s = small(x);
    if s.v < 1000 { s.v + 1 } else { x }
}

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const LAWS: &str = r#"use sandblaster::prelude::*;
use super::inc;

/// The successor, capped at 1000.
#[spec]
#[example(succ_capped(1) == 2 && succ_capped(1000) == 1000)]
pub fn succ_capped(x: Nat) -> Nat {
    if x < 1000 { x + 1 } else { x }
}

/// `inc` is the capped successor.
#[law]
fn inc_is_succ(x: u32) {
    ensures(inc(x) as Nat == succ_capped(x as Nat));
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
use super::inc;
use crate::laws::succ_capped;

/// A helper only proofs use.
#[spec]
#[example(helper(3) == 4 && helper(0) == 1)]
fn helper(x: Nat) -> Nat { x + 1 }

#[lemma]
fn helper_below_cap(x: Nat) {
    requires(x < 1000);
    ensures(helper(x) == succ_capped(x));
}

#[proof]
fn inc_is_succ(x: u32) {}
"#;

type Files = Vec<(String, String)>;

fn fixture() -> Files {
    vec![("r/mod.rs".into(), ROOT.into()), ("r/LAWS.rs".into(), LAWS.into()), ("r/PROOF.rs".into(), PROOF.into())]
}

fn edit(files: &Files, file: &str, from: &str, to: &str) -> Files {
    let mut out = files.clone();
    let (_, text) = out.iter_mut().find(|(p, _)| p == file).unwrap_or_else(|| panic!("no file {file}"));
    assert!(text.contains(from), "edit site not found in {file}: {from}");
    *text = text.replacen(from, to, 1);
    out
}

fn check(files: &Files) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front end rejected the fixture:\n{}", c.render());
    c
}

fn spec(files: &Files) -> SpecRun {
    let c = check(files);
    let r = driver::stage::spec_run(&c, &SpecBaseline::None, false);
    assert!(r.v.proofs_ok, "the fixture does not verify:\n{}", r.v.diags.render(&c.sm));
    r
}

/// The lock `sandblaster spec --accept` would write (no old lock).
fn lock_text(files: &Files) -> String {
    let r = spec(files);
    lock::preview_accept(None, r.surface.as_ref().unwrap(), &Selection::All).expect("accept").0.render()
}

fn keys(r: &SpecRun) -> BTreeSet<String> {
    r.surface.as_ref().unwrap().items.iter().map(|i| i.key.clone()).collect()
}

#[test]
fn proof_internals_are_computed_but_not_locked() {
    let r = spec(&fixture());
    let s = r.surface.as_ref().unwrap();
    let k = keys(&r);
    for want in ["law:crate::laws::inc_is_succ", "spec-fn:crate::laws::succ_capped", "example:crate::laws::succ_capped#0", "boundary-fn:crate::inc"] {
        assert!(k.contains(want), "`{want}` is on the review surface: {k:?}");
    }
    for internal in ["spec-fn:crate::proof::helper", "example:crate::proof::helper#0", "invariant:crate::Small", "type:crate::Small"] {
        assert!(!k.contains(internal), "`{internal}` is a proof internal: {k:?}");
        assert!(s.internal.contains(&internal.to_string()), "`{internal}` is listed as internal: {:?}", s.internal);
    }
    assert_eq!(r.status.internal, s.internal.len());
    // closed under dependencies: every kept item's dependencies are kept,
    // so the filter moves no kept hash
    for i in &s.items {
        for d in i.deps.iter().filter(|d| d.item) {
            assert!(k.contains(&d.name), "`{}` depends on `{}`, which is not kept", i.key, d.name);
        }
    }
    // the lock names no internal
    let text = lock_text(&fixture());
    assert!(!text.contains("crate::proof::helper") && !text.contains("crate::Small"), "{text}");
}

#[test]
fn a_proof_refactor_leaves_the_lock_byte_for_byte_unchanged() {
    let base = lock_text(&fixture());
    // rename the helper, change and add examples, rewrite the lemma
    let proof = edit(&fixture(), "r/PROOF.rs", "#[example(helper(3) == 4 && helper(0) == 1)]\nfn helper(x: Nat) -> Nat { x + 1 }", "#[example(step(3) == 4)]\n#[example(step(9) == 10)]\nfn step(x: Nat) -> Nat { 1 + x }");
    let proof = edit(&proof, "r/PROOF.rs", "    ensures(helper(x) == succ_capped(x));", "    ensures(step(x) == succ_capped(x));");
    // a second helper with its own examples, placed first (reordering)
    let proof = edit(&proof, "r/PROOF.rs", "/// A helper only proofs use.", "/// Another helper.\n#[spec]\n#[example(twice(2) == 4)]\nfn twice(x: Nat) -> Nat { x + x }\n\n/// A helper only proofs use.");
    // the internal type's invariant (a proof device)
    let refactor = edit(&proof, "r/mod.rs", "#[invariant(self.v < 2000)]", "#[invariant(self.v <= 1000)]");
    let r = spec(&refactor);
    assert_eq!(lock_text(&refactor), base, "a proof refactor must not change the lock");
    let c = lock::compare(Some(&base), r.surface.as_ref().unwrap(), "r/SPEC.lock");
    assert_eq!(c.state, LockState::Matches, "{} {:#?}", c.summary(), c.mismatches);
    // the refactor's items are internal
    assert!(r.surface.as_ref().unwrap().internal.iter().any(|k| k == "spec-fn:crate::proof::twice"));
}

#[test]
fn a_changed_law_vocabulary_or_known_answer_changes_the_lock() {
    let base = lock_text(&fixture());
    let changed = |files: &Files| -> Vec<String> {
        let r = spec(files);
        let st = lock::compare(Some(&base), r.surface.as_ref().unwrap(), "r/SPEC.lock");
        assert_eq!(st.state, LockState::Mismatch, "{}", st.summary());
        st.mismatches.iter().map(|m| m.key.clone()).collect()
    };
    // the law (a weaker, still proven claim)
    let law = edit(&fixture(), "r/LAWS.rs", "ensures(inc(x) as Nat == succ_capped(x as Nat));", "ensures(inc(x) as Nat <= succ_capped(x as Nat));");
    assert!(changed(&law).contains(&"law:crate::laws::inc_is_succ".to_string()));
    // the vocabulary's body (an equal function, a different statement)
    let vocab = edit(&fixture(), "r/LAWS.rs", "if x < 1000 { x + 1 } else { x }", "if x < 1000 { 1 + x } else { x }");
    let ks = changed(&vocab);
    assert!(ks.contains(&"spec-fn:crate::laws::succ_capped".to_string()) && ks.contains(&"law:crate::laws::inc_is_succ".to_string()), "{ks:?}");
    // a known answer of the vocabulary
    let example = edit(&fixture(), "r/LAWS.rs", "succ_capped(1000) == 1000", "succ_capped(999) == 1000");
    assert!(changed(&example).contains(&"example:crate::laws::succ_capped#0".to_string()));
}

#[test]
fn a_helper_a_law_uses_and_a_boundary_type_are_on_the_surface() {
    let base = lock_text(&fixture());
    // a law that mentions the helper makes it (and its examples) vocabulary
    let uses = edit(&fixture(), "r/LAWS.rs", "#[law]\nfn inc_is_succ", "#[law]\nfn helper_is_succ(x: Nat) {\n    requires(x < 1000);\n    ensures(crate::proof::helper(x) == succ_capped(x));\n}\n\n#[law]\nfn inc_is_succ");
    let uses = edit(&uses, "r/PROOF.rs", "#[proof]\nfn inc_is_succ(x: u32) {}", "#[proof]\nfn inc_is_succ(x: u32) {}\n\n#[proof]\nfn helper_is_succ(x: Nat) {}");
    let uses = edit(&uses, "r/PROOF.rs", "fn helper(x: Nat)", "pub fn helper(x: Nat)");
    let r = spec(&uses);
    let k = keys(&r);
    assert!(k.contains("spec-fn:crate::proof::helper") && k.contains("example:crate::proof::helper#0"), "{k:?}");
    assert_ne!(lock_text(&uses), base);
    // an internal type that becomes a boundary type brings its invariant
    let public = edit(&fixture(), "r/mod.rs", "struct Small { v: u32 }", "pub struct Small { v: u32 }");
    let r = spec(&public);
    let k = keys(&r);
    assert!(k.contains("invariant:crate::Small") && k.contains("boundary-type:crate::Small"), "{k:?}");
}

#[test]
fn the_review_surface_is_deterministic() {
    let a = lock_text(&fixture());
    let b = lock_text(&fixture());
    assert_eq!(a, b);
    // PROOF.rs items in another order: the same lock
    let reordered = edit(&fixture(), "r/PROOF.rs", "#[lemma]\nfn helper_below_cap(x: Nat) {\n    requires(x < 1000);\n    ensures(helper(x) == succ_capped(x));\n}\n\n#[proof]\nfn inc_is_succ(x: u32) {}\n", "#[proof]\nfn inc_is_succ(x: u32) {}\n\n#[lemma]\nfn helper_below_cap(x: Nat) {\n    requires(x < 1000);\n    ensures(helper(x) == succ_capped(x));\n}\n");
    assert_eq!(lock_text(&reordered), a);
}
