//! What `SPEC.lock` holds of a lifted crate (DESIGN.md §15.6) and which of
//! its functions §15.5 determines, on the host file `src/a.rs` lifted in
//! place (`mir_fixtures/lk_prim`: two newtypes, `From<Pos> for u64`,
//! `From<Loc> for u64`, `PartialEq<Pos> for u64` and a free function). Each
//! feature has a positive test and a negative twin.
//!
//! * a proof file's `ensures` never enters the lock: the contract is the
//!   laws file's `ensures` alone (`f::contract`), the proof file's summary
//!   is still proven and a fact at call sites, and nothing of the proof
//!   file (`crate::proof::*`) is on the review surface — a locked statement
//!   that reaches it is a surface error;
//! * the `pub` free functions of an in-place module — the impls on
//!   primitives among them — are host-callable: without a contract their
//!   §15.5 section is not fully specified, and with one they are locked;
//! * two `From` impls on `u64` get separate contracts (an attachment names
//!   an impl on a primitive by its lifted name); a bare method name that
//!   reaches both is refused, naming them, while an unambiguous one still
//!   works;
//! * the lock's source text of an attached statement is the text the laws
//!   file wrote: a line added elsewhere in the laws file changes no hash,
//!   while an edit of the statement changes its item's;
//! * a precondition or an invariant a proof file attaches to a boundary
//!   item is refused (the lock would hold it), while the same from the laws
//!   file is not.
//!
//! On `mir_fixtures/lk_paths` (`src/a.rs` and `src/b.rs`, both lifted in
//! place: a `pub(crate)` and a private free function, a sealed trait's
//! method on `u32`, a struct, and a function `third` in both files):
//!
//! * every non-private free function of an in-place module — the
//!   `pub(crate)` one and the sealed trait's method on a primitive among
//!   them — is host-callable, so on the boundary; a private one is not;
//! * attachments are resolved by their full path: `crate::a::third` and
//!   `crate::b::third` get separate contracts, and a path whose module does
//!   not hold the item is refused, naming where it is.
//!
//! On `mir_fixtures/lk_host` (`src/a.rs` with the host child module
//! `child`, and `src/b.rs` with only a test module and the host method
//! `Tick::left_out`, both lifted in place):
//!
//! * a `pub(crate)` method and the `pub` methods of a type the root does
//!   not export are host-callable; a private method of a module without
//!   host children is not;
//! * a module with a host child module (`mod child;`, left out by the
//!   lift) has every private function and method host-callable; one whose
//!   only child is `#[cfg(test)]` does not, except a private method its own
//!   left-out code calls (`Tick::left_out` calls `sixth`), which is;
//! * a proof file's precondition on any locked item (a function a law
//!   mentions, off the boundary) is refused, the same from the laws file is
//!   the locked contract; a proof file's plain termination measure stays
//!   out of the lock, the laws file's is part of the contract's source.
//!
//! On `mir_fixtures/lk_rec` (`src/a.rs`, whose left-out `left_out` calls
//! the private non-tail recursive `depth`): `depth` is host-callable, its
//! depth bound a host obligation the laws file states (the lock holds it,
//! the record lists it); the same bound from the proof file is refused.
//!
//! And on `lk_prim`: a lifted function's source text is its lifted
//! signature, while a DSL function keeps its source as written; a laws
//! file's example's source text is its expression's tokens (an edit changes
//! its hash, a move or a new layout does not); a lifted crate's lock pins
//! the lift prelude (the `lift` header line), and a lock without it, or with
//! another prelude, does not match.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::{Diagnostics, Severity};
use sandblaster_front::driver::{self, Checked};
use sandblaster_front::elab::DefStatus;
use sandblaster_front::loader::MemFs;
use sandblaster_front::surface::{self, SurfaceOptions};
use sandblaster_front::target::TargetInfo;

const A_SRC: &str = include_str!("mir_fixtures/lk_prim/src/a.rs");
const A_MIR: &str = include_str!("mir_fixtures/lk_prim/a.sbmir");

const R: &str = "c/sandblaster/m/mod.rs";
const A: &str = "c/src/a.rs";
const L: &str = "c/sandblaster/m/LAWS.rs";
const P: &str = "c/sandblaster/m/PROOF.rs";
const M: &str = "c/sandblaster/m/a.sbmir";

/// The DSL root: `src/a.rs` lifted in place in a private module (only the
/// two types are exported), with `LAWS.rs` and `PROOF.rs`.
const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::{Loc, Pos};\n";

const HEAD: &str = "use sandblaster::prelude::*;\nuse crate::a::{Loc, Pos};\n\n";

/// The contracts of every host-callable function but `half` and the two
/// `From` impls.
const BASE: &str = r#"
#[lift_attach(crate::a::Pos::new)]
fn pos_new() {
    ensures(|ret: Pos| ret == Pos(x));
}

#[lift_attach(crate::a::Loc::new)]
fn loc_new() {
    ensures(|ret: Loc| ret == Loc(x));
}

#[lift_attach(crate::a::u64__eq__Pos)]
fn u64_eq_pos() {
    ensures(|ret: bool| ret == (self_ == other.0));
}
"#;

const FROM_POS: &str = "\n#[lift_attach(crate::a::u64__from__Pos)]\nfn u64_from_pos() {\n    ensures(|ret: u64| ret == pos.0);\n}\n";
const FROM_LOC: &str = "\n#[lift_attach(crate::a::u64__from__Loc)]\nfn u64_from_loc() {\n    ensures(|ret: u64| ret == loc.0);\n}\n";

/// `half`'s value, in the laws file's vocabulary.
const HLF_LAWS: &str = "\n/// Half of `n`, rounded down.\n#[spec]\n#[example(hlf(6) == 3 && hlf(7) == 3)]\npub fn hlf(n: Nat) -> Nat {\n    n / 2\n}\n";
/// The same function as a proof file's helper.
const HLF_PROOF: &str = "\n/// Half of `n`, rounded down (a proof helper).\n#[spec]\n#[example(hlf(6) == 3 && hlf(7) == 3)]\npub fn hlf(n: Nat) -> Nat {\n    n / 2\n}\n";

fn half_contract(module: &str) -> String {
    format!("\n#[lift_attach(crate::a::half)]\nfn half_value() {{\n    ensures(|ret: u64| (ret as Nat) == crate::{module}::hlf(x as Nat));\n}}\n")
}

fn check(laws: &str, proof: &str) -> Checked {
    let laws = format!("{HEAD}{laws}");
    let proof = format!("{HEAD}{proof}");
    let fs = MemFs::from_files([(R, ROOT), (A, A_SRC), (L, laws.as_str()), (P, proof.as_str()), (M, A_MIR)]);
    driver::check(Path::new(R), &fs, &TargetInfo::aarch64_apple_darwin())
}

const PA_SRC: &str = include_str!("mir_fixtures/lk_paths/src/a.rs");
const PB_SRC: &str = include_str!("mir_fixtures/lk_paths/src/b.rs");
const PAB_MIR: &str = include_str!("mir_fixtures/lk_paths/ab.sbmir");

/// The DSL root of `lk_paths`: `src/a.rs` and `src/b.rs` lifted in place
/// (one MIR extraction), with `LAWS.rs` and `PROOF.rs`.
const PATHS_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"ab.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[lift(in_place, mir = \"ab.sbmir\")]\n#[path = \"../../src/b.rs\"]\nmod b;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::Pos;\n";

/// The front end on `lk_paths`.
fn check_paths(laws: &str, proof: &str) -> Checked {
    let laws = format!("use sandblaster::prelude::*;\n\n{laws}");
    let proof = format!("use sandblaster::prelude::*;\n\n{proof}");
    let fs = MemFs::from_files([(R, PATHS_ROOT), (A, PA_SRC), ("c/src/b.rs", PB_SRC), (L, laws.as_str()), (P, proof.as_str()), ("c/sandblaster/m/ab.sbmir", PAB_MIR)]);
    driver::check(Path::new(R), &fs, &TargetInfo::aarch64_apple_darwin())
}

/// An attachment of `body` to `target`.
fn attach(name: &str, target: &str, body: &str) -> String {
    format!("\n#[lift_attach({target})]\nfn {name}() {{\n    {body}\n}}\n")
}

/// What a run of the proofs, the surface and the §15.5 gate says.
struct Run {
    rendered: String,
    verified: bool,
    checked_defs: Vec<String>,
    /// The review surface: `(key, statement lines)`.
    surface: Vec<(String, Vec<String>)>,
    surface_errors: Vec<String>,
    /// The §15.5 gate's errors (sections not fully specified).
    gate: Vec<String>,
    /// Every section's members.
    sections: Vec<Vec<String>>,
    /// Every surface item's source text (`src` is its hash).
    sources: Vec<(String, String)>,
}

impl Run {
    fn explain(&self) -> String {
        format!("surface: {:#?}\nsurface errors: {:#?}\ngate: {:#?}\nsections: {:?}\n{}", self.surface.iter().map(|(k, _)| k).collect::<Vec<_>>(), self.surface_errors, self.gate, self.sections, self.rendered)
    }

    #[track_caller]
    fn statement(&self, key: &str) -> String {
        self.surface.iter().find(|(k, _)| k == key).map(|(_, s)| s.join("\n")).unwrap_or_else(|| panic!("`{key}` is not on the review surface:\n{}", self.explain()))
    }

    fn keys(&self) -> Vec<&str> {
        self.surface.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[track_caller]
    fn source(&self, key: &str) -> &str {
        self.sources.iter().find(|(k, _)| k == key).map(|(_, s)| s.as_str()).unwrap_or_else(|| panic!("`{key}` is not on the review surface:\n{}", self.explain()))
    }
}

#[track_caller]
fn run(laws: &str, proof: &str) -> Run {
    run_checked(check(laws, proof))
}

/// Every surface item's key with its hash, `src` and `canon` hashes.
type Hashes = Vec<(String, [u8; 32], [u8; 32], [u8; 32])>;

#[track_caller]
fn run_checked(c: Checked) -> Run {
    run_full(c).0
}

#[track_caller]
fn run_full(c: Checked) -> (Run, Hashes) {
    assert!(c.ok(), "front end rejected the crate:\n{}", c.render());
    let k = c.krate.clone().unwrap();
    let (kr, sm) = (&k, &c.sm);
    sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let s = surface::compute(&out, kr, sm, &SurfaceOptions::default());
        let mut g = Diagnostics::new();
        sandblaster_front::elab::complete::spec15_gate_s3(&out, kr, &mut g);
        let hashes: Hashes = s.items.iter().map(|i| (i.key.clone(), i.hash, i.src, i.canon)).collect();
        let r = Run {
            rendered: out.diags.render(sm),
            verified: out.verified(),
            checked_defs: out.defs.iter().filter(|d| d.status == DefStatus::Checked).map(|d| d.name.clone()).collect(),
            surface: s.items.iter().map(|i| (i.key.clone(), i.statement.clone())).collect(),
            surface_errors: s.errors.iter().map(|e| e.msg.clone()).collect(),
            gate: g.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.msg.clone()).collect(),
            sections: out.sections.iter().map(|x| x.members.iter().map(|m| kr.item(*m).path.to_string()).collect()).collect(),
            sources: s.items.iter().map(|i| (i.key.clone(), i.source.clone())).collect(),
        };
        (r, hashes)
    })
}

#[track_caller]
fn verified(laws: &str, proof: &str) -> Run {
    let r = run(laws, proof);
    assert!(r.verified, "the crate does not verify:\n{}", r.explain());
    r
}

// ---------------------------------------------------------------------
// a laws-file contract that is an equation establishes its function
// ---------------------------------------------------------------------

/// A spec function that builds a position with `Pos::new` (the laws file
/// cannot name `Pos`'s field) and its known answer.
const THREE: &str = "\n/// The position 3.\n#[spec]\n#[example(three() == Pos::new(3u64))]\npub fn three() -> Pos {\n    Pos::new(3u64)\n}\n";

#[test]
fn an_equation_contract_establishes_a_lifted_function_for_spec_closure() {
    // `Pos::new`'s contract `ret == Pos(x)` determines it at once (DESIGN.md
    // §15.1): a specification may build positions with it
    let r = verified(&format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}{THREE}", half_contract("laws")), "");
    assert!(!r.rendered.contains("depends on the exec function"), "{}", r.rendered);
    assert!(r.surface_errors.is_empty(), "{}", r.explain());
    // the spec function's hash pins `Pos::new`'s contract
    assert!(r.keys().contains(&"boundary-fn:crate::a::Pos::new"), "{}", r.explain());
}

#[test]
fn a_contract_that_is_not_an_equation_does_not_establish() {
    // the twin: `ret.0 == x` determines `Pos::new` as well, but is not an
    // equation of its result: a specification built on it is refused
    let base = BASE.replace("ensures(|ret: Pos| ret == Pos(x));", "ensures(|ret: Pos| ret.0 == x);");
    assert_ne!(base, BASE);
    let r = run(&format!("{base}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}{THREE}", half_contract("laws")), "");
    assert!(r.rendered.contains("depends on the exec function `crate::a::Pos::new`"), "{}", r.rendered);
}

// ---------------------------------------------------------------------
// a proof file's `ensures` never enters the lock
// ---------------------------------------------------------------------

#[test]
fn a_proof_file_ensures_never_enters_the_lock() {
    // `half`'s contract is a proof file's summary over a proof helper
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}");
    let proof = format!("{HLF_PROOF}{}", half_contract("proof"));
    let r = verified(&laws, &proof);
    // still proven (a fact at call sites), with no contract lemma of its own
    assert!(r.checked_defs.iter().any(|d| d == "crate::a::half::ensures"), "{:?}", r.checked_defs);
    assert!(!r.checked_defs.iter().any(|d| d == "crate::a::half::contract"), "{:?}", r.checked_defs);
    // locked without it: nothing of the proof file is on the review surface
    let st = r.statement("boundary-fn:crate::a::half");
    assert!(!st.contains("ensures") && !st.contains("hlf"), "the proof file's summary is locked:\n{st}");
    assert!(!r.keys().iter().any(|k| k.contains("crate::proof")), "{}", r.explain());
    assert!(r.surface_errors.is_empty(), "{}", r.explain());
}

#[test]
fn a_laws_file_ensures_is_the_locked_contract() {
    // the twin: the same contract in the laws file is locked, with its
    // vocabulary
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, "");
    let st = r.statement("boundary-fn:crate::a::half");
    assert!(st.contains("ensures") && st.contains("crate::laws::hlf"), "{st}");
    assert!(r.keys().contains(&"spec-fn:crate::laws::hlf"), "{}", r.explain());
    assert!(r.gate.is_empty(), "{}", r.explain());
}

#[test]
fn a_contract_with_a_proof_summary_locks_the_laws_part_only() {
    // both files attach an `ensures` to `half`: the laws file's is the
    // contract (`half::contract`, proven from `half::ensures`), the
    // proof file's is a summary over a proof helper
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let proof = "\n/// Whether `a` is at most `b` (a proof helper).\n#[spec]\n#[example(below(3, 4) && !below(4, 3))]\npub fn below(a: Nat, b: Nat) -> bool {\n    a <= b\n}\n\n#[lift_attach(crate::a::half)]\nfn half_below() {\n    ensures(|ret: u64| crate::proof::below(ret as Nat, x as Nat));\n}\n";
    let r = verified(&laws, proof);
    for d in ["crate::a::half::ensures", "crate::a::half::contract"] {
        assert!(r.checked_defs.iter().any(|x| x == d), "`{d}` is checked: {:?}", r.checked_defs);
    }
    let st = r.statement("boundary-fn:crate::a::half");
    assert!(st.contains("crate::laws::hlf") && !st.contains("below"), "the contract is the laws file's part:\n{st}");
    assert!(!r.keys().iter().any(|k| k.contains("crate::proof")), "{}", r.explain());
    // §15.5 determines `half` from the laws file's part alone
    assert!(r.gate.is_empty(), "{}", r.explain());
}

#[test]
fn a_locked_statement_that_reaches_the_proof_file_is_a_surface_error() {
    // a law over a proof helper: the review surface would hold it
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{}\n#[law]\nfn half_is_hlf(x: u64) {{\n    ensures((crate::a::half(x) as Nat) == crate::proof::hlf(x as Nat));\n}}\n", half_contract("proof"));
    let proof = format!("{HLF_PROOF}\n#[proof]\nfn half_is_hlf(x: u64) {{}}\n");
    let r = verified(&laws, &proof);
    assert!(r.surface_errors.iter().any(|e| e.contains("`crate::proof::hlf` is a proof internal")), "{}", r.explain());
    // the twin: the same law over the laws file's vocabulary is no error
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}\n#[law]\nfn half_is_hlf(x: u64) {{\n    ensures((crate::a::half(x) as Nat) == crate::laws::hlf(x as Nat));\n}}\n", half_contract("laws"));
    let r = verified(&laws, "\n#[proof]\nfn half_is_hlf(x: u64) {}\n");
    assert!(r.surface_errors.is_empty(), "{}", r.explain());
}

// ---------------------------------------------------------------------
// the boundary covers every host-callable function
// ---------------------------------------------------------------------

#[test]
fn a_primitive_impl_of_an_in_place_module_without_a_contract_fails_determinacy() {
    // `u64::from(Loc)` has no contract: host code calls it (the module is
    // the host's own file), so its section is not fully specified
    let laws = format!("{BASE}{FROM_POS}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, "");
    assert!(r.sections.iter().any(|s| s.iter().any(|m| m == "crate::a::u64__from__Loc")), "{}", r.explain());
    assert!(r.gate.iter().any(|g| g.contains("u64__from__Loc")), "the gate names it:\n{}", r.explain());
    assert!(!r.gate.iter().any(|g| g.contains("u64__from__Pos")), "{}", r.explain());
    assert!(r.keys().contains(&"boundary-fn:crate::a::u64__from__Loc"), "{}", r.explain());
}

#[test]
fn a_primitive_impl_with_a_contract_is_determined_and_locked() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, "");
    assert!(r.gate.is_empty(), "{}", r.explain());
    for f in ["u64__from__Pos", "u64__from__Loc", "u64__eq__Pos", "half"] {
        let st = r.statement(&format!("boundary-fn:crate::a::{f}"));
        assert!(st.contains("ensures"), "`{f}`'s contract is locked:\n{st}");
        assert!(r.keys().contains(&format!("section:crate::a::{f}").as_str()), "{}", r.explain());
    }
}

// ---------------------------------------------------------------------
// attachments to impls on primitives
// ---------------------------------------------------------------------

#[test]
fn two_from_impls_on_u64_get_separate_contracts() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, "");
    let (p, l) = (r.statement("boundary-fn:crate::a::u64__from__Pos"), r.statement("boundary-fn:crate::a::u64__from__Loc"));
    assert!(p.contains("(pos).0") && !p.contains("loc"), "{p}");
    assert!(l.contains("(loc).0") && !l.contains("pos"), "{l}");
    // the twin: a false contract on one fails that one alone
    let wrong = FROM_LOC.replace("ret == loc.0", "ret == 0u64");
    let r = run(&format!("{BASE}{FROM_POS}{wrong}{HLF_LAWS}{}", half_contract("laws")), "");
    assert!(!r.verified, "{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::a::u64__from__Pos::ensures"), "{:?}", r.checked_defs);
    assert!(!r.checked_defs.iter().any(|d| d == "crate::a::u64__from__Loc::ensures"), "{:?}", r.checked_defs);
}

#[test]
fn an_ambiguous_attachment_to_impls_on_primitives_is_refused() {
    // `from` is the method of both `From` impls on `u64`
    let bare = "\n#[lift_attach(crate::a::from)]\nfn u64_from() {\n    ensures(|ret: u64| true);\n}\n";
    let c = check(&format!("{BASE}{bare}"), "");
    let errs: Vec<String> = c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.msg.clone()).collect();
    assert!(
        errs.iter().any(|m| m.contains("the attachment to `crate::a::from` is ambiguous") && m.contains("crate::a::u64__from__Pos") && m.contains("crate::a::u64__from__Loc")),
        "the refusal names both candidates:\n{}",
        c.render()
    );
    // the twin: a bare name only one impl answers to still attaches
    let laws = BASE.replace("crate::a::u64__eq__Pos", "crate::a::eq");
    let r = verified(&format!("{laws}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws")), "");
    assert!(r.statement("boundary-fn:crate::a::u64__eq__Pos").contains("ensures"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// the lock's source text of an attached statement
// ---------------------------------------------------------------------

#[test]
fn a_line_added_to_the_laws_file_changes_no_lock_hash() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let (_, before) = run_full(check(&laws, ""));
    // a comment line before every attachment: each statement moves one line down
    let (r, after) = run_full(check(&format!("// a comment line\n{laws}"), ""));
    assert!(r.verified && r.surface_errors.is_empty(), "{}", r.explain());
    assert_eq!(before.len(), after.len());
    let changed: Vec<&String> = before.iter().zip(&after).filter(|(b, a)| b != a).map(|(b, _)| &b.0).collect();
    assert!(changed.is_empty(), "a comment line changed the hashes of {changed:?}");
    // the source text is the laws file's statement
    let c = check(&laws, "");
    let k = c.krate.as_ref().unwrap();
    let f = k.items.iter().find(|i| i.path.to_string() == "crate::a::u64__from__Pos").and_then(|i| k.fn_def(i.id)).unwrap();
    assert!(f.spec.attached.iter().any(|a| a.kind == "ensures" && a.in_laws && a.module == "crate::laws" && a.text == "|ret: u64| ret == pos.0"), "{:?}", f.spec.attached);
}

#[test]
fn an_edited_statement_changes_its_source_text() {
    // the twin: the same meaning written differently changes `src` (and the
    // hash) of that item, and its kernel statement (`canon`) not at all
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let (_, before) = run_full(check(&laws, ""));
    let edited = laws.replace("ensures(|ret: u64| ret == pos.0);", "ensures(|ret: u64| ret == (pos.0));");
    assert_ne!(edited, laws);
    let (r, after) = run_full(check(&edited, ""));
    assert!(r.verified, "{}", r.explain());
    let key = "boundary-fn:crate::a::u64__from__Pos";
    let (b, a) = (before.iter().find(|x| x.0 == key).unwrap(), after.iter().find(|x| x.0 == key).unwrap());
    assert_ne!(b.2, a.2, "the edited statement's src did not change");
    assert_ne!(b.1, a.1, "the edited statement's hash did not change");
    assert_eq!(b.3, a.3, "the kernel statement changed");
    // nothing else of the boundary changed but what depends on it
    assert_eq!(before.iter().find(|x| x.0 == "boundary-fn:crate::a::half"), after.iter().find(|x| x.0 == "boundary-fn:crate::a::half"));
}

// ---------------------------------------------------------------------
// a proof file's statements on a boundary item are refused
// ---------------------------------------------------------------------

const HALF_PRE: &str = "\n#[lift_attach(crate::a::half)]\nfn half_pre() {\n    requires(x < 100u64);\n}\n";
const POS_INV: &str = "\n#[lift_attach(crate::a::Pos)]\nfn pos_inv() {\n    invariant((self.0 as Int) >= 0);\n}\n";

#[test]
fn a_proof_file_precondition_on_a_boundary_function_is_refused() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, HALF_PRE);
    assert!(
        r.surface_errors.iter().any(|e| e.contains("`crate::a::half`") && e.contains("precondition") && e.contains("`crate::proof`") && e.contains("requires(x < 100u64)")),
        "the refusal names the item and the proof file:\n{}",
        r.explain()
    );
    // the twin: the same precondition in the laws file is the contract's
    let r = verified(&format!("{laws}{HALF_PRE}"), "");
    assert!(r.surface_errors.is_empty(), "{}", r.explain());
    assert!(r.statement("boundary-fn:crate::a::half").contains("requires"), "{}", r.explain());
}

#[test]
fn a_proof_file_invariant_on_a_boundary_type_is_refused() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, POS_INV);
    assert!(
        r.surface_errors.iter().any(|e| e.contains("`crate::a::Pos`") && e.contains("invariant") && e.contains("`crate::proof`")),
        "the refusal names the type and the proof file:\n{}",
        r.explain()
    );
    // the twin: the same invariant in the laws file is locked with its type
    let r = verified(&format!("{laws}{POS_INV}"), "");
    assert!(r.surface_errors.is_empty(), "{}", r.explain());
    assert!(r.keys().contains(&"invariant:crate::a::Pos"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// every host-callable free function is on the boundary (`lk_paths`)
// ---------------------------------------------------------------------

/// The contracts of `lk_paths`' boundary functions but `quarter` and the
/// sealed trait's method.
fn paths_base() -> String {
    [
        attach("pos_new", "crate::a::Pos::new", "ensures(|ret: crate::a::Pos| ret == crate::a::Pos(x));"),
        attach("a_third", "crate::a::third", "ensures(|ret: u64| (ret as Nat) == (x as Nat) / 3);"),
        attach("b_third", "crate::b::third", "ensures(|ret: u64| ret == x / 5u64);"),
        attach("sixteenth", "crate::a::sixteenth", "ensures(|ret: u64| ret == x / 8u64 / 2u64);"),
        attach("half_of", "crate::a::half_of", "ensures(|ret: u32| (ret as Nat) == (x as Nat) / 2);"),
    ]
    .concat()
}

fn paths_rest() -> String {
    [
        attach("quarter", "crate::a::quarter", "ensures(|ret: u64| (ret as Nat) == (x as Nat) / 4);"),
        attach("halve", "crate::a::Halve__u32__halve", "ensures(|ret: u32| (ret as Nat) == (self_ as Nat) / 2);"),
    ]
    .concat()
}

#[test]
fn every_non_private_free_function_of_an_in_place_module_is_on_the_boundary() {
    let c = check_paths(&paths_base(), "");
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let paths = |ids: Vec<sandblaster_front::hir::ItemId>| -> Vec<String> { ids.into_iter().map(|i| k.item(i).path.to_string()).collect() };
    let host = paths(sandblaster_front::validate::in_place_host_fns(k));
    for f in ["crate::a::quarter", "crate::a::Halve__u32__halve", "crate::a::third", "crate::b::third"] {
        assert!(host.iter().any(|h| h == f), "`{f}` is host-callable: {host:?}");
    }
    // the twin: the private function is not (nor are the lift's loop helpers)
    assert!(!host.iter().any(|h| h == "crate::a::eighth"), "{host:?}");
    let boundary = paths(sandblaster_front::validate::boundary_functions(k));
    assert!(boundary.iter().any(|h| h == "crate::a::quarter") && !boundary.iter().any(|h| h == "crate::a::eighth"), "{boundary:?}");
    // without their contracts, §15.5 names the `pub(crate)` function and the
    // sealed trait's method, and the lock holds both
    let r = run_checked(c);
    assert!(r.verified, "{}", r.explain());
    for f in ["quarter", "Halve__u32__halve"] {
        assert!(r.gate.iter().any(|g| g.contains(f)), "the gate names `{f}`:\n{}", r.explain());
        assert!(r.keys().contains(&format!("boundary-fn:crate::a::{f}").as_str()), "{}", r.explain());
    }
    assert!(!r.gate.iter().any(|g| g.contains("eighth")) && !r.keys().iter().any(|k| k.contains("eighth")), "{}", r.explain());
    // with them, every section is fully specified
    let r = run_checked(check_paths(&format!("{}{}", paths_base(), paths_rest()), ""));
    assert!(r.verified && r.gate.is_empty(), "{}", r.explain());
}

// ---------------------------------------------------------------------
// attachments are resolved by their full path (`lk_paths`)
// ---------------------------------------------------------------------

#[test]
fn same_named_functions_of_two_modules_get_separate_contracts() {
    // `a::third` is `x / 3`, `b::third` is `x / 5`: each attachment reaches
    // its own module's function only
    let r = run_checked(check_paths(&format!("{}{}", paths_base(), paths_rest()), ""));
    assert!(r.verified, "{}", r.explain());
    let (a, b) = (r.statement("boundary-fn:crate::a::third"), r.statement("boundary-fn:crate::b::third"));
    assert!(a.contains("3") && !a.contains("5"), "{a}");
    assert!(b.contains("5") && !b.contains("3"), "{b}");
    // the twin: an attachment to `crate::a::third` alone leaves `b::third`
    // without a contract (it is not `a::third`'s)
    let only_a = paths_base().replace(&attach("b_third", "crate::b::third", "ensures(|ret: u64| ret == x / 5u64);"), "");
    let r = run_checked(check_paths(&format!("{only_a}{}", paths_rest()), ""));
    assert!(r.verified, "{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::a::third::ensures"), "{:?}", r.checked_defs);
    assert!(!r.checked_defs.iter().any(|d| d == "crate::b::third::ensures"), "{:?}", r.checked_defs);
    assert!(r.gate.iter().any(|g| g.contains("crate::b::third")) && !r.gate.iter().any(|g| g.contains("crate::a::third")), "{}", r.explain());
}

#[test]
fn an_attachment_whose_module_does_not_hold_the_item_is_refused() {
    let errs = |c: &Checked| -> Vec<String> { c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.msg.clone()).collect() };
    // a free function: `quarter` is `a`'s
    let wrong = attach("quarter", "crate::b::quarter", "ensures(|ret: u64| (ret as Nat) == (x as Nat) / 4);");
    let c = check_paths(&format!("{}{wrong}", paths_base()), "");
    assert!(errs(&c).iter().any(|m| m.contains("`crate::b::quarter`") && m.contains("the module `crate::b` holds no lifted `quarter`") && m.contains("`crate::a::quarter`")), "{}", c.render());
    // a method: `Pos` is declared in `a`
    let base = paths_base().replace("crate::a::Pos::new", "crate::b::Pos::new");
    let c = check_paths(&base, "");
    assert!(errs(&c).iter().any(|m| m.contains("`crate::b::Pos::new`") && m.contains("the module `crate::b` holds no lifted `Pos`") && m.contains("`crate::a::Pos`")), "{}", c.render());
    // the twin: the full paths attach
    let c = check_paths(&format!("{}{}", paths_base(), paths_rest()), "");
    assert!(c.ok(), "{}", c.render());
}


// ---------------------------------------------------------------------
// every host-callable function of an in-place module (`lk_host`)
// ---------------------------------------------------------------------

const HA_SRC: &str = include_str!("mir_fixtures/lk_host/src/a.rs");
const HB_SRC: &str = include_str!("mir_fixtures/lk_host/src/b.rs");
const HAB_MIR: &str = include_str!("mir_fixtures/lk_host/ab.sbmir");

/// The DSL root of `lk_host`: `src/a.rs` (with the host child module
/// `child`) and `src/b.rs` (with only a test module; `Tick::left_out` stays
/// host code) lifted in place, exporting `Pos` and `Tick` (not `Hidden`).
const HOST_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"ab.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[lift(in_place, mir = \"ab.sbmir\", unverified_fns = \"Tick::left_out\")]\n#[path = \"../../src/b.rs\"]\nmod b;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::Pos;\npub use b::Tick;\n";

/// `down`'s termination measure (a proof file's: proof text).
const DOWN_MEASURE: &str = "\n#[lift_attach(crate::a::down)]\nfn down_measure() {\n    decreases(h);\n}\n";

/// The front end on `lk_host`.
fn check_host(laws: &str, proof: &str) -> Checked {
    let laws = format!("use sandblaster::prelude::*;\n\n{laws}");
    let proof = format!("use sandblaster::prelude::*;\n\n{proof}");
    let fs = MemFs::from_files([(R, HOST_ROOT), (A, HA_SRC), ("c/src/b.rs", HB_SRC), (L, laws.as_str()), (P, proof.as_str()), ("c/sandblaster/m/ab.sbmir", HAB_MIR)]);
    driver::check(Path::new(R), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn host_fns(c: &Checked) -> Vec<String> {
    let k = c.krate.as_ref().unwrap();
    sandblaster_front::validate::in_place_host_fns(k).into_iter().map(|i| k.item(i).path.to_string()).collect()
}

#[test]
fn a_pub_crate_method_and_the_methods_of_an_unexported_type_are_host_callable() {
    let c = check_host("", DOWN_MEASURE);
    assert!(c.ok(), "{}", c.render());
    let host = host_fns(&c);
    // `pub(crate) fn halve` of an exported type, `pub fn get` of `Hidden`,
    // which the root does not export (host code still calls it)
    for f in ["crate::a::Pos::halve", "crate::a::Hidden::get", "crate::a::Pos::new", "crate::b::Tick::new", "crate::a::down"] {
        assert!(host.iter().any(|h| h == f), "`{f}` is host-callable: {host:?}");
    }
    // the twin: a private method of a module whose only child is a test
    // module is not (the lift makes it `pub(crate)` in the model; host
    // code still sees it private)
    assert!(!host.iter().any(|h| h == "crate::b::Tick::fifth"), "{host:?}");
    // without contracts, §15.5 names both methods and the lock holds them
    let r = run_checked(c);
    assert!(r.verified, "{}", r.explain());
    for (f, key) in [("halve", "boundary-fn:crate::a::Pos::halve"), ("get", "boundary-fn:crate::a::Hidden::get")] {
        assert!(r.gate.iter().any(|g| g.contains(f)), "the gate names `{f}`:\n{}", r.explain());
        assert!(r.keys().contains(&key), "{}", r.explain());
    }
    assert!(!r.keys().iter().any(|k| k.contains("fifth")), "{}", r.explain());
}

#[test]
fn a_private_function_a_host_child_module_can_call_is_host_callable() {
    let c = check_host("", DOWN_MEASURE);
    assert!(c.ok(), "{}", c.render());
    let host = host_fns(&c);
    // `a` declares the host module `child` (`mod child;`, left out by the
    // lift), which calls `quarter` and `Pos::third`: Rust lets it call
    // every private item of `a`
    for f in ["crate::a::quarter", "crate::a::Pos::third"] {
        assert!(host.iter().any(|h| h == f), "`{f}` is host-callable: {host:?}");
    }
    let k = c.krate.as_ref().unwrap();
    let a = k.modules.iter().find(|m| m.path.to_string() == "crate::a").unwrap();
    assert_eq!(a.host_access.host_children, vec!["child".to_string()]);
    // the twin: `b`'s only child is `#[cfg(test)] mod tests`, so its private
    // free function and methods stay internal ...
    for f in ["crate::b::seventh", "crate::b::Tick::fifth"] {
        assert!(!host.iter().any(|h| h == f), "`{f}` is not host-callable: {host:?}");
    }
    let b = k.modules.iter().find(|m| m.path.to_string() == "crate::b").unwrap();
    assert!(b.host_access.host_children.is_empty(), "{:?}", b.host_access);
    // ... except what its own left-out code calls: `Tick::left_out`
    // (`unverified_fns`, host code) calls `sixth`, which is host-callable
    // (DESIGN.md §15.5), not `fifth`
    assert!(host.iter().any(|h| h == "crate::b::Tick::sixth"), "{host:?}");
    let left_out: Vec<String> = sandblaster_front::validate::left_out_callers(k).into_iter().map(|i| k.item(i).path.to_string()).collect();
    assert_eq!(left_out, vec!["crate::b::Tick::sixth".to_string()]);
    assert!(!c.diags.list.iter().any(|d| d.severity == Severity::Warning && d.msg.contains("sixth")), "{}", c.render());
    // and the lock holds the host-callable private functions
    let r = run_checked(c);
    assert!(r.verified, "{}", r.explain());
    for key in ["boundary-fn:crate::a::quarter", "boundary-fn:crate::a::Pos::third", "boundary-fn:crate::b::Tick::sixth"] {
        assert!(r.keys().contains(&key), "{}", r.explain());
    }
    assert!(r.gate.iter().any(|g| g.contains("sixth")), "§15.5 names `sixth` (no contract):\n{}", r.explain());
    assert!(!r.keys().iter().any(|k| k.contains("seventh") || k.contains("fifth")), "{}", r.explain());
}

// ---------------------------------------------------------------------
// a private function left-out code calls, with a depth bound (`lk_rec`)
// ---------------------------------------------------------------------

const RA_SRC: &str = include_str!("mir_fixtures/lk_rec/src/a.rs");
const RA_MIR: &str = include_str!("mir_fixtures/lk_rec/a.sbmir");

/// The DSL root of `lk_rec`: `src/a.rs` lifted in place, its method
/// `Pos::left_out` (which calls the private `depth`) declared unverified
/// host code.
const REC_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\", unverified_fns = \"Pos::left_out\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::Pos;\n";

/// `depth`'s precondition and depth bound (non-tail recursion, DESIGN.md
/// §3.7): a host obligation.
const DEPTH_BOUND: &str = "\n/// `depth` recurses `h` deep: host code keeps `h` at most 64.\n#[lift_attach(crate::a::depth)]\nfn depth_bound() {\n    requires(h <= 64u32);\n    decreases(h, max = 64);\n}\n";

/// The contracts of the host-callable functions (`Pos::new`, `depth`).
const REC_CONTRACTS: &str = "\n#[lift_attach(crate::a::Pos::new)]\nfn pos_new() {\n    ensures(|ret: crate::a::Pos| ret == crate::a::Pos(x));\n}\n\n#[lift_attach(crate::a::depth)]\nfn depth_value() {\n    ensures(|ret: u32| ret == (if h == 0u32 { 0u32 } else { 1u32 }));\n}\n";

/// The front end on `lk_rec`.
fn check_rec(laws: &str, proof: &str) -> Checked {
    let laws = format!("use sandblaster::prelude::*;\n\n{laws}");
    let proof = format!("use sandblaster::prelude::*;\n\n{proof}");
    let fs = MemFs::from_files([(R, REC_ROOT), (A, RA_SRC), (L, laws.as_str()), (P, proof.as_str()), (M, RA_MIR)]);
    driver::check(Path::new(R), &fs, &TargetInfo::aarch64_apple_darwin())
}

#[test]
fn a_depth_bound_of_a_host_callable_function_is_a_host_obligation_of_the_laws_file() {
    let c = check_rec(&format!("{DEPTH_BOUND}{REC_CONTRACTS}"), "");
    // `depth` is private, `src/a.rs` has no host child module, but the
    // left-out `Pos::left_out` calls it: host-callable, so a boundary function;
    // its depth bound is not a boundary error (a host obligation)
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let host: Vec<String> = sandblaster_front::validate::in_place_host_fns(k).into_iter().map(|i| k.item(i).path.to_string()).collect();
    assert!(host.iter().any(|h| h == "crate::a::depth"), "{host:?}");
    let obligations = &c.lift_facts.host_depth_bounds;
    assert!(obligations.iter().any(|(f, b)| f.contains("depth") && b.contains("<= 64")), "the record lists the depth bound: {obligations:?}");
    // the lock holds it with the contract (the laws file's statement), and
    // §15.5 determines `depth` by its contract
    let r = run_checked(c);
    assert!(r.verified, "{}", r.explain());
    assert!(r.surface_errors.is_empty(), "{}", r.explain());
    assert!(r.source("boundary-fn:crate::a::depth").contains("decreases(h, max = 64)"), "{}", r.source("boundary-fn:crate::a::depth"));
    assert!(!r.gate.iter().any(|g| g.contains("depth")), "{}", r.explain());
}

#[test]
fn a_depth_bound_of_a_host_callable_function_from_the_proof_file_is_refused() {
    // the twin: the same bound attached from the proof file would put a
    // proof file's statement into the lock
    let r = run_checked(check_rec(REC_CONTRACTS, DEPTH_BOUND));
    assert!(
        r.surface_errors.iter().any(|e| e.contains("`crate::a::depth`") && e.contains("recursion depth bound") && e.contains("`crate::proof`")),
        "the refusal names the item and the proof file:\n{}",
        r.explain()
    );
}

// ---------------------------------------------------------------------
// a proof file's statements on any locked item (`lk_host`)
// ---------------------------------------------------------------------

/// A law about `b`'s private `seventh` (not host-callable): its contract is
/// locked as vocabulary, not as a boundary signature.
const SEVENTH_LAW: &str = "\n/// `seventh` divides by 7.\n#[law]\nfn seventh_divides(x: u64) {\n    requires(x < 100u64);\n    ensures(crate::b::seventh(x) == x / 7u64);\n}\n";
const SEVENTH_PRE: &str = "\n#[lift_attach(crate::b::seventh)]\nfn seventh_pre() {\n    requires(x < 100u64);\n}\n";

#[test]
fn a_proof_file_precondition_on_a_locked_function_off_the_boundary_is_refused() {
    let r = run_checked(check_host(SEVENTH_LAW, &format!("{DOWN_MEASURE}{SEVENTH_PRE}")));
    assert!(r.keys().contains(&"contract:crate::b::seventh"), "{}", r.explain());
    assert!(
        r.surface_errors.iter().any(|e| e.contains("locked item `crate::b::seventh`") && e.contains("precondition") && e.contains("`crate::proof`") && e.contains("requires(x < 100u64)")),
        "the refusal names the item and the proof file:\n{}",
        r.explain()
    );
    // the twin: the same precondition in the laws file is the locked contract's
    let r = run_checked(check_host(&format!("{SEVENTH_LAW}{SEVENTH_PRE}"), DOWN_MEASURE));
    assert!(!r.surface_errors.iter().any(|e| e.contains("seventh")), "{}", r.explain());
    assert!(r.statement("contract:crate::b::seventh").contains("requires"), "{}", r.explain());
}

#[test]
fn a_proof_file_termination_measure_stays_out_of_the_lock() {
    // `down`'s plain measure (`decreases(h)`, no depth bound) is proof text:
    // writing it differently in the proof file changes no lock hash
    let (r, before) = run_full(check_host("", DOWN_MEASURE));
    assert!(r.verified, "{}", r.explain());
    assert!(!r.source("boundary-fn:crate::a::down").contains("decreases"), "{}", r.source("boundary-fn:crate::a::down"));
    let (r, after) = run_full(check_host("", &DOWN_MEASURE.replace("decreases(h);", "decreases(h as Int);")));
    assert!(r.verified, "{}", r.explain());
    let key = "boundary-fn:crate::a::down";
    assert_eq!(before.iter().find(|x| x.0 == key), after.iter().find(|x| x.0 == key), "a proof file's measure changed the lock");
    // the twin: the laws file's measure is part of the contract's source
    let (r, laws_before) = run_full(check_host(DOWN_MEASURE, ""));
    assert!(r.verified && r.source(key).contains("decreases(h)"), "{}", r.source(key));
    let (_, laws_after) = run_full(check_host(&DOWN_MEASURE.replace("decreases(h);", "decreases(h as Int);"), ""));
    assert_ne!(laws_before.iter().find(|x| x.0 == key).unwrap().2, laws_after.iter().find(|x| x.0 == key).unwrap().2, "an edit of the laws file's measure changed no src");
}

// ---------------------------------------------------------------------
// a lifted function's signature text; the lift prelude in the header
// ---------------------------------------------------------------------

#[test]
fn a_lifted_function_hashes_its_signature_text() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let r = verified(&laws, "");
    // the lifted signature (`Self` as the lift reads it), then the laws
    // file's statements: no stray host text
    let src = r.source("boundary-fn:crate::a::Pos::new");
    assert_eq!(src, "fn new (x : u64) -> Self ensures(|ret: Pos| ret == Pos(x))");
    for f in ["u64__from__Pos", "u64__from__Loc", "u64__eq__Pos", "half"] {
        let src = r.source(&format!("boundary-fn:crate::a::{f}"));
        let sig = src.split(" ensures(").next().unwrap();
        assert!(sig.starts_with(&format!("fn {f} (")) && !sig.contains('#') && !sig.contains(';') && !sig.contains('{'), "`{f}`'s source text starts with its lifted signature:\n{src}");
    }
    // the twin: a function written in the DSL keeps its source as written
    // (the laws file's spec function `hlf`)
    let src = r.source("spec-fn:crate::laws::hlf");
    assert!(src.starts_with("fn hlf(n: Nat) -> Nat { n / 2 }"), "{src}");
}

#[test]
fn a_laws_file_example_hashes_its_text() {
    // the lift re-emits the laws file's attributes without spans: an
    // example's source text is its expression's tokens, so an edit of it
    // changes its `src` and hash
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let key = "example:crate::laws::hlf#0";
    let (r, before) = run_full(check(&laws, ""));
    assert!(r.verified, "{}", r.explain());
    assert_eq!(r.source(key), "hlf (6) == 3 && hlf (7) == 3");
    let edited = laws.replace("#[example(hlf(6) == 3 && hlf(7) == 3)]", "#[example(hlf(6) == 3 && hlf(7) == (3))]");
    assert_ne!(edited, laws);
    let (r, after) = run_full(check(&edited, ""));
    assert!(r.verified, "{}", r.explain());
    assert_eq!(r.source(key), "hlf (6) == 3 && hlf (7) == (3)");
    let (b, a) = (before.iter().find(|x| x.0 == key).unwrap(), after.iter().find(|x| x.0 == key).unwrap());
    assert_ne!(b.2, a.2, "the edited example's src did not change");
    assert_ne!(b.1, a.1, "the edited example's hash did not change");
    // every example of the surface has a source text
    assert!(r.sources.iter().filter(|(k, _)| k.starts_with("example:")).all(|(_, s)| !s.is_empty()), "{:?}", r.sources);
}

#[test]
fn a_laws_file_example_moved_or_relaid_changes_no_hash() {
    // the twin: the text is the tokens, not the position or the layout — a
    // line added before it and its spacing changed leave every hash alone
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let (_, before) = run_full(check(&laws, ""));
    let moved = format!("// a comment line\n{}", laws.replace("#[example(hlf(6) == 3 && hlf(7) == 3)]", "#[example(hlf( 6 )==3\n    && hlf(7) == 3)]"));
    let (r, after) = run_full(check(&moved, ""));
    assert!(r.verified, "{}", r.explain());
    assert_eq!(r.source("example:crate::laws::hlf#0"), "hlf (6) == 3 && hlf (7) == 3");
    let changed: Vec<&String> = before.iter().zip(&after).filter(|(b, a)| b != a).map(|(b, _)| &b.0).collect();
    assert!(changed.is_empty(), "moving the example changed the hashes of {changed:?}");
}

#[test]
fn a_lifted_crate_pins_the_lift_prelude() {
    let laws = format!("{BASE}{FROM_POS}{FROM_LOC}{HLF_LAWS}{}", half_contract("laws"));
    let c = check(&laws, "");
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.clone().unwrap();
    let (kr, sm) = (&k, &c.sm);
    let (now, edited) = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let now = surface::compute(&out, kr, sm, &SurfaceOptions::default());
        let mut tc = surface::Toolchain::current().clone();
        tc.lift = [9; 32];
        let edited = surface::compute(&out, kr, sm, &SurfaceOptions { toolchain: Some(tc), ..Default::default() });
        (now, edited)
    });
    assert_eq!(now.lift, Some(surface::Toolchain::current().lift), "a lifted crate's surface pins the lift prelude");
    let text = sandblaster_front::lock::preview_accept(None, &now, &sandblaster_front::lock::Selection::All).unwrap().0.render();
    assert!(text.lines().any(|l| l == format!("lift {}", surface::hex(&surface::Toolchain::current().lift))), "the header has the `lift` line:\n{}", &text[..600]);
    let parsed = sandblaster_front::lock::Lock::parse(&text).unwrap();
    assert_eq!(parsed.lift, now.lift);
    assert_eq!(sandblaster_front::lock::compare(Some(&text), &now, "c/sandblaster/m/SPEC.lock").state, sandblaster_front::lock::LockState::Matches);
    // a changed lift prelude is a header mismatch
    let st = sandblaster_front::lock::compare(Some(&text), &edited, "c/sandblaster/m/SPEC.lock");
    assert_eq!(st.state, sandblaster_front::lock::LockState::Mismatch);
    assert!(st.header.iter().any(|h| h.starts_with("lift:")), "{:?}", st.header);
    // the twin: a lock without the line (accepted before the prelude was
    // pinned) does not match a lifted crate either
    let stripped: String = text.lines().filter(|l| !l.starts_with("lift ")).map(|l| format!("{l}\n")).collect();
    let mut old = sandblaster_front::lock::Lock::parse(&stripped).unwrap_or_else(|e| panic!("{e}"));
    old.root = old.compute_root();
    let st = sandblaster_front::lock::compare(Some(&old.render()), &now, "c/sandblaster/m/SPEC.lock");
    assert!(st.header.iter().any(|h| h.starts_with("lift:") && h.contains("not locked")), "{:?}", st.header);
}
