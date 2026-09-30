//! §15 S3 determinacy (DESIGN.md §15.5): computed sections (SCCs of "a law
//! or contract mentions an exec function", in the well-founded order ≺),
//! `P(R)`, `H(R)`, `complete_p(R)` built by the kernel's
//! `Env::abstract_section` and proven by `auto` (refinement, bool split,
//! induction) or a `#[proof(complete = p)]` item, well-foundedness over the
//! computed `Deps(R)`, `#[section(with = ..)]` merges, and the records of
//! the report, the spec sheet and the lock. The tests run the proofs (a
//! stage run, where a section that is not fully specified fails nothing)
//! and call the section gate (`spec15_gate_s3`) directly to see what the
//! crate path reports.

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Diagnostics, Severity};
use sandblaster_front::driver;
use sandblaster_front::elab::complete::{DepHow, SectionStatus};
use sandblaster_front::elab::DefStatus;
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// A section, by display paths.
#[derive(Clone, Debug)]
struct Sec {
    index: usize,
    members: Vec<String>,
    published: Vec<String>,
    deps: Vec<(String, DepHow)>,
    hyps: Vec<(String, String)>,
    status: SectionStatus,
    merged: bool,
    /// `(p, proven, how, core text, surface text, notes)`.
    complete: Vec<(String, bool, String, String, String, Vec<String>)>,
    problems: Vec<String>,
}

struct Run {
    front_ok: bool,
    verified: bool,
    rendered: String,
    errors: Vec<(DiagKind, String)>,
    sections: Vec<Sec>,
    /// What the §15.8 gate (S5) reports: `(kind, message, notes)`.
    gate: Vec<(DiagKind, String, Vec<String>)>,
    checked_defs: Vec<String>,
}

impl Run {
    fn explain(&self) -> String {
        let mut s = String::new();
        for x in &self.sections {
            s.push_str(&format!("section #{} {:?} P={:?} status={:?} merged={}\n  hyps={:?}\n  deps={:?}\n", x.index, x.members, x.published, x.status, x.merged, x.hyps, x.deps));
            for (p, ok, how, core, surf, notes) in &x.complete {
                s.push_str(&format!("  complete_{p}: proven={ok} by {how}\n    core: {core}\n    surface: {surf}\n"));
                for n in notes {
                    s.push_str(&format!("    note: {n}\n"));
                }
            }
            for p in &x.problems {
                s.push_str(&format!("  problem: {p}\n"));
            }
        }
        for (k, m, notes) in &self.gate {
            s.push_str(&format!("gate {k:?}: {m}\n"));
            for n in notes {
                s.push_str(&format!("   = {n}\n"));
            }
        }
        s.push_str(&self.rendered);
        s
    }

    #[track_caller]
    fn section_of(&self, f: &str) -> &Sec {
        self.sections.iter().find(|s| s.members.iter().any(|m| m == f)).unwrap_or_else(|| panic!("no section contains `{f}`:\n{}", self.explain()))
    }

    fn in_section(&self, f: &str) -> bool {
        self.sections.iter().any(|s| s.members.iter().any(|m| m == f))
    }

    fn gate_has(&self, kind: DiagKind, needle: &str) -> bool {
        self.gate.iter().any(|(k, m, notes)| *k == kind && (m.contains(needle) || notes.iter().any(|n| n.contains(needle))))
    }
}

fn run_files(files: &[(&str, &str)]) -> Run {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        let rendered = c.render();
        let errors = c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect();
        return Run { front_ok: false, verified: false, rendered, errors, sections: vec![], gate: vec![], checked_defs: vec![] };
    }
    let k = c.krate.clone().unwrap();
    let sm = &c.sm;
    let kr = &k;
    let (verified, rendered, errors, sections, gate, checked_defs) = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let path = |id: sandblaster_front::hir::ItemId| kr.item(id).path.to_string();
        let sections = out
            .sections
            .iter()
            .map(|s| Sec {
                index: s.index,
                members: s.members.iter().map(|m| path(*m)).collect(),
                published: s.published.iter().map(|m| path(*m)).collect(),
                deps: s.dep_status.iter().map(|(d, h)| (path(*d), h.clone())).collect(),
                hyps: s.hyps.clone(),
                status: s.status.clone(),
                merged: s.merged,
                complete: s.statements.iter().map(|c| (path(c.item), c.status == DefStatus::Checked, c.proof.clone(), c.text.clone(), c.surface.clone(), c.notes.clone())).collect(),
                problems: s.problems.clone(),
            })
            .collect::<Vec<_>>();
        let mut g = Diagnostics::new();
        sandblaster_front::elab::complete::spec15_gate_s3(&out, kr, &mut g);
        let gate = g.list.iter().map(|d| (d.kind, d.msg.clone(), d.notes.iter().map(|n| n.1.clone()).collect())).collect();
        let errors = out.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect::<Vec<_>>();
        let checked_defs = out.defs.iter().filter(|d| d.status == DefStatus::Checked).map(|d| d.name.clone()).collect();
        (out.verified(), out.diags.render(sm), errors, sections, gate, checked_defs)
    });
    Run { front_ok: true, verified, rendered, errors, sections, gate, checked_defs }
}

/// A crate with a root, a `LAWS.rs` and a `PROOF.rs` (a `follows()` proof
/// of the same name for every law of `laws`); both modules import `uses`
/// from the root.
fn with_laws(root: &str, uses: &str, laws: &str) -> Run {
    let root = format!("{root}\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    let names: Vec<String> = laws
        .split("#[law]")
        .skip(1)
        .filter_map(|s| s.trim_start().strip_prefix("fn ").map(|r| r.split('(').next().unwrap().trim().to_string()))
        .collect();
    let sigs: Vec<String> = laws
        .split("#[law]")
        .skip(1)
        .filter_map(|s| {
            let r = s.trim_start().strip_prefix("fn ")?;
            let open = r.find('(')?;
            let close = r.find(')')?;
            Some(r[open..=close].to_string())
        })
        .collect();
    let mut proof = format!("use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::{{{uses}}};\n");
    for (n, sig) in names.iter().zip(&sigs) {
        proof.push_str(&format!("\n#[proof]\nfn {n}{sig} {{\n    follows();\n}}\n"));
    }
    let laws = format!("use sandblaster::prelude::*;\nuse super::{{{uses}}};\n{laws}");
    run_files(&[("r/mod.rs", &root), ("r/LAWS.rs", &laws), ("r/PROOF.rs", &proof)])
}

#[track_caller]
fn verified(r: &Run) {
    assert!(r.front_ok && r.verified && r.errors.is_empty(), "the crate does not verify:\n{}", r.explain());
}

// ---------------------------------------------------------------------
// accept
// ---------------------------------------------------------------------

const IS_EVEN: &str = r#"
#[cfg(sandblaster)]
#[spec]
fn even(x: Nat) -> bool { x % 2 == 0 }

pub fn is_even(x: u32) -> bool { x % 2 == 0 }
"#;

#[test]
fn exact_characterization_of_a_boolean_function() {
    let r = with_laws(
        IS_EVEN,
        "is_even, even",
        r#"
/// `is_even` holds only of even numbers.
#[law]
fn is_even_sound(x: u32) {
    requires(is_even(x));
    ensures(even(x as Nat));
}

/// `is_even` holds of every even number.
#[law]
fn is_even_complete(x: u32) {
    requires(even(x as Nat));
    ensures(is_even(x));
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::is_even");
    assert_eq!(s.members, vec!["crate::is_even"]);
    assert_eq!(s.published, vec!["crate::is_even"]);
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.complete[0].1 && s.complete[0].2.contains("split"), "{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::is_even::complete"));
    assert!(r.gate.is_empty(), "{}", r.explain());
}

#[test]
fn golden_text_of_complete_p() {
    let r = with_laws(
        IS_EVEN,
        "is_even, even",
        r#"
/// `is_even` holds only of even numbers.
#[law]
fn is_even_sound(x: u32) {
    requires(is_even(x));
    ensures(even(x as Nat));
}

/// `is_even` holds of every even number.
#[law]
fn is_even_complete(x: u32) {
    requires(even(x as Nat));
    ensures(is_even(x));
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::is_even");
    assert_eq!(
        s.complete[0].3,
        "(is_even' : U32 -> Bool) -> \
         ((x : U32) -> Eq(Bool, is_even' x, true) -> Eq(Bool, crate::even #cast_u32_int(x), true)) -> \
         ((x : U32) -> Eq(Bool, crate::even #cast_u32_int(x), true) -> Eq(Bool, is_even' x, true)) -> \
         (x : U32) -> Eq(Bool, is_even' x, crate::is_even x)"
    );
    assert_eq!(
        s.complete[0].4,
        "for all is_even': u32 -> bool, \
         (for all x: u32, is_even'(x) ⇒ crate::even((x as Int))) ⇒ \
         (for all x: u32, crate::even((x as Int)) ⇒ is_even'(x)) ⇒ \
         for all x: u32, is_even'(x) == crate::is_even(x)",
        "{}",
        r.explain()
    );
    assert_eq!(s.hyps, vec![("law".to_string(), "crate::laws::is_even_sound".to_string()), ("law".to_string(), "crate::laws::is_even_complete".to_string())]);
}

/// A function refined only up to a domain (`#[refines(s, domain = P)]`,
/// which does not determine it by itself), with `requires(P)`: its section
/// has the refinement lemma as its only hypothesis, and `auto` discharges
/// it through the injective view `u64 ↦ Nat` (transitivity).
#[test]
fn refinement_only_section() {
    let r = run_files(&[(
        "r/mod.rs",
        r#"
#[cfg(sandblaster)]
#[spec]
fn halve(x: Nat) -> Nat { x / 2 }

#[requires(x <= 1000)]
#[refines(halve(x as Nat), domain = x <= 1000)]
fn halve_impl(x: u64) -> u64 { x / 2 }

#[ensures(|r: u64| r == halve_impl(x as u64))]
pub fn api(x: u8) -> u64 { halve_impl(x as u64) }

#[refines(halve)]
pub fn exact(x: u32) -> u64 { (x / 2) as u64 }
"#,
    )]);
    verified(&r);
    let s = r.section_of("crate::halve_impl");
    assert_eq!(s.members, vec!["crate::halve_impl"]);
    assert_eq!(s.hyps, vec![("refines".to_string(), "crate::halve_impl::refines".to_string())], "{}", r.explain());
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.complete[0].2.contains("refinement"), "{}", r.explain());
    // the requires is a binder of the statement (the domain of determinacy)
    assert!(s.complete[0].3.contains("(.h_req0 : Eq(Bool, #le_u64(x, 1000u64), true))") || s.complete[0].3.contains("#le_u64(x, 1000u64)"), "{}", r.explain());
    // `api`'s contract mentions `halve_impl`: its section comes after (≺)
    let a = r.section_of("crate::api");
    assert!(a.index > s.index, "{}", r.explain());
    assert!(a.deps.iter().any(|(d, h)| d == "crate::halve_impl" && *h == DepHow::Section(s.index)), "{}", r.explain());
    assert_eq!(a.status, SectionStatus::FullySpecified, "{}", r.explain());
    // a determining refinement: determined immediately, no section
    assert!(!r.in_section("crate::exact"), "{}", r.explain());
}

const MINI_SPEC: &str = r#"
/// The reference verdict: a tag is accepted exactly when it is the key's
/// successor.
#[cfg(sandblaster)]
#[spec]
fn verify_spec(key: Nat, tag: Nat) -> bool { tag == key + 1 }

/// What acceptance means, written independently: the tag exceeds the key
/// by exactly one.
#[cfg(sandblaster)]
#[spec]
fn accepts(key: Nat, tag: Nat) -> bool { key < tag && tag <= key + 1 }
"#;

/// The QMDB design (docs/qmdb-spec-design.md): `verify` refines the
/// reference verdict (a `bool`: determined immediately), and the laws — both
/// directions — are stated over spec items only, so they create no section.
/// The same laws over the exec `verify` (no refinement) make its section,
/// determined by splitting both results.
#[test]
fn mini_verify_with_soundness_and_completeness_laws_is_determined() {
    let root = format!(
        "{MINI_SPEC}
#[refines(verify_spec)]
pub fn verify(key: u32, tag: u64) -> bool {{ if tag == (key as u64) + 1 {{ true }} else {{ false }} }}
"
    );
    let r = with_laws(
        &root,
        "verify_spec, accepts",
        r#"
/// Sound: an accepted tag is the key's checksum.
#[law]
fn verified_tags_are_checksums(key: Nat, tag: Nat) {
    requires(verify_spec(key, tag));
    ensures(accepts(key, tag));
}

/// Complete: the key's checksum is accepted.
#[law]
fn checksums_verify(key: Nat, tag: Nat) {
    requires(accepts(key, tag));
    ensures(verify_spec(key, tag));
}
"#,
    );
    verified(&r);
    assert!(!r.in_section("crate::verify"), "a determining refinement: no section\n{}", r.explain());
    assert!(r.gate.is_empty(), "{}", r.explain());

    // the laws over the exec function instead: a section, determined
    let root = format!(
        "{MINI_SPEC}
pub fn verify(key: u32, tag: u64) -> bool {{ if tag == (key as u64) + 1 {{ true }} else {{ false }} }}
"
    );
    let r = with_laws(
        &root,
        "verify, verify_spec",
        r#"
/// Sound: `verify` accepts only the key's checksum.
#[law]
fn verified_tags_are_checksums(key: u32, tag: u64) {
    requires(verify(key, tag));
    ensures(verify_spec(key as Nat, tag as Nat));
}

/// Complete: `verify` accepts the key's checksum.
#[law]
fn checksums_verify(key: u32, tag: u64) {
    requires(verify_spec(key as Nat, tag as Nat));
    ensures(verify(key, tag));
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::verify");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(r.gate.is_empty(), "{}", r.explain());
}

/// A law reaching the section through a spec function's body: the kernel
/// λ-lifts the spec function (its body with the member abstracted), and the
/// spec function is a dependency, never an exec one.
#[test]
fn law_reaching_the_section_through_a_spec_fn_is_lifted() {
    let r = with_laws(
        r#"
pub fn low3(x: u8) -> u8 { x & 7 }

/// (A legacy spec function calling the implementation: recorded by spec
/// closure, an error of the crate path's examples gate.)
#[cfg(sandblaster)]
#[spec]
fn low3_of(x: u8) -> u8 { low3(x) }
"#,
        "low3_of",
        r#"
/// `low3_of` is the low three bits.
#[law]
fn low3_is_a_mask(x: u8) {
    ensures(low3_of(x) == x & 7u8);
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::low3");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    let core = &s.complete[0].3;
    assert!(core.contains("(fun (x1 : U8) => low3' x1) x") && !core.contains("crate::low3_of"), "the spec fn is inlined with the member abstracted:\n{}", r.explain());
    assert!(s.deps.is_empty(), "{}", r.explain());
}

/// A generic function in an exported contract: its section is `Kind`-sorted
/// (it quantifies over the type parameter) and comes first in ≺.
#[test]
fn generic_kind_sorted_section() {
    let r = run_files(&[(
        "r/mod.rs",
        r#"
#[ensures(|r: T| r == x)]
fn ident<T: Copy>(x: T) -> T { x }

#[ensures(|r: u32| r == ident(x))]
pub fn wrap(x: u32) -> u32 { ident(x) }
"#,
    )]);
    verified(&r);
    let s = r.section_of("crate::ident");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.complete[0].3.starts_with("(ident' : (T : Type) -> T -> T) -> "), "{}", r.explain());
    let w = r.section_of("crate::wrap");
    assert!(w.index > s.index && w.deps.iter().any(|(d, h)| d == "crate::ident" && *h == DepHow::Section(s.index)), "{}", r.explain());
    assert_eq!(w.status, SectionStatus::FullySpecified, "{}", r.explain());
}

/// A recursive function whose law is its recursive equation: induction on
/// its measure, with the induction hypothesis at the recursive call.
#[test]
fn recursive_equation_by_induction() {
    let r = with_laws(
        r#"
#[decreases(b)]
pub fn gcd(a: u32, b: u32) -> u32 { if b == 0 { a } else { gcd(b, a % b) } }
"#,
        "gcd",
        r#"
/// Euclid's recursion.
#[law]
fn gcd_step(a: u32, b: u32) {
    ensures(gcd(a, b) == if b == 0 { a } else { gcd(b, a % b) });
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::gcd");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.complete[0].2.contains("induction"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// reject (what the §15.8 section gate reports; the stage run's proofs
// still check)
// ---------------------------------------------------------------------

/// Soundness alone does not determine a `bool` function (`λ_. false`
/// satisfies it): `complete_verify` is unproven.
#[test]
fn soundness_only_verify_is_not_determined() {
    let root = format!(
        "{MINI_SPEC}
pub fn verify(key: u32, tag: u64) -> bool {{ if tag == (key as u64) + 1 {{ true }} else {{ false }} }}
"
    );
    let r = with_laws(
        &root,
        "verify, verify_spec",
        r#"
/// Sound: `verify` accepts only the key's checksum.
#[law]
fn verified_tags_are_checksums(key: u32, tag: u64) {
    requires(verify(key, tag));
    ensures(verify_spec(key as Nat, tag as Nat));
}
"#,
    );
    // a stage run: the proofs still check ...
    verified(&r);
    let s = r.section_of("crate::verify");
    assert_eq!(s.status, SectionStatus::Unproven, "{}", r.explain());
    assert!(!s.complete[0].1);
    // ... and the gate reports it
    assert!(r.gate_has(DiagKind::Completeness, "`crate::verify` is not determined by the specification"), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Completeness, "both directions"), "{}", r.explain());
}

/// Twins: from `f(x) == g(x)` alone neither is determined. They form one
/// section (no well-founded order separates them) and it is not proven.
#[test]
fn twin_sections_have_no_well_founded_order() {
    let r = with_laws(
        r#"
pub fn f(x: u32) -> u32 { x / 2 }
pub fn g(x: u32) -> u32 { x >> 1u32 }
"#,
        "f, g",
        r#"
/// `f` and `g` agree.
#[law]
fn twins(x: u32) {
    ensures(f(x) == g(x));
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::f");
    assert_eq!(s.members, vec!["crate::f", "crate::g"], "one section:\n{}", r.explain());
    assert_eq!(s.published, vec!["crate::f", "crate::g"]);
    assert_eq!(s.status, SectionStatus::Unproven, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("constrained only jointly")), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Completeness, "not determined"), "{}", r.explain());
}

const CALLER: &str = r#"
pub fn f2(x: u32) -> u32 { x / 2 }

#[ensures(|r: u32| r as Nat <= g(x) as Nat)]
pub fn f1(x: u32) -> u32 { x / 2 }
"#;

/// A function outside the section whose body reaches it (`g` calls `f2`),
/// named by a hypothesis (`f1`'s contract): its implementation is not a
/// specification, so the kernel refuses to inline it — establish it in an
/// earlier section or merge it.
#[test]
fn a_caller_outside_the_section_must_be_established_or_merged() {
    let laws = r#"
/// `f2` halves.
#[law]
fn f2_halves(x: u32) {
    ensures(f2(x) == x / 2);
}

/// `f1` is `f2`.
#[law]
fn f1_is_f2(x: u32) {
    ensures(f1(x) == f2(x));
}
"#;
    let r = with_laws(&format!("{CALLER}\nfn g(x: u32) -> u32 {{ f2(x) + 1 }}\n"), "f1, f2", laws);
    verified(&r);
    let s = r.section_of("crate::f1");
    assert_eq!(s.members, vec!["crate::f2", "crate::f1"], "{}", r.explain());
    assert_eq!(s.status, SectionStatus::Unstated, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("`crate::g` reaches this section") && p.contains("establish it in an earlier section") && p.contains("merge it")), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Section, "establish it in an earlier section"), "{}", r.explain());

    // established (a determining refinement): the section is stated and proven
    let root = format!("{CALLER}\n#[cfg(sandblaster)]\n#[spec]\nfn g_spec(x: Nat) -> Nat {{ x / 2 + 1 }}\n\n#[refines(g_spec)]\nfn g(x: u32) -> u64 {{ (f2(x) as u64) + 1 }}\n");
    let root = root.replace("r as Nat <= g(x) as Nat", "(r as Nat) <= (g(x) as Nat)");
    let r = with_laws(&root, "f1, f2", laws);
    verified(&r);
    let s = r.section_of("crate::f1");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.deps.iter().any(|(d, h)| d == "crate::g" && *h == DepHow::Refines), "{}", r.explain());

    // merged: stated (not proven: `g`'s value is then unconstrained, and
    // f1's contract only bounds it)
    let root = format!("{CALLER}\nfn g(x: u32) -> u32 {{ f2(x) + 1 }}\n").replace("pub fn f1", "#[section(with = [g])]\npub fn f1");
    let r = with_laws(&root, "f1, f2", laws);
    verified(&r);
    let s = r.section_of("crate::f1");
    assert!(s.members.contains(&"crate::g".to_string()) && s.merged, "{}", r.explain());
    assert_ne!(s.status, SectionStatus::Unstated, "{}", r.explain());
}

/// Relative completeness must be well founded: `f` is determined relative
/// to `h` (its contract), but `h` is not fully specified in an earlier
/// section, so `f`'s section is not either — even though `complete_f` is
/// proven.
#[test]
fn completeness_relative_to_an_unspecified_dependency_is_not_well_founded() {
    let r = run_files(&[(
        "r/mod.rs",
        r#"
fn h(x: u32) -> u32 { x / 2 }

#[ensures(|r: u32| r == h(x))]
pub fn f(x: u32) -> u32 { x >> 1u32 }
"#,
    )]);
    verified(&r);
    let hs = r.section_of("crate::h");
    assert_eq!(hs.status, SectionStatus::Unproven, "{}", r.explain());
    let s = r.section_of("crate::f");
    assert!(s.index > hs.index, "{}", r.explain());
    assert!(s.complete[0].1, "proven relative to `h`:\n{}", r.explain());
    assert_eq!(s.status, SectionStatus::NotWellFounded, "{}", r.explain());
    assert!(s.deps.iter().any(|(d, h)| d == "crate::h" && *h == DepHow::Unspecified), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Section, "depends on `crate::h`, which is not fully specified in an earlier section"), "{}", r.explain());
    // `h` established by a refinement: fully specified
    let r = run_files(&[(
        "r/mod.rs",
        r#"
#[cfg(sandblaster)]
#[spec]
fn half(x: Nat) -> Nat { x / 2 }

#[refines(half)]
fn h(x: u32) -> u32 { x / 2 }

#[ensures(|r: u32| r == h(x))]
pub fn f(x: u32) -> u32 { x >> 1u32 }
"#,
    )]);
    verified(&r);
    let s = r.section_of("crate::f");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.deps.iter().any(|(d, h)| d == "crate::h" && *h == DepHow::Refines), "{}", r.explain());
}

/// An exported function with no specification at all: its proofs check
/// (a stage run), and the section gate reports it.
#[test]
fn unspecified_exported_function_is_recorded_not_enforced() {
    let r = run_files(&[("r/mod.rs", "pub fn clamp(x: u32) -> u32 { if x > 100 { 100 } else { x } }\n")]);
    verified(&r);
    let s = r.section_of("crate::clamp");
    assert_eq!(s.status, SectionStatus::Unproven, "{}", r.explain());
    assert!(s.hyps.is_empty());
    assert!(r.gate_has(DiagKind::Completeness, "no law, `ensures` or refinement mentions the section"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// the kernel owns the statement
// ---------------------------------------------------------------------

/// Elaborates `files` and runs `f` on the output (on the elaboration
/// thread).
fn with_output<T: Send>(files: &[(&str, &str)], f: impl FnOnce(&sandblaster_front::elab::Output, &sandblaster_front::hir::Crate) -> T + Send) -> T {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.clone().unwrap();
    let kr = &k;
    sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        f(&out, kr)
    })
}

fn laws_files(root: &str, uses: &str, laws: &str) -> Vec<(String, String)> {
    let root = format!("{root}\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    let mut proof = format!("use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::{{{uses}}};\n");
    for part in laws.split("#[law]").skip(1) {
        let r = part.trim_start().strip_prefix("fn ").unwrap();
        let (name, rest) = r.split_once('(').unwrap();
        let sig = &rest[..rest.find(')').unwrap()];
        proof.push_str(&format!("\n#[proof]\nfn {name}({sig}) {{\n    follows();\n}}\n"));
    }
    vec![("r/mod.rs".into(), root), ("r/LAWS.rs".into(), format!("use sandblaster::prelude::*;\nuse super::{{{uses}}};\n{laws}")), ("r/PROOF.rs".into(), proof)]
}

const IS_EVEN_LAWS: &str = r#"
/// `is_even` holds only of even numbers.
#[law]
fn is_even_sound(x: u32) {
    requires(is_even(x));
    ensures(even(x as Nat));
}

/// `is_even` holds of every even number.
#[law]
fn is_even_complete(x: u32) {
    requires(even(x as Nat));
    ensures(is_even(x));
}
"#;

/// The statement is the kernel's, never the front end's: a proof of an
/// easier (corrupted) statement does not check as `complete_p`, a forged
/// hypothesis restatement is rejected by `abstract_section`, and the
/// accepted lemma's type is exactly the returned term.
#[test]
fn a_corrupted_statement_is_caught_by_the_kernel() {
    use sandblaster_kernel::api::{Section, SectionHyp};
    use sandblaster_kernel::term::{DefDecl, DefKind, Recursion, Term};
    use sandblaster_kernel::util::mk;
    use sandblaster_kernel::value::Budget;
    let files = laws_files(IS_EVEN, "is_even, even", IS_EVEN_LAWS);
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    with_output(&refs, |out, k| {
        let s = &out.sections[0];
        let c = &s.statements[0];
        assert_eq!(c.status, DefStatus::Checked);
        let lemma = c.lemma.unwrap();
        // the lemma's type is exactly the kernel's statement
        assert!(std::rc::Rc::ptr_eq(&out.env.global_type(lemma).unwrap(), &c.statement) || out.env.alpha_eq_relevant(&out.env.global_type(lemma).unwrap(), &c.statement, &|a, b| a == b));
        // a corrupted statement: the conclusion `F' x = p x` replaced by
        // `p x = p x` (provable by refl); its proof does not prove the real one
        let (bs, concl) = sandblaster_front::auto::complete::telescope(&c.statement);
        let Term::Eq { ty, rhs, .. } = &*concl else { panic!("not an equation") };
        let forged_body = mk::refl(ty.clone(), rhs.clone());
        let forged_proof = sandblaster_front::auto::complete::lams(&bs, forged_body);
        let d = DefDecl { name: "forged::complete".into(), kind: DefKind::Lemma, ty: c.statement.clone(), body: forged_proof, recursion: Recursion::None, arity: 0, opaque: false };
        let mut b = Budget { steps: 10_000_000 };
        // the kernel checks the proof against the statement
        let tv = out.env.eval(&Default::default(), sandblaster_kernel::term::Lvl(0), &d.ty, &mut b).unwrap();
        assert!(out.env.check(&Default::default(), &d.body, &tv, &mut b).is_err(), "a proof of `p x = p x` must not prove complete_p");
        // a forged restatement of a hypothesis (the goal smuggled in) is rejected
        let g = |p: &str| out.fn_globals[&k.find(p).unwrap()];
        let law = out.defs.iter().find(|d| d.name == "crate::laws::is_even_sound").and_then(|d| d.global).unwrap();
        let forged = out.env.parse_term(&["F"], "(x : U32) -> Eq(Bool, F x, crate::is_even x)").unwrap();
        let e = out
            .env
            .abstract_section(&Section { members: &[g("crate::is_even")], published: &[g("crate::is_even")], hyps: &[SectionHyp { lemma: law, restated: Some(forged) }], views: &[], established: &[] }, &mut Budget { steps: 10_000_000 })
            .unwrap_err();
        assert!(e.message.contains("relevant position"), "{}", e.message);
    });
}

// ---------------------------------------------------------------------
// proof items and merges
// ---------------------------------------------------------------------

/// `#[proof(complete = p)]`: the script proves `complete_p` with the
/// section's hypotheses (and their real counterparts) as facts and `p`'s
/// parameters as its own; a call of a member denotes the hypothetical
/// implementation `F'` the statement quantifies over. A script that does
/// not prove is an error now (an explicit proof item).
#[test]
fn proof_item_proves_complete_p() {
    let item = |body: &str| format!("\n/// `is_even` is pinned down by its two laws.\n#[proof(complete = super::is_even)]\nfn is_even_determined(x: u32) {{\n    {body}\n}}\n");
    // `follows()` alone: nothing splits `is_even'(x)`
    let mut files = laws_files(IS_EVEN, "is_even, even", IS_EVEN_LAWS);
    files[2].1.push_str(&item("follows();"));
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    let r = run_files(&refs);
    assert!(r.errors.iter().any(|(k, m)| *k == DiagKind::Obligation && m.contains("[completeness]")), "{}", r.explain());
    assert_eq!(r.section_of("crate::is_even").status, SectionStatus::Unproven);
    // splitting on the hypothetical `is_even'(x)` and on `even(x)`: proven
    let mut files = laws_files(IS_EVEN, "is_even, even", IS_EVEN_LAWS);
    files[2].1.push_str(&item("by_cases(is_even(x), even(x as Nat));"));
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    let r = run_files(&refs);
    verified(&r);
    let s = r.section_of("crate::is_even");
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert_eq!(s.complete[0].2, "crate::proof::is_even_determined", "the proof item, not auto:\n{}", r.explain());
}

/// A proof item for a function with no completeness obligation, and a
/// merge naming a function determined by its refinement, are errors now
/// (explicit annotations whose meaning is defined).
#[test]
fn misused_proof_item_and_merge_are_errors() {
    let root = r#"
#[cfg(sandblaster)]
#[spec]
fn halve(x: Nat) -> Nat { x / 2 }

#[refines(halve)]
pub fn exact(x: u32) -> u64 { (x / 2) as u64 }

#[section(with = [exact])]
pub fn other(x: u32) -> u32 { x }

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;
    let proof = "use sandblaster::prelude::*;\n\n#[proof(complete = super::exact)]\nfn exact_determined(x: u32) {\n    follows();\n}\n";
    let r = run_files(&[("r/mod.rs", root), ("r/PROOF.rs", proof)]);
    assert!(r.errors.iter().any(|(k, m)| *k == DiagKind::Completeness && m.contains("proves nothing") && m.contains("determined by its `#[refines]`")), "{}", r.explain());
    assert!(r.errors.iter().any(|(k, m)| *k == DiagKind::Section && m.contains("determined by its `#[refines]`")), "{}", r.explain());
}

// ---------------------------------------------------------------------
// deterministic budgets (DESIGN.md §15.8)
// ---------------------------------------------------------------------

const NEEDS_PROVER: &str = r#"
#[requires(x < 1000)]
fn inc(x: u32) -> u32 { x + 1 }

pub fn use_inc(x: u8) -> u32 { inc(x as u32) }
"#;

/// A goal stopped by a safety net (here a deadline that has already passed)
/// is a resource failure of the build (`error[resource]`), never an
/// unproven obligation; a goal that runs out of steps is a proof result.
#[test]
fn deadline_trips_are_resource_failures_never_proof_results() {
    let fs_files = [("r/mod.rs".to_string(), format!("{HEADER}{NEEDS_PROVER}"))];
    let fs = MemFs::from_files(fs_files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.clone().unwrap();
    let kr = &k;
    let (kinds_deadline, verified_deadline, kinds_steps, kinds_ok, gate) = sandblaster_front::elab::with_big_stack(move || {
        let kinds = |out: &sandblaster_front::elab::Output| out.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect::<Vec<_>>();
        // the safety net: a per-goal deadline that has passed at once
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        chain.timeout = Some(std::time::Duration::from_nanos(1));
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let kd = kinds(&out);
        let vd = out.verified();
        // the driver's gate sees the trips of this thread
        let mut v = driver::Verification { defs: vec![], obligations: vec![], laws: vec![], diags: Diagnostics::new(), deferred: vec![], proofs_ok: true, elapsed: std::time::Duration::ZERO, provers: vec![], exec_only: false };
        driver::resource_gate(&mut v);
        let gate = (v.proofs_ok, v.diags.list.iter().map(|d| (d.kind, d.msg.clone())).collect::<Vec<_>>());
        // the deterministic budget: a goal budget too small for the prover
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options { goal_budget: 1, ..Default::default() });
        let ks = kinds(&out);
        let _ = sandblaster_front::auto::meter::take_trips();
        // the control
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        (kd, vd, ks, kinds(&out), gate)
    });
    assert!(!verified_deadline);
    assert!(kinds_deadline.iter().any(|(k, m)| *k == DiagKind::Resource && m.contains("not a proof result")), "{kinds_deadline:?}");
    assert!(!kinds_deadline.iter().any(|(k, m)| *k == DiagKind::Obligation && m.contains("unproven obligation")), "a trip is never reported as an unproven obligation: {kinds_deadline:?}");
    assert!(!gate.0 && gate.1.iter().any(|(k, m)| *k == DiagKind::Resource && m.contains("resource safety nets tripped")), "{gate:?}");
    assert!(kinds_steps.iter().any(|(k, m)| *k == DiagKind::Obligation && m.contains("unproven obligation")), "{kinds_steps:?}");
    assert!(!kinds_steps.iter().any(|(k, _)| *k == DiagKind::Resource), "a step budget is a proof result: {kinds_steps:?}");
    assert!(kinds_ok.is_empty(), "{kinds_ok:?}");
}

// ---------------------------------------------------------------------
// records: the report, the spec sheet, the SPEC.lock entries and header
// ---------------------------------------------------------------------

#[test]
fn sections_are_recorded_in_the_report_the_sheet_and_the_lock() {
    use sandblaster_front::driver::stage::SpecBaseline;
    use sandblaster_front::lock::{self, Lock, Selection};
    use sandblaster_front::surface::SurfaceKind;
    let files = laws_files(IS_EVEN, "is_even, even", IS_EVEN_LAWS);
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    // the report
    let reports = with_output(&refs, |out, k| driver::spec15_report(out, k).sections);
    assert_eq!(reports.len(), 1);
    let rep = &reports[0];
    assert_eq!(rep.members, vec!["crate::is_even"]);
    assert!(rep.fully_specified && rep.status == "fully specified");
    assert_eq!(rep.hypotheses.len(), 2);
    assert!(rep.complete[0].1.starts_with("for all is_even': u32 -> bool") && rep.complete[0].3 == "checked", "{rep:?}");
    // the surface, the lock and the sheet
    let mut owned: Vec<(String, String)> = files.clone();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let run = driver::stage::spec_run(&c, &SpecBaseline::Lock, false);
    assert!(run.v.proofs_ok, "{}", run.v.diags.render(&c.sm));
    let surface = run.surface.as_ref().unwrap();
    let item = surface.items.iter().find(|i| i.kind == SurfaceKind::Section).expect("a section entry");
    assert_eq!(item.key, "section:crate::is_even");
    assert_eq!(item.statement[0], "section R = {crate::is_even}");
    assert!(item.statement.iter().any(|l| l.starts_with("  complete_crate::is_even(R) : for all is_even'")), "{:?}", item.statement);
    assert!(item.kernel.iter().any(|(p, t)| p == "complete:crate::is_even" && t.contains("Eq(Bool, is_even' x, crate::is_even x)")), "{:?}", item.kernel);
    assert!(item.notes.iter().any(|n| n.contains("fully specified")), "{:?}", item.notes);
    // the lock: an entry and a header line, both covered by the root
    let (l, _) = lock::preview_accept(None, surface, &Selection::All).expect("accept");
    let text = l.render();
    assert!(text.contains("\nsections 1\n"), "{text}");
    assert!(text.contains("\nsection section:crate::is_even R {crate::is_even} P {crate::is_even} Deps {} H "), "{text}");
    assert!(text.contains("\nitem section:crate::is_even\n"), "{text}");
    let parsed = Lock::parse(&text).expect("the lock parses back");
    assert_eq!(parsed.section_lines(), l.section_lines());
    assert!(lock::compare(Some(&text), surface, "SPEC.lock").matches());
    // a hand-edited header line is malformed
    let edited = text.replace("P {crate::is_even}", "P {}");
    assert!(Lock::parse(&edited).is_err());
    // the sheet shows the statement and the (unlocked) status
    let sheet = sandblaster_front::specdiff::sheet("r", surface, &run.status, &run.changes);
    assert!(sheet.contains("== Sections (1) ==") && sheet.contains("note:      status (this build, not locked): fully specified"), "{sheet}");
}

/// The build's pipeline with proven sections: the completeness lemmas are
/// ordinary checked lemmas of the environment; the optimizer, the printer
/// and the round trip are unaffected, and the report lists the sections.
#[test]
fn a_crate_with_proven_sections_builds_optimized() {
    let files = laws_files(IS_EVEN, "is_even, even", IS_EVEN_LAWS);
    let mut owned = files.clone();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let built = driver::stage::verify_and_optimize(&c, &driver::VerifyOptions::default(), &sandblaster_front::opt::OptOptions::default(), "r");
    assert!(built.v.proofs_ok, "{}", built.v.diags.render(&c.sm));
    let em = built.emit.expect("optimized").expect("emitted");
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    assert!(built.v.defs.iter().any(|d| d.name == "crate::is_even::complete"));
    assert!(built.v.obligations.iter().any(|o| o.def == "crate::is_even::complete" && o.proven()));
    assert_eq!(built.spec15.sections.len(), 1);
    assert!(built.spec15.sections[0].fully_specified);
    let json = driver::stage::report_json(&c, &built.v, &built.law_audit, "r", Some(&em), Some(&built.spec), Some(&built.spec15));
    assert!(json.contains("\"sections\"") && json.contains("\"fully_specified\": true"), "{json}");
}

// ---------------------------------------------------------------------
// what must be determined, and what counts as a hypothesis
// ---------------------------------------------------------------------

const TOKEN: &str = "use sandblaster::prelude::*;\n\n#[derive(Clone, Copy)]\npub struct Token(u32);\n\nimpl Token {\n    pub fn leak(&self) -> u32 { self.0 ^ 7u32 }\n}\n\n#[ensures(|r: Token| r.0 == x as u32)]\npub fn make(x: u8) -> Token { Token(x as u32) }\n";

/// Host code can call every `pub` method of a type an exported function
/// returns, whether or not the type is in the root's `pub use` list (and
/// every `pub` function behind a `pub mod`): all of them must be
/// determined, so each has a section and the gate reports the unspecified
/// ones.
#[test]
fn every_host_callable_function_must_be_determined() {
    let r = run_files(&[("r/mod.rs", "mod m;\npub use m::make;\n"), ("r/m.rs", TOKEN)]);
    verified(&r);
    let s = r.section_of("crate::m::Token::leak");
    assert_eq!(s.status, SectionStatus::Unproven, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("no hypothesis constrains `crate::m::Token::leak`")), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Completeness, "`crate::m::Token::leak` is not determined by the specification"), "{}", r.explain());
    assert_eq!(r.section_of("crate::m::make").status, SectionStatus::FullySpecified, "{}", r.explain());
    // the public tree of a `pub mod` at the root (rejected by the §15.8
    // boundary gate, host-callable meanwhile)
    let r = run_files(&[("r/mod.rs", "pub mod m;\n"), ("r/m.rs", "use sandblaster::prelude::*;\npub fn f(x: u32) -> u32 { x ^ 3u32 }\n")]);
    verified(&r);
    assert!(r.in_section("crate::m::f"), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Completeness, "`crate::m::f` is not determined"), "{}", r.explain());
}

/// `#[section(with = ..)]` only merges: `h`, mentioned by the exported `f`'s
/// contract, stays published in the merged section (with its own
/// `complete_h`), so the merge determines exactly what the separate
/// sections do — here `h` is not determined, merged or not.
#[test]
fn a_merge_never_unpublishes_a_member_a_contract_mentions() {
    let root = "fn h(x: u32) -> u32 { x / 4u32 }\n\n#[ensures(|r: u32| r == x / 2u32 && h(x) <= r)]\npub fn f(x: u32) -> u32 { x >> 1u32 }\n";
    let r = run_files(&[("r/mod.rs", root)]);
    verified(&r);
    assert_ne!(r.section_of("crate::h").status, SectionStatus::FullySpecified, "{}", r.explain());
    assert_eq!(r.section_of("crate::f").status, SectionStatus::NotWellFounded, "{}", r.explain());
    let r = run_files(&[("r/mod.rs", &root.replace("#[ensures", "#[section(with = [h])]\n#[ensures"))]);
    verified(&r);
    let s = r.section_of("crate::h");
    assert!(s.merged, "{}", r.explain());
    assert_eq!(s.members, vec!["crate::h", "crate::f"], "{}", r.explain());
    assert_eq!(s.published, vec!["crate::h", "crate::f"], "the merge unpublished `h`:\n{}", r.explain());
    assert_ne!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
    assert!(s.complete.iter().any(|c| c.0 == "crate::h" && !c.1), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Completeness, "`crate::h` is not determined by the specification"), "{}", r.explain());
}

const SUM_CHECK: &str = "pub fn verify(a: u8, b: u8, tag: u16) -> bool { (a as u16) + (b as u16) == tag }\n";

/// A `#[definitional]` law restates a definition and is never counted as a
/// guarantee (DESIGN.md §15.1 LR6): it is no hypothesis of a section, so a
/// function whose only law is definitional is not determined — the same
/// law without the attribute is a hypothesis (and an LR6 echo).
#[test]
fn definitional_laws_are_not_hypotheses() {
    let law = r#"
/// A tag is accepted exactly when it equals the sum of the two bytes.
#[definitional(reason = "the checksum is defined by the code")]
#[law]
fn verify_is_sum_check(a: u8, b: u8, tag: u16) {
    ensures(verify(a, b, tag) == ((a as u16) + (b as u16) == tag));
}
"#;
    let r = with_laws(SUM_CHECK, "verify", law);
    verified(&r);
    let s = r.section_of("crate::verify");
    assert!(s.hyps.is_empty(), "a definitional law is a hypothesis:\n{}", r.explain());
    assert_eq!(s.status, SectionStatus::Unproven, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("`crate::laws::verify_is_sum_check`") && p.contains("`#[definitional]`")), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Completeness, "only `#[definitional]` laws mention the section"), "{}", r.explain());
    let r = with_laws(SUM_CHECK, "verify", &law.replace("#[definitional(reason = \"the checksum is defined by the code\")]\n", ""));
    verified(&r);
    let s = r.section_of("crate::verify");
    assert_eq!(s.hyps, vec![("law".to_string(), "crate::laws::verify_is_sum_check".to_string())], "{}", r.explain());
    assert_eq!(s.status, SectionStatus::FullySpecified, "{}", r.explain());
}

/// A law that mentions a member but did not verify leaves `H(R)` incomplete:
/// the section is blocked and says which law, instead of reporting that no
/// law mentions the function.
#[test]
fn a_hypothesis_that_did_not_verify_blocks_its_section() {
    let r = with_laws(
        "pub fn wrap(x: u8) -> u8 { x.wrapping_add(1u8) }\n",
        "wrap",
        r#"
/// Wrapping adds one to every byte (false at 255).
#[law]
fn wrap_adds_one(x: u8) {
    ensures(wrap(x) as Nat == x as Nat + 1);
}
"#,
    );
    assert!(r.front_ok && !r.verified, "{}", r.explain());
    let s = r.section_of("crate::wrap");
    assert_eq!(s.status, SectionStatus::Blocked, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("the law `crate::laws::wrap_adds_one` mentions `crate::wrap` but did not verify")), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Section, "`H(R)` is incomplete without it"), "{}", r.explain());
    assert!(!r.gate_has(DiagKind::Section, "no law, `ensures` or refinement mentions the section"), "{}", r.explain());
    // a member's own `#[ensures]` that did not verify
    let r = run_files(&[("r/mod.rs", "#[ensures(|r: u8| r as Nat == x as Nat + 1)]\npub fn wrap(x: u8) -> u8 { x.wrapping_add(1u8) }\n")]);
    assert!(r.front_ok && !r.verified, "{}", r.explain());
    let s = r.section_of("crate::wrap");
    assert_eq!(s.status, SectionStatus::Blocked, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("the `#[ensures]` of `crate::wrap` did not verify")), "{}", r.explain());
}

// ---------------------------------------------------------------------
// what an unproven section reports
// ---------------------------------------------------------------------

const TABLE: &str = r#"
#[cfg(sandblaster)]
#[spec]
fn slot_of(k: Nat) -> Nat { k % 4 }

pub fn slot(k: u8) -> usize { (k % 4) as usize }

pub fn lookup(t: [u8; 4], k: u8) -> u8 { t[slot(k)] }
"#;

const TABLE_LAWS: &str = r#"
/// A key's slot is its value modulo four.
#[law]
fn slot_is_mod(k: u8) {
    ensures(slot(k) as Nat == slot_of(k as Nat));
}

/// Looking a key up reads the table at the key's slot.
#[law]
fn lookup_reads_slot(t: [u8; 4], k: u8) {
    ensures(lookup(t, k) == t[slot(k)]);
}
"#;

/// Abstractability (DESIGN.md §15.5): the index bound of `t[slot(k)]` was
/// proven by unfolding `slot`; with the section abstracted the law is
/// re-elaborated and the bound re-proven from the earlier hypothesis
/// `slot_is_mod`, so the section is stated. A slot that still fails is
/// reported where it is, with the proposition it needs.
#[test]
fn a_law_whose_slots_need_a_member_is_restated_from_earlier_hypotheses() {
    let r = with_laws(TABLE, "slot, lookup, slot_of", TABLE_LAWS);
    verified(&r);
    let s = r.section_of("crate::slot");
    assert_eq!(s.members, vec!["crate::slot", "crate::lookup"], "{}", r.explain());
    assert_ne!(s.status, SectionStatus::Unstated, "the restatement was not accepted:\n{}", r.explain());
    assert!(s.complete.iter().any(|c| c.0 == "crate::slot" && c.1), "{}", r.explain());
    // the statement of `lookup_reads_slot` uses `slot_is_mod` (a dependent
    // binder of the restated section)
    assert!(s.complete[0].4.contains("for all h0: (k: u8) -> (slot'(k) as Int) == crate::slot_of((k as Int))"), "{}", r.explain());
    // `lookup` is not proven by auto: an attempt that failed, never a
    // verdict on the specification, and no "jointly" note (`slot` is proven)
    let l = s.complete.iter().find(|c| c.0 == "crate::lookup").expect("complete_lookup");
    if !l.1 {
        assert!(s.problems.iter().any(|p| p.contains("`complete_crate::lookup` is not proven: `auto` could not prove it") && p.contains("#[proof(complete = crate::lookup)]")), "{}", r.explain());
        assert!(!s.problems.iter().any(|p| p.contains("do not pin") || p.contains("jointly")), "{}", r.explain());
    }
    // the laws in the other order: `slot_is_mod` comes after the law that
    // needs it, so the index bound is located and its proposition named
    let (a, b) = TABLE_LAWS.split_at(TABLE_LAWS.find("/// Looking").unwrap());
    let r = with_laws(TABLE, "slot, lookup, slot_of", &format!("{b}\n{a}"));
    verified(&r);
    let s = r.section_of("crate::slot");
    assert_eq!(s.status, SectionStatus::Unstated, "{}", r.explain());
    assert!(s.problems.iter().any(|p| p.contains("the law `crate::laws::lookup_reads_slot` does not re-check with the section abstracted") && p.contains("cannot be re-proven from the earlier hypotheses (none: it comes first)")), "{}", r.explain());
    assert!(!s.problems.iter().any(|p| p.contains("`#[ensures]` of the member")), "{}", r.explain());
    assert!(r.gate_has(DiagKind::Section, "this index-bounds proof slot of `crate::laws::lookup_reads_slot` needs `(slot'(k) < 4usize)`"), "{}", r.explain());
}

/// The gate's error for an unproven section: the stuck goal first, in
/// surface syntax with the function unfolded once, then why (the budget
/// named when it ran out), with no prover internals.
#[test]
fn an_unproven_section_reports_the_stuck_goal_in_surface_syntax() {
    let r = with_laws(
        "pub fn tag(a: u8, b: u8) -> u16 { (a as u16) + (b as u16) }\n",
        "tag",
        r#"
/// A tag is at least its first byte.
#[law]
fn tag_ge(a: u8, b: u8) {
    ensures(tag(a, b) >= a as u16);
}
"#,
    );
    verified(&r);
    let s = r.section_of("crate::tag");
    assert_eq!(s.status, SectionStatus::Unproven, "{}", r.explain());
    let (_, notes) = r.gate.iter().find(|(k, m, _)| *k == DiagKind::Completeness && m.contains("`crate::tag`")).map(|(k, _, n)| (k, n.clone())).expect("the gate reports `tag`");
    assert!(notes[0].contains("`auto` got stuck on `complete_crate::tag` at the goal (with `crate::tag` unfolded once): tag'(a, b) == ((a as u16) + (b as u16))"), "{notes:#?}");
    assert!(notes.iter().any(|n| n.contains("`auto` could not prove it") && !n.contains("do not pin")), "{notes:#?}");
    assert!(!notes.iter().any(|n| n.starts_with("tried:")), "{notes:#?}");
}
