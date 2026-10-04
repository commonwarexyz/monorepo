//! §15.1 law rules (DESIGN.md §15.1 "Laws state guarantees, not code",
//! LR1–LR10 but LR8): every rule on crates built for it, the law table
//! (LR9), the gate that turns the recorded findings into diagnostics
//! (`law_rules::spec15_gate_laws`, a gate of the crate path), the draft
//! `LAWS.rs` of docs/qmdb-spec-design.md §2.2 over stub spec items, which
//! passes every rule, and QMDB's own `LAWS.rs` (the draft over the real
//! spec, proven), which does too.
//!
//! The rules are errors (or warnings) for every crate; the build records
//! them (`Output::law_rules`) and the gate reports them; these tests run
//! the proofs (a stage run) and call the gate directly. Run with
//! `--test-threads=1` (one test elaborates QMDB).

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Diagnostics, Severity};
use sandblaster_front::driver;
use sandblaster_front::elab::law_rules::{self, LawHeading, LawRule};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// A finding, by display path.
#[derive(Clone, Debug)]
struct Finding {
    rule: LawRule,
    item: String,
    msg: String,
    notes: Vec<String>,
}

struct Run {
    front_ok: bool,
    rendered: String,
    /// Errors of the build itself (not the gate's).
    errors: Vec<(DiagKind, String)>,
    findings: Vec<Finding>,
    /// What the gate reports: `(is an error, kind, message)`.
    gate: Vec<(bool, DiagKind, String)>,
    /// The law table: `(law, guarantee, assumes, heading)`.
    table: Vec<(String, Option<String>, Vec<String>, LawHeading)>,
    table_text: Vec<String>,
}

impl Run {
    fn explain(&self) -> String {
        let mut s = String::new();
        for f in &self.findings {
            s.push_str(&format!("{} {}: {}\n", f.rule.code(), f.item, f.msg));
            for n in &f.notes {
                s.push_str(&format!("   = {n}\n"));
            }
        }
        for l in &self.table_text {
            s.push_str(&format!("table: {l}\n"));
        }
        s.push_str(&self.rendered);
        s
    }

    /// The findings of `rule` about `item`.
    fn of(&self, rule: LawRule, item: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.rule == rule && f.item == item).collect()
    }

    #[track_caller]
    fn has(&self, rule: LawRule, item: &str, needle: &str) {
        assert!(self.of(rule, item).iter().any(|f| f.msg.contains(needle) || f.notes.iter().any(|n| n.contains(needle))), "no {} finding on `{item}` containing {needle:?}:\n{}", rule.code(), self.explain());
    }

    #[track_caller]
    fn lacks(&self, rule: LawRule, item: &str) {
        assert!(self.of(rule, item).is_empty(), "unexpected {} finding on `{item}`:\n{}", rule.code(), self.explain());
    }

    #[track_caller]
    fn front(&self) {
        assert!(self.front_ok, "the front end rejected the crate:\n{}", self.rendered);
    }
}

fn run_files(files: &[(&str, &str)]) -> Run {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    run_owned(owned)
}

/// [`run_files`] without the header (the root carries its own).
fn run_owned(owned: Vec<(String, String)>) -> Run {
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        let rendered = c.render();
        let errors = c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect();
        return Run { front_ok: false, rendered, errors, findings: vec![], gate: vec![], table: vec![], table_text: vec![] };
    }
    let k = c.krate.clone().unwrap();
    let sm = &c.sm;
    let kr = &k;
    let (rendered, errors, findings, gate) = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let path = |id: sandblaster_front::hir::ItemId| kr.item(id).path.to_string();
        let findings = out.law_rules.iter().map(|r| Finding { rule: r.rule, item: path(r.item), msg: r.msg.clone(), notes: r.notes.iter().map(|n| n.1.clone()).collect() }).collect::<Vec<_>>();
        let mut g = Diagnostics::new();
        law_rules::spec15_gate_laws(&out, kr, &mut g);
        let gate = g.list.iter().map(|d| (d.severity == Severity::Error, d.kind, d.msg.clone())).collect();
        let errors = out.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect::<Vec<_>>();
        (out.diags.render(sm), errors, findings, gate)
    });
    let rows = law_rules::law_table(&k);
    let table_text = law_rules::table_lines(&rows);
    let table = rows.into_iter().map(|r| (r.path, r.guarantee, r.assumes.into_iter().map(|a| a.0).collect(), r.heading)).collect();
    Run { front_ok: true, rendered, errors, findings, gate, table, table_text }
}

/// A crate: `root` (after the header; it declares its modules), the
/// `extra` files (paths relative to the root's directory), a `LAWS.rs`
/// with `laws` (after `use sandblaster::prelude::*;`) mounted as `mod laws`,
/// and, with `proofs`, a `PROOF.rs` mounted as `mod proof`. Without proofs
/// the laws are open claims: the rules do not need their proofs.
fn crate_with(root: &str, extra: &[(&str, &str)], laws: &str, proofs: Option<&str>) -> Run {
    let mut root_text = root.to_string();
    root_text.push_str("\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n");
    if proofs.is_some() {
        root_text.push_str("\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    }
    let mut files: Vec<(String, String)> = vec![("r/mod.rs".into(), root_text), ("r/LAWS.rs".into(), format!("use sandblaster::prelude::*;\n{laws}"))];
    if let Some(p) = proofs {
        files.push(("r/PROOF.rs".into(), format!("use sandblaster::prelude::*;\n{p}")));
    }
    for (p, t) in extra {
        files.push((format!("r/{p}"), t.to_string()));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    run_files(&refs)
}

/// A small verifier-like module: an exported predicate and helper, an
/// internal helper, an exec constant, an exported type with a public and a
/// crate-visible method.
const M: &str = r#"
use sandblaster::prelude::*;

pub const LIMIT: u32 = 10;

pub fn is_even(x: u32) -> bool { x % 2 == 0 }
pub fn halve(x: u32) -> u32 { x / 2 }
pub fn helper(x: u32) -> u32 { x / 2 }

#[derive(Clone, Copy)]
pub struct Counter { n: u32 }

impl Counter {
    pub fn get(self) -> u32 { self.n }
    pub(crate) fn raw(self) -> u32 { self.n }
}

#[derive(Clone, Copy)]
#[view(|w| w.lo as Nat + 1)]
pub struct Shifted { lo: u32 }
"#;

const M_ROOT: &str = "mod m;\npub use m::{is_even, halve, Counter};\n";

// ---------------------------------------------------------------------
// LR1 vocabulary, LR2 closure, LR3 state it over the spec
// ---------------------------------------------------------------------

#[test]
fn lr1_laws_mention_only_spec_items_and_exported_functions() {
    let r = crate_with(
        M_ROOT,
        &[("m.rs", M)],
        r#"use super::m::{is_even, halve, helper, Counter, Shifted, LIMIT};

/// Halving an exported value never grows it.
#[law]
fn exported_only(x: u32) {
    ensures(halve(x) <= x);
}

/// The public accessor of an exported type may be named.
#[law]
fn public_method(c: Counter, x: u32) {
    requires(c.get() == x);
    ensures(halve(c.get()) <= x);
}

/// The internal helper never grows its argument.
#[law]
fn internal_helper(x: u32) {
    ensures(helper(x) <= x);
}

/// Values below the limit stay below it.
#[law]
fn exec_constant(x: u32) {
    requires(x < LIMIT);
    ensures(halve(x) < LIMIT);
}

/// The raw count of a counter is its public count.
#[law]
fn crate_method(c: Counter) {
    ensures(is_even(c.raw()) == is_even(c.get()));
}

/// The stored value of a shifted number is below its meaning.
#[law]
fn reads_representation(s: Shifted, x: Nat) {
    requires(x == s.lo as Nat + 1);
    ensures((s.lo as Nat) < x);
}
"#,
        None,
    );
    r.front();
    r.lacks(LawRule::Lr1, "crate::laws::exported_only");
    r.lacks(LawRule::Lr1, "crate::laws::public_method");
    r.has(LawRule::Lr1, "crate::laws::internal_helper", "mentions the internal exec function `crate::m::helper`");
    r.has(LawRule::Lr1, "crate::laws::internal_helper", "#[refines(spec::");
    r.has(LawRule::Lr1, "crate::laws::internal_helper", "#[lemma]");
    r.has(LawRule::Lr1, "crate::laws::exec_constant", "mentions the exec constant `crate::m::LIMIT`");
    r.has(LawRule::Lr1, "crate::laws::crate_method", "`crate::m::Counter::raw`");
    assert_eq!(r.of(LawRule::Lr1, "crate::laws::crate_method").len(), 1, "{}", r.explain());
    // exec types are read through their views
    r.has(LawRule::Lr1, "crate::laws::reads_representation", "reads the field `lo` of the exec type `crate::m::Shifted`, whose meaning is its view");
    assert_eq!(r.of(LawRule::Lr1, "crate::laws::reads_representation").len(), 1, "{}", r.explain());
    r.lacks(LawRule::Lr1, "crate::laws::public_method");
    // recorded, not enforced: the build has no law-rule error
    assert!(!r.errors.iter().any(|(k, _)| *k == DiagKind::LawMentionsInternal), "{}", r.explain());
    // the gate reports each as an error
    assert!(r.gate.iter().any(|(e, k, m)| *e && *k == DiagKind::LawMentionsInternal && m.contains("crate::m::helper")), "{:?}", r.gate);
}

#[test]
fn lr1_lr2_through_spec_items() {
    let r = crate_with(
        r#"
mod m;
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;

#[refines(spec::triple)]
fn scale(x: u32) -> u64 { (x as u64) * 3 }
pub fn api(x: u32) -> u64 { scale(x) }
pub use m::halve;
"#,
        &[("m.rs", M), ("spec.rs", "pub fn triple(x: Nat) -> Nat { 3 * x }\n/// A spec function over an established exec function (spec closure allows it).\npub fn triple_plus(x: u32) -> Nat { super::scale(x) as Nat + 1 }\n")],
        r#"use super::m::{halve, helper};
use super::spec::triple_plus;

/// A legacy spec function that calls the implementation.
#[spec]
fn halved(x: u32) -> u32 { helper(x) }

/// Halving through a spec function that calls the implementation.
#[law]
fn through_legacy_spec(x: u32) {
    ensures(halved(x) <= x);
}

/// Tripling plus one is positive.
#[law]
fn through_established(x: u32) {
    ensures(triple_plus(x) > 0);
}

/// Halving an exported value never grows it.
#[law]
fn clean(x: u32) {
    ensures(halve(x) <= x);
}
"#,
        None,
    );
    r.front();
    // spec closure (LR2): the spec item reaches an unestablished function
    r.has(LawRule::Lr2, "crate::laws::through_legacy_spec", "depends on the exec function `crate::m::helper` through the spec item `crate::laws::halved`, which is not spec-closed");
    r.has(LawRule::Lr2, "crate::laws::through_legacy_spec", "transcribe what `crate::laws::halved` needs into `spec::`");
    r.lacks(LawRule::Lr1, "crate::laws::through_legacy_spec");
    // vocabulary (LR1): an established internal function is allowed by
    // spec closure but not in a law
    r.has(LawRule::Lr1, "crate::laws::through_established", "depends on the internal exec function `crate::scale` through the spec item `crate::spec::triple_plus`");
    r.lacks(LawRule::Lr2, "crate::laws::through_established");
    r.lacks(LawRule::Lr1, "crate::laws::clean");
    r.lacks(LawRule::Lr2, "crate::laws::clean");
    assert!(r.gate.iter().any(|(e, k, _)| *e && *k == DiagKind::SpecDependsOnImpl), "{:?}", r.gate);
}

#[test]
fn lr3_laws_over_refining_functions_are_stated_over_the_spec() {
    let root = r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;

#[refines(spec::half)]
pub fn halve(x: u32) -> u32 { x / 2 }
"#;
    let spec = ("spec.rs", "/// Half, rounded down.\n#[example(half(5) == 2)]\npub fn half(x: Nat) -> Nat { x / 2 }\n");
    let r = crate_with(
        root,
        &[spec],
        r#"use super::halve;
use super::spec::half;

/// Halving never grows the value.
#[law]
fn over_the_code(x: u32) {
    ensures(halve(x) <= x);
}

/// Half never grows the value.
#[law]
fn over_the_spec(x: Nat) {
    ensures(half(x) <= x);
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr3, "crate::laws::over_the_code", "mentions `crate::halve`, which refines `crate::spec::half`: state it over `crate::spec::half`");
    r.lacks(LawRule::Lr3, "crate::laws::over_the_spec");
    // a warning, never an error
    assert!(r.gate.iter().any(|(e, k, _)| !*e && *k == DiagKind::LawBypassesRefinement), "{:?}", r.gate);
    assert!(!r.gate.iter().any(|(e, k, _)| *e && *k == DiagKind::LawBypassesRefinement), "{:?}", r.gate);
}

// ---------------------------------------------------------------------
// LR4 closed disjuncts, extraction form
// ---------------------------------------------------------------------

const BREAK_SPEC: &str = r#"
/// A pair of different messages with one digest (a stub digest: the length).
pub fn collision(c: Option<(Seq<u8>, Seq<u8>)>) -> bool {
    match c {
        Some((x, y)) => x != y && x.len() == y.len(),
        None => false,
    }
}

/// The first two different messages among `a`, `b`.
pub fn pair(a: Seq<u8>, b: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> {
    if a == b { None } else { Some((a, b)) }
}

/// Some property of two messages.
pub fn same(a: Seq<u8>, b: Seq<u8>) -> bool { a == b }

/// A proposition (not a computed break).
pub fn clashes(a: Seq<u8>, b: Seq<u8>) -> Prop { a != b && a.len() == b.len() }

/// Finding a collision is infeasible.
#[assumption(class = computational, cite = "stub hash collision resistance")]
pub fn collision_resistance() {}

/// Not an assumption.
pub fn not_an_assumption() {}

pub const M: Nat = 3;
"#;

const BREAK_ROOT: &str = "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::halve;\n";

#[test]
fn lr4_closed_disjuncts_and_conjuncts() {
    let m = "use sandblaster::prelude::*;\npub fn halve(x: u32) -> u32 { x / 2 }\n#[requires(x > 0 && super::LOW > 0)]\npub fn dec(x: u32) -> u32 { x - 1 }\n#[ensures(|r: u32| r <= x || super::LOW == 3)]\npub fn keep(x: u32) -> u32 { x }\n#[requires(true)]\n#[ensures(|r: u32| true)]\npub fn placeholder(x: u32) -> u32 { x }\n";
    let r = crate_with(
        "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::halve;\nconst LOW: u32 = 3;\n",
        &[("m.rs", m), ("spec.rs", BREAK_SPEC)],
        r#"use super::m::halve;
use super::spec::M;

/// Halving never grows the value, or three is three.
#[law]
fn closed_disjunct(x: u32) {
    ensures(halve(x) <= x || M == 3);
}

/// Under a closed hypothesis, halving never grows the value.
#[law]
fn closed_conjunct(x: u32) {
    requires(x > 1 && M > 2);
    ensures(halve(x) < x);
}

/// A closed law is an example.
#[law]
fn closed_law() {
    ensures(M + 1 == 4);
}

/// Halving never grows the value.
#[law]
fn open_parts(x: u32) {
    requires(x > 1);
    ensures(halve(x) < x || halve(x) == x);
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr4, "crate::laws::closed_disjunct", "a disjunct of the conclusion of law `crate::laws::closed_disjunct` mentions none of its binders");
    r.has(LawRule::Lr4, "crate::laws::closed_conjunct", "a hypothesis of law `crate::laws::closed_conjunct` mentions none of its binders");
    assert_eq!(r.of(LawRule::Lr4, "crate::laws::closed_conjunct").len(), 1, "{}", r.explain());
    r.has(LawRule::Lr4, "crate::laws::closed_law", "a closed law is an `#[example]`");
    r.lacks(LawRule::Lr4, "crate::laws::open_parts");
    // contracts too: a closed conjunct of a `requires`, a closed disjunct
    // of an `ensures`
    r.has(LawRule::Lr4, "crate::m::dec", "a hypothesis of the contract of `crate::m::dec`");
    r.has(LawRule::Lr4, "crate::m::keep", "a disjunct of the conclusion of the contract of `crate::m::keep`");
    // a contract's literal `true` is a placeholder, not a claim
    r.lacks(LawRule::Lr4, "crate::m::placeholder");
    assert!(r.gate.iter().any(|(e, k, _)| *e && *k == DiagKind::VacuousReduction), "{:?}", r.gate);
}

#[test]
fn lr4_extraction_form_of_reduces_to() {
    let r = crate_with(
        BREAK_ROOT,
        &[("m.rs", "use sandblaster::prelude::*;\npub fn halve(x: u32) -> u32 { x / 2 }\npub(crate) fn bytes(x: u32) -> u8 { x as u8 }\n"), ("spec.rs", BREAK_SPEC)],
        r#"use super::m::bytes;
use super::spec::{clashes, collision, collision_resistance, not_an_assumption, pair, same};

/// Two messages are the same, or they collide.
#[law]
#[reduces_to(collision_resistance)]
fn extraction_form(a: Seq<u8>, b: Seq<u8>) {
    requires(a.len() == b.len());
    ensures(same(a, b) || collision(pair(a, b)));
}

/// Two messages are the same, or some collision exists.
#[law]
#[reduces_to(collision_resistance)]
fn closed_exists(a: Seq<u8>, b: Seq<u8>) {
    requires(a.len() == b.len());
    ensures(same(a, b) || exists(|x: Seq<u8>, y: Seq<u8>| collision(pair(x, y))));
}

/// Two messages are the same, or they clash (a proposition).
#[law]
#[reduces_to(collision_resistance)]
fn prop_break(a: Seq<u8>, b: Seq<u8>) {
    requires(a.len() == b.len());
    ensures(same(a, b) || clashes(a, b));
}

/// Two messages are the same.
#[law]
#[reduces_to(collision_resistance)]
fn no_break(a: Seq<u8>, b: Seq<u8>) {
    requires(a.len() == b.len() && collision(pair(a, b)) == false);
    ensures(same(a, b));
}

/// Two numbers are equal, or the implementation's bytes collide.
#[law]
#[reduces_to(collision_resistance)]
fn not_spec_closed(x: u32, y: u32) {
    ensures(x == y || collision(pair(seq![bytes(x)], seq![bytes(y)])));
}

/// Two messages are the same, or they collide.
#[law]
#[reduces_to(not_an_assumption)]
fn names_no_assumption(a: Seq<u8>, b: Seq<u8>) {
    requires(a.len() == b.len());
    ensures(same(a, b) || collision(pair(a, b)));
}
"#,
        None,
    );
    r.front();
    r.lacks(LawRule::Lr4, "crate::laws::extraction_form");
    r.lacks(LawRule::Lr9, "crate::laws::extraction_form");
    r.has(LawRule::Lr4, "crate::laws::closed_exists", "the break disjunct of law `crate::laws::closed_exists` is an `exists`");
    r.has(LawRule::Lr4, "crate::laws::closed_exists", "pigeonhole");
    r.has(LawRule::Lr4, "crate::laws::prop_break", "is a proposition (`-> Prop`)");
    r.has(LawRule::Lr4, "crate::laws::no_break", "has no break disjunct");
    r.has(LawRule::Lr4, "crate::laws::not_spec_closed", "are not spec-closed: they use the exec item `crate::m::bytes`");
    // LR9: `#[reduces_to]` names an `#[assumption]`
    r.has(LawRule::Lr9, "crate::laws::names_no_assumption", "names `crate::spec::not_an_assumption`, which is not an `#[assumption]`");
    r.lacks(LawRule::Lr4, "crate::laws::names_no_assumption");
    // the table lists the assumption with its class and citation
    let row = r.table.iter().find(|t| t.0 == "crate::laws::extraction_form").expect("row");
    assert_eq!(row.2, vec!["crate::spec::collision_resistance".to_string()]);
    assert!(r.table_text.iter().any(|l| l.contains("`laws::extraction_form`") && l.contains("computational: stub hash collision resistance")), "{:?}", r.table_text);
}

#[test]
fn assumptions_have_no_logical_content() {
    let r = crate_with(
        "#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub fn f(x: u32) -> u32 { x }\n",
        &[("spec.rs", "#[assumption(class = statistical, cite = \"a bias bound\")]\npub fn with_body() { let x = 1; }\n")],
        "",
        None,
    );
    r.front();
    assert!(r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("`#[assumption]` `crate::spec::with_body` has a body")), "{}", r.explain());
    let r = crate_with("#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n", &[("spec.rs", "#[assumption(class = computational, cite = \"x\")]\npub fn with_params(n: Nat) {}\n")], "", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("no logical content")), "{}", r.explain());
    let r = crate_with("#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n", &[("spec.rs", "#[assumption(class = hopeful, cite = \"x\")]\npub fn a() {}\n")], "", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("`class` must be")), "{}", r.explain());
    // `#[assumption]` only on spec functions
    let r = crate_with("#[assumption(class = computational, cite = \"x\")]\npub fn f(x: u32) -> u32 { x }\n", &[], "", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("`#[assumption]` is not allowed on an exec function")), "{}", r.explain());
}

// ---------------------------------------------------------------------
// LR5 mirrors against every function
// ---------------------------------------------------------------------

#[test]
fn lr5_spec_functions_are_compared_with_every_exec_function() {
    let root = r#"
mod m;
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
pub use m::{step, round};
"#;
    let m = "use sandblaster::prelude::*;\npub fn step(x: u32, y: u32) -> u32 { (x & y) ^ (!x & y.rotate_right(3)) }\npub fn round(x: u32) -> u32 { x.wrapping_mul(3) }\n";
    let spec = r#"
/// A copy of `crate::m::step` (not its refinement target).
#[example(copied(1, 2) == copied(1, 2))]
pub fn copied(x: u32, y: u32) -> u32 { (x & y) ^ (!x & y.rotate_right(3)) }

/// The same body, declared: a locked claim with an independent example.
#[mirrors_impl(of = crate::m::step, justification = "a one-line formula")]
#[example(declared(3, 5) == 2684354561)]
pub fn declared(x: u32, y: u32) -> u32 { (x & y) ^ (!x & y.rotate_right(3)) }

/// Declared, but about the wrong function.
#[mirrors_impl(of = crate::m::round, justification = "wrong target")]
#[example(misdeclared(3, 5) == 2684354561)]
pub fn misdeclared(x: u32, y: u32) -> u32 { (x & y) ^ (!x & y.rotate_right(3)) }

/// A different body.
pub fn different(x: u32, y: u32) -> u32 { (x | y) ^ y.rotate_right(3) }
"#;
    let r = crate_with(root, &[("m.rs", m), ("spec.rs", spec)], "", None);
    r.front();
    r.has(LawRule::Lr5, "crate::spec::copied", "spec function `crate::spec::copied` is a copy of the exec function `crate::m::step`");
    r.has(LawRule::Lr5, "crate::spec::copied", "#[mirrors_impl(of = crate::m::step, justification = \"..\")]");
    r.lacks(LawRule::Lr5, "crate::spec::declared");
    r.has(LawRule::Lr5, "crate::spec::misdeclared", "copy of the exec function `crate::m::step`");
    r.lacks(LawRule::Lr5, "crate::spec::different");
    assert!(r.gate.iter().any(|(e, k, _)| *e && *k == DiagKind::SpecMirrorsImpl), "{:?}", r.gate);
}

/// LR5 compares code, not proofs (its hash erases the proofs a body's
/// checked operations carry, so helpers with large proofs inline cheaply):
/// a spec copying an exec function with a checked `+` is still a copy, and
/// a different body is not.
#[test]
fn lr5_compares_code_not_proofs() {
    let root = "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::inc;\n";
    let m = "use sandblaster::prelude::*;\npub fn inc(x: u8) -> u16 { (x as u16) + 1 }\n";
    let spec = "/// A copy of `crate::m::inc`.\n#[example(copied(1u8) == 2u16)]\npub fn copied(x: u8) -> u16 { (x as u16) + 1 }\n\n/// A different body.\n#[example(other(1u8) == 3u16)]\npub fn other(x: u8) -> u16 { (x as u16) + 2 }\n";
    let r = crate_with(root, &[("m.rs", m), ("spec.rs", spec)], "", None);
    r.front();
    r.has(LawRule::Lr5, "crate::spec::copied", "copy of the exec function `crate::m::inc`");
    r.lacks(LawRule::Lr5, "crate::spec::other");
}

// ---------------------------------------------------------------------
// LR6 laws that restate
// ---------------------------------------------------------------------

const RESTATE_ROOT: &str = r#"
mod m;
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
pub use m::{is_even, accept};
"#;

const RESTATE_M: &str = r#"
use sandblaster::prelude::*;
pub fn is_even(x: u32) -> bool { x % 2 == 0 }
pub fn accept(tag: u32, key: u32) -> bool { tag == key.wrapping_add(1) && key % 2 == 0 }
"#;

const RESTATE_SPEC: &str = r#"
/// Evenness.
#[example(even(4))]
#[example(!even(3))]
pub fn even(x: Nat) -> bool { x % 2 == 0 }

/// Twice.
#[example(double(3) == 6)]
pub fn double(x: Nat) -> Nat { 2 * x }

/// The sum of `0..=n`.
#[decreases(n)]
#[example(sum(3) == 6)]
pub fn sum(n: Nat) -> Nat { if n == 0 { 0 } else { n + sum(n - 1) } }
"#;

#[test]
fn lr6_echo_laws_are_rejected_with_their_unfolding() {
    let r = crate_with(
        RESTATE_ROOT,
        &[("m.rs", RESTATE_M), ("spec.rs", RESTATE_SPEC)],
        r#"use super::m::{is_even, accept};
use super::spec::{even, double, sum};

/// Every accepted number is even (by the definition of the predicate).
#[law]
fn restates_the_check(x: u32) {
    requires(is_even(x));
    ensures(x % 2 == 0);
}

/// An accepted tag is one more than its key, which is even.
#[law]
fn restates_the_guard(tag: u32, key: u32) {
    requires(accept(tag, key));
    ensures(key % 2 == 0);
}

/// A definition, stated on purpose.
#[law]
#[definitional(reason = "documents the encoding of evenness for readers of the spec")]
fn stated_on_purpose(x: u32) {
    requires(is_even(x));
    ensures(x % 2 == 0);
}

/// The exact characterization of the predicate (needs arithmetic across the view).
#[law]
fn characterization(x: u32) {
    requires(is_even(x));
    ensures(even(x as Nat));
}

/// Doubling a small number stays small (needs arithmetic).
#[law]
fn arithmetic(x: Nat) {
    requires(x < 10);
    ensures(double(x) < 20);
}

/// The sum of `0..=n` is at least `n` (needs induction).
#[law]
fn induction(n: Nat) {
    ensures(sum(n) >= n);
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr6Echo, "crate::laws::restates_the_check", "restates its definitions");
    r.has(LawRule::Lr6Echo, "crate::laws::restates_the_check", "unfolded once: `m::is_even`");
    r.has(LawRule::Lr6Echo, "crate::laws::restates_the_check", "after the unfolding the law reads: ((x % 2u32) == 0u32) ⊢ (x % 2u32) == 0u32");
    r.has(LawRule::Lr6Echo, "crate::laws::restates_the_check", "#[definitional(reason = \"..\")]");
    r.has(LawRule::Lr6Echo, "crate::laws::restates_the_guard", "unfolded once: `m::accept`");
    r.lacks(LawRule::Lr6Echo, "crate::laws::stated_on_purpose");
    r.lacks(LawRule::Lr6Echo, "crate::laws::characterization");
    r.lacks(LawRule::Lr6Echo, "crate::laws::arithmetic");
    r.lacks(LawRule::Lr6Echo, "crate::laws::induction");
    assert!(r.gate.iter().any(|(e, k, m)| *e && *k == DiagKind::LawRestatesImpl && m.contains("restates_the_check")), "{:?}", r.gate);
    // a definitional law is printed under its own heading, never as a guarantee
    let row = r.table.iter().find(|t| t.0 == "crate::laws::stated_on_purpose").expect("row");
    assert!(matches!(&row.3, LawHeading::Definitional(reason) if reason.contains("encoding of evenness")), "{:?}", row.3);
    let defs = r.table_text.iter().position(|l| l.starts_with("Definitional laws")).expect("heading");
    let at = r.table_text.iter().position(|l| l.contains("stated_on_purpose")).expect("listed");
    assert!(at > defs, "{:?}", r.table_text);
}

#[test]
fn lr6_resemblance_to_an_exec_body_is_a_warning() {
    let m = r#"
use sandblaster::prelude::*;
pub fn mix(a: u32, b: u32) -> u32 { ((a ^ b).rotate_left(5).wrapping_add(a & b)).wrapping_mul(0x9e37u32) ^ (b >> 3u32) }
pub fn gate(a: u32) -> bool { a > 7 }
"#;
    let r = crate_with(
        "mod m;\npub use m::{mix, gate};\n",
        &[("m.rs", m)],
        r#"use super::m::gate;

/// When the gate opens, the mixed value of the pair is not zero.
#[law]
fn transcribes_the_mixer(a: u32, b: u32) {
    requires(gate(a));
    ensures((((a ^ b).rotate_left(5).wrapping_add(a & b)).wrapping_mul(0x9e37u32) ^ (b >> 3u32)) != 0);
}

/// When the gate opens, the value is large.
#[law]
fn short(a: u32) {
    requires(gate(a));
    ensures(a > 3);
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr6Resemblance, "crate::laws::transcribes_the_mixer", "resembles the implementation");
    r.has(LawRule::Lr6Resemblance, "crate::laws::transcribes_the_mixer", "also occurs in the body of `crate::m::mix`");
    r.lacks(LawRule::Lr6Resemblance, "crate::laws::short");
    assert!(r.gate.iter().any(|(e, k, _)| !*e && *k == DiagKind::LawResemblesImpl), "{:?}", r.gate);
}

// ---------------------------------------------------------------------
// LR7 corollaries
// ---------------------------------------------------------------------

#[test]
fn lr7_laws_proven_from_other_laws_alone() {
    let root = "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::halve;\n";
    let m = "use sandblaster::prelude::*;\npub fn halve(x: u32) -> u32 { x / 2 }\n";
    let spec = "/// Half.\n#[example(half(5) == 2)]\npub fn half(x: Nat) -> Nat { x / 2 }\n";
    let laws = r#"use super::spec::half;

/// Half never grows its argument.
#[law]
fn half_le(x: Nat) {
    ensures(half(x) <= x);
}

/// Half of a positive number is smaller.
#[law]
fn half_lt(x: Nat) {
    requires(x > 0);
    ensures(half(x) < x);
}

/// Half never grows a positive argument.
#[law]
fn from_laws(x: Nat) {
    requires(x > 0);
    ensures(half(x) <= x);
}

/// Half never grows a positive argument (marked).
#[law]
#[corollary]
fn marked(x: Nat) {
    requires(x > 0);
    ensures(half(x) <= x);
}
"#;
    // a proof applies another law through its proof item (the validator
    // rewrites the application to the law)
    let proofs = r#"use super::spec::half;

#[proof]
fn half_le(x: Nat) {
    follows();
}

#[proof]
fn half_lt(x: Nat) {
    follows();
}

#[proof]
fn from_laws(x: Nat) {
    apply(half_le);
}

#[proof]
fn marked(x: Nat) {
    apply(half_le);
}
"#;
    let r = crate_with(root, &[("m.rs", m), ("spec.rs", spec)], laws, Some(proofs));
    r.front();
    r.has(LawRule::Lr7, "crate::laws::from_laws", "law `crate::laws::from_laws` follows from the laws `crate::laws::half_le` alone");
    r.has(LawRule::Lr7, "crate::laws::from_laws", "#[corollary]");
    r.lacks(LawRule::Lr7, "crate::laws::marked");
    r.lacks(LawRule::Lr7, "crate::laws::half_le");
    r.lacks(LawRule::Lr7, "crate::laws::half_lt");
    assert!(r.gate.iter().any(|(e, k, _)| !*e && *k == DiagKind::LawCorollary), "{:?}", r.gate);
    // the corollary is printed under the law it follows from
    let row = r.table.iter().find(|t| t.0 == "crate::laws::marked").expect("row");
    assert_eq!(row.3, LawHeading::Corollary(vec!["crate::laws::half_le".to_string()]));
    let parent = r.table_text.iter().position(|l| l.contains("`laws::half_le`")).expect("parent");
    assert!(r.table_text[parent + 1].contains("↳ corollary `laws::marked`"), "{:?}", r.table_text);
}

// ---------------------------------------------------------------------
// LR9 readable, the law table
// ---------------------------------------------------------------------

#[test]
fn lr9_every_law_states_its_guarantee_in_words() {
    let r = crate_with(
        "mod m;\npub use m::halve;\n",
        &[("m.rs", "use sandblaster::prelude::*;\npub fn halve(x: u32) -> u32 { x / 2 }\n")],
        r#"use super::m::halve;

#[law]
fn undocumented(x: u32) {
    ensures(halve(x) <= x);
}

/// Halve le.
#[law]
fn halve_le(x: u32) {
    ensures(halve(x) <= x);
}

/// `halve(x) <= x`.
#[law]
fn only_code(x: u32) {
    ensures(halve(x) <= x);
}

/// Halving never makes a number larger. It is used by the bound checks.
///
/// A second paragraph.
#[law]
fn documented(x: u32) {
    ensures(halve(x) <= x);
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr9, "crate::laws::undocumented", "has no doc comment stating its guarantee");
    r.has(LawRule::Lr9, "crate::laws::halve_le", "does not state a guarantee in words: \"Halve le.\"");
    r.has(LawRule::Lr9, "crate::laws::only_code", "does not state a guarantee in words");
    r.lacks(LawRule::Lr9, "crate::laws::documented");
    let row = r.table.iter().find(|t| t.0 == "crate::laws::documented").expect("row");
    assert_eq!(row.1.as_deref(), Some("Halving never makes a number larger."));
    assert!(row.2.is_empty());
    assert_eq!(r.table_text[0], "| law | guarantee | assumes |");
    assert!(r.table_text.iter().any(|l| l == "| `laws::documented` | Halving never makes a number larger. | nothing |"), "{:?}", r.table_text);
    assert!(r.table_text.iter().any(|l| l.contains("`laws::undocumented` | (no doc comment)")), "{:?}", r.table_text);
    assert!(r.gate.iter().any(|(e, k, _)| *e && *k == DiagKind::LawUndocumented), "{:?}", r.gate);
}

#[test]
fn guarantee_sentences() {
    let s = |d: &[&str]| law_rules::guarantee_sentence(&d.iter().map(|x| x.to_string()).collect::<Vec<_>>());
    assert_eq!(s(&[]), None);
    assert_eq!(s(&[" ", " First part", " continues. Second."]).as_deref(), Some("First part continues."));
    assert_eq!(s(&[" Uses `a.b` inside. Next."]).as_deref(), Some("Uses `a.b` inside."));
    assert_eq!(s(&[" No period at all"]).as_deref(), Some("No period at all"));
    assert!(law_rules::states_guarantee("Every accepted proof is honest.", "sound"));
    assert!(!law_rules::states_guarantee("Digest equal sound.", "digest_equal_sound"));
    assert!(!law_rules::states_guarantee("`f(x) == g(x)`.", "eq"));
    assert!(!law_rules::states_guarantee("Holds.", "h"));
}

// ---------------------------------------------------------------------
// LR10 both directions
// ---------------------------------------------------------------------

#[test]
fn lr10_boolean_exported_functions_need_both_directions() {
    let root = r#"
mod m;
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
pub use m::{sound_only, complete_only, both, refined, refined_one_way};
"#;
    let m = r#"
use sandblaster::prelude::*;
pub fn sound_only(x: u32) -> bool { x > 3 }
pub fn complete_only(x: u32) -> bool { x > 3 }
pub fn both(x: u32) -> bool { x > 3 }
#[refines(crate::spec::big)]
pub fn refined(x: u32) -> bool { x > 3 }
#[refines(crate::spec::big2)]
pub fn refined_one_way(x: u32) -> bool { x > 3 }
"#;
    let spec = "/// Big.\n#[example(big(4))]\n#[example(!big(3))]\npub fn big(x: u32) -> bool { x > 3 }\n/// Big too.\n#[example(big2(4))]\n#[example(!big2(3))]\npub fn big2(x: u32) -> bool { 3 < x }\n";
    let r = crate_with(
        root,
        &[("m.rs", m), ("spec.rs", spec)],
        r#"use super::m::{sound_only, complete_only, both};
use super::spec::{big, big2};

/// An accepted number exceeds two.
#[law]
fn sound(x: u32) {
    requires(sound_only(x));
    ensures(x > 2);
}

/// Every number above five is accepted.
#[law]
fn complete(x: u32) {
    requires(x > 5);
    ensures(complete_only(x));
}

/// An accepted number exceeds two.
#[law]
fn both_sound(x: u32) {
    requires(both(x));
    ensures(x > 2);
}

/// A rejected number is at most five.
#[law]
fn both_complete(x: u32) {
    requires(!both(x));
    ensures(x <= 5);
}

/// Exactly the numbers above three are big.
#[law]
fn spec_both(x: u32) {
    ensures(iff(big(x), x > 3));
}

/// A big number (the other spec) exceeds two.
#[law]
fn spec_one_way(x: u32) {
    requires(big2(x));
    ensures(x > 2);
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr10, "crate::m::sound_only", "only in hypotheses: nothing states when it is true");
    r.has(LawRule::Lr10, "crate::m::complete_only", "only in conclusions: nothing states when it is false");
    // `!both(x)` in a hypothesis states when it is false: both directions
    r.lacks(LawRule::Lr10, "crate::m::both");
    // through the refinement target
    r.lacks(LawRule::Lr10, "crate::m::refined");
    r.has(LawRule::Lr10, "crate::m::refined_one_way", "(or its refinement target `crate::spec::big2`) only in hypotheses");
    assert!(r.gate.iter().any(|(e, k, _)| !*e && *k == DiagKind::OneDirectionalLaws), "{:?}", r.gate);
}

// ---------------------------------------------------------------------
// the gate, and the misuse of the annotations
// ---------------------------------------------------------------------

#[test]
fn the_gate_reports_hard_rules_as_errors_and_the_others_as_warnings() {
    for rule in LawRule::ALL {
        let hard = matches!(rule, LawRule::Lr1 | LawRule::Lr2 | LawRule::Lr4 | LawRule::Lr5 | LawRule::Lr6Echo | LawRule::Lr9);
        assert_eq!(rule.hard(), hard, "{}", rule.code());
    }
    assert_eq!(LawRule::Lr1.kind().code(), "law-mentions-internal");
    assert_eq!(LawRule::Lr2.kind().code(), "spec-depends-on-impl");
    assert_eq!(LawRule::Lr3.kind().code(), "law-bypasses-refinement");
    assert_eq!(LawRule::Lr4.kind().code(), "vacuous-reduction");
    assert_eq!(LawRule::Lr5.kind().code(), "spec-mirrors-impl");
    assert_eq!(LawRule::Lr6Echo.kind().code(), "law-restates-impl");
    assert_eq!(LawRule::Lr6Resemblance.kind().code(), "law-resembles-impl");
    assert_eq!(LawRule::Lr7.kind().code(), "law-corollary");
    assert_eq!(LawRule::Lr9.kind().code(), "law-undocumented");
    assert_eq!(LawRule::Lr10.kind().code(), "one-directional-laws");
}

#[test]
fn misused_law_rule_annotations_are_errors_now() {
    let spec = ("spec.rs", "#[assumption(class = computational, cite = \"x\")]\npub fn a() {}\n");
    let root = "#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub fn f(x: u32) -> u32 { x }\n";
    let r = crate_with(root, &[spec], "/// Always.\n#[law]\n#[corollary(of = x)]\nfn c(x: u32) { ensures(x == x); }\n", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("expected `#[corollary]`")), "{}", r.explain());
    let r = crate_with(root, &[spec], "/// Always.\n#[law]\n#[definitional]\nfn d(x: u32) { ensures(x == x); }\n", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("`#[definitional(reason = \"..\")]`")), "{}", r.explain());
    let r = crate_with(root, &[spec], "/// Always.\n#[law]\n#[reduces_to(super::f)]\nfn e(x: u32) { ensures(x == x); }\n", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("`#[reduces_to(..)]` must name a spec function")), "{}", r.explain());
    let r = crate_with("#[corollary]\npub fn f(x: u32) -> u32 { x }\n", &[], "", None);
    assert!(!r.front_ok && r.errors.iter().any(|(k, m)| *k == DiagKind::Attribute && m.contains("`#[corollary]` is not allowed on an exec function")), "{}", r.explain());
    let r = crate_with(root, &[("spec.rs", "#[mirrors_impl(of = crate::nope, justification = \"j\")]\npub fn g(x: u32) -> u32 { x }\n")], "", None);
    assert!(!r.front_ok, "{}", r.explain());
}

// ---------------------------------------------------------------------
// the draft QMDB laws (docs/qmdb-spec-design.md §2.2)
// ---------------------------------------------------------------------

/// The ```rust block of §2.2 of the design document, verbatim.
fn draft_laws() -> String {
    let doc = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/docs/qmdb-spec-design.md")).expect("docs/qmdb-spec-design.md");
    let start = doc.find("### 2.2 `LAWS.rs`").expect("§2.2");
    let block = &doc[start..];
    let open = block.find("```rust\n").expect("a rust block") + "```rust\n".len();
    let close = block[open..].find("```").expect("end of the block");
    block[open..open + close].to_string()
}

/// The fixture crate with `laws` as its `LAWS.rs`, as in-memory files.
fn draft_files(laws: &str) -> Vec<(String, String)> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/qmdb_laws_draft");
    let mut files = vec![("r/mod.rs".to_string(), std::fs::read_to_string(base.join("mod.rs")).unwrap())];
    files.push(("r/LAWS.rs".to_string(), laws.to_string()));
    files.push(("r/verifier.rs".to_string(), std::fs::read_to_string(base.join("verifier.rs")).unwrap()));
    let mut spec: Vec<_> = std::fs::read_dir(base.join("spec")).unwrap().map(|e| e.unwrap().path()).collect();
    spec.sort();
    for p in spec {
        files.push((format!("r/spec/{}", p.file_name().unwrap().to_str().unwrap()), std::fs::read_to_string(&p).unwrap()));
    }
    files
}

const DRAFT_LAWS: [&str; 5] = ["current_updates_have_proofs", "verified_updates_are_current", "one_proof_per_location", "proofs_have_one_encoding", "verified_proofs_are_small"];

#[test]
fn draft_qmdb_laws_pass_every_rule() {
    let laws = draft_laws();
    for l in DRAFT_LAWS {
        assert!(laws.contains(&format!("fn {l}(")), "{l} not in the draft:\n{laws}");
    }
    let r = run_owned(draft_files(&laws));
    r.front();
    // no finding of any rule: not on the laws, the spec items, or `verify`
    assert!(r.findings.is_empty(), "the draft laws fail a rule:\n{}", r.explain());
    assert!(r.gate.is_empty(), "{:?}", r.gate);
    // the table: five guarantees, two of them assuming collision resistance
    assert_eq!(r.table.len(), 5, "{}", r.explain());
    for (path, guarantee, assumes, heading) in &r.table {
        assert_eq!(*heading, LawHeading::Guarantee, "{path}");
        let name = path.rsplit("::").next().unwrap();
        assert!(guarantee.as_deref().is_some_and(|g| law_rules::states_guarantee(g, name)), "{path}: {guarantee:?}");
        let reduced = name == "verified_updates_are_current" || name == "one_proof_per_location";
        assert_eq!(assumes.clone(), if reduced { vec!["crate::spec::sha256::collision_resistance".to_string()] } else { vec![] }, "{path}");
    }
    assert!(r.table_text.iter().any(|l| l.starts_with("| `laws::verified_updates_are_current` | Sound: if a proof verifies against a database's root") && l.ends_with("(computational: SHA-256 collision resistance; NIST SP 800-107 Rev. 1, §4.1) |")), "{:?}", r.table_text);
}

#[test]
fn draft_qmdb_laws_rules_bite_on_mutations() {
    let laws = draft_laws();
    // a closed break disjunct (LR4)
    let closed = laws.replace("|| collision(clash(p1.tree(update(k1, v1)), p2.tree(update(k2, v2)))));", "|| exists(|x: Seq<u8>, y: Seq<u8>| collision(Some((x, y)))));");
    assert_ne!(closed, laws);
    let r = run_owned(draft_files(&closed));
    r.front();
    r.has(LawRule::Lr4, "crate::laws::one_proof_per_location", "is an `exists`");
    // the completeness law removed: `verify` is mentioned in hypotheses only
    let start = laws.find("/// Complete:").unwrap();
    let end = laws.find("/// Sound:").unwrap();
    let sound_only = format!("{}{}", &laws[..start], &laws[end..]);
    let r = run_owned(draft_files(&sound_only));
    r.front();
    r.has(LawRule::Lr10, "crate::verifier::verify", "(or its refinement target `crate::spec::proof::verify`) only in hypotheses");
    r.has(LawRule::Lr10, "crate::verifier::verify_fixed", "only in hypotheses");
    // an undocumented law (LR9)
    let doc_start = laws.find("/// Bounded").unwrap();
    let doc_end = laws[doc_start..].find("#[law]").unwrap() + doc_start;
    let undocumented = format!("{}{}", &laws[..doc_start], &laws[doc_end..]);
    let r = run_owned(draft_files(&undocumented));
    r.front();
    r.has(LawRule::Lr9, "crate::laws::verified_proofs_are_small", "has no doc comment");
}

// ---------------------------------------------------------------------
// QMDB's LAWS.rs: the fully specified QMDB passes every rule, its proofs check
// ---------------------------------------------------------------------

#[path = "common/qmdb.rs"]
mod qmdb;

/// QMDB's own `LAWS.rs` (the production root `mod.rs`, N = 32, with every
/// file it mounts: `qmdb::crate_files`). Until 2026-09 the fixture had the
/// legacy laws (13 laws restating the code, docs/qmdb-spec-design.md §1),
/// which this test showed failing the rules only through the gate; §15 S5
/// replaced them with the five laws of the design's §2.2 (the draft above,
/// over the real `spec/` and proven by `PROOF.rs`). The fixture's proofs
/// check and the gate reports no error; what the rules record are LR6 (b)
/// resemblance warnings only (a subterm of the real spec's statements of
/// 15 or 17 kernel nodes also occurs in `merkle::path_node` and
/// `sha256::equal`; the draft over stub spec items has none), and the
/// table is the draft's with the two laws of `spec/tree.rs`. (Elaborates
/// all of QMDB: about twelve minutes.)
#[test]
fn qmdb_laws_pass_every_rule() {
    let r = run_owned(qmdb::crate_files("mod.rs"));
    r.front();
    // the build itself: no error at all (the laws and refinements verify)
    assert!(r.errors.is_empty(), "{}", r.explain());
    // no error-level finding of any rule: not on the laws, the spec items,
    // or `verify`; the resemblance warnings name the two exec functions
    assert!(!r.gate.iter().any(|(e, _, _)| *e), "{:?}", r.gate);
    for f in &r.findings {
        assert!(f.rule == LawRule::Lr6Resemblance && (f.msg.contains("`crate::merkle::path_node`") || f.msg.contains("`crate::sha256::equal`")), "QMDB's laws fail a rule:\n{}", r.explain());
    }
    // the table: the draft's five guarantees, two of them assuming collision
    // resistance, and the two laws of `spec/tree.rs` (why one root binds,
    // docs/qmdb-spec-design.md §2.4)
    assert_eq!(r.table.len(), 7, "{}", r.explain());
    for (path, guarantee, assumes, heading) in &r.table {
        assert_eq!(*heading, LawHeading::Guarantee, "{path}");
        let name = path.rsplit("::").next().unwrap();
        assert!(DRAFT_LAWS.contains(&name) || ["agreeing_trees_have_one_root", "equal_roots_agree"].contains(&name), "{path}");
        assert!(guarantee.as_deref().is_some_and(|g| law_rules::states_guarantee(g, name)), "{path}: {guarantee:?}");
        let reduced = name == "verified_updates_are_current" || name == "one_proof_per_location";
        assert_eq!(assumes.clone(), if reduced { vec!["crate::spec::sha256::collision_resistance".to_string()] } else { vec![] }, "{path}");
    }
}

// ---------------------------------------------------------------------
// the spec sheet, the lock entries and the report
// ---------------------------------------------------------------------

#[test]
fn the_sheet_the_surface_and_the_report_carry_the_law_rules() {
    let root = format!("{HEADER}mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::halve;\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    // a proven law is on the surface
    let proofs = "use sandblaster::prelude::*;\nuse super::spec::{collision, pair, same};\n#[proof]\nfn extraction_form(a: Seq<u8>, b: Seq<u8>) { follows(); }\n";
    let laws = r#"use sandblaster::prelude::*;
use super::m::helper;
use super::spec::{collision, collision_resistance, pair, same};

/// Two messages are the same, or they collide.
#[law]
#[reduces_to(collision_resistance)]
fn extraction_form(a: Seq<u8>, b: Seq<u8>) {
    requires(same(a, b));
    ensures(same(a, b) || collision(pair(a, b)));
}

/// The helper never grows its argument.
#[law]
#[definitional(reason = "how halving rounds")]
fn internal(x: u32) {
    ensures(helper(x) <= x);
}
"#;
    let files = [("r/mod.rs", root.as_str()), ("r/LAWS.rs", laws), ("r/PROOF.rs", proofs), ("r/m.rs", "use sandblaster::prelude::*;\npub fn halve(x: u32) -> u32 { x / 2 }\npub fn helper(x: u32) -> u32 { x / 2 }\n"), ("r/spec.rs", BREAK_SPEC)];
    let fs = MemFs::from_files(files.iter().copied());
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.clone().unwrap();
    let (kr, cr) = (&k, &c);
    let (sheet, sources, statements, report) = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let surface = sandblaster_front::surface::compute(&out, kr, &cr.sm, &sandblaster_front::surface::SurfaceOptions::default());
        let status = sandblaster_front::lock::compare(None, &surface, "SPEC.lock");
        let sheet = sandblaster_front::specdiff::sheet("r", &surface, &status, &[]);
        let sources: Vec<(String, String)> = surface.items.iter().map(|i| (i.key.clone(), i.source.clone())).collect();
        let statements: Vec<(String, Vec<String>)> = surface.items.iter().map(|i| (i.key.clone(), i.statement.clone())).collect();
        let s15 = driver::spec15_report(&out, kr);
        let v = driver::Verification { defs: out.defs.clone(), obligations: out.obligations.clone(), laws: out.laws.clone(), diags: out.diags.clone(), deferred: out.deferred.clone(), proofs_ok: false, elapsed: std::time::Duration::ZERO, provers: vec![], exec_only: false };
        let report = driver::stage::report_json(cr, &v, &[], "r", None, None, Some(&s15));
        (sheet, sources, statements, report)
    });
    // the sheet prints the law table, the definitional law under its own heading
    let at = sheet.find("== Laws: guarantees and assumptions (DESIGN.md §15.1 LR9) ==").unwrap_or_else(|| panic!("{sheet}"));
    let table = &sheet[at..];
    assert!(table.contains("| `laws::extraction_form` | Two messages are the same, or they collide. | `spec::collision_resistance` (computational: stub hash collision resistance) |"), "{table}");
    assert!(table.contains("Definitional laws (restate a definition; not guarantees):\n  `laws::internal`: The helper never grows its argument. — reason: how halving rounds"), "{table}");
    // the law-rule annotations are part of the law's locked claim …
    let src = |key: &str| sources.iter().find(|(k, _)| k == key).map(|(_, s)| s.clone());
    let s = src("law:crate::laws::extraction_form").unwrap_or_else(|| panic!("no law entry: {sources:?}"));
    assert!(s.contains("#[reduces_to(crate::spec::collision_resistance)]"), "{s}");
    // … and an assumption's class and citation are part of its entry
    let st = statements.iter().find(|(k, _)| k == "spec-fn:crate::spec::collision_resistance").map(|(_, s)| s.join("\n")).unwrap_or_else(|| panic!("{sources:?}"));
    assert!(st.contains("assumption (computational): stub hash collision resistance"), "{st}");
    // the report: the findings (LR1 on `internal`, recorded, enforced by
    // the gate) and the table
    assert!(report.contains("\"law_rules\""), "{report}");
    assert!(report.contains("\"rule\": \"LR1\"") || report.contains("\"rule\":\"LR1\""), "{report}");
    assert!(report.contains("law-mentions-internal"), "{report}");
    assert!(report.contains("\"laws\""), "{report}");
    assert!(report.contains("\"heading\": \"definitional\"") || report.contains("\"heading\":\"definitional\""), "{report}");
    assert!(report.contains("stub hash collision resistance"), "{report}");
}

// ---------------------------------------------------------------------
// review fixes: the vocabulary is the real boundary, hard rules fail
// closed, vacuous reductions, readable diagnostics
// ---------------------------------------------------------------------

/// A type that an exported function returns is reachable from the boundary
/// even when it is not in the root's `pub use` list: its `pub` methods are
/// host-callable, so a law may name them (LR1) and LR10 sees them.
#[test]
fn lr1_methods_of_types_reachable_from_the_boundary_are_exported() {
    let m = "use sandblaster::prelude::*;\n#[derive(Clone, Copy)]\npub struct Token(u32);\nimpl Token {\n    pub fn leak(&self) -> u32 { self.0 ^ 7u32 }\n    pub fn odd(&self) -> bool { self.0 % 2 == 1 }\n}\npub fn make(x: u8) -> Token { Token(x as u32) }\n";
    let r = crate_with(
        "mod m;\npub use m::make;\n",
        &[("m.rs", m)],
        r#"use super::m::make;

/// The leaked value of a token made from zero is seven.
#[law]
fn leak_of_zero() {
    ensures(make(0).leak() == 7);
}

/// A token made from an odd byte is odd.
#[law]
fn odd_tokens(x: u8) {
    requires(x % 2 == 1);
    ensures(make(x).odd());
}
"#,
        None,
    );
    r.front();
    r.lacks(LawRule::Lr1, "crate::laws::leak_of_zero");
    r.lacks(LawRule::Lr1, "crate::laws::odd_tokens");
    // `odd` is a `bool` boundary function named only in a conclusion
    r.has(LawRule::Lr10, "crate::m::Token::odd", "only in conclusions");
}

/// A recursive proposition in a law (`tt`) has no defining equation to
/// unfold by: it stays unknown in the echo check's view, which still runs,
/// so an echo is caught — the check is never skipped.
#[test]
fn lr6_echo_is_never_skipped_by_a_recursive_proposition() {
    let spec = "/// Holds of every natural number.\n#[decreases(n)]\npub fn tt(n: Nat) -> Prop { if n == 0 { true } else { tt(n - 1) } }\n";
    let root = "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::id;\n";
    let laws = r#"use super::m::id;
use super::spec::tt;

/// The identity function returns its argument unchanged.
#[law]
fn id_is_identity(x: u32) {
    requires(x == x || tt(x as Nat));
    ensures(id(x) == x);
}
"#;
    let r = crate_with(root, &[("m.rs", "use sandblaster::prelude::*;\npub fn id(x: u32) -> u32 { x }\n"), ("spec.rs", spec)], laws, None);
    r.front();
    r.has(LawRule::Lr6Echo, "crate::laws::id_is_identity", "restates its definitions");
    r.has(LawRule::Lr6Echo, "crate::laws::id_is_identity", "not unfolded, treated as unknown: `spec::tt`");
    // the same law without the recursive proposition: the same finding
    let r = crate_with(root, &[("m.rs", "use sandblaster::prelude::*;\npub fn id(x: u32) -> u32 { x }\n"), ("spec.rs", spec)], &laws.replace("x == x || tt(x as Nat)", "x == x"), None);
    r.front();
    r.has(LawRule::Lr6Echo, "crate::laws::id_is_identity", "restates its definitions");
}

/// The echo note says what the law reduced to (no fixed guard sentence),
/// and a law caught by LR6 (a) is not reported again by LR6 (b).
#[test]
fn lr6_echo_notes_describe_the_finding_and_are_not_repeated_by_resemblance() {
    let m = "use sandblaster::prelude::*;\n#[refines(crate::spec::tagged)]\npub fn encode(x: u8) -> [u8; 2] { [1u8, x] }\npub fn decode(b: [u8; 2]) -> Option<u8> { if b[0] == 1 { Some(b[1]) } else { None } }\n";
    let spec = "/// The encoding of a byte: the tag 1, then the byte.\n#[example(tagged(7u8) == [1u8, 7u8])]\npub fn tagged(x: u8) -> [u8; 2] { [1u8, x] }\n";
    let r = crate_with(
        "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::{encode, decode};\n",
        &[("m.rs", m), ("spec.rs", spec)],
        r#"use super::m::decode;
use super::spec::tagged;

/// Round trip: decoding the encoding of a byte gives the byte back.
#[law]
fn decode_encode(x: u8) {
    ensures(decode(tagged(x)) == Some(x));
}

/// Decoding reads the byte after a correct tag, and rejects any other tag.
#[law]
fn decode_reads_tag(b: [u8; 2]) {
    ensures(decode(b) == if b[0] == 1u8 { Some(b[1]) } else { None });
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr6Echo, "crate::laws::decode_encode", "the law is a consequence of the bodies of `spec::tagged`, `m::decode` as written");
    r.has(LawRule::Lr6Echo, "crate::laws::decode_encode", "a round trip through code without arithmetic");
    r.has(LawRule::Lr6Echo, "crate::laws::decode_encode", "`#[lemma]` in PROOF.rs");
    assert!(!r.of(LawRule::Lr6Echo, "crate::laws::decode_encode").iter().any(|f| f.notes.iter().any(|n| n.contains("checks that a guard exists"))), "{}", r.explain());
    r.lacks(LawRule::Lr6Resemblance, "crate::laws::decode_encode");
    // a transcription of the body: one finding (the echo), not two
    r.has(LawRule::Lr6Echo, "crate::laws::decode_reads_tag", "unfolded once: `m::decode`");
    r.lacks(LawRule::Lr6Resemblance, "crate::laws::decode_reads_tag");
}

const MAC_SPEC: &str = r#"
/// What the verifier accepts.
#[example(accepts(1u32, 2u32))]
#[example(!accepts(2u32, 1u32))]
pub fn accepts(key: u32, tag: u32) -> bool { (tag as Nat) > (key as Nat) }

/// The tag an honest signer produces.
#[example(honest(1u32, 2u32))]
#[example(!honest(1u32, 3u32))]
pub fn honest(key: u32, tag: u32) -> bool { (tag as Nat) == (key as Nat) + 1 }

/// A forgery exhibited by the input (implied by acceptance).
#[example(forged(1u32, 3u32))]
#[example(!forged(3u32, 1u32))]
pub fn forged(key: u32, tag: u32) -> bool { (tag as Nat) >= (key as Nat) + 1 }

/// A far-off tag.
#[example(far(1u32, 9u32))]
#[example(!far(1u32, 2u32))]
pub fn far(key: u32, tag: u32) -> bool { (tag as Nat) > (key as Nat) + 5 }

/// Always a break.
#[example(always(1u32, 2u32))]
pub fn always(key: u32, tag: u32) -> bool { true }

/// Forging a tag is infeasible.
#[assumption(class = computational, cite = "MAC unforgeability")]
pub fn unforgeable() {}
"#;

/// LR4 beyond the form: a `#[reduces_to]` law is vacuous when its break
/// predicate follows from the hypotheses (the law holds of any
/// specification) or ignores its arguments; its break is dead when the
/// guarantee follows from the hypotheses alone.
#[test]
fn lr4_vacuous_reductions_are_rejected() {
    let m = "use sandblaster::prelude::*;\n#[refines(crate::spec::accepts)]\npub fn verify(key: u32, tag: u32) -> bool { tag > key }\n";
    let r = crate_with(
        "mod m;\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\npub use m::verify;\n",
        &[("m.rs", m), ("spec.rs", MAC_SPEC)],
        r#"use super::spec::{accepts, honest, forged, far, always, unforgeable};

/// Every accepted tag is the honest one, or the input exhibits a forgery.
#[law]
#[reduces_to(unforgeable)]
fn implied_break(key: u32, tag: u32) {
    requires(accepts(key, tag));
    ensures(honest(key, tag) || forged(key, tag));
}

/// Every accepted tag is the honest one, or something always true holds.
#[law]
#[reduces_to(unforgeable)]
fn constant_break(key: u32, tag: u32) {
    requires(accepts(key, tag));
    ensures(honest(key, tag) || always(key, tag));
}

/// Every honest tag is accepted, or the tag is far off.
#[law]
#[reduces_to(unforgeable)]
fn dead_break(key: u32, tag: u32) {
    requires(honest(key, tag));
    ensures(accepts(key, tag) || far(key, tag));
}

/// Every accepted tag is the honest one, or it is far off.
#[law]
#[reduces_to(unforgeable)]
fn meaningful(key: u32, tag: u32) {
    requires(accepts(key, tag));
    ensures(honest(key, tag) || far(key, tag));
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr4, "crate::laws::implied_break", "the break disjunct of law `crate::laws::implied_break` follows from its hypotheses");
    r.has(LawRule::Lr4, "crate::laws::constant_break", "ignores its arguments");
    r.has(LawRule::Lr4, "crate::laws::dead_break", "the break disjunct of law `crate::laws::dead_break` is dead");
    r.lacks(LawRule::Lr4, "crate::laws::meaningful");
    assert!(r.gate.iter().any(|(e, k, m)| *e && *k == DiagKind::VacuousReduction && m.contains("implied_break")), "{:?}", r.gate);
}

/// A plain `fn` of a ghost module (`LAWS.rs`) is neither a spec item nor
/// exported: a law may not mention it (LR1), so a copy of the
/// implementation cannot slip past the spec-side rules.
#[test]
fn lr1_ghost_exec_functions_are_not_law_vocabulary() {
    let r = crate_with(
        "mod m;\npub use m::clamp;\n",
        &[("m.rs", "use sandblaster::prelude::*;\nfn internal(x: u32) -> u32 { if x > 100u32 { 100u32 } else { x } }\npub fn clamp(x: u32) -> u32 { internal(x) }\n")],
        r#"use super::m::clamp;

fn helper(x: u32) -> u32 { if x > 100u32 { 100u32 } else { x } }

/// Clamping agrees with the reference clamp on every input.
#[law]
fn clamp_is_helper(x: u32) {
    ensures(clamp(x) == helper(x));
}
"#,
        None,
    );
    r.front();
    r.has(LawRule::Lr1, "crate::laws::clamp_is_helper", "mentions `crate::laws::helper`, a plain `fn` of a ghost module");
    r.has(LawRule::Lr1, "crate::laws::clamp_is_helper", "`#[spec]` module");
    assert!(r.gate.iter().any(|(e, k, m)| *e && *k == DiagKind::LawMentionsInternal && m.contains("crate::laws::helper")), "{:?}", r.gate);
}

/// LR9: abbreviations do not end the first sentence, a code span counts as
/// a word, and the diagnostic states the rule.
#[test]
fn lr9_sentences_with_abbreviations_and_code_spans() {
    let s = |d: &[&str]| law_rules::guarantee_sentence(&d.iter().map(|x| x.to_string()).collect::<Vec<_>>());
    assert_eq!(s(&["Sound, i.e. every tag that `verify` accepts is the checksum of the message."]).as_deref(), Some("Sound, i.e. every tag that `verify` accepts is the checksum of the message."));
    assert_eq!(s(&["Complete (e.g. no honest tag is ever rejected): the checksum is accepted. More."]).as_deref(), Some("Complete (e.g. no honest tag is ever rejected): the checksum is accepted."));
    assert_eq!(s(&["Handles a, b, etc. The rest."]).as_deref(), Some("Handles a, b, etc."));
    assert_eq!(s(&["Covers a, b, etc. and more."]).as_deref(), Some("Covers a, b, etc. and more."));
    assert!(law_rules::states_guarantee("`decode` inverts `le16`.", "decode_encode"));
    assert!(!law_rules::states_guarantee("`f(x) == g(x)`.", "eq"));
    assert!(!law_rules::states_guarantee("`a` `b` `c`.", "abc"));
    let r = crate_with(
        "mod m;\npub use m::halve;\n",
        &[("m.rs", "use sandblaster::prelude::*;\npub fn halve(x: u32) -> u32 { x / 2 }\n")],
        r#"use super::m::halve;

/// Sound, i.e. halving never makes a number larger.
#[law]
fn abbreviated(x: u32) {
    ensures(halve(x) <= x);
}

/// `halve` shrinks `x`.
#[law]
fn spans(x: u32) {
    ensures(halve(x) <= x);
}

/// Halve le.
#[law]
fn halve_le(x: u32) {
    ensures(halve(x) <= x);
}
"#,
        None,
    );
    r.front();
    r.lacks(LawRule::Lr9, "crate::laws::abbreviated");
    r.lacks(LawRule::Lr9, "crate::laws::spans");
    r.has(LawRule::Lr9, "crate::laws::halve_le", "at least three words");
    let row = r.table.iter().find(|t| t.0 == "crate::laws::abbreviated").expect("row");
    assert_eq!(row.1.as_deref(), Some("Sound, i.e. halving never makes a number larger."));
}
