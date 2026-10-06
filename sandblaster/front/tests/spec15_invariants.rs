//! §15 S2 (DESIGN.md §15.3): types that carry invariants and meaning —
//! invariants as `Irr` constructor fields (construction obligations on every
//! path, free facts at parameters, bindings, projections and call results),
//! the readable `is_prop` pre-check and the `¬¬∃` encoding, the visibility
//! rule, evidence types, `Abstract(T)` and `ViewInjective` in determinacy,
//! ghost parameters (the `Irr` ghost bundle, `ghost!(e)` arguments), the
//! bounds of `Nat` fields and `sandblaster eval` inputs.

#[path = "spec15_util.rs"]
mod util;

use std::path::Path;

use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::*;

const LOCATION: &str = r#"
pub const MAX_LOCATION: u64 = 100;

/// A location in the log: always below `MAX_LOCATION`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[invariant(self.0 < MAX_LOCATION)]
pub struct Location(u64);

impl Location {
    pub fn new(x: u64) -> Option<Location> {
        if x < MAX_LOCATION { Some(Location(x)) } else { None }
    }
    pub fn get(self) -> u64 { self.0 }
}
"#;

fn loc(extra: &str) -> String {
    format!("{LOCATION}{extra}")
}

fn check(files: &[(&str, &str)]) -> Checked {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front end rejected the program:\n{}", c.render());
    c
}

/// Verification with the standard provers.
fn pipeline(files: &[(&str, &str)]) -> (Checked, driver::stage::StageBuild) {
    let c = check(files);
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_checked(&c, &opts);
    assert!(built.v.proofs_ok, "not verified:\n{}", built.v.diags.render(&c.sm));
    (c, built)
}

fn eval(body: &str, f: &str, args: &str) -> Result<String, String> {
    let c = check(&[("r/mod.rs", body)]);
    let k = c.krate.clone().unwrap();
    driver::stage::with_elaboration(&k, &VerifyOptions { provers: ProverSet::Standard, exec_only: false }, |out| {
        assert!(out.verified(), "not verified");
        driver::stage::eval_in(out, &k, f, args)
    })
}

fn first_error(r: &Run) -> (K, String) {
    r.errors.first().cloned().unwrap_or_else(|| panic!("no error:\n{}", r.explain()))
}

// ---------------------------------------------------------------------
// the kernel type, construction, facts
// ---------------------------------------------------------------------

#[test]
fn a_location_with_a_hand_written_constructor() {
    let r = verifies(&loc(""));
    for d in ["crate::Location::invariant#0", "crate::Location::holds#0", "crate::Location::inv#0", "crate::Location::new", "crate::Location::get"] {
        assert!(r.checked_defs.iter().any(|x| x == d), "{d} missing: {:?}", r.checked_defs);
    }
}

#[test]
fn indexing_by_the_field_needs_no_requires() {
    // the invariant is a fact at the parameter: the index is in bounds
    let body = loc(
        r#"
pub fn read(xs: [u8; 100], l: Location) -> u8 { xs[l.0 as usize] }

/// the fact follows a value through `Option`, a match and a call result
pub fn read_next(xs: [u8; 100], l: Location) -> u8 {
    match Location::new(l.get() + 1) {
        Some(m) => xs[m.0 as usize],
        None => xs[l.get() as usize],
    }
}
"#,
    );
    let (_, built) = pipeline(&[("r/mod.rs", &body)]);
    assert!(built.v.proofs_ok);
}

#[test]
fn functional_update_and_field_assignment_keep_the_invariant() {
    verifies(
        r#"
#[derive(Clone, Copy)]
#[invariant(self.lo <= self.hi && self.hi <= 1000)]
pub struct Span { lo: u32, hi: u32 }

impl Span {
    pub fn new(lo: u32, hi: u32) -> Option<Span> {
        if lo <= hi && hi <= 1000 { Some(Span { lo, hi }) } else { None }
    }
    /// the fact at `self` makes `hi - lo` safe
    pub fn len(self) -> u32 { self.hi - self.lo }
    /// `..self`: the obligation holds from the path condition and the fact
    pub fn shrink(self) -> Span { if self.lo < self.hi { Span { lo: self.lo + 1, ..self } } else { self } }
    /// a field assignment rebuilds the value, with the obligation
    pub fn widen(self) -> Span { let mut s = self; if s.lo > 0 { s.lo = s.lo - 1; } s }
}
"#,
    );
}

#[test]
fn a_derived_partial_eq_on_an_invariant_type() {
    // the derived equality ignores the `Irr` field; its soundness and
    // completeness lemmas are proven with the field generalized
    let r = verifies(&loc(
        r#"
#[ensures(|r: bool| r == true)]
fn refl(a: Location) -> bool { a == a }

pub fn same(a: Location, b: Location) -> bool { a == b }
pub fn api(a: Location) -> bool { refl(a) }
"#,
    ));
    for d in ["crate::Location::eq", "crate::Location::eq_sound", "crate::Location::eq_complete"] {
        assert!(r.checked_defs.iter().any(|x| x == d), "{d} missing: {:?}", r.checked_defs);
    }
}

#[test]
fn an_evidence_type_returned_by_a_verifier() {
    // "parse, don't validate": the certified property is the invariant; a
    // holder of the evidence relies on it without re-checking
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn accepts(key: u8, proof: u8) -> bool { key ^ proof == 0x5a }

/// A membership that verified: the witness (`proof`) is stored.
#[derive(Clone, Copy)]
#[invariant(accepts(self.key, self.proof))]
pub struct VerifiedMembership { key: u8, proof: u8 }

#[ensures(|r: bool| r == accepts(key, proof))]
fn verify(key: u8, proof: u8) -> bool { key ^ proof == 0x5a }

pub fn verify_member(key: u8, proof: u8) -> Option<VerifiedMembership> {
    if verify(key, proof) { Some(VerifiedMembership { key, proof }) } else { None }
}

impl VerifiedMembership {
    pub fn key(self) -> u8 { self.key }
}

#[ensures(|r: bool| r == true)]
fn recheck(v: VerifiedMembership) -> bool { v.key ^ v.proof == 0x5a }

pub fn api(v: VerifiedMembership) -> bool { recheck(v) }
"#,
    );
    assert!(r.checked_defs.iter().any(|d| d == "crate::recheck::ensures"), "{:?}", r.checked_defs);
}

#[test]
fn an_existential_invariant_is_double_negated_and_reported() {
    let r = verifies(
        r#"
/// Some element is zero (an existential: encoded as `¬¬∃`).
#[derive(Clone, Copy)]
#[invariant(exists(|i: u64| i < 4 && self.xs[i as usize] == 0))]
pub struct HasZero { xs: [u8; 4] }

impl HasZero {
    pub fn new() -> HasZero {
        let xs: [u8; 4] = [0, 1, 2, 3];
        proof! { assert(exists(|i: u64| i < 4 && xs[i as usize] == 0), { witness(0u64); }); }
        HasZero { xs }
    }
    /// the double-negated fact of `self` rebuilds the value
    pub fn copy(self) -> HasZero { HasZero { xs: self.xs } }
}
"#,
    );
    assert!(r.warnings.iter().any(|(k, m)| *k == K::Invariant && m.contains("encoded as `¬¬∃`")), "{:?}", r.warnings);
}

#[test]
fn a_proposition_invariant_over_the_fields() {
    verifies(
        r#"
#[derive(Clone, Copy)]
#[invariant(forall(|i: u64| implies(i < 4, self.xs[i as usize] <= 10)))]
pub struct Small { xs: [u8; 4] }

impl Small {
    pub fn zero() -> Small { Small { xs: [0, 0, 0, 0] } }
}
"#,
    );
}

#[test]
fn a_bool_disjunction_is_an_invariant() {
    // `||` between `bool` comparisons is a `bool` expression (§15.3)
    verifies(
        r#"
#[derive(Clone, Copy)]
#[invariant((self.a == 1) || (self.b == 2))]
pub struct Either { a: u64, b: u64 }

impl Either {
    pub fn left() -> Either { Either { a: 1, b: 0 } }
    pub fn flip(self) -> Either { if self.a == 1 { Either { a: 0, b: 2 } } else { Either { a: 1, b: self.b } } }
}
"#,
    );
}

// ---------------------------------------------------------------------
// rejections
// ---------------------------------------------------------------------

#[test]
fn a_location_of_an_unconstrained_value_is_rejected() {
    let r = fails(&loc("pub fn bad(x: u64) -> Location { Location(x) }\n"));
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::bad" && k == "type-invariant"), "{}", r.explain());
    assert!(r.rendered.contains("can only be built where its invariant holds"), "{}", r.rendered);
    // the goal is shown in the invariant's terms
    assert!(r.rendered.contains("#lt_u64(x, crate::MAX_LOCATION)"), "{}", r.rendered);
}

#[test]
fn assigning_a_violating_field_is_rejected() {
    let r = fails(&loc("pub fn bump(l: Location) -> Location { let mut m = l; m.0 = 200; m }\n"));
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::bump" && k == "type-invariant"), "{}", r.explain());
}

#[test]
fn a_functional_update_with_a_violating_field_is_rejected() {
    let r = fails(
        r#"
#[derive(Clone, Copy)]
#[invariant(self.lo <= self.hi)]
pub struct Range { lo: u64, hi: u64 }

impl Range {
    pub fn set_lo(r: Range, x: u64) -> Range { Range { lo: x, ..r } }
}
"#,
    );
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::Range::set_lo" && k == "type-invariant"), "{}", r.explain());
}

#[test]
fn a_public_field_on_an_invariant_type_is_rejected() {
    for vis in ["pub", "pub(crate)", "pub(super)"] {
        let r = run(&format!("#[derive(Clone, Copy)]\n#[invariant(self.0 < 100)]\npub struct L({vis} u64);\npub fn get(l: L) -> u64 {{ l.0 }}\n"));
        assert!(r.has_error(K::Invariant, &format!("field `0` of `L` is `{vis}`, but the type has an invariant")), "{vis}: {}", r.rendered);
    }
    let r = run("#[derive(Clone, Copy)]\n#[view(|p| p.x as Nat)]\npub struct P { pub x: u32 }\n");
    assert!(r.has_error(K::Invariant, "field `x` of `P` is `pub`, but the type has a view"), "{}", r.rendered);
}

#[test]
fn a_non_proposition_invariant_is_reported_readably_before_any_kernel_error() {
    let r = fails(
        r#"
#[derive(Clone, Copy)]
#[invariant(forall(|i: u64| implies(i < 4, self.xs[i as usize] <= 10)) || self.n == 0)]
pub struct L { xs: [u8; 4], n: u64 }
pub fn f(l: L) -> u64 { l.n }
"#,
    );
    let (k, m) = first_error(&r);
    assert_eq!(k, K::Invariant, "{}", r.rendered);
    assert!(m.contains("is not a proposition") && m.contains("`||` between propositions"), "{m}");
    assert!(!r.rendered.contains("the kernel rejected"), "no kernel error:\n{}", r.rendered);
}

#[test]
fn an_invariant_mentioning_its_own_type_is_rejected() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn small(s: S) -> bool { s.0 < 5 }
#[derive(Clone, Copy)]
#[invariant(small(S(self.0)))]
pub struct S(u8);
"#,
    );
    assert!(r.errors.iter().any(|(k, m)| (*k == K::Invariant && m.contains("mentions `crate::S` itself")) || m.contains("cannot use")), "{}", r.rendered);
}

#[test]
fn an_invariant_calling_an_exec_function_is_rejected() {
    // the free variables of an invariant are the fields, constants and
    // spec-closed globals (§15.3), never an unestablished exec function
    let r = fails(
        r#"
fn limit() -> u64 { 7 }
#[derive(Clone, Copy)]
#[invariant(self.0 < limit())]
pub struct L(u64);
pub fn get(l: L) -> u64 { l.0 }
"#,
    );
    assert!(r.has_error(K::SpecDependsOnImpl, "the invariant of `crate::L` depends on the exec function `crate::limit`"), "{}", r.rendered);
}

#[test]
fn a_position_where_a_location_is_expected_is_a_type_error() {
    let r = run(
        r#"
#[derive(Clone, Copy)]
#[invariant(self.0 < 100)]
pub struct Location(u64);
#[derive(Clone, Copy)]
#[invariant(self.0 < 200)]
pub struct Position(u64);
fn get(l: Location) -> u64 { l.0 }
pub fn f(p: Position) -> u64 { get(p) }
"#,
    );
    assert!(!r.front_ok && r.has_error(K::Type, "mismatched types: expected `Location`, found `Position`"), "{}", r.rendered);
}

#[test]
fn eval_rejects_an_input_that_violates_the_invariant() {
    let body = loc("pub fn read(xs: [u8; 4], l: Location) -> u64 { l.0 }\n");
    assert_eq!(eval(&body, "read", "[[1,2,3,4], [42]]").unwrap(), "42");
    let e = eval(&body, "read", "[[1,2,3,4], [150]]").unwrap_err();
    assert!(e.contains("violates the invariant of `crate::Location`"), "{e}");
}

// ---------------------------------------------------------------------
// views: ViewInjective, Abstract(T), determinacy
// ---------------------------------------------------------------------

#[test]
fn a_lossy_view_on_a_public_type_without_view_inj_is_rejected() {
    let r = fails(
        r#"
#[derive(Clone, Copy, PartialEq)]
#[view(|p| p.x as Nat)]
pub struct Point { x: u32, tag: u8 }
#[cfg(sandblaster)] #[spec] fn next(x: Nat) -> Nat { if x < 100 { x + 1 } else { 100 } }
#[refines(next)]
pub fn step(p: Point) -> Point { if p.x < 100 { Point { x: p.x + 1, tag: 0 } } else { Point { x: 100, tag: 7 } } }
"#,
    );
    assert!(r.has_error(K::ViewInjective, "the view of the public type `crate::Point` is not proven injective"), "{}", r.rendered);
    assert!(r.rendered.contains("not `Abstract(Point)`: it derives `PartialEq`"), "{}", r.rendered);
}

#[test]
fn a_proven_view_inj_makes_a_closure_view_determine_and_establish() {
    // a closure view that keeps every field: `view_inj` proves, so the
    // public (non-abstract: `PartialEq`) type is fine and the refinement
    // determines and establishes `step` (§15.2)
    let r = verifies(
        r#"
#[derive(Clone, Copy, PartialEq)]
#[view(|p| (p.x as Nat, p.y as Nat))]
pub struct Pt { x: u32, y: u8 }
#[cfg(sandblaster)] #[spec] fn swap(p: (Nat, Nat)) -> (Nat, Nat) { (p.0, p.1) }
#[refines(swap)]
pub fn same(p: Pt) -> Pt { Pt { x: p.x, y: p.y } }
"#,
    );
    assert!(r.checked_defs.iter().any(|d| d == "crate::Pt::view_inj"), "{:?}", r.checked_defs);
    let f = r.refinement("crate::same");
    assert!(f.checked && f.up_to.is_none(), "{}", r.explain());
    assert!(r.established.iter().any(|g| g == "crate::same"), "{:?}", r.established);
}

#[test]
fn a_representation_relation_needs_an_abstract_type() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn get(a: Nat) -> Nat { a }
#[derive(Clone, Copy, Debug)]
#[represents(|s: &Ctr, a: Nat| s.count as Nat == a)]
pub struct Ctr { count: u16 }
impl Ctr {
    #[refines(get)]
    pub fn get(&self) -> u16 { self.count }
}
"#,
    );
    assert!(r.has_error(K::Invariant, "has a representation relation, so it must be `Abstract(Ctr)`"), "{}", r.rendered);
    assert!(r.rendered.contains("it derives `Debug`"), "{}", r.rendered);
}

#[test]
fn abstract_and_boundary_helpers() {
    let c = check(&[(
        "r/mod.rs",
        "#[derive(Clone, Copy)]\n#[view(|p| p.x as Nat)]\npub struct A { x: u32, y: u32 }\n\
         #[derive(Clone, Copy, Debug)]\npub struct B { x: u32 }\n\
         pub fn mk_a(x: u32) -> A { A { x, y: 0 } }\npub fn mk_b(x: u32) -> B { B { x } }\n\
         impl A { pub fn x(self) -> u32 { self.x } }\n",
    )]);
    let k = c.krate.as_ref().unwrap();
    let a = k.find("crate::A").unwrap();
    let b = k.find("crate::B").unwrap();
    let ra = sandblaster_front::validate::abstract_reasons(k, a, false);
    assert!(ra.iter().any(|x| x.contains("`crate::mk_a` takes or returns it without `#[refines]`")), "{ra:?}");
    let rb = sandblaster_front::validate::abstract_reasons(k, b, false);
    assert!(rb.iter().any(|x| x.contains("derives `Debug`")), "{rb:?}");
    // LR1's exported functions: the root's exports and the `pub` methods of
    // exported types (invariant and evidence types included)
    let ex: Vec<String> = sandblaster_front::validate::exported_functions(k).into_iter().map(|i| k.item(i).path.to_string()).collect();
    for f in ["crate::mk_a", "crate::mk_b", "crate::A::x"] {
        assert!(ex.iter().any(|x| x == f), "{f}: {ex:?}");
    }
}

// ---------------------------------------------------------------------
// ghost parameters
// ---------------------------------------------------------------------

const GHOST: &str = r#"
/// the ghost `k` is a proof-only budget: `x + 1 < k <= 200`
#[requires(x as Int + 1 < k && k <= 200)]
#[ensures(|r: u8| r as Int == x as Int + 1)]
fn bump(x: u8, #[ghost] k: Int) -> u8 { x + 1 }

#[requires(x < 100)]
#[ensures(|r: u8| r as Int == x as Int + 2)]
fn bump2(x: u8, #[ghost] k: Int) -> u8 {
    let y = bump(x, ghost!(x as Int + 5));
    bump(y, ghost!(y as Int + 2))
}

#[ensures(|r: u8| r == 12)]
pub fn api() -> u8 { bump2(10, ghost!(0)) }
"#;

#[test]
fn ghost_parameters_are_irrelevant_binders() {
    let (_, built) = pipeline(&[("r/mod.rs", GHOST)]);
    assert!(built.v.proofs_ok);
}

#[test]
fn a_wrong_ghost_argument_is_an_unproven_requires() {
    let r = fails(&GHOST.replace("bump(y, ghost!(y as Int + 2))", "bump(y, ghost!(y as Int))"));
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::bump2" && k == "callee-requires"), "{}", r.explain());
}

#[test]
fn ghost_argument_syntax_and_placement() {
    // exec code writes `ghost!(e)`
    let r = run("#[requires(true)]\nfn f(x: u8, #[ghost] k: Int) -> u8 { x }\n#[ensures(|r: u8| true)]\npub fn g() -> u8 { f(1, 2) }\n");
    assert!(r.has_error(K::Ghost, "is written `ghost!(e)` in exec code"), "{}", r.rendered);
    // only for a ghost parameter
    let r = run("#[requires(true)]\nfn f(x: u8, #[ghost] k: Int) -> u8 { x }\n#[ensures(|r: u8| true)]\npub fn g() -> u8 { f(ghost!(1), ghost!(2)) }\n");
    assert!(r.has_error(K::Ghost, "`ghost!(..)` is only the argument of a `#[ghost]` parameter"), "{}", r.rendered);
    // the caller needs an annotation (its macro erases the argument)
    let r = run("#[requires(true)]\nfn f(x: u8, #[ghost] k: Int) -> u8 { x }\npub fn g() -> u8 { f(1, ghost!(2)) }\n");
    assert!(r.has_error(K::Attribute, "a function passing `ghost!(..)` arguments needs a sandblaster function annotation"), "{}", r.rendered);
    // ghost parameters come last
    let r = run("#[requires(true)]\nfn f(#[ghost] k: Int, x: u8) -> u8 { x }\n");
    assert!(r.has_error(K::Ghost, "`#[ghost]` parameters come after the other parameters"), "{}", r.rendered);
    // and make a function non-boundary
    let r = run("#[requires(true)]\npub fn f(x: u8, #[ghost] k: Int) -> u8 { x }\n");
    assert!(r.has_error(K::Boundary, "with `#[ghost]` parameters is reachable from the DSL root"), "{}", r.rendered);
}

#[test]
fn eval_takes_no_ghost_arguments() {
    assert_eq!(eval(GHOST, "bump", "[3]").unwrap(), "4");
}

// ---------------------------------------------------------------------
// `Nat` fields
// ---------------------------------------------------------------------

#[test]
fn the_bounds_of_nat_fields_are_facts() {
    // spec functions guard their body on the `Nat` components of their
    // parameters (like S1's `Nat` parameters), lemmas take them as
    // hypotheses: `c.n - 1` needs no check beyond `c.n != 0`
    verifies_files(&[
        ("r/mod.rs", "#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n#[cfg(sandblaster)] #[path = \"LEMMAS.rs\"] mod lemmas;\npub fn api() -> u8 { 0 }\n"),
        (
            "r/spec.rs",
            "#[derive(Clone, Copy)]\npub struct Counter { pub n: Nat, pub total: (Nat, u8) }\n\
             pub fn dec(c: Counter) -> Nat { if c.n != 0 { c.n - 1 } else { 0 } }\n\
             pub fn tot(c: Counter) -> Nat { c.total.0 + c.n }\n\
             pub fn next(c: Counter, by: Nat) -> Counter { let t = if c.n < 5 { c.n + by } else { c.n }; Counter { n: t, total: c.total } }\n",
        ),
        ("r/LEMMAS.rs", "#[lemma]\nfn dec_le(c: super::spec::Counter) {\n    ensures(super::spec::dec(c) <= c.n);\n    follows();\n}\n"),
    ]);
}

// ---------------------------------------------------------------------
// the specification surface
// ---------------------------------------------------------------------

#[test]
fn invariants_and_evidence_types_are_surface_items_with_their_kernel_statements() {
    let body = loc(
        r#"
#[cfg(sandblaster)] #[spec] fn accepts(key: u8, proof: u8) -> bool { key ^ proof == 0x5a }

#[derive(Clone, Copy)]
#[invariant(accepts(self.key, self.proof))]
pub struct VerifiedMembership { key: u8, proof: u8 }

pub fn verify_member(key: u8, proof: u8) -> Option<VerifiedMembership> {
    if key ^ proof == 0x5a { Some(VerifiedMembership { key, proof }) } else { None }
}
"#,
    );
    let c = check(&[("r/mod.rs", &body)]);
    let r = driver::stage::spec_run(&c, &driver::stage::SpecBaseline::Lock, true);
    assert!(r.v.proofs_ok, "{}", r.v.diags.render(&c.sm));
    let s = r.surface.as_ref().unwrap();
    let inv = s.get("invariant:crate::Location").expect("the invariant is a surface item");
    assert!(inv.kernel.iter().any(|(k, _)| k.starts_with("invariant#0")), "{:?}", inv.kernel);
    // an evidence type is an invariant type: the same key, whatever the
    // invariant is written with; the spec functions it calls are
    // dependencies of the entry
    let ev = s.get("invariant:crate::VerifiedMembership").expect("an invariant stating a certified property is an invariant entry");
    assert!(ev.deps.iter().any(|d| format!("{d:?}").contains("spec-fn:crate::accepts")), "{:?}", ev.deps);
    assert!(s.get("evidence-type:crate::VerifiedMembership").is_none());
}

// ---------------------------------------------------------------------
// review fixes (S2 review): forging, Abstract(T), projections in pure
// contexts, ghost reads, dependent conjuncts, `match` invariants, the
// surface key, `view_inj` diagnostics and proof items, determinacy
// reasons, omitted ghost arguments
// ---------------------------------------------------------------------

#[test]
fn a_struct_without_fields_cannot_carry_an_invariant() {
    // no private field: the constructor is public to host code, which could
    // build the value without the invariant (a `false` invariant would then
    // justify anything, e.g. an unchecked index)
    for (decl, lit) in [("pub struct Never;", "`Never`"), ("pub struct Never {}", "`Never {}`"), ("pub struct Never();", "`Never()`")] {
        let r = run(&format!(
            "#[cfg(sandblaster)] #[spec] fn never() -> bool {{ false }}\n#[derive(Clone, Copy)]\n#[invariant(never())]\n{decl}\npub fn boom(n: Never, xs: [u8; 4], i: u64) -> u8 {{ xs[i as usize] }}\n"
        ));
        assert!(!r.front_ok && r.has_error(K::Invariant, &format!("but no fields, so its constructor {lit} is public")), "{decl}:\n{}", r.rendered);
    }
    for attr in ["#[represents(|s: &Tok, a: Nat| a == 0)]", "#[view(|t| 0 as Nat)]"] {
        let r = run(&format!("#[derive(Clone, Copy)]\n{attr}\npub struct Tok;\n"));
        assert!(!r.front_ok && r.has_error(K::Invariant, "but no fields"), "{attr}:\n{}", r.rendered);
    }
    // a private field seals it: only the crate builds the token
    verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn ready() -> bool { true }
#[derive(Clone, Copy)]
#[invariant(ready())]
pub struct Ready { _sealed: () }
impl Ready {
    pub fn init() -> Ready { Ready { _sealed: () } }
}
pub fn use_it(r: Ready, x: u8) -> u8 { x }
"#,
    );
}

const LOSSY_POINT: &str = r#"
#[cfg(sandblaster)] #[spec] fn next(x: Nat) -> Nat { if x < 100 { x + 1 } else { 100 } }
#[derive(Clone, Copy)]
#[view(|p| p.x as Nat)]
pub struct Point { x: u32, tag: u8 }
#[refines(next)]
pub fn step(p: Point) -> Point { if p.x < 100 { Point { x: p.x + 1, tag: 1 } } else { Point { x: 100, tag: 7 } } }
"#;

#[test]
fn abstract_fails_when_a_boundary_function_exchanges_a_type_containing_it() {
    // `Holder` shows `Point`'s hidden `tag` to `tag_spec` and host code:
    // `tag(Holder { p: step(q) })` observes what `step`'s refinement leaves
    // open, so `Point` is not `Abstract` and its lossy view is an error
    let r = fails(&format!(
        "{LOSSY_POINT}
#[cfg(sandblaster)] #[spec] fn tag_spec(h: Holder) -> u8 {{ h.p.tag }}
#[derive(Clone, Copy)]
pub struct Holder {{ pub p: Point }}
#[refines(tag_spec)]
pub fn tag(h: Holder) -> u8 {{ h.p.tag }}
"
    ));
    assert!(r.has_error(K::ViewInjective, "the view of the public type `crate::Point` is not proven injective"), "{}", r.rendered);
    assert!(r.rendered.contains("the boundary function `crate::tag` exchanges `crate::Holder`, which contains `Point`"), "{}", r.rendered);
    // through a container returned without a refinement, too
    let r = fails(&format!("{LOSSY_POINT}\n#[derive(Clone, Copy)]\npub struct Holder {{ pub p: Point }}\npub fn forge(x: u32) -> Holder {{ Holder {{ p: Point {{ x, tag: 9 }} }} }}\n"));
    assert!(r.rendered.contains("the boundary function `crate::forge` exchanges `crate::Holder`"), "{}", r.rendered);
}

#[test]
fn abstract_needs_refinements_through_the_view() {
    // a boundary function refining a spec over `Point` itself reads the
    // hidden `tag`
    let r = fails(&format!("{LOSSY_POINT}\n#[cfg(sandblaster)] #[spec] fn raw_spec(p: Point) -> u8 {{ p.tag }}\n#[refines(raw_spec)]\npub fn raw(p: Point) -> u8 {{ p.tag }}\n"));
    assert!(r.has_error(K::ViewInjective, "`crate::Point` is not proven injective"), "{}", r.rendered);
    assert!(r.rendered.contains("the boundary function `crate::raw` refines `crate::raw_spec`, a specification over the representation of `Point`"), "{}", r.rendered);
    // an explicit argument map that reads a field is the same
    let r = fails(&format!("{LOSSY_POINT}\n#[cfg(sandblaster)] #[spec] fn id8(t: u8) -> u8 {{ t }}\n#[refines(id8(p.tag))]\npub fn raw(p: Point) -> u8 {{ p.tag }}\n"));
    assert!(r.rendered.contains("the explicit argument map of `crate::raw`'s `#[refines]` reads a field of `Point`"), "{}", r.rendered);
    // a representation relation: an observer over the representation
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn zero() -> Nat { 0 }
#[cfg(sandblaster)] #[spec] fn raw_spec(c: Ctr) -> u8 { c.secret }
#[derive(Clone, Copy)]
#[represents(|s: &Ctr, a: Nat| s.count as Nat == a)]
pub struct Ctr { count: u16, secret: u8 }
impl Ctr {
    #[refines(zero)]
    pub fn start() -> Ctr { Ctr { count: 0, secret: 5 } }
}
#[refines(raw_spec)]
pub fn raw(c: Ctr) -> u8 { c.secret }
"#,
    );
    assert!(r.has_error(K::Invariant, "has a representation relation, so it must be `Abstract(Ctr)`"), "{}", r.rendered);
    assert!(r.rendered.contains("a specification over the representation of `Ctr`"), "{}", r.rendered);
    // through the view: determined up to the view, with the reason recorded
    let r = verifies(LOSSY_POINT);
    let f = r.refinement("crate::step");
    assert!(f.checked && f.up_to.is_none(), "{}", r.explain());
    let why = f.determined_by.as_deref().unwrap_or_default();
    assert!(why.contains("`Abstract(Point)`") && why.contains("not established"), "{why}");
}

#[test]
fn the_determinacy_reason_is_recorded_and_printed() {
    // identity; an injective view; a representation relation; an unproven
    // refinement determines nothing (the spec sheet says so)
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn dbl(x: u8) -> u16 { (x as u16) * 2 }
#[refines(dbl)]
pub fn double(x: u8) -> u16 { (x as u16) + (x as u16) }
#[cfg(sandblaster)] #[spec] fn inc(x: Nat) -> Nat { x + 1 }
#[refines(inc)]
pub fn inc8(x: u8) -> u16 { (x as u16) + 1 }
"#,
    );
    assert_eq!(r.refinement("crate::double").determined_by.as_deref(), Some("identity result view"));
    assert_eq!(r.refinement("crate::inc8").determined_by.as_deref(), Some("injective result view"));
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn zero() -> Nat { 0 }
#[cfg(sandblaster)] #[spec] fn get(a: Nat) -> Nat { a }
#[derive(Clone, Copy)]
#[represents(|s: &Ctr, a: Nat| s.count as Nat == a)]
pub struct Ctr { count: u16 }
impl Ctr {
    #[refines(zero)]
    pub fn new() -> Ctr { Ctr { count: 0 } }
    #[refines(get)]
    pub fn get(&self) -> u16 { self.count }
}
"#,
    );
    let why = r.refinement("crate::Ctr::get").determined_by.clone().unwrap_or_default();
    assert!(why.contains("`Abstract(Ctr)`") && why.contains("established by `crate::Ctr::new`"), "{why}");
    let c = check(&[("r/mod.rs", "#[cfg(sandblaster)] #[spec] fn dbl(x: u8) -> u16 { (x as u16) * 2 }\n#[refines(dbl)]\npub fn double(x: u8) -> u16 { (x as u16) + 1 }\n")]);
    let k = c.krate.clone().unwrap();
    let reports = driver::stage::with_elaboration(&k, &VerifyOptions { provers: ProverSet::Standard, exec_only: false }, |out| driver::refinement_reports(out, &k));
    let d = reports.iter().find(|x| x.function == "crate::double").expect("a report");
    assert!(!d.determines && d.determined_by.is_none(), "{:?}", d.statement);
    assert!(d.statement.iter().any(|l| l.contains("NOT DETERMINING: the refinement is not proven")), "{:?}", d.statement);
    assert!(!d.statement.iter().any(|l| l.starts_with("determines")), "{:?}", d.statement);
}

#[test]
fn projections_of_invariant_values_in_loops_measures_and_place_indices() {
    // the loop condition and invariant read a field of a read-only invariant
    // value (a kernel type mismatch before); bounds, measures and place
    // indices read fields too (they had to be "simple expressions")
    let (_, built) = pipeline(&[(
        "r/mod.rs",
        r#"
pub const CAP: u64 = 16;
#[derive(Clone, Copy)]
#[invariant(self.len <= CAP)]
pub struct Buf { data: [u8; 16], len: u64 }
impl Buf {
    pub fn count(self) -> u64 {
        let mut i: u64 = 0;
        while i < self.len {
            proof! { decreases(16 - i); invariant(i <= self.len); }
            i = i + 1;
        }
        i
    }
    pub fn count2(self) -> u64 {
        let mut i: u64 = 0;
        while i < self.len {
            proof! { decreases(self.len - i); invariant(i <= self.len); }
            i = i + 1;
        }
        i
    }
    pub fn sum(self) -> u64 {
        let mut s: u64 = 0;
        for i in 0..self.len {
            proof! { invariant(s <= i * 255); }
            s = s + self.data[i as usize] as u64;
        }
        s
    }
    pub fn fill(self, x: u8) -> Buf {
        let mut b = self;
        while b.len < CAP {
            proof! { decreases(CAP - b.len); }
            b.data[b.len as usize] = x;
            b.len = b.len + 1;
        }
        b
    }
}
"#,
    )]);
    assert!(built.v.proofs_ok);
    verifies(&loc(
        r#"
/// Sum of the first `end` entries.
pub fn prefix(xs: [u8; 100], end: Location) -> u64 {
    let mut s: u64 = 0;
    for i in 0..end.0 {
        proof! { invariant(s <= i * 255); }
        s = s + xs[i as usize] as u64;
    }
    s
}

#[decreases(n.0, max = 100)]
fn depth(n: Location) -> u64 { if n.0 == 0 { 0 } else { depth(Location(n.0 - 1)) } }
pub fn api(n: Location) -> u64 { depth(n) }

#[derive(Clone, Copy)]
#[invariant(self.pos < 16)]
pub struct Cursor { pos: u64 }
#[derive(Clone, Copy)]
pub struct Pair { a: Cursor, b: Cursor }
/// Writes `x` at both cursors (the index bounds come from `Cursor`'s
/// invariant, through a projection of a projection).
pub fn mark(p: Pair, x: u8) -> [u8; 16] {
    let mut out: [u8; 16] = [0; 16];
    out[p.a.pos as usize] = x;
    out[p.b.pos as usize] = x;
    out
}
/// A compound assignment at a projected index.
pub fn bump(p: Pair, xs: [u32; 16]) -> [u32; 16] {
    let mut out = xs;
    if out[p.a.pos as usize] < 100 { out[p.a.pos as usize] += 1; }
    out
}
/// A proof step over a projection of a projection (its facts are bound
/// before the step).
#[ensures(|r: u64| r < 16)]
pub fn first(p: Pair) -> u64 {
    proof! { assert(p.a.pos < 16); }
    p.a.pos
}
"#,
    ));
}

#[test]
fn ghost_code_reads_private_fields_across_modules() {
    // the type lives in a submodule (its fields private, as S2 requires);
    // the spec module, a lemma and a contract at the root read them
    verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
#[cfg(sandblaster)] #[path = "LEMMAS.rs"] mod lemmas;
mod loc;
mod user;
pub use loc::Location;
pub use user::half;
pub use user::raw2;
"#,
        ),
        ("r/spec.rs", "use crate::loc::Location;\npub fn raw(l: Location) -> Nat { l.0 as Nat }\n"),
        (
            "r/loc.rs",
            "use sandblaster::prelude::*;\n/// A location.\n#[derive(Clone, Copy, PartialEq, Eq)]\n#[invariant(self.0 < 100)]\npub struct Location(u64);\nimpl Location {\n    pub fn new(x: u64) -> Option<Location> { if x < 100 { Some(Location(x)) } else { None } }\n    pub fn get(self) -> u64 { self.0 }\n}\n",
        ),
        (
            "r/user.rs",
            "use sandblaster::prelude::*;\nuse crate::loc::Location;\n#[ensures(|r: u64| r as Nat * 2 <= crate::spec::raw(l))]\npub fn half(l: Location) -> u64 { l.get() / 2 }\n#[ensures(|r: u64| match l { Location(x) => r == x })]\npub fn raw2(l: Location) -> u64 { l.get() }\n",
        ),
        ("r/LEMMAS.rs", "use sandblaster::prelude::*;\nuse crate::loc::Location;\n#[lemma]\nfn loc_small(l: Location) {\n    ensures(l.0 < 100);\n    follows();\n}\n"),
    ]);
    // exec code outside the module still may not
    let r = run_files(&[
        ("r/mod.rs", "mod loc;\npub use loc::Location;\npub fn peek(l: Location) -> u64 { l.0 }\n"),
        ("r/loc.rs", "use sandblaster::prelude::*;\n#[derive(Clone, Copy)]\n#[invariant(self.0 < 100)]\npub struct Location(u64);\n"),
    ]);
    assert!(!r.front_ok && r.has_error(K::Privacy, "field `0` is private"), "{}", r.rendered);
}

const SPAN: &str = r#"
/// A span; `w` caches the width (its definition needs the first part).
#[derive(Clone, Copy)]
#[invariant(self.lo <= self.hi && self.hi <= 1000000 && self.w == self.hi - self.lo)]
pub struct Span { lo: u64, hi: u64, w: u64 }
impl Span {
    pub fn new(lo: u64, hi: u64) -> Option<Span> { if lo <= hi && hi <= 1000000 { Some(Span { lo, hi, w: hi - lo }) } else { None } }
    pub fn width(self) -> u64 { self.w }
}
/// Uses each conjunct separately.
pub fn f(s: Span, t: Span) -> Option<Span> {
    let a = s.hi - s.lo + t.w;
    if s.lo + 1 <= s.hi { Span::new(s.lo + 1, s.hi) } else { Span::new(t.lo, t.hi + (a % 7)) }
}
#[ensures(|r: u64| r <= 1000000)]
pub fn g(s: Span) -> u64 { s.w }
"#;

#[test]
fn dependent_conjuncts_are_split_with_their_hypotheses() {
    // `self.w == self.hi - self.lo` needs `self.lo <= self.hi`: it is its own
    // conjunct, with the earlier ones as `Irr` hypotheses — three simple
    // facts, all proven by the basic prover
    let r = verifies(SPAN);
    for k in 0..3 {
        assert!(r.checked_defs.iter().any(|d| d == &format!("crate::Span::invariant#{k}")), "{:?}", r.checked_defs);
        assert!(r.checked_defs.iter().any(|d| d == &format!("crate::Span::inv#{k}")), "{:?}", r.checked_defs);
    }
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    // eval checks each conjunct
    let e = eval(SPAN, "g", "[[5, 9, 3]]").unwrap_err();
    assert!(e.contains("violates the invariant of `crate::Span`"), "{e}");
    assert_eq!(eval(SPAN, "g", "[[5, 9, 4]]").unwrap(), "4");
    let (_, built) = pipeline(&[("r/mod.rs", SPAN)]);
    assert!(built.v.proofs_ok);
}

#[test]
fn match_and_if_let_invariants_are_bool_invariants() {
    verifies(
        r#"
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind { Leaf, Inner }
/// Leaves have height 0, inner nodes 1..63.
#[derive(Clone, Copy)]
#[invariant(match self.kind { Kind::Leaf => self.height == 0, Kind::Inner => self.height >= 1 && self.height < 64 })]
pub struct Node { kind: Kind, height: u32 }
/// A parent comes before its child.
#[derive(Clone, Copy)]
#[invariant(if let Some(p) = self.parent { p < self.idx } else { true })]
pub struct Link { idx: u64, parent: Option<u64> }
impl Node {
    pub fn leaf() -> Node { Node { kind: Kind::Leaf, height: 0 } }
    #[ensures(|r: u32| r < 64)]
    pub fn h(self) -> u32 { self.height }
}
impl Link {
    pub fn root() -> Link { Link { idx: 0, parent: None } }
    pub fn gap(self) -> u64 { match self.parent { Some(p) => self.idx - p, None => 0 } }
}
"#,
    );
}

#[test]
fn an_invariant_keeps_its_surface_key_whatever_it_is_written_with() {
    // inline, or through a spec function (a "certified property"): one key
    let key_of = |inv: &str| {
        let body = format!(
            "#[cfg(sandblaster)] #[spec] fn ok(i: u64, p: Option<u64>) -> bool {{ match p {{ Some(q) => q < i, None => true }} }}\n#[derive(Clone, Copy)]\n#[invariant({inv})]\npub struct Link {{ idx: u64, parent: Option<u64> }}\nimpl Link {{ pub fn root() -> Link {{ Link {{ idx: 0, parent: None }} }} }}\n"
        );
        let c = check(&[("r/mod.rs", &body)]);
        let r = driver::stage::spec_run(&c, &driver::stage::SpecBaseline::Lock, false);
        assert!(r.v.proofs_ok, "{}", r.v.diags.render(&c.sm));
        r.surface.unwrap().items.iter().filter(|i| i.key.starts_with("invariant:") || i.key.starts_with("evidence-type:")).map(|i| i.key.clone()).collect::<Vec<_>>()
    };
    let a = key_of("if let Some(q) = self.parent { q < self.idx } else { true }");
    let b = key_of("ok(self.idx, self.parent)");
    assert_eq!(a, vec!["invariant:crate::Link".to_string()]);
    assert_eq!(a, b);
}

#[test]
fn a_failed_view_inj_names_the_field_and_suggests_a_proof_item() {
    let r = fails(
        r#"
#[derive(Clone, Copy, PartialEq)]
#[view(|p| p.x as Nat)]
pub struct Point { x: u32, tag: u8 }
"#,
    );
    assert!(r.rendered.contains("did not prove: the view does not determine the field `tag`"), "{}", r.rendered);
    assert!(r.rendered.contains("#[proof(view_inj = Point)]"), "{}", r.rendered);
    // the two values' fields have distinct names in the goal
    assert!(r.unproven.iter().any(|(_, k, g)| k == "view-injective" && g.contains("a.tag") && g.contains("b.tag")), "{}", r.explain());
}

fn as_refs(v: &[(String, String)]) -> Vec<(&str, &str)> {
    v.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect()
}

const COUNTER: &str = r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;
#[cfg(sandblaster)] #[path = "PROOF.rs"] mod proofs;
/// A counter with a cached parity bit: the view drops `odd`, which the
/// invariant determines.
#[derive(Clone, Copy)]
#[invariant(self.odd == (self.n % 2 == 1))]
#[view(|c| c.n as Nat)]
pub struct Counter { n: u32, odd: bool }
impl Counter {
    #[refines(spec::zero)]
    pub fn zero() -> Counter { Counter { n: 0, odd: false } }
    #[refines(spec::same)]
    pub fn same(self) -> Counter { self }
}
"#;

#[test]
fn a_view_inj_proof_item_proves_the_view_injective() {
    let files = |proof: &str| -> Vec<(String, String)> {
        vec![
            ("r/mod.rs".into(), COUNTER.into()),
            ("r/spec.rs".into(), "pub fn zero() -> Nat { 0 }\npub fn same(x: Nat) -> Nat { x }\n".into()),
            ("r/PROOF.rs".into(), proof.into()),
        ]
    };
    let ok = files("#[proof(view_inj = super::Counter)]\nfn counter_view_inj(a: super::Counter, b: super::Counter) {\n    assert(a.n == b.n);\n    assert(a.odd == (a.n % 2 == 1));\n    assert(b.odd == (b.n % 2 == 1));\n    assert(a.odd == b.odd);\n}\n");
    let r = verifies_files(&as_refs(&ok));
    assert!(r.checked_defs.iter().any(|d| d == "crate::Counter::view_inj_fields") && r.checked_defs.iter().any(|d| d == "crate::Counter::view_inj"), "{:?}", r.checked_defs);
    for f in ["crate::Counter::zero", "crate::Counter::same"] {
        let x = r.refinement(f);
        assert!(x.checked && x.up_to.is_none(), "{f}: {}", r.explain());
        assert!(x.determined_by.as_deref().is_some_and(|w| w.contains("`crate::Counter::view_inj`")), "{f}: {:?}", x.determined_by);
        assert!(r.established.iter().any(|g| g == f), "{f}: {:?}", r.established);
    }
    // a proof that does not show it is an error
    let bad = files("#[proof(view_inj = super::Counter)]\nfn counter_view_inj(a: super::Counter, b: super::Counter) {\n    assert(a.n == b.n);\n    todo();\n}\n");
    let r = run_files(&as_refs(&bad));
    assert!(!r.verified, "{}", r.explain());
    // the wrong shape is reported in the front end
    let shape = files("#[proof(view_inj = super::Counter)]\nfn counter_view_inj(a: super::Counter) { }\n");
    let r = run_files(&as_refs(&shape));
    assert!(!r.front_ok && r.has_error(K::Law, "must take two values of `Counter`"), "{}", r.rendered);
}

#[test]
fn an_omitted_ghost_argument_is_reported() {
    let r = run(
        r#"
#[requires(k == x as Int)]
#[ensures(|r: u8| r == x)]
fn ident(x: u8, #[ghost] k: Int) -> u8 { x }
#[ensures(|r: u8| r == 10)]
pub fn api() -> u8 { ident(10) }
"#,
    );
    assert!(!r.front_ok && r.has_error(K::Ghost, "missing `ghost!(..)` argument for the `#[ghost]` parameter `k` of `ident`"), "{}", r.rendered);
    assert!(r.rendered.contains("`ident` requires `k == x as Int`"), "{}", r.rendered);
}
