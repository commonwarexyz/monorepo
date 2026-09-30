//! §15 S1 spec closure, fuel and mirrors (DESIGN.md §15.1): a spec item
//! (spec function or constant, view, representation relation, example,
//! explicit refinement argument map) may not reach an exec function or
//! constant unless it is established (refined, with an injective view, by
//! a proven `#[refines]` earlier in the crate) — computed with the kernel's
//! `Env::refs_closure`; fuel-bounded specs need `#[fuel_sufficient]`; a spec
//! that copies its implementation needs `#[mirrors_impl]` and independent
//! evidence. Legacy `#[spec] fn`s outside the S1 surface are recorded and
//! are errors of the crate path's examples gate.

#[path = "spec15_util.rs"]
mod util;

use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::elab::examples::ClosureKind;
use util::*;

const EXEC: &str = "fn scale(x: u32) -> u64 { (x as u64) * 3 }\npub fn api(x: u32) -> u64 { scale(x) }\n";

#[test]
fn a_spec_module_function_calling_the_implementation_is_rejected() {
    let r = run_files(&[
        ("r/mod.rs", &format!("{EXEC}#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n")),
        ("r/spec.rs", "pub fn scaled(x: u32) -> Nat { super::scale(x) as Nat }\n"),
    ]);
    assert!(r.has_error(K::SpecDependsOnImpl, "spec function `crate::spec::scaled` depends on the exec function `crate::scale`"), "{}", r.explain());
}

#[test]
fn the_vacuous_refinement_attack_is_rejected() {
    // `#[spec] fn s(x) { f(x) }` with `#[refines(s)] fn f` would make any `f`
    // "refine its spec"
    let r = run(
        r#"
#[cfg(sandblaster)] #[spec] fn s(x: u32) -> Nat { f(x) as Nat }
#[refines(s)]
pub fn f(x: u32) -> u64 { (x as u64) + 7 }
"#,
    );
    assert!(!r.verified, "{}", r.explain());
    assert!(r.has_error(K::SpecDependsOnImpl, "depends on the exec function `crate::f`"), "{}", r.explain());
    assert!(!r.established.iter().any(|g| g == "crate::f"));
}

#[test]
fn established_functions_may_be_used_by_specs() {
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;

#[refines(spec::triple)]
fn scale(x: u32) -> u64 { (x as u64) * 3 }
pub fn api(x: u32) -> u64 { scale(x) }
"#,
        ),
        ("r/spec.rs", "pub fn triple(x: Nat) -> Nat { 3 * x }\n// `scale` is established (refined with an injective view): specs may use it\npub fn triple_plus(x: u32) -> Nat { super::scale(x) as Nat + 1 }\n"),
    ]);
    assert!(r.established.iter().any(|g| g == "crate::scale"), "{:?}", r.established);
}

#[test]
fn a_function_refined_up_to_a_lossy_view_is_not_established() {
    let r = run_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] #[path = "spec.rs"] mod spec;

#[derive(Clone, Copy)]
#[view(|p| p.x as Nat)]
pub struct P { x: u32, tag: u8 }

#[refines(spec::id)]
fn keep(p: P) -> P { P { x: p.x, tag: 1 } }
pub fn api(p: P) -> P { keep(p) }
"#,
        ),
        ("r/spec.rs", "pub fn id(x: Nat) -> Nat { x }\npub fn uses(p: super::P) -> Nat { super::keep(p).x as Nat }\n"),
    ]);
    assert!(r.has_error(K::SpecDependsOnImpl, "`crate::spec::uses` depends on the exec function `crate::keep`"), "{}", r.explain());
}

#[test]
fn legacy_spec_functions_are_recorded_for_the_gate() {
    // a `#[spec] fn` outside a `#[spec]` module that is no refinement target
    // (QMDB's legacy `Acceptance`): recorded, an error of the examples gate
    let r = run(&format!("{EXEC}#[cfg(sandblaster)] #[spec] fn legacy(x: u32) -> u64 {{ scale(x) }}\n"));
    assert!(r.verified, "{}", r.explain());
    assert!(r.closure.iter().any(|(i, k, m)| i == "crate::legacy" && *k == ClosureKind::DependsOnImpl && m.contains("crate::scale")), "{:?}", r.closure);
}

#[test]
fn spec_constants_views_examples_and_argument_maps_are_spec_items() {
    // an exec constant in a spec constant
    let r = run_files(&[
        ("r/mod.rs", "const K: u64 = 7;\npub fn api() -> u64 { K }\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n"),
        ("r/spec.rs", "pub const SK: u64 = super::K + 1;\n"),
    ]);
    assert!(r.has_error(K::SpecDependsOnImpl, "spec constant `crate::spec::SK` depends on the exec constant `crate::K`"), "{}\n{:?}\n{:?}", r.explain(), r.closure, r.checked_defs);
    // a view
    let r = run(&format!("{EXEC}#[derive(Clone, Copy)]\n#[view(|w| scale(w.0) as Nat)]\npub struct W(u32);\npub fn w(x: W) -> W {{ x }}\n"));
    assert!(r.has_error(K::SpecDependsOnImpl, "depends on the exec function `crate::scale`"), "{}", r.explain());
    // an example of a spec function
    let r = run(&format!("{EXEC}#[cfg(sandblaster)] #[spec] #[example(t(1) == scale(1) as Nat)] fn t(x: Nat) -> Nat {{ 3 * x }}\n"));
    assert!(r.has_error(K::SpecDependsOnImpl, "example #0 of `crate::t` depends on the exec function `crate::scale`"), "{}", r.explain());
    // the explicit argument map of a refinement
    let r = run(&format!("{EXEC}#[cfg(sandblaster)] #[spec] fn id(x: Nat) -> Nat {{ x }}\n#[refines(id(scale(x) as Nat))]\nfn g(x: u32) -> u64 {{ (x as u64) * 3 }}\npub fn gg(x: u32) -> u64 {{ g(x) }}\n"));
    assert!(r.has_error(K::SpecDependsOnImpl, "the explicit argument map of `#[refines]` on `crate::g` depends on the exec function `crate::scale`"), "{}", r.explain());
}

#[test]
fn derived_equality_is_not_an_implementation() {
    verifies_files(&[
        (
            "r/mod.rs",
            "#[derive(Clone, Copy, PartialEq)]\npub struct D { pub a: u8 }\npub fn d(x: D) -> D { x }\n#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n",
        ),
        ("r/spec.rs", "pub fn same(x: super::D, y: super::D) -> bool { x == y }\n"),
    ]);
}

// ---------------------------------------------------------------------
// fuel
// ---------------------------------------------------------------------

const FUEL_SPEC: &str = r#"
/// Bend-style: `fuel` only counts down; `peaks` returns `0` when it runs out
pub fn peaks(fuel: Nat, size: Nat) -> Nat {
    if fuel == 0 { 0 } else if size == 0 { 0 } else { 1 + peaks(fuel - 1, size / 2) }
}
/// not fuel: the countdown is the value
pub fn count(n: Nat) -> Nat { if n == 0 { 0 } else { 1 + count(n - 1) } }
"#;

#[test]
fn a_fuel_bounded_spec_needs_fuel_sufficient() {
    let r = run_files(&[("r/mod.rs", "#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n"), ("r/spec.rs", FUEL_SPEC)]);
    assert!(r.has_error(K::FuelSufficient, "spec function `crate::spec::peaks` is fuel-bounded (parameter `fuel`)"), "{}", r.explain());
    assert!(!r.errors.iter().any(|(_, m)| m.contains("crate::spec::count")), "a countdown whose count is the value is not fuel: {}", r.explain());
}

#[test]
fn a_proven_fuel_sufficient_lemma_discharges_it() {
    let spec = format!(
        "{FUEL_SPEC}\n#[lemma]\n#[fuel_sufficient(peaks)]\nfn peaks_fuel(size: Nat) {{\n    requires(size < 4);\n    ensures(peaks(3, size) == peaks(4, size));\n    by_cases(size, 0..4);\n}}\n"
    );
    let r = run_files(&[("r/mod.rs", "#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n"), ("r/spec.rs", &spec)]);
    assert!(!r.errors.iter().any(|(k, _)| *k == K::FuelSufficient), "{}", r.explain());
}

// ---------------------------------------------------------------------
// mirrors
// ---------------------------------------------------------------------

#[test]
fn a_spec_that_copies_its_implementation_needs_mirrors_impl() {
    let r = run(
        r#"
#[cfg(sandblaster)] #[spec] fn max3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
#[refines(max3)]
pub fn m3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
"#,
    );
    assert!(r.has_error(K::SpecMirrorsImpl, "spec function `crate::max3` is a copy of the exec function `crate::m3`"), "{}", r.explain());
    // justified, but without an independent description
    let r = run(
        r#"
#[cfg(sandblaster)] #[spec] #[mirrors_impl(justification = "max is its own reference")] fn max3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
#[refines(max3)]
pub fn m3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
"#,
    );
    assert!(r.has_error(K::SpecMirrorsImpl, "is a copy of the exec function"), "{}", r.explain());
    // justified and backed by examples
    verifies(
        r#"
#[cfg(sandblaster)]
#[spec]
#[mirrors_impl(justification = "max is its own reference")]
#[example(max3(1, 9, 4) == 9 && max3(7, 2, 3) == 7)]
fn max3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
#[refines(max3)]
pub fn m3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
"#,
    );
}

#[test]
fn a_different_formulation_is_not_a_mirror() {
    verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn max3(a: u8, b: u8, c: u8) -> u8 { if a >= b && a >= c { a } else if b >= c { b } else { c } }
#[refines(max3)]
pub fn m3(a: u8, b: u8, c: u8) -> u8 { a.max(b).max(c) }
"#,
    );
}
