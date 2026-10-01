//! Toolchain features added for the MMR verified in place
//! (`storage/sandblaster/mmr`): each has a positive test and a negative
//! twin.
//!
//! * an attachment to a derived `default` (`ensures(..)`, `at_start!`);
//! * a contract's paths name what they use (a qualified
//!   `crate::m::T::f` does not keep an import of `f`);
//! * the attached `ensures(..)` of one function are conjoined;
//! * a getter's contract (`ret == self.0`) is proven from the projection;
//! * lift prelude functions (`crate::__lift::ord_lt`) in a section's
//!   dependencies are trusted primitives, not functions to determine;
//! * `use_real(i, args..)` in `#[proof(complete = ..)]` items: the section
//!   hypothesis `l{i}` about the real function.
//!
//! (The in-place conformance harness and the restoration of unit fields in
//! rewrite motives have unit tests beside their code.) The lifted bodies are
//! rustc's MIR (the fixtures `mir_fixtures/mt_*`).

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::Severity;
use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::elab::complete::DepHow;
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::explain;

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// The MIR fixtures of this file (`mir_fixtures/mt_*`): a lifted `src/a.rs`
/// and rustc's MIR of it (`mir_fixtures/extract.py`).
const FIXTURES: &[(&str, &str)] = &[
    (include_str!("mir_fixtures/mt_derived/src/a.rs"), include_str!("mir_fixtures/mt_derived/a.sbmir")),
    (include_str!("mir_fixtures/mt_qualified/src/a.rs"), include_str!("mir_fixtures/mt_qualified/a.sbmir")),
    (include_str!("mir_fixtures/mt_half/src/a.rs"), include_str!("mir_fixtures/mt_half/a.sbmir")),
    (include_str!("mir_fixtures/mt_pair/src/a.rs"), include_str!("mir_fixtures/mt_pair/a.sbmir")),
    (include_str!("mir_fixtures/mt_cmp/src/a.rs"), include_str!("mir_fixtures/mt_cmp/a.sbmir")),
];

/// The files, and rustc's MIR of the lifted `src/a.rs` beside the DSL root
/// (`a.sbmir`).
fn check(files: &[(&str, &str)]) -> Checked {
    let mir = files.iter().find(|(p, _)| *p == A).and_then(|(_, c)| FIXTURES.iter().find(|(s, _)| s == c)).map(|(_, m)| *m).unwrap_or("");
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)).chain([("c/sandblaster/m/a.sbmir", mir)]));
    driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn error_text(c: &Checked) -> String {
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.msg.clone()).collect::<Vec<_>>().join("\n")
}

#[track_caller]
fn front_ok(files: &[(&str, &str)]) -> Checked {
    let c = check(files);
    assert!(c.ok(), "front end rejected the crate:\n{}", c.render());
    c
}

fn verify(c: &Checked) -> Verification {
    driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false })
}

#[track_caller]
fn verified(files: &[(&str, &str)]) {
    let c = front_ok(files);
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

/// The names of the definitions that did not check (at least one).
#[track_caller]
fn failed(files: &[(&str, &str)]) -> Vec<String> {
    let c = front_ok(files);
    let v = verify(&c);
    let f: Vec<String> = v.failed_defs().iter().map(|d| d.name.clone()).collect();
    assert!(!f.is_empty(), "expected a definition to fail; everything checked:\n{}", explain(&c, &v));
    f
}

/// A DSL root lifting `src/a.rs` in place, with `LAWS.rs` and `PROOF.rs`.
fn lifted_root() -> String {
    format!("{ROOT}#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\npub mod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n")
}

const R: &str = "c/sandblaster/m/mod.rs";
const A: &str = "c/src/a.rs";
const L: &str = "c/sandblaster/m/LAWS.rs";
const P: &str = "c/sandblaster/m/PROOF.rs";
const EMPTY: &str = "use sandblaster::prelude::*;\n";

fn attach(target: &str, body: &str) -> String {
    format!("use sandblaster::prelude::*;\n\n#[lift_attach({target})]\nfn contract() {{\n    {body}\n}}\n")
}

// ---------------------------------------------------------------------
// an attachment to a derived `default`
// ---------------------------------------------------------------------

const DERIVED: &str = include_str!("mir_fixtures/mt_derived/src/a.rs");

#[test]
fn a_derived_default_takes_an_attached_contract() {
    let proof = attach("crate::a::S::default", "ensures(|ret: crate::a::S| ret.x == 0u64);\n    at_start! {\n        assert(0u64 == 0u64, { follows(); });\n    }");
    verified(&[(R, &lifted_root()), (A, DERIVED), (L, EMPTY), (P, &proof)]);
}

#[test]
fn a_derived_default_contract_is_checked_and_holds_nothing_else() {
    // a false contract: the derived body does not meet it
    let proof = attach("crate::a::S::default", "ensures(|ret: crate::a::S| ret.x == 1u64);");
    let f = failed(&[(R, &lifted_root()), (A, DERIVED), (L, EMPTY), (P, &proof)]);
    assert!(f.iter().any(|n| n.contains("default")), "{f:?}");
    // a precondition: refused (a derived `default` takes no argument)
    let proof = attach("crate::a::S::default", "requires(true);\n    ensures(|ret: crate::a::S| ret.x == 0u64);");
    let c = check(&[(R, &lifted_root()), (A, DERIVED), (L, EMPTY), (P, &proof)]);
    assert!(error_text(&c).contains("an attachment to a derived `default` holds `ensures(..);` and `at_start! { .. }` only"), "{}", c.render());
}

// ---------------------------------------------------------------------
// a contract's paths name what they use
// ---------------------------------------------------------------------

/// `helper` is imported from a host module the lift does not read, and
/// used by the lifted code only as the qualified `crate::a::S::helper`.
const QUALIFIED: &str = include_str!("mir_fixtures/mt_qualified/src/a.rs");

#[test]
fn a_qualified_path_in_a_contract_does_not_keep_an_import() {
    let proof = attach("crate::a::f", "ensures(|ret: u64| ret == crate::a::S::helper(x));");
    verified(&[(R, &lifted_root()), (A, QUALIFIED), (L, EMPTY), (P, &proof)]);
}

#[test]
fn a_contract_naming_the_import_keeps_it() {
    // the contract uses the imported `helper` itself: the import stays,
    // and names a host module the lift does not read
    let proof = attach("crate::a::f", "ensures(|ret: u64| ret == helper(x));");
    let c = check(&[(R, &lifted_root()), (A, QUALIFIED), (L, EMPTY), (P, &proof)]);
    assert!(!c.ok() && error_text(&c).contains("helper"), "expected the kept import to fail to resolve:\n{}", c.render());
}

// ---------------------------------------------------------------------
// attached `ensures(..)` are conjoined
// ---------------------------------------------------------------------

const HALF: &str = include_str!("mir_fixtures/mt_half/src/a.rs");

#[test]
fn two_attached_ensures_are_conjoined() {
    let laws = attach("crate::a::half", "ensures(|ret: u64| ret <= x);");
    let proof = attach("crate::a::half", "ensures(|ret: u64| ret <= x / 2u64);");
    verified(&[(R, &lifted_root()), (A, HALF), (L, &laws), (P, &proof)]);
}

#[test]
fn attached_ensures_must_bind_the_result_alike() {
    for (first, second, needle) in [
        ("ensures(x >= 0u64);", "ensures(|ret: u64| ret <= x);", "must all bind the result, or none"),
        ("ensures(|ret: u64| ret <= x);", "ensures(x >= 0u64);", "must bind the result alike"),
        ("ensures(|ret: u64| ret <= x);", "ensures(|r: u64| r <= x / 2u64);", "must bind the result alike"),
    ] {
        let laws = attach("crate::a::half", first);
        let proof = attach("crate::a::half", second);
        let c = check(&[(R, &lifted_root()), (A, HALF), (L, &laws), (P, &proof)]);
        assert!(error_text(&c).contains(needle), "{needle}: {}", c.render());
    }
}

// ---------------------------------------------------------------------
// a getter's contract
// ---------------------------------------------------------------------

const PAIR: &str = include_str!("mir_fixtures/mt_pair/src/a.rs");

#[test]
fn a_getter_contract_is_proven_from_the_projection() {
    let proof = attach("crate::a::Pair::first", "ensures(|ret: u64| ret == self.0);");
    verified(&[(R, &lifted_root()), (A, PAIR), (L, EMPTY), (P, &proof)]);
}

#[test]
fn a_getter_contract_naming_the_wrong_field_fails() {
    let proof = attach("crate::a::Pair::first", "ensures(|ret: u64| ret == self.1);");
    let f = failed(&[(R, &lifted_root()), (A, PAIR), (L, EMPTY), (P, &proof)]);
    assert!(f.iter().any(|n| n.contains("first")), "{f:?}");
}

// ---------------------------------------------------------------------
// lift prelude functions in a section's dependencies
// ---------------------------------------------------------------------

const CMP: &str = include_str!("mir_fixtures/mt_cmp/src/a.rs");

/// The sections of a lifted crate with its dependency records, by display path.
fn section_deps(files: &[(&str, &str)]) -> Vec<(Vec<String>, Vec<(String, DepHow)>)> {
    let c = front_ok(files);
    let k = c.krate.clone().unwrap();
    let kr = &k;
    sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &sandblaster_front::elab::Options::default());
        let path = |id: sandblaster_front::hir::ItemId| kr.item(id).path.to_string();
        out.sections.iter().map(|s| (s.members.iter().map(|m| path(*m)).collect(), s.dep_status.iter().map(|(d, h)| (path(*d), h.clone())).collect())).collect()
    })
}

#[test]
fn a_lift_prelude_function_is_a_trusted_dependency() {
    let laws = "use sandblaster::prelude::*;\n\n/// `order` answers `Less` exactly below.\n#[law]\nfn order_lt(a: u64, b: u64) {\n    ensures(crate::__lift::ord_lt(crate::a::order(a, b)) == (a < b));\n}\n";
    let proof = "use sandblaster::prelude::*;\n\n#[proof]\nfn order_lt(a: u64, b: u64) {\n    follows();\n}\n";
    let secs = section_deps(&[(R, &lifted_root()), (A, CMP), (L, laws), (P, proof)]);
    let deps: Vec<&(String, DepHow)> = secs.iter().filter(|(m, _)| m.iter().any(|x| x == "crate::a::order")).flat_map(|(_, d)| d).collect();
    assert!(deps.iter().any(|(d, h)| d == "crate::__lift::ord_lt" && *h == DepHow::Prelude), "{secs:?}");
}

#[test]
fn a_host_function_in_a_law_is_not_a_trusted_dependency() {
    // the same law through the host's own `lt`: a dependency to determine
    let laws = "use sandblaster::prelude::*;\n\n/// `order` answers `Less` exactly when `lt` holds.\n#[law]\nfn order_lt(a: u64, b: u64) {\n    ensures(crate::__lift::ord_lt(crate::a::order(a, b)) == crate::a::lt(a, b));\n}\n";
    let proof = "use sandblaster::prelude::*;\n\n#[proof]\nfn order_lt(a: u64, b: u64) {\n    follows();\n}\n";
    let secs = section_deps(&[(R, &lifted_root()), (A, CMP), (L, laws), (P, proof)]);
    let deps: Vec<&(String, DepHow)> = secs.iter().flat_map(|(_, d)| d).collect();
    assert!(!deps.iter().any(|(d, h)| d == "crate::a::lt" && *h == DepHow::Prelude), "{secs:?}");
    assert!(deps.iter().any(|(d, h)| d == "crate::__lift::ord_lt" && *h == DepHow::Prelude), "{secs:?}");
}

// ---------------------------------------------------------------------
// use_real in completeness proofs
// ---------------------------------------------------------------------

const IS_EVEN: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[cfg(sandblaster)]\n#[spec]\nfn even(x: Nat) -> bool { x % 2 == 0 }\n\npub fn is_even(x: u32) -> bool { x % 2 == 0 }\n\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n";

const IS_EVEN_LAWS: &str = "use sandblaster::prelude::*;\nuse super::{is_even, even};\n\n/// `is_even` holds only of even numbers.\n#[law]\nfn is_even_sound(x: u32) {\n    requires(is_even(x));\n    ensures(even(x as Nat));\n}\n\n/// `is_even` holds of every even number.\n#[law]\nfn is_even_complete(x: u32) {\n    requires(even(x as Nat));\n    ensures(is_even(x));\n}\n";

fn is_even_proof(body: &str) -> String {
    format!(
        "use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::{{is_even, even}};\n\n#[proof]\nfn is_even_sound(x: u32) {{\n    follows();\n}}\n\n#[proof]\nfn is_even_complete(x: u32) {{\n    follows();\n}}\n\n/// Pinned by its laws, with explicit instances of them.\n#[proof(complete = super::is_even)]\nfn is_even_determined(x: u32) {{\n{body}\n}}\n"
    )
}

/// `use_hyp(0, x)`: the soundness law for the hypothetical `is_even'`;
/// `use_real(1, x)`: the completeness law for the real `is_even`.
const USE_REAL: &str = "    if is_even(x) {\n        use_hyp(0, x);\n        use_real(1, x);\n        follows();\n    } else if even(x as Nat) {\n        use_hyp(1, x);\n        by_contradiction();\n    } else {\n        follows();\n    }";

#[test]
fn use_real_instantiates_a_hypothesis_about_the_real_function() {
    let p = is_even_proof(USE_REAL);
    verified(&[("r/mod.rs", IS_EVEN), ("r/LAWS.rs", IS_EVEN_LAWS), ("r/PROOF.rs", &p)]);
}

#[test]
fn use_real_of_a_missing_hypothesis_or_without_its_requires_fails() {
    for (body, needle) in [
        (USE_REAL.replace("use_real(1, x);", "use_real(7, x);"), Some("use_real")),
        // the real completeness law where `even(x)` is unknown
        (USE_REAL.replace("    } else {\n        follows();\n    }", "    } else {\n        use_real(1, x);\n        follows();\n    }"), None),
    ] {
        let p = is_even_proof(&body);
        let c = front_ok(&[("r/mod.rs", IS_EVEN), ("r/LAWS.rs", IS_EVEN_LAWS), ("r/PROOF.rs", &p)]);
        let v = verify(&c);
        assert!(!v.proofs_ok, "expected a failure:\n{}", explain(&c, &v));
        if let Some(n) = needle {
            assert!(explain(&c, &v).contains(n), "{n}: {}", explain(&c, &v));
        }
    }
}
