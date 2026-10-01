//! The lift extensions for commonware-storage's Merkle proof verifier
//! (`storage/sandblaster/verifier`, SEMANTICS.md §19.5–§19.10): an item
//! selection for in-place files, an open trait declared in the lifted file
//! (its provided methods at the instance, and the rule for names shared
//! with inherent methods), erasure only where a parameter was erased, host
//! models of types and functions, the value/iterator/`Vec` state
//! parameters, a depth bound for non-tail recursion by attachment, the
//! in-place type invariant as a host obligation, `core::ops::Range`,
//! thiserror's `#[error]` text, and the SHA-256 model against a native
//! FIPS 180-4 implementation. The lifted bodies are rustc's MIR (the
//! fixtures `mir_fixtures/lv_*`). Each feature has a positive test and a
//! negative twin.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::Severity;
use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::opts;

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// The MIR fixtures of this file (`mir_fixtures/lv_*`): a lifted `src/a.rs`
/// and rustc's MIR of it (`mir_fixtures/extract.py`).
const FIXTURES: &[(&str, &str)] = &[
    (include_str!("mir_fixtures/lv_items/src/a.rs"), include_str!("mir_fixtures/lv_items/a.sbmir")),
    (include_str!("mir_fixtures/lv_tr/src/a.rs"), include_str!("mir_fixtures/lv_tr/a.sbmir")),
    (include_str!("mir_fixtures/lv_er/src/a.rs"), include_str!("mir_fixtures/lv_er/a.sbmir")),
    (include_str!("mir_fixtures/lv_st/src/a.rs"), include_str!("mir_fixtures/lv_st/a.sbmir")),
    (include_str!("mir_fixtures/lv_wb/src/a.rs"), include_str!("mir_fixtures/lv_wb/a.sbmir")),
    (include_str!("mir_fixtures/lv_bump/src/a.rs"), include_str!("mir_fixtures/lv_bump/a.sbmir")),
    (include_str!("mir_fixtures/lv_rec/src/a.rs"), include_str!("mir_fixtures/lv_rec/a.sbmir")),
    (include_str!("mir_fixtures/lv_inv/src/a.rs"), include_str!("mir_fixtures/lv_inv/a.sbmir")),
];

/// rustc's MIR of a fixture's source; for a source no fixture has (a
/// negative twin the item skeleton refuses), a MIR that does not match it
/// (the load reports the stale MIR besides the refusal the test names).
fn mir_of(src: &str) -> &'static str {
    FIXTURES.iter().find(|(s, _)| *s == src).map(|(_, m)| *m).unwrap_or(FIXTURES[4].1)
}

/// The files, and the MIR of `src/a.rs` beside the DSL root (`a.sbmir`).
fn check(files: &[(&str, &str)]) -> Checked {
    let mir = files.iter().find(|(p, _)| *p == A).map(|(_, c)| mir_of(c)).unwrap_or(FIXTURES[4].1);
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)).chain([("c/sandblaster/m/a.sbmir", mir)]));
    driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn errors(c: &Checked) -> Vec<String> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.msg.clone()).collect()
}

fn warnings(c: &Checked) -> Vec<String> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| d.msg.clone()).collect()
}

#[track_caller]
fn rejects(c: &Checked, needle: &str) {
    assert!(errors(c).iter().any(|m| m.contains(needle)), "expected an error containing {needle:?}; got:\n{}", c.render());
}

#[track_caller]
fn front_ok(files: &[(&str, &str)]) -> Checked {
    let c = check(files);
    assert!(c.ok(), "front end rejected the lifted crate:\n{}", c.render());
    c
}

fn verify(c: &Checked) -> Verification {
    let o = VerifyOptions { exec_only: false, ..opts(ProverSet::Standard) };
    driver::stage::verify(c.krate.as_ref().unwrap(), &o)
}

#[track_caller]
fn verified(files: &[(&str, &str)]) -> Checked {
    let c = front_ok(files);
    let v = verify(&c);
    util::assert_verified(&c, &v);
    c
}

/// The names of the definitions that did not check.
#[track_caller]
fn failed(files: &[(&str, &str)]) -> Vec<String> {
    let c = front_ok(files);
    let v = verify(&c);
    let f: Vec<String> = v.failed_defs().iter().map(|d| d.name.clone()).collect();
    assert!(!f.is_empty(), "expected a definition to fail; everything checked:\n{}", util::explain(&c, &v));
    f
}

/// A DSL root lifting the host file `src/a.rs` in place with `opts`, the
/// proof file when `proof` is given, and `extra` items (host models).
fn root(opts: &str, proof: bool, extra: &str) -> String {
    let mut r = format!("{ROOT}#[lift(in_place, mir = \"a.sbmir\"{opts})]\n#[path = \"../../src/a.rs\"]\npub mod a;\n{extra}");
    if proof {
        r.push_str("#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    }
    r
}

const R: &str = "c/sandblaster/m/mod.rs";
const A: &str = "c/src/a.rs";
const P: &str = "c/sandblaster/m/PROOF.rs";
const H: &str = "c/sandblaster/m/host.rs";

/// The host model module declaration (`host.rs`).
const HOST_DECL: &str = "#[lift(host)]\nmod host;\n";

// ---------------------------------------------------------------------
// `items = ".."`: the verified items of an in-place file
// ---------------------------------------------------------------------

const ITEMS: &str = include_str!("mir_fixtures/lv_items/src/a.rs");

#[test]
fn only_the_selected_items_of_an_in_place_file_are_lifted() {
    // `Skip::dec` and `helper` would fail (an unproven underflow) if lifted
    let c = verified(&[(R, &root(", items = \"Keep\"", false, "")), (A, ITEMS)]);
    let w = warnings(&c);
    for left_out in ["struct `Skip`", "function `helper`", "function `uses_helper`", "impl `Skip`"] {
        assert!(w.iter().any(|m| m.contains(left_out) && m.contains("selected `items`")), "`{left_out}` must be listed as left out:\n{}", c.render());
    }
}

#[test]
fn a_selected_item_cannot_call_one_left_out() {
    let c = check(&[(R, &root(", items = \"uses_helper\"", false, "")), (A, ITEMS)]);
    assert!(!c.ok(), "a call of an item left out must not load:\n{}", c.render());
}

#[test]
fn an_item_selection_needs_in_place() {
    let r = format!("{ROOT}#[lift(items = \"Keep\")]\n#[path = \"a.rs\"]\npub mod a;\n");
    let c = check(&[(R, &r), ("c/sandblaster/m/a.rs", ITEMS)]);
    rejects(&c, "`items = \"..\"` needs `in_place`");
}

// ---------------------------------------------------------------------
// an open trait declared in the lifted file: its provided methods at the
// instance; names shared with inherent methods
// ---------------------------------------------------------------------

const TR: &str = include_str!("mir_fixtures/lv_tr/src/a.rs");

const TR_LAW: &str = "use sandblaster::prelude::*;\n\n#[law]\nfn run_flips() {\n    ensures(crate::a::run(&crate::a::Std::new(2u64), 5u64) == 6u64 | 7u64);\n    by_computation();\n}\n";

#[test]
fn provided_methods_of_an_open_trait_are_methods_of_its_instance() {
    let c = verified(&[(R, &root(", instance = \"Mix: crate::a::Std\"", true, "")), (A, TR), (P, TR_LAW)]);
    let w = warnings(&c);
    assert!(w.iter().any(|m| m.contains("`Mix::base` of `Std`") && m.contains("pure delegation")), "{}", c.render());
    assert!(w.iter().any(|m| m.contains("`Mix::low` at `Std`") && m.contains("same parameters and body")), "{}", c.render());
}

#[test]
fn a_wrong_value_of_a_provided_method_is_refuted() {
    let law = TR_LAW.replace("6u64 | 7u64", "6u64 | 6u64");
    let f = failed(&[(R, &root(", instance = \"Mix: crate::a::Std\"", true, "")), (A, TR), (P, &law)]);
    assert!(f.iter().any(|n| n.contains("run_flips")), "{f:?}");
}

#[test]
fn a_trait_method_named_like_an_inherent_one_must_delegate_to_it() {
    let bad = TR.replace("        Self::base(self, x)\n", "        x\n");
    let c = check(&[(R, &root(", instance = \"Mix: crate::a::Std\"", false, "")), (A, &bad)]);
    rejects(&c, "is not a pure delegation");
}

#[test]
fn a_provided_method_named_like_an_inherent_one_must_be_the_same() {
    let bad = TR.replace("    pub fn low(&self, x: u64) -> u64 {\n        self.base(x) & 15", "    pub fn low(&self, x: u64) -> u64 {\n        self.base(x) & 7");
    let c = check(&[(R, &root(", instance = \"Mix: crate::a::Std\"", false, "")), (A, &bad)]);
    rejects(&c, "not its parameters and body");
}

#[test]
fn a_provided_method_left_unverified_has_no_lifted_caller() {
    let c = check(&[(R, &root(", instance = \"Mix: crate::a::Std\", unverified_fns = \"Mix::flip\"", false, "")), (A, TR)]);
    assert!(warnings(&c).iter().any(|m| m.contains("provided method `Mix::flip`")), "{}", c.render());
    assert!(!c.ok(), "`run` calls the unverified `flip`: it must not load:\n{}", c.render());
}

// ---------------------------------------------------------------------
// erasure only where a parameter was erased; host models of types and
// functions (in place)
// ---------------------------------------------------------------------

const ER: &str = include_str!("mir_fixtures/lv_er/src/a.rs");

const ER_HOST: &str = r#"
/// A marker family.
pub struct Mark;

/// The host's word type, read as `u64`.
pub type W = u64;

/// The host's hash function.
pub struct Hw;

impl HashFn for Hw {
    type Out = u64;
    fn f(x: u64) -> u64 {
        x ^ 7
    }
}
"#;

const ER_OPTS: &str = ", instance = \"Fam: crate::host::Mark, Word: crate::host::W, HashFn: crate::host::Hw\"";

const ER_LAW: &str = "use sandblaster::prelude::*;\n\n#[law]\nfn keep_keeps() {\n    ensures((crate::a::keep(9u64, crate::a::Tag::new(1u64)), crate::a::digest(1u64)) == (crate::__lift::Result::Ok(9u64), 6u64));\n    by_computation();\n}\n";

#[test]
fn erasure_drops_only_erased_parameters_and_host_models_give_meaning() {
    let c = verified(&[(R, &root(ER_OPTS, true, HOST_DECL)), (A, ER), (H, ER_HOST), (P, ER_LAW)]);
    let models = &c.lift_facts.host_models;
    assert!(models.iter().any(|m| m.contains("type `W` = `u64`")), "{models:?}");
    assert!(models.iter().any(|m| m.contains("`<Hw as HashFn>::f` modeled as")), "{models:?}");
}

#[test]
fn a_wrong_host_model_value_is_refuted() {
    let law = ER_LAW.replace("Ok(9u64), 6u64", "Ok(9u64), 7u64");
    let f = failed(&[(R, &root(ER_OPTS, true, HOST_DECL)), (A, ER), (H, ER_HOST), (P, &law)]);
    assert!(f.iter().any(|n| n.contains("keep_keeps")), "{f:?}");
}

#[test]
fn host_models_of_types_and_functions_need_an_in_place_crate() {
    let r = format!("{ROOT}#[lift]\n#[path = \"a.rs\"]\npub mod a;\n#[lift(host)]\nmod host;\n");
    let c = check(&[(R, &r), ("c/sandblaster/m/a.rs", "pub fn g(x: u64) -> u64 { x }\n"), (H, ER_HOST)]);
    rejects(&c, "holds only non-generic enums");
}

// ---------------------------------------------------------------------
// state parameters: `&mut` of a value, a byte-string iterator,
// `Option<&mut Vec<T>>`; `core::ops::Range`; `copied`, `ok_or(..)?`
// ---------------------------------------------------------------------

const ST: &str = include_str!("mir_fixtures/lv_st/src/a.rs");

const ST_LAW: &str = r#"use sandblaster::prelude::*;

#[law]
fn states_are_passed() {
    ensures({
        let mut c = 1usize;
        let v = crate::a::take(&[4u64, 5u64], &mut c);
        let mut d = 2usize;
        let w = crate::a::take(&[4u64, 5u64], &mut d);
        let mut it: &[&[u8]] = &[&[1u8, 2u8], &[3u8]];
        let n = crate::a::first_len(&mut it);
        let mut none: &[&[u8]] = &[];
        let m = crate::a::first_len(&mut none);
        let mut out: Option<Seq<u64>> = Some(seq![7u64]);
        let b = crate::a::log(&crate::__lift::Range { start: 1u64, end: 3u64 }, 2u64, out.as_deref_mut());
        let b2 = crate::a::log(&crate::__lift::Range { start: 1u64, end: 3u64 }, 3u64, None);
        (v, c, w, d, n, it.len(), m, b, out, b2)
            == (Some(5u64), 2usize, None, 2usize, crate::__lift::Result::Ok(2usize), 1usize, crate::__lift::Result::Err(1u8), true, Some(seq![7u64, 2u64]), false)
    });
    by_computation();
}
"#;

#[test]
fn value_iterator_and_vec_states_are_passed() {
    verified(&[(R, &root("", true, "")), (A, ST), (P, ST_LAW)]);
}

#[test]
fn a_wrong_state_result_is_refuted() {
    let law = ST_LAW.replace("(Some(5u64), 2usize, None", "(Some(5u64), 1usize, None");
    let f = failed(&[(R, &root("", true, "")), (A, ST), (P, &law)]);
    assert!(f.iter().any(|n| n.contains("states_are_passed")), "{f:?}");
}

const WB: &str = include_str!("mir_fixtures/lv_wb/src/a.rs");

const WB_LAW: &str = "use sandblaster::prelude::*;\n\n#[law]\nfn written_back() {\n    ensures({\n        let mut b = seq![7u8];\n        crate::a::push1(&mut b);\n        b == seq![7u8, 1u8]\n    });\n    by_computation();\n}\n";

#[test]
fn a_state_argument_is_written_back_even_when_its_type_is_not_inferred() {
    // `b`'s type is not known to the lift's local typing (a `seq!` literal):
    // it is still the place the call writes back to (a copy would lose it)
    verified(&[(R, &root("", true, "")), (A, WB), (P, WB_LAW)]);
}

#[test]
fn a_write_back_that_did_not_happen_is_refuted() {
    let law = WB_LAW.replace("b == seq![7u8, 1u8]", "b == seq![7u8]");
    let f = failed(&[(R, &root("", true, "")), (A, WB), (P, &law)]);
    assert!(f.iter().any(|n| n.contains("written_back")), "{f:?}");
}

#[test]
fn a_value_state_keeps_its_overflow_obligation() {
    let src = include_str!("mir_fixtures/lv_bump/src/a.rs");
    let f = failed(&[(R, &root("", false, "")), (A, src)]);
    assert!(f.iter().any(|n| n.contains("bump")), "{f:?}");
}

#[test]
fn an_iterator_of_other_items_is_not_a_state() {
    let src = "pub fn first<E: Iterator<Item = u64>>(items: &mut E) -> Option<u64> {\n    items.next()\n}\n";
    let c = check(&[(R, &root("", false, "")), (A, src)]);
    rejects(&c, "cannot monomorphize `first`");
}

// ---------------------------------------------------------------------
// a depth bound for non-tail recursion, by attachment
// ---------------------------------------------------------------------

const REC: &str = include_str!("mir_fixtures/lv_rec/src/a.rs");

const REC_PROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::depth)]\nfn depth_bound() {\n    requires(h <= 64u32);\n    decreases(h, max = 64);\n}\n";

#[test]
fn non_tail_recursion_is_bounded_by_its_attachment() {
    verified(&[(R, &root("", true, "")), (A, REC), (P, REC_PROOF)]);
}

#[test]
fn non_tail_recursion_without_a_bound_is_refused() {
    let c = check(&[(R, &root("", false, "")), (A, REC)]);
    rejects(&c, "needs a depth bound");
}

// ---------------------------------------------------------------------
// an in-place type invariant is a host obligation; thiserror's `#[error]`
// ---------------------------------------------------------------------

const INV: &str = include_str!("mir_fixtures/lv_inv/src/a.rs");

const INV_PROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::Span)]\nfn span_ordered() {\n    invariant(self.lo <= self.hi);\n}\n";

#[test]
fn an_in_place_type_invariant_is_a_host_obligation() {
    let c = verified(&[(R, &root("", true, "")), (A, INV), (P, INV_PROOF)]);
    let ob = &c.lift_facts.host_obligations;
    assert!(ob.iter().any(|(f, r)| f == "type Span" && r.contains("lo")), "{ob:?}");
}

#[test]
fn without_its_invariant_the_type_is_unsafe() {
    let f = failed(&[(R, &root("", false, "")), (A, INV)]);
    assert!(f.iter().any(|n| n.contains("width")), "{f:?}");
}

#[test]
fn an_error_attribute_without_the_thiserror_derive_is_refused() {
    let bad = INV.replace("#[derive(thiserror::Error, Debug)]", "#[derive(Debug)]");
    let c = check(&[(R, &root("", true, "")), (A, &bad), (P, INV_PROOF)]);
    assert!(!c.ok(), "`#[error]` is thiserror's; without its derive it is not known:\n{}", c.render());
}

// ---------------------------------------------------------------------
// the SHA-256 model (stdlib `sha256.rs`) against a native FIPS 180-4
// implementation (`sandblaster_targets::fips`)
// ---------------------------------------------------------------------

const SHA_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[cfg(sandblaster)]\n#[path = \"../../../stdlib/sha256.rs\"]\nmod sha256;\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n";
const SHA_R: &str = "c/front/tests/m/mod.rs";
const SHA_L: &str = "c/front/tests/m/LAWS.rs";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Known answers of `sha256_parts(parts)`, as examples of a spec function
/// (examples are kernel lemmas, evaluated through the opaque definitions):
/// the native FIPS digest of their concatenation, for part lists around the
/// padding boundaries (55, 56, 63, 64 bytes, two and three blocks), split
/// three ways. `flip` flips a bit of the last message's digest.
fn sha_laws(flip: bool) -> String {
    let mut out = String::from("use sandblaster::prelude::*;\n");
    let lens = [0usize, 1, 3, 55, 56, 63, 64, 65, 119, 120, 200];
    let mut examples = Vec::new();
    for (k, &n) in lens.iter().enumerate() {
        let msg: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(k as u8)).collect();
        let mut d = sandblaster_targets::fips::sha256(&msg);
        if flip && k == lens.len() - 1 {
            d[0] ^= 1;
        }
        // three splits: whole, halves, a byte, nothing, then the rest
        let splits: Vec<Vec<&[u8]>> = vec![vec![&msg[..]], vec![&msg[..n / 2], &msg[n / 2..]], vec![&msg[..n.min(1)], &[], &msg[n.min(1)..]]];
        for parts in &splits {
            let lits: Vec<String> = parts.iter().map(|p| format!("&[{}]", p.iter().map(|b| format!("{b}u8")).collect::<Vec<_>>().join(", "))).collect();
            examples.push(format!("#[example(digest_of(&[{}]) == hex!(\"{}\"))]\n", lits.join(", "), hex(&d)));
        }
    }
    out.push_str("\n/// SHA-256 of the concatenation of `parts`.\n#[spec]\n");
    for e in examples {
        out.push_str(&e);
    }
    out.push_str("fn digest_of(parts: &[&[u8]]) -> [u8; 32] {\n    crate::sha256::sha256_parts(parts)\n}\n");
    out
}

#[test]
fn the_sha256_model_agrees_with_fips_180_4() {
    let laws = sha_laws(false);
    verified(&[(SHA_R, SHA_ROOT), (SHA_L, &laws), ("c/stdlib/sha256.rs", include_str!("../stdlib/sha256.rs"))]);
}

#[test]
fn a_wrong_sha256_digest_is_refuted() {
    let laws = sha_laws(true);
    let c = front_ok(&[(SHA_R, SHA_ROOT), (SHA_L, &laws), ("c/stdlib/sha256.rs", include_str!("../stdlib/sha256.rs"))]);
    let v = verify(&c);
    let out = util::explain(&c, &v);
    // the flipped message's three splits are examples #30, #31, #32; no other is false
    for k in 0..33 {
        let false_k = out.contains(&format!("example #{k} of `crate::laws::digest_of` is false"));
        assert_eq!(false_k, (30..33).contains(&k), "example #{k}:\n{out}");
    }
}
