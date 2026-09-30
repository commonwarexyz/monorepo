//! §15 S5 front-end gaps (the features the fully specified QMDB needs):
//! recursive spec enums (`T::size'`, induction on fields, pair matches),
//! `?` and `return` in spec functions, the ghost prelude `pow2`, `log2`,
//! `popcount` with `lemmas/nat.core`, `#[example]` on ghost constants,
//! `Nat` indexes into arrays, struct/tuple/`Option` values in JSON records,
//! and `#[opaque]` spec functions. Positive and negative cases for each.

#[path = "spec15_util.rs"]
mod util;

use std::path::Path;

use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::elab::examples::ExampleMethod;
use util::*;

/// A crate with one `#[spec]` module `spec` holding `spec` and a trivial
/// boundary function.
fn spec_crate(spec: &str) -> Vec<(&'static str, String)> {
    vec![("r/mod.rs", "#[cfg(sandblaster)]\n#[spec]\nmod spec;\npub fn api(x: u8) -> u8 { x }\n".to_string()), ("r/spec.rs", spec.to_string())]
}

fn run_spec(spec: &str) -> Run {
    let files = spec_crate(spec);
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (*p, c.as_str())).collect();
    run_files(&refs)
}

#[track_caller]
fn spec_verifies(spec: &str) -> Run {
    let r = run_spec(spec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    assert!(r.verified && r.errors.is_empty(), "not verified:\n{}", r.explain());
    r
}

fn sample(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/s5_gaps").join(rel)
}

// ---------------------------------------------------------------------------
// G2: recursive spec enums
// ---------------------------------------------------------------------------

#[test]
fn recursive_spec_enum_with_size_and_structural_recursion() {
    let r = spec_verifies(
        r#"
#[derive(Clone, Copy)]
pub enum T { Leaf(u8), Node(T, T) }

#[example(sum(T::Node(T::Leaf(1u8), T::Node(T::Leaf(2u8), T::Leaf(3u8)))) == 6)]
pub fn sum(t: T) -> Nat {
    match t {
        T::Leaf(x) => x as Nat,
        T::Node(l, r) => sum(l) + sum(r),
    }
}

/// Recursion on the fields of two trees walked together.
#[example(same(T::Leaf(1u8), T::Leaf(1u8)))]
#[example(!same(T::Node(T::Leaf(1u8), T::Leaf(1u8)), T::Leaf(1u8)))]
pub fn same(a: T, b: T) -> bool {
    match (a, b) {
        (T::Leaf(x), T::Leaf(y)) => x == y,
        (T::Node(a1, a2), T::Node(b1, b2)) => same(a1, b1) && same(a2, b2),
        _ => false,
    }
}
"#,
    );
    // the generated structural size and its positivity lemma
    for d in ["crate::spec::T::size'", "crate::spec::T::size'_pos"] {
        assert!(r.checked_defs.iter().any(|x| x == d), "{d} missing:\n{}", r.explain());
    }
}

#[test]
fn a_recursive_constructor_first_and_a_non_exhaustive_match() {
    // the default value of the type (a `Nat` guard's else branch) is its
    // first constructor without a recursive field
    spec_verifies(
        r#"
#[derive(Clone, Copy)]
pub enum T { Node(T, T), Leaf(u8) }
#[example(leaf(grow(0)) && !leaf(grow(2)))]
pub fn grow(n: Nat) -> T { if n == 0 { T::Leaf(0u8) } else { T::Node(T::Leaf(0u8), T::Leaf(0u8)) } }
#[example(leaf(T::Leaf(1u8)))]
pub fn leaf(t: T) -> bool { match t { T::Leaf(_) => true, _ => false } }
"#,
    );
    let r = run_spec("#[derive(Clone, Copy)]\npub enum T { Node(T, T), Leaf(u8) }\npub fn f(t: T) -> Nat { match t { T::Leaf(x) => x as Nat } }\n");
    assert!(r.errors.iter().any(|(_, m)| m.contains("non-exhaustive") || m.contains("not covered")), "{}", r.rendered);
}

#[test]
fn the_tree_sample_verifies_with_induction_on_pair_fields() {
    // eval/agree/fits/clash of the QMDB design over a toy digest;
    // `agreeing_trees_have_one_root` and `agreeing_trees_do_not_clash` by
    // `#[induction(a)]` with `ih(x, y)` on the fields of a pair match
    let r = run_dir(&sample("tree/mod.rs"));
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.verified && r.errors.is_empty(), "{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::spec::tree::agreeing_trees_have_one_root"), "{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::proof::agreeing_trees_do_not_clash"), "{}", r.explain());
}

#[test]
fn a_recursive_call_on_a_non_field_is_a_termination_error() {
    let r = run_spec(
        r#"
#[derive(Clone, Copy)]
pub enum T { Leaf(u8), Node(T, T) }

pub fn bad(t: T) -> Nat {
    match t {
        T::Leaf(x) => x as Nat,
        T::Node(l, _) => bad(T::Node(l, l)),
    }
}
"#,
    );
    assert!(r.errors.iter().any(|(_, m)| m.contains("termination measure")), "{}", r.explain());
    assert!(!r.verified);
}

#[test]
fn a_decreases_measure_that_does_not_decrease_is_unproven() {
    let r = run_spec(
        r#"
#[derive(Clone, Copy)]
pub enum T { Leaf(u8), Node(T, T) }

pub fn depth(t: T) -> Nat {
    match t {
        T::Leaf(_) => 0,
        T::Node(l, r) => 1 + depth(l).max(depth(r)),
    }
}

#[decreases(n)]
pub fn bad(t: T, n: Nat) -> Nat {
    match t {
        T::Leaf(_) => n,
        T::Node(l, _) => bad(l, n + 1),
    }
}
"#,
    );
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::spec::bad" && k == "termination"), "{}", r.explain());
}

#[test]
fn induction_on_a_pair_match_of_sequences() {
    // script refinement of `Seq` columns in a tuple match, and `ih` on the
    // rest bindings of a `Seq` parameter
    spec_verifies(
        r#"
#[lemma]
#[induction(a1)]
fn append_eq_parts(a1: Seq<u8>, a2: Seq<u8>, b1: Seq<u8>, b2: Seq<u8>) {
    requires(seq![..a1, ..a2] == seq![..b1, ..b2] && a1.len() == b1.len());
    ensures(a1 == b1 && a2 == b2);
    match (a1, b1) {
        ([_, r @ ..], [_, s @ ..]) => {
            ih(r, a2, s, b2);
            follows();
        }
        ([], []) => follows(),
        _ => follows(),
    }
}
"#,
    );
}

#[test]
fn recursive_types_outside_spec_modules_and_nested_occurrences_are_rejected() {
    // an exec type
    let r = run("#[derive(Clone, Copy)]\npub enum E { A(u8), B(E) }\npub fn f(x: u8) -> u8 { x }\n");
    assert!(r.has_error(K::Type, "recursive type `E` is not supported"), "{}", r.rendered);
    // a spec type containing itself inside a `Seq` (not a direct field)
    let r = run_spec("#[derive(Clone, Copy)]\npub enum R { Leaf, Many(Seq<R>) }\n");
    assert!(r.has_error(K::Type, "recursive type `R` is not supported"), "{}", r.rendered);
    // a spec struct
    let r = run_spec("#[derive(Clone, Copy)]\npub enum S2 { A(u8), B(W) }\n#[derive(Clone, Copy)]\npub struct W { s: S2 }\n");
    assert!(r.has_error(K::Type, "is not supported"), "{}", r.rendered);
}

#[test]
fn partial_eq_on_a_recursive_spec_type_is_rejected() {
    let r = run_spec("#[derive(Clone, Copy, PartialEq, Eq)]\npub enum T { Leaf(u8), Node(T, T) }\n");
    assert!(r.errors.iter().any(|(_, m)| m.contains("`#[derive(PartialEq)]` is not supported on the recursive spec type `T`")), "{}", r.rendered);
}

#[test]
fn an_induction_hypothesis_on_a_non_field_is_rejected() {
    let r = run_spec(
        r#"
#[derive(Clone, Copy)]
pub enum T { Leaf(u8), Node(T, T) }
pub fn sum(t: T) -> Nat { match t { T::Leaf(x) => x as Nat, T::Node(l, r) => sum(l) + sum(r) } }

#[lemma]
#[induction(t)]
fn sum_nonneg(t: T) {
    ensures(sum(t) >= 0);
    match t {
        T::Node(l, _) => { ih(T::Node(l, l)); follows(); }
        _ => follows(),
    }
}
"#,
    );
    assert!(r.errors.iter().any(|(_, m)| m.contains("structurally smaller `t`")), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// G1: `?` and `return` in spec functions
// ---------------------------------------------------------------------------

#[test]
fn question_mark_and_early_return_in_spec_functions() {
    spec_verifies(
        r#"
/// Seven-bit groups, least significant first (the design's `groups`).
#[example(groups(seq![0x81u8, 0x01u8], true) == Some((129, seq![])))]
#[example(groups(seq![0x80u8], true) == None)]
fn groups(b: Seq<u8>, first: bool) -> Option<(Nat, Seq<u8>)> {
    match b {
        [g, rest @ ..] if g >= 128 => { let (x, rest) = groups(rest, false)?; Some((g as Nat - 128 + 128 * x, rest)) }
        [g, rest @ ..] if g != 0 || first => Some((g as Nat, rest)),
        _ => None,
    }
}

fn field(n: Nat, b: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> { if b.len() < n { None } else { Some((b.take(n), b.skip(n))) } }

/// `?` in a chain, a `return` in a match arm of a `let` initializer.
#[example(decode(seq![2u8, 1u8, 7u8, 8u8]) == Some((2, Some([7u8, 8u8]))))]
#[example(decode(seq![2u8, 0u8]) == Some((2, None)))]
#[example(decode(seq![2u8, 5u8]) == None)]
#[example(decode(seq![0x80u8]) == None)]
pub fn decode(b: Seq<u8>) -> Option<(Nat, Option<[u8; 2]>)> {
    let (n, b) = groups(b, true)?;
    let (p, b): (Option<[u8; 2]>, Seq<u8>) = match b {
        [0, b @ ..] => (None, b),
        [1, b @ ..] => { let (d, b) = field(2, b)?; (Some(d.to_array::<2>()), b) }
        _ => return None,
    };
    if b.len() == 0 { Some((n, p)) } else { None }
}

/// An early `return` at the top of a recursive function (the design's `peaks`).
#[decreases(n)]
#[example(ones(5) == seq![1u8, 1u8, 1u8, 1u8, 1u8])]
pub fn ones(n: Nat) -> Seq<u8> {
    if n == 0 { return seq![]; }
    seq![1u8, ..ones(n - 1)]
}
"#,
    );
}

#[test]
fn the_sheet_shows_the_desugared_match() {
    let r = spec_verifies("#[example(first(seq![3u8]) == Some(3u8))]\n#[example(first(seq![]) == None)]\npub fn first(b: Seq<u8>) -> Option<u8> { let x = b.get(0)?; Some(x) }\n");
    let k = r.checked.krate.as_ref().unwrap();
    let id = k.find("crate::spec::first").unwrap();
    let sandblaster_front::hir::ItemKind::Fn(f) = &k.item(id).kind else { panic!() };
    let text = sandblaster_front::deelab::DeElab::new(k, &f.locals).spec_fn(k.item(id), f).join("\n");
    assert!(text.contains("match Seq::get::<u8>(b, (0: Nat)) { Some(0: x) => Some(x), None::<u8> => None::<u8> }"), "{text}");
}

#[test]
fn question_mark_outside_an_option_spec_function_is_an_error() {
    let r = run_spec("fn f(x: Option<Nat>) -> Nat { let y = x?; y }\n");
    assert!(r.has_error(K::Type, "`?` requires the enclosing spec function to return `Option`"), "{}", r.rendered);
}

#[test]
fn an_exit_inside_an_expression_is_an_error() {
    let r = run_spec("fn g(x: Nat) -> Nat { x }\nfn f(x: Option<Nat>) -> Option<Nat> { Some(g(x?)) }\n");
    assert!(r.has_error(K::Unsupported, "inside a larger expression is not supported in a spec function"), "{}", r.rendered);
    let r = run_spec("fn f(x: Option<Nat>) -> bool { if x.is_some() { return true; } false }\n#[law]\nfn l(x: Nat) { ensures(x >= 0); }\n");
    // `return` in a `bool` spec function is fine (only `Prop` results are not)
    assert!(!r.errors.iter().any(|(_, m)| m.contains("`return`")), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// G3: `pow2`, `log2`, `popcount`
// ---------------------------------------------------------------------------

#[test]
fn nat_prelude_functions_compute_fast_on_64_bit_values() {
    let r = spec_verifies(
        r#"
#[example(p(0) == 1 && p(10) == 1024 && p(64) == 18446744073709551616)]
pub fn p(n: Nat) -> Nat { pow2(n) }
#[example(lg(0) == 0 && lg(1) == 0 && lg(2) == 1 && lg(1023) == 9 && lg(1024) == 10 && lg(18446744073709551615) == 63)]
pub fn lg(n: Nat) -> Nat { log2(n) }
#[example(pc(0) == 0 && pc(7) == 3 && pc(18446744073709551615) == 64)]
pub fn pc(n: Nat) -> Nat { popcount(n) }
"#,
    );
    assert_eq!(r.examples.iter().filter(|e| e.checked).count(), 3, "{}", r.explain());
}

#[test]
fn nat_prelude_facts_discharge_spec_obligations() {
    // `n - pow2(log2(n))` needs `pow2(log2(n)) ≤ n`, `2j - popcount(j)`
    // needs `popcount(j) ≤ j`, the division `n / pow2(h)` needs `pow2 ≥ 1`
    // (for any `h`, also a `Nat` result with no bound)
    spec_verifies(
        r#"
fn height(a: Nat, b: Nat) -> Nat { if a == b { 0 } else { 1 } }
pub fn f(n: Nat, s: Nat, h: Nat) -> Nat {
    if n == 0 { return 0; }
    let j = s + pow2(h) - 1;
    (n - pow2(log2(n))) + (2 * j - popcount(j)) + n / pow2(height(n, s) + 1)
}
"#,
    );
}

#[test]
fn nat_prelude_lemmas_apply_by_name() {
    spec_verifies(
        r#"
#[lemma]
fn doubling(n: Nat) {
    ensures(pow2(n + 1) == 2 * pow2(n));
    sandblaster::lemmas::nat::pow2_succ(n);
}
"#,
    );
}

#[test]
fn nat_prelude_functions_are_ghost_only() {
    let r = run("pub fn f(x: u8) -> u8 { let _ = pow2(3); x }\n");
    assert!(r.errors.iter().any(|(_, m)| m.contains("ghost function `pow2` in exec code")), "{}", r.rendered);
}

#[test]
fn nat_lemmas_match_their_source() {
    // `lemmas/nat.core` holds the kernel proofs of the DSL lemmas of
    // `samples/s5_gaps/nat_lemmas`: the source still proves exactly the
    // statements of the file
    use sandblaster_front::driver;
    use sandblaster_front::loader::MemFs;
    use sandblaster_front::target::TargetInfo;
    let dir = sample("nat_lemmas");
    let files: Vec<(String, String)> = ["mod.rs", "nat.rs"].iter().map(|f| (format!("r/{f}"), std::fs::read_to_string(dir.join(f)).unwrap())).collect();
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.clone().unwrap();
    let mismatches = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(&k, &mut chain, &sandblaster_front::elab::Options::default());
        let mut bad = Vec::new();
        let names = ["pow2_pos", "log2_nonneg", "popcount_nonneg", "popcount_le", "pow2_succ", "popcount_even", "popcount_odd", "log2_bounds"];
        for n in names {
            let (Some(src), Some(lib)) = (out.env.lookup_global(&format!("crate::nat::{n}")), out.env.lookup_global(&format!("nat::{n}"))) else {
                bad.push(format!("{n}: missing"));
                continue;
            };
            let ok = out.defs.iter().any(|d| d.name == format!("crate::nat::{n}") && d.status == sandblaster_front::elab::DefStatus::Checked);
            let st = |g| out.env.print_term(&[], &out.env.global_type(g).unwrap()).replace("crate::nat::", "nat::");
            if !ok || st(src) != st(lib) {
                bad.push(format!("{n}: checked={ok}\n  source: {}\n  file:   {}", st(src), st(lib)));
            }
        }
        bad
    });
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// ---------------------------------------------------------------------------
// G4: `#[example]` on ghost constants
// ---------------------------------------------------------------------------

#[test]
fn examples_on_ghost_constants() {
    let r = spec_verifies("#[example(pow2(G) == C)]\npub const G: Nat = 8;\npub const C: Nat = 256;\n#[example(N as Nat + 32 != 72)]\npub const N: usize = 32;\n");
    let ex: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::spec::G" || e.item == "crate::spec::N").collect();
    assert_eq!(ex.len(), 2, "{}", r.explain());
    assert!(ex.iter().all(|e| e.checked), "{}", r.explain());
    // a false one fails the build with its evaluated sides
    let r = run_spec("#[example(G == 9)]\npub const G: Nat = 8;\n");
    assert!(r.has_error(K::Example, "example #0 of `crate::spec::G` is false"), "{}", r.explain());
    // an exec constant takes none
    let r = run("#[example(K == 1)]\npub const K: u8 = 1;\npub fn f(x: u8) -> u8 { x }\n");
    assert!(r.errors.iter().any(|(_, m)| m.contains("`#[example]` is not allowed on a constant")), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// G5: `Nat` index into arrays
// ---------------------------------------------------------------------------

#[test]
fn a_nat_index_into_an_array_in_ghost_code() {
    spec_verifies(
        r#"
/// Bit `i` of a 4-byte chunk, least significant bit of each byte first.
#[example(bit([1u8, 0u8, 0u8, 128u8], 0) && bit([1u8, 0u8, 0u8, 128u8], 31) && !bit([1u8, 0u8, 0u8, 128u8], 1))]
pub fn bit(chunk: [u8; 4], i: Nat) -> bool {
    let b = i % 32;
    (chunk[b / 8] as Nat / pow2(b % 8)) % 2 == 1
}
"#,
    );
    // out of range: an unproven index obligation
    let r = run_spec("pub fn at(a: [u8; 4], i: Nat) -> u8 { a[i] }\n");
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::spec::at" && k == "index-bounds"), "{}", r.explain());
}

// ---------------------------------------------------------------------------
// G6: struct and tuple values in JSON records
// ---------------------------------------------------------------------------

const DB: &str = r#"
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Db {
    pub log: Seq<(Seq<u8>, bool)>,
    pub inactive: Nat,
    pub ops_root: [u8; 32],
}

pub fn active(db: Db) -> Nat { count(db.log) }
fn count(log: Seq<(Seq<u8>, bool)>) -> Nat { match log { [] => 0, [(_, a), rest @ ..] => a as Nat + count(rest) } }

#[examples(file = "dbs.json", format = "json", provenance = independent)]
fn dbs(db: Db, pair: (Nat, bool), partial: Option<[u8; 2]>, expected: Nat) -> bool {
    active(db) == expected && pair.0 < 10 && (partial.is_some() || !pair.1)
}
"#;

fn run_db(json: &str) -> Run {
    run_files(&[("r/mod.rs", "#[cfg(sandblaster)]\n#[spec]\nmod spec;\npub fn api(x: u8) -> u8 { x }\n"), ("r/spec.rs", DB), ("r/dbs.json", json)])
}

#[test]
fn struct_tuple_and_option_values_in_json_records() {
    let r = run_db(
        r#"[
 {"db": {"log": [["d201", true], ["d2", false], ["", true]], "inactive": 1, "OPS_ROOT": "0000000000000000000000000000000000000000000000000000000000000000"},
  "pair": [3, true], "partial": "abcd", "expected": 2, "note": "extra top-level fields are ignored"},
 {"db": {"log": [], "inactive": 0, "ops_root": "1111111111111111111111111111111111111111111111111111111111111111"},
  "pair": [9, false], "partial": null, "expected": 0}
]"#,
    );
    assert!(r.verified && r.errors.is_empty(), "{}", r.explain());
    let recs: Vec<&Ex> = r.examples.iter().filter(|e| e.file).collect();
    assert_eq!(recs.len(), 2, "{}", r.explain());
    assert!(recs.iter().all(|e| e.checked && e.method == Some(ExampleMethod::EvalClosed)), "{}", r.explain());
}

#[test]
fn malformed_struct_and_tuple_records_are_errors() {
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    // a missing struct field
    let r = run_db(&format!(r#"[{{"db": {{"log": [], "ops_root": "{zero}"}}, "pair": [1, false], "partial": null, "expected": 0}}]"#));
    assert!(r.errors.iter().any(|(_, m)| m.contains("vector file")) && r.rendered.contains("has no field `inactive`"), "{}", r.rendered);
    // an extra struct field
    let r = run_db(&format!(r#"[{{"db": {{"log": [], "inactive": 0, "ops_root": "{zero}", "extra": 1}}, "pair": [1, false], "partial": null, "expected": 0}}]"#));
    assert!(r.rendered.contains("`Db` has no field `extra`"), "{}", r.rendered);
    // a tuple of the wrong arity
    let r = run_db(&format!(r#"[{{"db": {{"log": [], "inactive": 0, "ops_root": "{zero}"}}, "pair": [1], "partial": null, "expected": 0}}]"#));
    assert!(r.rendered.contains("expected a tuple of 2 values, found 1"), "{}", r.rendered);
    // a negative `Nat` field
    let r = run_db(&format!(r#"[{{"db": {{"log": [], "inactive": -1, "ops_root": "{zero}"}}, "pair": [1, false], "partial": null, "expected": 0}}]"#));
    assert!(r.rendered.contains("`-1` is negative"), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// `#[opaque]` spec functions
// ---------------------------------------------------------------------------

#[test]
fn opaque_spec_functions() {
    // examples still compute (the kernel's closed evaluator); proofs see the
    // function folded until it is unfolded by name
    let r = spec_verifies(
        r#"
#[opaque]
#[example(twice(3) == 6)]
pub fn twice(x: Nat) -> Nat { 2 * x }

#[lemma]
fn twice_adds(x: Nat) {
    ensures(twice(x) == x + x);
    by_unfolding(twice);
}
"#,
    );
    assert!(r.examples.iter().any(|e| e.item == "crate::spec::twice" && e.checked && e.method == Some(ExampleMethod::EvalClosed)), "{}", r.explain());
    let r = run_spec("#[opaque]\npub fn twice(x: Nat) -> Nat { 2 * x }\n#[lemma]\nfn t(x: Nat) { ensures(twice(x) == x + x); by_arithmetic(); }\n");
    assert!(r.unproven.iter().any(|(d, _, _)| d == "crate::spec::t"), "{}", r.explain());
    // only on spec functions
    let r = run("#[opaque]\npub fn f(x: u8) -> u8 { x }\n");
    assert!(r.errors.iter().any(|(_, m)| m.contains("`#[opaque]`")), "{}", r.rendered);
}
