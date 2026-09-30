//! Prover ergonomics, package P2 (the elaborator: closers, script
//! semantics, spec/exec elaboration, typeck). Each test is the minimal
//! repro of a defect that made the QMDB refinement proof bloated
//! (`pe/INVENTORY.md`), and each strengthened closer has a negative test:
//! the closer still fails when the goal does not follow.

#[path = "spec15_util.rs"]
mod util;

use util::*;

/// A probe crate: `exec.rs` (exec code) and `PROOF.rs` (ghost items).
fn probe(proof: &str, exec: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let exec = format!("//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub boundary.\npub fn probe(x: u8) -> u8 {{ x }}\n{exec}");
    let proof = format!("//! Ghost part.\nuse sandblaster::prelude::*;\n{proof}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", &exec), ("r/PROOF.rs", &proof)])
}

/// Asserts that every definition checked.
#[track_caller]
fn proves(proof: &str, exec: &str) -> Run {
    let r = probe(proof, exec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    assert!(r.failed_defs.is_empty() && r.unproven.is_empty() && r.errors.is_empty(), "not proven:\n{}", r.explain());
    r
}

/// Asserts that the lemma `name` (of `PROOF.rs`) is not proven, and that
/// nothing was rejected by the kernel.
#[track_caller]
fn refutes(proof: &str, exec: &str, name: &str) -> Run {
    let r = probe(proof, exec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    let def = format!("crate::proof::{name}");
    assert!(r.unproven.iter().any(|(d, _, _)| *d == def), "expected `{def}` to be unproven:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected"), "a kernel rejection:\n{}", r.explain());
    r
}

const F: &str = "/// A spec function.\n#[spec]\nfn f(x: Nat) -> Nat { x + 1 }\n";

const R: &str = "/// A recursive spec function.\n#[spec]\n#[decreases(n)]\nfn r(n: Nat) -> Nat { if n == 0 { 0 } else { r(n - 1) + 2 } }\n";

// ---------------------------------------------------------------------------
// A1: the closers' view remaps references to copied facts
// ---------------------------------------------------------------------------

#[test]
fn a1_fact_embedding_the_proof_of_another_fact() {
    // the second `requires`' Nat subtraction embeds the proof of the first
    proves(&format!("{F}/// A1.\n#[lemma]\nfn split(x: Nat, y: Nat) {{\n    requires(f(x) <= y);\n    requires(y - f(x) < 10);\n    ensures(y < f(x) + 10);\n    by_arithmetic();\n}}\n"), "");
}

#[test]
fn a1_negative_the_goal_must_follow() {
    refutes(&format!("{F}/// A1, off by one.\n#[lemma]\nfn split(x: Nat, y: Nat) {{\n    requires(f(x) <= y);\n    requires(y - f(x) < 10);\n    ensures(y < f(x) + 9);\n    by_arithmetic();\n}}\n"), "", "split");
}

// ---------------------------------------------------------------------------
// A2: calc! with an exec link followed by a view link
// ---------------------------------------------------------------------------

const WRAP: &str = "/// Wrap a slice.\npub fn wrap(xs: &[u8]) -> Option<(u8, &[u8])> { Some((7u8, xs)) }\n/// Wrap twice.\npub fn wrap2(xs: &[u8]) -> Option<(u8, &[u8])> { wrap(xs) }\n";

#[test]
fn a2_calc_exec_link_then_view_link() {
    proves(
        r#"
/// Spec wrap.
#[spec]
fn swrap(ys: Seq<u8>) -> Option<(Nat, Seq<u8>)> { Some((7, ys)) }

/// The view link.
#[lemma]
fn direct(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::exec::wrap(xs) == swrap(ys));
    unfold(crate::exec::wrap);
    follows();
}

/// Exec link first, then the view link.
#[lemma]
fn via_calc_mixed(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::exec::wrap2(xs) == swrap(ys));
    calc! {
        crate::exec::wrap2(xs)
            == crate::exec::wrap(xs) by { by_unfolding(crate::exec::wrap2); };
            == swrap(ys) by { direct(xs, ys); };
    }
}
"#,
        WRAP,
    );
}

// ---------------------------------------------------------------------------
// A4: rewrite_rev of an array variable
// ---------------------------------------------------------------------------

#[test]
fn a4_rewrite_rev_of_an_array_variable() {
    proves(
        r#"
/// A tagged encoding.
#[spec]
fn tagged(x: u8) -> [u8; 2] { [1u8, x] }

/// Rewrite the variable by its encoding.
#[lemma]
fn a4(b: [u8; 2]) {
    requires(tagged(b[1]) == b);
    ensures(b[0] == 1u8);
    rewrite_rev(tagged(b[1]) == b);
    follows();
}
"#,
        "",
    );
}

// ---------------------------------------------------------------------------
// B1: by_unfolding unfolds the named definitions in the facts too
// ---------------------------------------------------------------------------

#[test]
fn b1_by_unfolding_unfolds_facts() {
    proves(&format!("{R}/// B1.\n#[lemma]\nfn b1(n: Nat) {{\n    requires(n >= 1 && r(n) == 7);\n    ensures(r(n - 1) == 5);\n    by_unfolding(r);\n}}\n"), "");
}

#[test]
fn b1_negative_wrong_value() {
    refutes(&format!("{R}/// B1, wrong value.\n#[lemma]\nfn b1(n: Nat) {{\n    requires(n >= 1 && r(n) == 7);\n    ensures(r(n - 1) == 4);\n    by_unfolding(r);\n}}\n"), "", "b1");
}

#[test]
fn b1_negative_by_arithmetic_does_not_unfold() {
    // only the named definitions unfold
    refutes(&format!("{R}/// B1 without naming `r`.\n#[lemma]\nfn b1(n: Nat) {{\n    requires(n >= 1 && r(n) == 7);\n    ensures(r(n - 1) == 5);\n    by_arithmetic();\n}}\n"), "", "b1");
}

#[test]
fn b1_negative_undecided_guard() {
    // without `n >= 1` the body's `n == 0` test is not decided
    refutes(&format!("{R}/// B1 without the guard.\n#[lemma]\nfn b1(n: Nat) {{\n    requires(r(n) == 7);\n    ensures(r(n - 1) == 5);\n    by_unfolding(r);\n}}\n"), "", "b1");
}

// ---------------------------------------------------------------------------
// B2: by_computation uses the facts that fix a variable
// ---------------------------------------------------------------------------

#[test]
fn b2_by_computation_with_fixed_variables() {
    proves(
        r#"
/// Prop equation.
#[lemma]
fn b2(e: Int) {
    requires(e == 0);
    ensures(pow2(e) == 1);
    by_computation();
}

/// A spec function.
#[spec]
fn sq(x: Int) -> Int { x * x }

/// Through a spec function.
#[lemma]
fn b2_sq(x: Int) {
    requires(x == 3);
    ensures(sq(x) == 9);
    by_computation();
}
"#,
        "",
    );
}

#[test]
fn b2_negative_wrong_value() {
    refutes("/// B2, wrong value.\n#[lemma]\nfn b2(e: Int) {\n    requires(e == 1);\n    ensures(pow2(e) == 1);\n    by_computation();\n}\n", "", "b2");
}

#[test]
fn b2_negative_bounds_are_not_equations() {
    // still evaluation only: bounds do not fix a value
    refutes("/// B2, bounds.\n#[lemma]\nfn b2(e: Int) {\n    requires(e <= 0 && e >= 0);\n    ensures(pow2(e) == 1);\n    by_computation();\n}\n", "", "b2");
}

// ---------------------------------------------------------------------------
// D1: a script `let` keeps its value in the closers' view
// ---------------------------------------------------------------------------

#[test]
fn d1_script_let_is_definitional() {
    proves(&format!("{R}/// D1.\n#[lemma]\nfn d1(x: Nat) {{\n    requires(r(x + 1) == 3);\n    ensures(r(x + 1) + 1 == 4);\n    let z: Nat = x + 1;\n    assert(r(z) == 3, {{ by_arithmetic(); }});\n    by_arithmetic();\n}}\n"), "");
}

#[test]
fn d1_negative_different_value() {
    refutes(&format!("{R}/// D1, another value.\n#[lemma]\nfn d1(x: Nat) {{\n    requires(r(x + 1) == 3);\n    ensures(true);\n    let z: Nat = x + 2;\n    assert(r(z) == 3, {{ by_arithmetic(); }});\n    follows();\n}}\n"), "", "d1");
}

// ---------------------------------------------------------------------------
// C6/C7: Nat results carry 0 <= result; Nat guards are decided
// ---------------------------------------------------------------------------

const GRP: &str = r#"
/// A recursive reader (like `groups`).
#[spec]
fn grp(b: Seq<u8>, first: bool) -> Option<(Nat, Seq<u8>)> {
    match b {
        [g, rest @ ..] if g >= 128 => { let (x, rest) = grp(rest, false)?; Some((g as Nat - 128 + 128 * x, rest)) }
        [g, rest @ ..] if g != 0 || first => Some((g as Nat, rest)),
        _ => None,
    }
}

/// A Nat-parameter lemma.
#[lemma]
fn nat_id(n: Nat) {
    ensures(n + 0 == n);
    by_arithmetic();
}
"#;

#[test]
fn c6_pattern_bound_nat_of_a_recursive_spec_result() {
    proves(&format!("{GRP}/// C6.\n#[lemma]\nfn c6(b: Seq<u8>) {{\n    ensures(true);\n    match grp(b, true) {{\n        Some((y, s)) => {{ nat_id(y); follows(); }}\n        None => follows(),\n    }}\n}}\n"), "");
}

#[test]
fn c6_projection_of_a_recursive_spec_result() {
    proves(&format!("{GRP}/// C6.\n#[lemma]\nfn c6(b: Seq<u8>) {{\n    requires(grp(b, true).is_some());\n    ensures(true);\n    nat_id(grp(b, true).unwrap_or((0, seq![])).0);\n    follows();\n}}\n"), "");
}

const MK: &str = r#"
/// A struct with Nat fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P { pub a: Nat, pub b: Nat }

/// An opaque maker.
#[spec]
#[opaque]
fn mk(x: Nat) -> P { P { a: x, b: x + 1 } }

/// A Nat-parameter spec helper (its body is behind a `0 <= n` guard).
#[spec]
fn inc(n: Nat) -> Nat { n + 1 }

/// A Nat-parameter lemma.
#[lemma]
fn nat_id(n: Nat) {
    ensures(n + 0 == n);
    by_arithmetic();
}
"#;

#[test]
fn c6_nat_field_of_an_opaque_spec_result() {
    proves(&format!("{MK}/// C6.\n#[lemma]\nfn c6(x: Nat) {{\n    ensures(true);\n    nat_id(mk(x).a);\n    follows();\n}}\n"), "");
}

#[test]
fn c7_nat_guard_of_a_spec_result() {
    proves(&format!("{MK}/// C7.\n#[lemma]\nfn c7(x: Nat) {{\n    ensures(inc(mk(x).a) == mk(x).a + 1);\n    by_unfolding(inc);\n}}\n"), "");
}

#[test]
fn c6_negative_int_results_have_no_range() {
    refutes("/// An Int-valued spec function.\n#[spec]\nfn neg(x: Int) -> Int { -1 - x }\n\n/// C6: `neg(x)` is not a Nat.\n#[lemma]\nfn c6(x: Int) {\n    requires(x >= 0);\n    ensures(0 <= neg(x));\n    by_arithmetic();\n}\n", "", "c6");
}

#[test]
fn c6_negative_range_is_not_a_bound() {
    // `0 <= f(x)`, nothing more
    refutes(&format!("{F}/// C6: no upper bound.\n#[lemma]\nfn c6(x: Nat) {{\n    ensures(f(x) <= 100);\n    by_arithmetic();\n}}\n"), "", "c6");
}

// ---------------------------------------------------------------------------
// C8: the callee facts of a branch's pattern variables
// ---------------------------------------------------------------------------

#[test]
fn c8_callee_ensures_on_a_match_bound_argument() {
    proves(
        r#"
/// C8: the callee's ensures on a match-bound argument.
#[lemma]
fn c8(o: Option<u8>) {
    ensures(crate::exec::h(o) <= 10u8);
    unfold(crate::exec::h);
    match o {
        Some(v) => by_arithmetic(),
        None => by_arithmetic(),
    }
}
"#,
        r#"
/// Bounded.
#[ensures(|r: u8| r <= 10u8)]
pub fn g(x: u8) -> u8 { if x > 10 { 10 } else { x } }

/// Through a match.
pub fn h(o: Option<u8>) -> u8 {
    match o {
        Some(v) => g(v),
        None => 0,
    }
}
"#,
    );
}

#[test]
fn c8_callee_refinement_on_a_match_bound_argument() {
    // `verify` calling `verify_fixed` on the digest read by `first_chunk`
    // (QMDB X9), in its natural form: the refinement of `fixed(k)` is a
    // fact of the branch
    let r = proves(
        r#"
/// The spec.
#[spec]
pub(crate) fn sf(a: Seq<u8>) -> bool {
    a.len() == 4 && a[0] == 1u8
}

/// `top` refines `sf` through `fixed`.
#[proof(refines = crate::exec::top)]
fn top(a: &[u8]) {
    unfold(crate::exec::top);
    if a.len() != 4usize {
        follows();
    } else {
        match a.first_chunk::<4>() {
            None => follows(),
            Some(k) => {
                sandblaster::lemmas::slice::first_chunk_exact::<u8>(a, 4usize, *k);
                follows();
            }
        }
    }
}
"#,
        r#"
/// Fixed-size check.
#[refines(crate::proof::sf)]
pub fn fixed(a: &[u8; 4]) -> bool {
    a[0] == 1
}

/// Variable-size check through `fixed` on a match-bound value.
#[refines(crate::proof::sf)]
pub fn top(a: &[u8]) -> bool {
    if a.len() != 4 {
        return false;
    }
    let Some(k) = a.first_chunk::<4>() else { return false };
    fixed(k)
}
"#,
    );
    assert!(r.refinement("crate::exec::top").checked, "{}", r.explain());
}

// ---------------------------------------------------------------------------
// E1: long `&&` chains elaborate to terms linear in their length
// ---------------------------------------------------------------------------

#[test]
fn e1_long_left_nested_chain() {
    // twelve checks: left nested, the chain used to be a term exponential
    // in its length (a read-back of over 2,000,000 nodes)
    proves(
        r#"
/// Twelve checks.
#[spec]
fn chk(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int, h: Int, i: Int, j: Int, k: Int, l: Int) -> bool {
    a < 10 && b < 10 && c < 10 && d < 10 && e < 10 && f < 10 && g < 10 && h < 10 && i < 10 && j < 10 && k < 10 && l < 10
}

/// Its first check.
#[lemma]
fn e1(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int, h: Int, i: Int, j: Int, k: Int, l: Int) {
    requires(chk(a, b, c, d, e, f, g, h, i, j, k, l));
    ensures(a < 10);
    follows();
}

/// A mixed chain.
#[spec]
fn mixed(a: Int, b: Int, c: Int) -> bool {
    (a < 10 || b < 10) && c < 10
}

/// Its last check.
#[lemma]
fn e1_mixed(a: Int, b: Int, c: Int) {
    requires(mixed(a, b, c));
    ensures(c < 10);
    follows();
}
"#,
        "",
    );
}

#[test]
fn e1_negative_chain_value_is_kept() {
    refutes(
        "/// Three checks.\n#[spec]\nfn three(a: Int, b: Int, c: Int) -> bool { a < 10 || b < 10 || c < 10 }\n\n/// Not implied.\n#[lemma]\nfn e1(a: Int, b: Int, c: Int) {\n    requires(three(a, b, c));\n    ensures(a < 10);\n    follows();\n}\n",
        "",
        "e1",
    );
}

// ---------------------------------------------------------------------------
// D2, D3, D5, D6(a)
// ---------------------------------------------------------------------------

#[test]
fn d2_prelude_lemma_parameter_named_like_a_constant() {
    proves(
        r#"
use crate::exec::N;

/// `slice::first_chunk_exact` has a parameter `N`.
#[lemma]
fn d2(s: &[u8], k: [u8; 4]) {
    requires(s.len() == N && s.first_chunk::<4>() == Some(&k));
    ensures(s.len() == 4usize);
    sandblaster::lemmas::slice::first_chunk_exact::<u8>(s, 4usize, k);
    follows();
}
"#,
        "/// A constant named like the lemma's parameter.\npub const N: usize = 4;\n",
    );
}

#[test]
fn d3_induction_on_a_nat_implies_the_measure() {
    proves(
        "/// A recursive spec fn over Nat.\n#[spec]\n#[decreases(n)]\nfn tri(n: Nat) -> Nat { if n == 0 { 0 } else { tri(n - 1) + n } }\n\n/// Induction without `#[decreases]`.\n#[lemma]\n#[induction(n)]\nfn d3(n: Nat) {\n    ensures(tri(n) >= n);\n    if n == 0 { follows(); } else { ih(n - 1); by_unfolding(tri); }\n}\n",
        "",
    );
}

#[test]
fn d3_negative_the_measure_must_decrease() {
    let r = probe(
        "/// A recursive spec fn over Nat.\n#[spec]\n#[decreases(n)]\nfn tri(n: Nat) -> Nat { if n == 0 { 0 } else { tri(n - 1) + n } }\n\n/// The hypothesis on `n + 1`.\n#[lemma]\n#[induction(n)]\nfn d3(n: Nat) {\n    ensures(tri(n) >= n);\n    if n == 0 { follows(); } else { ih(n + 1); by_unfolding(tri); }\n}\n",
        "",
    );
    assert!(!r.unproven.is_empty() || !r.failed_defs.is_empty() || !r.errors.is_empty(), "an increasing induction was accepted:\n{}", r.explain());
}

#[test]
fn d5_private_lemma_from_an_exec_proof_block() {
    proves(
        "/// The bound (private).\n#[lemma]\nfn sum4_le(msg: &[u8; 4]) {\n    ensures(crate::exec::sum4(msg) <= 1020u32);\n    by_unfolding(crate::exec::sum4);\n}\n",
        r#"
/// Sum of four bytes.
pub fn sum4(b: &[u8; 4]) -> u32 {
    b[0] as u32 + b[1] as u32 + b[2] as u32 + b[3] as u32
}

/// A caller.
#[ensures(|r: u32| r <= 1020)]
pub fn head_sum(msg: &[u8; 8]) -> u32 {
    let mut first = [0u8; 4];
    first.copy_from_slice(&msg[0..4]);
    let s = sum4(&first);
    proof! { crate::proof::sum4_le(&first); }
    s
}
"#,
    );
}

#[test]
fn d6_contract_abbreviation() {
    proves(
        r#"
/// A pair.
#[spec]
fn halves(n: Nat) -> (Nat, Nat) { (n / 2, n % 2) }

/// With an abbreviation.
#[lemma]
fn d6(n: Nat) {
    let t = halves(n);
    requires(t.1 == 0);
    ensures(t.0 * 2 == n);
    by_unfolding(halves);
}

/// Using it.
#[lemma]
fn d6_use(m: Nat) {
    requires(m % 2 == 0);
    ensures(halves(m).0 * 2 == m);
    d6(m);
    follows();
}
"#,
        "",
    );
}

#[test]
fn d6_negative_abbreviation_is_its_value() {
    refutes(
        "/// A pair.\n#[spec]\nfn halves(n: Nat) -> (Nat, Nat) { (n / 2, n % 2) }\n\n/// Wrong claim.\n#[lemma]\nfn d6(n: Nat) {\n    let t = halves(n);\n    ensures(t.0 * 2 == n);\n    by_unfolding(halves);\n}\n",
        "",
        "d6",
    );
}
