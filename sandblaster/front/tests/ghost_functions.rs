//! Ghost function values (DESIGN.md §13.2's `spec_fn`): function-typed parameters `fn(A, T) -> A`
//! of spec functions, lemmas, laws and proofs, lambdas `|a: A, x: T| e`, application, and spec
//! functions or tuple constructors named as values. They elaborate to the kernel's `Π`, `λ` and
//! application (no kernel change) and never reach exec code.
//!
//! Every proven lemma has a negative twin: a claim that does not follow, which must stay unproven
//! without a kernel rejection. Every accepted form has a rejected twin at the typing rules.

#[path = "spec15_util.rs"]
mod util;

use sandblaster_front::diag::DiagKind as K;
use util::*;

const EXEC: &str = "//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub.\npub fn probe(x: u8) -> u8 { x }\n";

const SPEC: &str = r#"//! Spec.
use sandblaster::prelude::*;
/// A left fold over any function.
#[example(fold(seq![1 as Int, 2 as Int], 0 as Int, |a: Int, x: Int| 2 * a + x) == 4)]
pub fn fold<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A) -> A {
    match xs { [x, rest @ ..] => fold(rest, f(a, x), f), [] => a }
}
/// A map.
#[example(map(seq![1 as Int, 2 as Int], |x: Int| x * 2) == seq![2 as Int, 4 as Int])]
pub fn map<T: Copy, U: Copy>(xs: Seq<T>, f: fn(T) -> U) -> Seq<U> {
    match xs { [x, rest @ ..] => seq![f(x), ..map(rest, f)], [] => seq![] }
}
/// Addition, named as a function value below.
pub fn add(a: Int, b: Int) -> Int { a + b }
/// A sum, as a fold of `add`.
#[example(sum(seq![1 as Int, 2 as Int]) == 3)]
pub fn sum(xs: Seq<Int>) -> Int { fold(xs, 0 as Int, add) }
/// A wrapper type whose constructor is named as a function value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct W(pub Int);
/// Wrap every element.
#[example(wrap(seq![1 as Int]) == seq![W(1)])]
pub fn wrap(xs: Seq<Int>) -> Seq<W> { map(xs, W) }
"#;

fn run_probe(proof: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[spec]\nmod spec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let proof = format!("//! Probe.\nuse sandblaster::prelude::*;\nuse super::spec::{{W, add, fold, map, sum, wrap}};\n{proof}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", EXEC), ("r/spec.rs", SPEC), ("r/PROOF.rs", &proof)])
}

/// The lemma `crate::proof::<name>` checked, with every obligation proven.
#[track_caller]
fn proven(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let bad: Vec<String> = r.unproven.iter().filter(|(d, _, _)| *d == full).map(|(_, k, g)| format!("[{k}] {g}")).collect();
    assert!(bad.is_empty(), "`{full}` has unproven obligations:\n{}\n{}", bad.join("\n"), r.rendered);
    assert!(r.checked_defs.iter().any(|d| *d == full), "`{full}` was not checked:\n{}", r.explain());
}

/// The lemma `crate::proof::<name>` is not proven, and nothing was rejected by the kernel.
#[track_caller]
fn refuted(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    assert!(!r.checked_defs.iter().any(|d| *d == full), "`{full}` was proven, but its goal does not follow:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected by the kernel") && !r.rendered.contains("the kernel rejected"), "a kernel rejection:\n{}", r.explain());
}

#[test]
fn function_parameters_lambdas_and_function_values() {
    let r = run_probe(
        r#"
/// A law of every fold, proven once for every function.
#[lemma]
fn fold_append<T: Copy, A: Copy>(xs: Seq<T>, ys: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(fold(seq![..xs, ..ys], a, f) == fold(ys, fold(xs, a, f), f));
    match xs {
        [x, rest @ ..] => { fold_append(rest, ys, f(a, x), f); follows(); }
        [] => follows(),
    }
}
/// Negative twin: the stretches swapped.
#[lemma]
fn fold_append_bad<T: Copy, A: Copy>(xs: Seq<T>, ys: Seq<T>, a: A, f: fn(A, T) -> A) {
    ensures(fold(seq![..xs, ..ys], a, f) == fold(xs, fold(ys, a, f), f));
    match xs {
        [x, rest @ ..] => { fold_append_bad(rest, ys, f(a, x), f); follows(); }
        [] => follows(),
    }
}
/// Instantiated with a spec function named as a value.
#[lemma]
fn sum_append(xs: Seq<Int>, ys: Seq<Int>) {
    ensures(sum(seq![..xs, ..ys]) == fold(ys, sum(xs), add));
    fold_append(xs, ys, 0 as Int, add);
    follows();
}
/// Negative twin: another start.
#[lemma]
fn sum_append_bad(xs: Seq<Int>, ys: Seq<Int>) {
    ensures(sum(seq![..xs, ..ys]) == fold(ys, 0 as Int, add));
    fold_append(xs, ys, 0 as Int, add);
    follows();
}
/// A map of any function keeps the length; a constructor named as a value.
#[lemma]
fn map_len<T: Copy, U: Copy>(xs: Seq<T>, f: fn(T) -> U) {
    ensures(map(xs, f).len() == xs.len());
    by_induction(xs);
}
#[lemma]
fn wrap_len(xs: Seq<Int>) {
    ensures(wrap(xs).len() == xs.len());
    map_len(xs, W);
}
/// Negative twin: one longer.
#[lemma]
fn wrap_len_bad(xs: Seq<Int>) {
    ensures(wrap(xs).len() == xs.len() + 1);
    map_len(xs, W);
}
"#,
    );
    proven(&r, "fold_append");
    refuted(&r, "fold_append_bad");
    proven(&r, "sum_append");
    refuted(&r, "sum_append_bad");
    proven(&r, "map_len");
    proven(&r, "wrap_len");
    refuted(&r, "wrap_len_bad");
    // the examples with lambdas, a named function and a constructor are decided by the kernel
    for f in ["fold", "map", "sum", "wrap"] {
        let item = format!("crate::spec::{f}");
        assert!(r.examples.iter().any(|e| e.item == item && e.checked), "example of `{item}` not checked:\n{}", r.explain());
    }
}

#[test]
fn quantified_premises_over_function_values() {
    let r = run_probe(
        r#"
/// Induction for folds: an invariant every step keeps.
#[lemma]
fn fold_inv<T: Copy, A: Copy>(xs: Seq<T>, a: A, f: fn(A, T) -> A, p: fn(A) -> bool) {
    requires(p(a) && forall(|b: A, x: T| implies(p(b), p(f(b, x)))));
    ensures(p(fold(xs, a, f)));
    match xs {
        [x, rest @ ..] => { fold_inv(rest, f(a, x), f, p); follows(); }
        [] => follows(),
    }
}
/// Its premise, for a step that keeps the invariant, discharged at the call.
#[lemma]
fn sums(xs: Seq<Int>) {
    ensures(fold(xs, 0 as Int, |a: Int, x: Int| if x >= 0 { a + x } else { a - x }) >= 0);
    fold_inv(xs, 0 as Int, |a: Int, x: Int| if x >= 0 { a + x } else { a - x }, |a: Int| a >= 0);
}
/// Negative twin: a step that does not keep it.
#[lemma]
fn sums_bad(xs: Seq<Int>) {
    ensures(fold(xs, 0 as Int, |a: Int, x: Int| a + x) >= 0);
    fold_inv(xs, 0 as Int, |a: Int, x: Int| a + x, |a: Int| a >= 0);
}
/// A lemma whose conclusion is a `forall` gives that fact at its application.
#[spec]
fn step(a: Int, x: Int) -> Int { if x >= 0 { a + x } else { a - x } }
#[lemma]
fn step_keeps() {
    ensures(forall(|a: Int, x: Int| implies(a >= 0, step(a, x) >= 0)));
    follows();
}
#[lemma]
fn stepped(xs: Seq<Int>) {
    ensures(fold(xs, 0 as Int, step) >= 0);
    step_keeps();
    fold_inv(xs, 0 as Int, step, |a: Int| a >= 0);
}
/// Negative twin: a bound the fact does not give.
#[lemma]
fn stepped_bad(xs: Seq<Int>) {
    ensures(fold(xs, 0 as Int, step) >= 1);
    step_keeps();
    fold_inv(xs, 0 as Int, step, |a: Int| a >= 0);
}
"#,
    );
    proven(&r, "fold_inv");
    proven(&r, "sums");
    refuted(&r, "sums_bad");
    proven(&r, "step_keeps");
    proven(&r, "stepped");
    refuted(&r, "stepped_bad");
}

/// A probe with the given spec and exec text (no proof).
fn run_spec(spec: &str, exec: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[spec]\nmod spec;\npub use exec::probe;\n";
    let exec = format!("{EXEC}{exec}");
    let spec = format!("//! Spec.\nuse sandblaster::prelude::*;\n{spec}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", &exec), ("r/spec.rs", &spec)])
}

#[test]
fn function_values_stay_in_ghost_code() {
    // exec code: no closures, no function types (the accepted twin is every ghost form above)
    let r = run_spec("", "fn bad(x: u8) -> u8 { let f = |y: u8| y; x }\n");
    assert!(r.has_error(K::Closure, "closures are not supported in exec code"), "{}", r.explain());
    let r = run_spec("", "fn bad(f: fn(u8) -> u8, x: u8) -> u8 { x }\n");
    assert!(r.has_error(K::Closure, "function pointers are not supported"), "{}", r.explain());
    // never inside data, never returned, never a type argument
    let r = run_spec("/// Holds a function.\n#[derive(Clone, Copy)]\npub struct H { pub f: fn(Int) -> Int }\n", "");
    assert!(r.has_error(K::Closure, "cannot be stored in data"), "{}", r.explain());
    let r = run_spec("/// Returns a function.\npub fn ret(x: Int) -> fn(Int) -> Int { |y: Int| y + x }\n", "");
    assert!(r.has_error(K::Closure, "cannot be stored in data, returned"), "{}", r.explain());
    let r = run_spec("/// A sequence of functions.\npub fn fs(xs: Seq<fn(Int) -> Int>) -> Int { 0 }\n", "");
    assert!(r.has_error(K::Closure, "cannot be stored in data"), "{}", r.explain());
    // no `Nat` or `Prop` inside a function type: no bound travels with a function value
    let r = run_spec("/// A `Nat` function.\npub fn n(f: fn(Nat) -> Int) -> Int { 0 }\n", "");
    assert!(r.has_error(K::Type, "cannot mention `Nat`"), "{}", r.explain());
    let r = run_spec("/// A predicate.\npub fn p(f: fn(Int) -> Prop) -> bool { true }\n", "");
    assert!(r.has_error(K::Type, "cannot mention `Prop`"), "{}", r.explain());
    // a lambda is a total expression over its enclosing locals
    let r = run_spec("/// Apply.\npub fn ap(f: fn(Int) -> Int, x: Int) -> Int { f(x) }\n/// Returns from inside.\npub fn r(x: Int) -> Int { ap(|a: Int| { return a; }, x) }\n", "");
    assert!(r.has_error(K::Closure, "cannot `return`"), "{}", r.explain());
    let r = run_spec("/// Apply.\npub fn ap(f: fn(Int) -> Int, x: Int) -> Int { f(x) }\n/// Wrong arity.\npub fn r(x: Int) -> Int { ap(|a: Int, b: Int| a, x) }\n", "");
    assert!(r.has_error(K::Type, "expected a lambda of 1 argument(s), found 2"), "{}", r.explain());
    // the accepted twin of the rejections above
    let r = run_spec("/// Apply.\n#[example(ap(|a: Int| a + 1, 1) == 2)]\npub fn ap(f: fn(Int) -> Int, x: Int) -> Int { f(x) }\n", "");
    assert!(r.front_ok && r.examples.iter().any(|e| e.item == "crate::spec::ap" && e.checked), "{}", r.explain());
}

#[test]
fn a_lambda_in_a_spec_keeps_spec_closure() {
    // a lambda calling exec code makes the spec depend on the implementation
    let r = run_spec(
        "/// Apply.\npub fn ap(f: fn(u8) -> u8, x: u8) -> u8 { f(x) }\n/// Calls the implementation through a lambda.\npub fn bad(x: u8) -> u8 { ap(|y: u8| super::exec::probe(y), x) }\n",
        "",
    );
    assert!(r.has_error(K::SpecDependsOnImpl, "spec function `crate::spec::bad` depends on the exec function `crate::exec::probe`"), "{}", r.explain());
    // twin: the same lambda over spec code only
    let r = run_spec("/// Apply.\npub fn ap(f: fn(u8) -> u8, x: u8) -> u8 { f(x) }\n/// A spec lambda.\npub fn good(x: u8) -> u8 { ap(|y: u8| y, x) }\n", "");
    assert!(!r.closure.iter().any(|(i, _, _)| i == "crate::spec::good"), "{:?}", r.closure);
    assert!(!r.errors.iter().any(|(k, _)| *k == K::SpecDependsOnImpl), "{}", r.explain());
}
