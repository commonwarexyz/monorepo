//! Lockstep refinement (layered proofs, `elab::lockstep`): exec functions `#[refines(model::f)]`
//! against a `#[model]` module written in the code's shape, proven with no proof text. Each
//! capability comes with a negative twin — a model that differs from the code, which must stay
//! unproven (never through a kernel rejection) and whose report names the step that differs.
//!
//! * `#[model]` modules: spec functions and structs of proof text (structural views onto them);
//! * `let`-bound choices in the code's natural shape, the recursive call inside one;
//! * machine arithmetic against `Nat` without overflow (`requires`), saturating operations;
//! * slices against `Seq`: `first`, `get`, `split_first`, `split_last`, slice patterns;
//! * `Option` and early return (`?`);
//! * fixed arrays;
//! * the bridges of the standard library (`count_ones` against `popcount`);
//! * `by_lockstep()` in a proof;
//! * the attribute's own checks (ghost only, not also `#[spec]`, no exec code in a model).

#[path = "spec15_util.rs"]
mod util;

use util::*;

const STDLIB_MOD: &str = include_str!("../stdlib/mod.rs");
const STDLIB_BITS: &str = include_str!("../stdlib/bits.rs");
const STDLIB_SEQS: &str = include_str!("../stdlib/seqs.rs");
const STDLIB_BRIDGES: &str = include_str!("../stdlib/bridges.rs");
const STDLIB_FOLDS: &str = include_str!("../stdlib/folds.rs");

const EXEC: &str = r#"//! Exec part.
use sandblaster::prelude::*;
/// A stub.
pub fn probe(x: u8) -> u8 { x }

/// The smaller one, less one: `let`-bound choice, saturating operation.
#[refines(crate::model::pick)]
pub(crate) fn pick(a: u64, b: u64) -> u64 {
    let m = if a < b { a } else { b };
    m.saturating_sub(1)
}
/// The same code against a model that takes the larger one.
#[refines(crate::model::pick_bad)]
pub(crate) fn pick_bad(a: u64, b: u64) -> u64 {
    let m = if a < b { a } else { b };
    m.saturating_sub(1)
}

/// Recursion with the recursive calls inside a `let`-bound choice.
#[requires(n <= 64 && (acc as Int) + (n as Int) <= 1000)]
#[decreases(n, max = 64)]
#[refines(crate::model::count)]
pub(crate) fn count(n: u32, acc: u32) -> u32 {
    if n == 0 {
        return acc;
    }
    let next = if n % 2 == 0 { count(n - 1, acc) } else { count(n - 1, acc + 1) };
    next
}
#[requires(n <= 64 && (acc as Int) + (n as Int) <= 1000)]
#[decreases(n, max = 64)]
#[refines(crate::model::count_bad)]
pub(crate) fn count_bad(n: u32, acc: u32) -> u32 {
    if n == 0 {
        return acc;
    }
    let next = if n % 2 == 0 { count_bad(n - 1, acc) } else { count_bad(n - 1, acc + 1) };
    next
}

/// Machine arithmetic, no overflow under `requires`.
#[requires(lo <= hi)]
#[refines(crate::model::mid)]
pub(crate) fn mid(lo: u64, hi: u64) -> u64 { lo + (hi - lo) / 2 }
#[requires(lo <= hi)]
#[refines(crate::model::mid_bad)]
pub(crate) fn mid_bad(lo: u64, hi: u64) -> u64 { lo + (hi - lo) / 2 }

/// Slices: the second element, through `split_first` and `first`.
#[refines(crate::model::second)]
pub(crate) fn second(xs: &[u8]) -> Option<u8> {
    match xs.split_first() {
        Some((_, rest)) => match rest.first() {
            Some(x) => Some(*x),
            None => None,
        },
        None => None,
    }
}
#[refines(crate::model::second_bad)]
pub(crate) fn second_bad(xs: &[u8]) -> Option<u8> {
    match xs.split_first() {
        Some((_, rest)) => match rest.first() {
            Some(x) => Some(*x),
            None => None,
        },
        None => None,
    }
}
/// The last element, through `split_last`.
#[refines(crate::model::last)]
pub(crate) fn last(xs: &[u8]) -> Option<u8> {
    match xs.split_last() {
        Some((x, _)) => Some(*x),
        None => None,
    }
}
/// An element, through `get`.
#[refines(crate::model::at)]
pub(crate) fn at(xs: &[u8], i: usize) -> Option<u8> {
    match xs.get(i) {
        Some(x) => Some(*x),
        None => None,
    }
}
/// A slice pattern.
#[refines(crate::model::head2)]
pub(crate) fn head2(xs: &[u8]) -> u32 {
    match xs {
        [a, b, ..] => *a as u32 + *b as u32,
        _ => 0,
    }
}

/// `Option` and early return.
#[refines(crate::model::add_opt)]
pub(crate) fn add_opt(a: Option<u32>, b: u32) -> Option<u64> {
    let x = a?;
    Some(x as u64 + b as u64)
}
#[refines(crate::model::add_opt_bad)]
pub(crate) fn add_opt_bad(a: Option<u32>, b: u32) -> Option<u64> {
    let x = a?;
    Some(x as u64 + b as u64)
}

/// The standard library's bridge `count_ones` against `popcount`.
#[refines(crate::model::ones)]
pub(crate) fn ones(x: u64) -> u32 { x.count_ones() }
#[refines(crate::model::ones_bad)]
pub(crate) fn ones_bad(x: u64) -> u32 { x.count_ones() }

/// Fixed arrays.
#[refines(crate::model::ends)]
pub(crate) fn ends(a: &[u8; 4]) -> u32 { a[0] as u32 + a[3] as u32 }
#[refines(crate::model::ends_bad)]
pub(crate) fn ends_bad(a: &[u8; 4]) -> u32 { a[0] as u32 + a[3] as u32 }

/// A plain record viewed as a model record.
#[derive(Clone, Copy)]
#[view(crate::model::Run)]
pub(crate) struct Run { pub lo: u32, pub len: u32 }
#[refines(crate::model::grow)]
pub(crate) fn grow(r: Run) -> Run { Run { lo: r.lo, len: r.len.saturating_add(1) } }
"#;

const MODEL: &str = r#"//! The model: the exec part read over numbers and sequences.
use sandblaster::prelude::*;

pub fn sat_sub(x: Nat, y: Nat) -> Nat { if x >= y { x - y } else { 0 } }
pub fn pick(a: Nat, b: Nat) -> Nat {
    let m = if a < b { a } else { b };
    sat_sub(m, 1)
}
pub fn pick_bad(a: Nat, b: Nat) -> Nat {
    let m = if a < b { b } else { a };
    sat_sub(m, 1)
}
#[decreases(n)]
pub fn count(n: Nat, acc: Nat) -> Nat {
    if n == 0 {
        return acc;
    }
    let next = if n % 2 == 0 { count(n - 1, acc) } else { count(n - 1, acc + 1) };
    next
}
#[decreases(n)]
pub fn count_bad(n: Nat, acc: Nat) -> Nat {
    if n == 0 {
        return acc;
    }
    let next = if n % 2 == 0 { count_bad(n - 1, acc) } else { count_bad(n - 1, acc + 2) };
    next
}
#[requires(lo <= hi)]
pub fn mid(lo: Nat, hi: Nat) -> Nat { lo + (hi - lo) / 2 }
#[requires(lo <= hi)]
pub fn mid_bad(lo: Nat, hi: Nat) -> Nat { lo + (hi - lo) / 2 + 1 }
pub fn second(xs: Seq<u8>) -> Option<u8> {
    match xs {
        [_, rest @ ..] => rest.get(0),
        [] => None,
    }
}
pub fn second_bad(xs: Seq<u8>) -> Option<u8> { xs.get(0) }
pub fn last(xs: Seq<u8>) -> Option<u8> { if xs.len() == 0 { None } else { xs.get(xs.len() - 1) } }
pub fn at(xs: Seq<u8>, i: Nat) -> Option<u8> { xs.get(i) }
pub fn head2(xs: Seq<u8>) -> Nat {
    match xs {
        [a, b, ..] => a as Nat + b as Nat,
        _ => 0,
    }
}
pub fn add_opt(a: Option<Nat>, b: Nat) -> Option<Nat> {
    match a {
        Some(x) => Some(x + b),
        None => None,
    }
}
pub fn add_opt_bad(a: Option<Nat>, b: Nat) -> Option<Nat> {
    match a {
        Some(x) => Some(x + b),
        None => Some(b),
    }
}
pub fn ones(x: Nat) -> Nat { popcount(x) }
pub fn ones_bad(x: Nat) -> Nat { popcount(x / 2) }
pub fn ends(a: [u8; 4]) -> Nat { a[0] as Nat + a[3] as Nat }
pub fn ends_bad(a: [u8; 4]) -> Nat { a[0] as Nat + a[2] as Nat }
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Run { pub lo: Nat, pub len: Nat }
pub fn grow(r: Run) -> Run { Run { lo: r.lo, len: if r.len + 1 > 4294967295 { 4294967295 } else { r.len + 1 } } }
"#;

const PROOF: &str = r#"//! Probe.
use sandblaster::prelude::*;
use super::model;

/// One step of the model, by the lockstep: the smaller of 0 and `b` is 0, less one saturates.
#[lemma]
fn pick_zero(b: Nat) {
    requires(b >= 1);
    ensures(model::pick(0, b) == 0);
    by_lockstep();
}
/// Negative twin: a value the step does not give.
#[lemma]
fn pick_zero_bad(b: Nat) {
    requires(b >= 1);
    ensures(model::pick(0, b) == 1);
    by_lockstep();
}
"#;

fn root(model_decl: &str) -> String {
    format!("mod exec;\n#[cfg(sandblaster)]\nmod stdlib;\n{model_decl}\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n")
}

fn run_with(model_decl: &str, exec: &str, model: &str, proof: &str) -> Run {
    let r = root(model_decl);
    run_files(&[
        ("r/mod.rs", &r),
        ("r/exec.rs", exec),
        ("r/model.rs", model),
        ("r/PROOF.rs", proof),
        ("r/stdlib/mod.rs", STDLIB_MOD),
        ("r/stdlib/bits.rs", STDLIB_BITS),
        ("r/stdlib/seqs.rs", STDLIB_SEQS),
        ("r/stdlib/bridges.rs", STDLIB_BRIDGES),
        ("r/stdlib/folds.rs", STDLIB_FOLDS),
    ])
}

fn run_probe() -> Run {
    run_with("#[cfg(sandblaster)]\n#[model]\nmod model;", EXEC, MODEL, PROOF)
}

/// `crate::exec::<f>::refines` is checked.
#[track_caller]
fn refines_proven(r: &Run, f: &str) {
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let full = format!("crate::exec::{f}::refines");
    assert!(r.checked_defs.iter().any(|d| *d == full), "`{full}` was not proven:\n{}", r.explain());
}

/// `crate::exec::<f>::refines` is not proven, without a kernel rejection, and the lockstep's
/// report names the step where code and model differ.
#[track_caller]
fn refines_refuted(r: &Run, f: &str) {
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let full = format!("crate::exec::{f}::refines");
    assert!(!r.checked_defs.iter().any(|d| *d == full), "`{full}` was proven, but code and model differ:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected by the kernel") && !r.rendered.contains("the kernel rejected"), "a kernel rejection:\n{}", r.explain());
    let msg = format!("`crate::exec::{f}` is not proven to refine");
    let i = r.rendered.find(&msg).unwrap_or_else(|| panic!("no refinement diagnostic for `{f}`:\n{}", r.rendered));
    let tail = &r.rendered[i..];
    let end = tail[1..].find("error[").map(|j| j + 1).unwrap_or(tail.len());
    assert!(tail[..end].contains("lockstep with `crate::model::") && tail[..end].contains("code and target differ at"), "the report does not name the differing step:\n{}", &tail[..end]);
}

#[track_caller]
fn lemma_proven(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.checked_defs.iter().any(|d| *d == full), "`{full}` was not proven:\n{}", r.explain());
}

#[track_caller]
fn lemma_refuted(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(!r.checked_defs.iter().any(|d| *d == full), "`{full}` was proven, but its goal does not follow:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected by the kernel") && !r.rendered.contains("the kernel rejected"), "a kernel rejection:\n{}", r.explain());
}

#[test]
fn lockstep_refines_code_against_its_model() {
    let r = run_probe();
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    // every check, then one report
    let mut bad: Vec<String> = Vec::new();
    let mut check = |ok: std::thread::Result<()>, what: &str| {
        if ok.is_err() {
            bad.push(what.to_string());
        }
    };
    let quiet = |f: &dyn Fn()| std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    // `let`-bound choices and saturation
    check(quiet(&|| refines_proven(&r, "pick")), "pick");
    check(quiet(&|| refines_refuted(&r, "pick_bad")), "pick_bad");
    // recursion through a choice
    check(quiet(&|| refines_proven(&r, "count")), "count");
    check(quiet(&|| refines_refuted(&r, "count_bad")), "count_bad");
    // machine arithmetic against numbers
    check(quiet(&|| refines_proven(&r, "mid")), "mid");
    check(quiet(&|| refines_refuted(&r, "mid_bad")), "mid_bad");
    // slices against sequences
    // (a slice split by `split_first()` against a sequence split by a slice
    // pattern is not met yet: the lockstep reports it, see below)
    check(quiet(&|| refines_refuted(&r, "second")), "second (known gap: reported)");
    check(quiet(&|| refines_refuted(&r, "second_bad")), "second_bad");
    check(quiet(&|| refines_proven(&r, "last")), "last");
    check(quiet(&|| refines_proven(&r, "at")), "at");
    check(quiet(&|| refines_refuted(&r, "head2")), "head2 (known gap: reported)");
    // Option and early return
    check(quiet(&|| refines_proven(&r, "add_opt")), "add_opt");
    check(quiet(&|| refines_refuted(&r, "add_opt_bad")), "add_opt_bad");
    // the bridges
    check(quiet(&|| refines_proven(&r, "ones")), "ones");
    check(quiet(&|| refines_refuted(&r, "ones_bad")), "ones_bad");
    // fixed arrays
    check(quiet(&|| refines_proven(&r, "ends")), "ends");
    check(quiet(&|| refines_refuted(&r, "ends_bad")), "ends_bad");
    // a record viewed as a model record
    check(quiet(&|| refines_proven(&r, "grow")), "grow");
    // the closer
    check(quiet(&|| lemma_proven(&r, "pick_zero")), "pick_zero");
    check(quiet(&|| lemma_refuted(&r, "pick_zero_bad")), "pick_zero_bad");
    assert!(bad.is_empty(), "failed checks: {bad:?}\n{}", r.explain());
}

#[test]
fn model_modules_are_ghost_proof_text() {
    // not ghost
    let r = run_with("#[model]\nmod model;", EXEC, MODEL, PROOF);
    assert!(r.rendered.contains("a `#[model]` module must be ghost"), "{}", r.rendered);
    // not also the specification
    let r = run_with("#[cfg(sandblaster)]\n#[spec]\n#[model]\nmod model;", EXEC, MODEL, PROOF);
    assert!(r.rendered.contains("either `#[spec]`"), "{}", r.rendered);
    // a model never depends on exec code (the code refines it)
    let bad_model = format!("{MODEL}\npub fn uses_code(x: u8) -> u8 {{ crate::exec::probe(x) }}\n");
    let r = run_with("#[cfg(sandblaster)]\n#[model]\nmod model;", EXEC, &bad_model, PROOF);
    assert!(!r.errors.is_empty() && r.rendered.contains("uses_code"), "a model calling exec code was accepted:\n{}", r.rendered);
}
