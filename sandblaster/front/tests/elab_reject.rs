//! Must-reject programs: each has a panic path (or a false claim) that the
//! front end accepts but verification must refuse. A rejected program is
//! never reported verified, the failing definition is not `Checked`, and
//! the diagnostic names the obligation.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::elab::DefStatus;
use util::{explain, status_of, unproven, verify_src};

/// Asserts that `def` fails with an unproven obligation of `kind`.
#[track_caller]
fn rejects(src: &str, def: &str, kind: &str) {
    let (c, v) = verify_src(src, ProverSet::Basic);
    let bad = unproven(&v);
    assert!(bad.iter().any(|(d, k)| d == def && k == kind), "expected an unproven `{kind}` obligation in `{def}`; got:\n{}", explain(&c, &v));
    assert_ne!(status_of(&v, def), &DefStatus::Checked, "{def} must not be checked");
    let rendered = v.diags.render(&c.sm);
    assert!(rendered.contains(&format!("unproven obligation [{kind}] in `{def}`")), "{rendered}");
    assert!(rendered.contains("goal:"), "the goal is shown: {rendered}");
}

#[test]
fn overflow() {
    rejects("pub fn f(a: u32, b: u32) -> u32 { a + b }", "crate::f", "overflow");
    rejects("pub fn f(a: u64) -> u64 { a * 3 }", "crate::f", "overflow");
    // a narrowing cast does not bound the sum
    rejects("pub fn f(a: u64) -> u8 { (a as u8) + 1 }", "crate::f", "overflow");
}

#[test]
fn underflow_and_division() {
    rejects("pub fn f(a: u32, b: u32) -> u32 { a - b }", "crate::f", "underflow");
    rejects("pub fn f(a: u32, b: u32) -> u32 { if a > 0 { a / b } else { 0 } }", "crate::f", "div-zero");
    rejects("pub fn f(a: u8, b: u8) -> u8 { a % (b & 1) }", "crate::f", "div-zero");
}

#[test]
fn shifts_wider_than_the_type() {
    rejects("pub fn f(x: u32, k: u32) -> u32 { x << k }", "crate::f", "shift-width");
    // `k mod 2^32 < 32` does not help: rustc panics on the 64-bit amount
    rejects("pub fn f(x: u32, k: u64) -> u32 { x >> k }", "crate::f", "shift-width");
}

#[test]
fn out_of_bounds_indexing_and_slicing() {
    rejects("pub fn f(xs: &[u8], i: usize) -> u8 { xs[i] }", "crate::f", "index-bounds");
    rejects("pub fn f(xs: &[u8]) -> u8 { if xs.len() > 3 { xs[4] } else { 0 } }", "crate::f", "index-bounds");
    rejects("pub fn f(a: [u8; 4], i: usize) -> u8 { a[i % 5] }", "crate::f", "index-bounds");
    rejects("pub fn f(xs: &[u8]) -> usize { let w = &xs[1..3]; w.len() }", "crate::f", "slice-range");
    rejects("pub fn f(src: &[u8]) -> [u8; 4] { let mut a = [0u8; 4]; a[0..2].copy_from_slice(src); a }", "crate::f", "slice-range");
}

#[test]
fn reachable_unreachable() {
    rejects("pub fn f(x: u8) -> u8 { match x % 3 { 0 => 1, 1 => 2, _ => unreachable!() } }", "crate::f", "unreachable");
}

#[test]
fn preconditions_of_callees() {
    rejects("#[requires(x < 10)]\nfn g(x: u32) -> u32 { x }\npub fn f(y: u32) -> u32 { g(y) }", "crate::f", "callee-requires");
    rejects("pub fn f(xs: &[u8], m: usize) -> usize { let (a, _b) = xs.split_at(m); a.len() }", "crate::f", "callee-requires");
}

#[test]
fn false_loop_invariants() {
    // false at entry
    rejects(
        "pub fn f(n: u8) -> u32 { let mut c: u32 = 5; for i in 0u32..n as u32 { proof! { invariant(c <= i); } c += 1; } c }",
        "crate::f",
        "invariant-entry",
    );
    // not preserved
    rejects(
        "pub fn f(n: u8) -> u32 { let mut c: u32 = 0; for i in 0u32..n as u32 { proof! { invariant(c <= i); } c += 2; } c }",
        "crate::f::loop#0",
        "invariant-preserve",
    );
}

#[test]
fn termination_and_stack_depth() {
    // the measure does not decrease
    rejects("#[decreases(n)]\npub fn f(n: u32) -> u32 { if n == 0 { 0 } else { f(n) } }", "crate::f", "termination");
    // a call from outside exceeds the declared depth bound
    rejects(
        "#[requires(n <= 8)]\n#[decreases(n, max = 8)]\nfn d(n: u32) -> u32 { if n == 0 { 0 } else { d(n - 1) } }\npub fn f(m: u32) -> u32 { if m <= 9 { d(m) } else { 0 } }",
        "crate::f",
        "stack-depth",
    );
    // no measure can be inferred: unsupported, never checked
    let (_c, v) = verify_src("pub fn f(a: u32, b: u32) -> u32 { if b == 0 { a } else { f(b, a % b) } }", ProverSet::Basic);
    assert!(matches!(status_of(&v, "crate::f"), DefStatus::Unsupported(m) if m.contains("decreases")), "{:?}", status_of(&v, "crate::f"));
}

#[test]
fn a_failure_blocks_nothing_it_does_not_reach_but_never_verifies() {
    let (c, v) = verify_src("pub fn ok(a: u8) -> u16 { a as u16 + 1 }\npub fn bad(a: u8) -> u8 { a + 1 }", ProverSet::Basic);
    assert_eq!(status_of(&v, "crate::ok"), &DefStatus::Checked);
    assert_eq!(status_of(&v, "crate::bad"), &DefStatus::Unproven);
    let v2 = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Basic, exec_only: false });
    assert!(!v2.proofs_ok, "one unproven obligation fails the whole crate");
    assert!(driver::stage::emit_stage(&c, &v2, "r/mod.rs").is_none(), "nothing is emitted");
}

#[test]
fn open_laws_fail_the_build() {
    let root = "pub fn double(x: u8) -> u16 { x as u16 * 2 }\n#[cfg(sandblaster)]\n#[path = \"laws.rs\"]\nmod laws;\n";
    let laws = "use sandblaster::prelude::*;\nuse super::double;\n#[law]\nfn double_even(x: u8) {\n    ensures((double(x) as Int) == 2 * (x as Int));\n}\n";
    let c = util::check_files(&[("r/mod.rs", root), ("r/laws.rs", laws)]);
    assert!(c.ok(), "{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Basic, exec_only: false });
    assert!(!v.proofs_ok, "an open claim fails verification:\n{}", explain(&c, &v));
    assert!(v.laws.iter().any(|l| l.name.contains("double_even") && l.status == DefStatus::Open), "{:?}", v.laws);
    assert!(v.diags.render(&c.sm).contains("double_even"));
}

#[test]
fn todo_in_a_proof_fails() {
    let src = r#"
pub fn f(x: u8) -> u8 {
    proof! { assert((x as Int) < 256, { todo(); }); }
    x
}
"#;
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert!(!(v.failed_defs().is_empty() && v.obligations.iter().all(|o| o.proven())), "todo() must fail:\n{}", explain(&c, &v));
}
