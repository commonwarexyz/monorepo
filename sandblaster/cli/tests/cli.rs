//! `sandblaster check|emit|report|eval` (DESIGN.md §10.2): the crate path
//! from the command line — every command that states a verdict runs the
//! proofs, every §15 gate, the optimizer and the round trip, and only a
//! crate verdict prints `VERIFIED` or exits 0; `eval` is a stage tool.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandblaster")
}

fn samples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../front/tests/samples")
}

fn tmp(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A small fully specified crate: two functions in a private module,
/// re-exported by the root, each refining a reference specification with
/// known answers.
const GOOD_ROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

mod m;

pub use m::{clamp_add, pick};

#[cfg(sandblaster)]
#[spec]
#[path = "spec.rs"]
mod spec;
"#;

const GOOD_M: &str = r#"use sandblaster::prelude::*;

/// `a + b`, saturating at 255.
#[refines(crate::spec::saturating_sum)]
pub fn clamp_add(a: u8, b: u8) -> u8 {
    let s = a as u16 + b as u16;
    if s > 255 { 255 } else { s as u8 }
}

/// The distance from `b` to `a` (to zero when `a` is `None`).
#[refines(crate::spec::distance)]
pub fn pick(a: Option<u32>, b: u32) -> u32 {
    match a {
        Some(x) if x > b => x - b,
        Some(x) => b - x,
        None => b,
    }
}
"#;

const GOOD_SPEC: &str = r#"//! What the two functions compute, over unbounded numbers.

/// `a + b`, capped at 255.
#[example(saturating_sum(1, 2) == 3)]
#[example(saturating_sum(200, 100) == 255)]
#[example(saturating_sum(255, 0) == 255)]
pub fn saturating_sum(a: Nat, b: Nat) -> Nat {
    (a + b).min(255)
}

/// How far `a` (zero when absent) is from `b`.
#[example(distance(Some(9), 4) == 5)]
#[example(distance(Some(4), 9) == 5)]
#[example(distance(Some(4), 4) == 0)]
#[example(distance(None, 4) == 4)]
pub fn distance(a: Option<Nat>, b: Nat) -> Nat {
    let x = a.unwrap_or(0);
    x.max(b) - x.min(b)
}
"#;

/// The good crate in a fresh directory, without a lock.
fn good_crate_unlocked(name: &str) -> PathBuf {
    let d = tmp(name);
    std::fs::write(d.join("mod.rs"), GOOD_ROOT).unwrap();
    std::fs::write(d.join("m.rs"), GOOD_M).unwrap();
    std::fs::write(d.join("spec.rs"), GOOD_SPEC).unwrap();
    d
}

/// The good crate with the lock `sandblaster spec --accept` wrote for it.
fn good_crate(name: &str) -> PathBuf {
    let d = good_crate_unlocked(name);
    let out = Command::new(bin()).args(["spec", "--accept"]).arg(&d).output().unwrap();
    assert!(out.status.success(), "spec --accept: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(d.join("SPEC.lock").is_file());
    d
}

/// A crate whose every obligation is provable but which has no
/// specification (for the stage tool `eval`, and as a crate the gates
/// reject).
const UNSPECIFIED: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// Sum of the first `n` bytes (at most 1000), saturating the count at the
/// slice length.
pub fn sum(xs: &[u8], n: usize) -> u32 {
    let mut acc: u32 = 0;
    let k = n.min(xs.len()).min(1000usize);
    for i in 0..k {
        proof! { invariant((acc as Int) <= (i as Int) * 255); }
        acc += xs[i] as u32;
    }
    acc
}

pub fn pick(a: Option<u32>, b: u32) -> u32 {
    match a {
        Some(x) if x > b => x - b,
        Some(x) => b - x,
        None => b,
    }
}
"#;

fn unspecified_crate(name: &str) -> PathBuf {
    let d = tmp(name);
    std::fs::write(d.join("mod.rs"), UNSPECIFIED).unwrap();
    d
}

#[test]
fn check_verifies_a_crate() {
    let d = good_crate("cli-good");
    let out = Command::new(bin()).args(["check"]).arg(&d).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}{}", stdout, String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("diagnostics: 0 error(s)"), "{stdout}");
    assert!(stdout.contains("status: VERIFIED + OPTIMIZED (phase 3)"), "{stdout}");
    assert!(stdout.contains("obligations: "), "{stdout}");
    assert!(stdout.contains("0 failed"), "{stdout}");
    for g in ["boundary", "examples", "sections", "law-rules", "lock", "mutation"] {
        assert!(stdout.contains(&format!("gate {g}: passed")), "{g}: {stdout}");
    }
    assert!(stdout.contains("emitted: sandblaster.rs sha256 "), "{stdout}");
    // `check` writes nothing
    assert!(!d.join("sandblaster.rs").exists());
}

/// The proofs of a crate check, but it has no specification: `check` runs
/// every gate and never says VERIFIED.
#[test]
fn check_fails_a_crate_that_fails_the_gates() {
    let d = unspecified_crate("cli-unspecified");
    let out = Command::new(bin()).args(["check"]).arg(&d).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("0 failed"), "the proofs check: {stdout}");
    assert!(stdout.contains("status: NOT VERIFIED"), "{stdout}");
    assert!(!stdout.contains("VERIFIED +"), "{stdout}");
    assert!(stderr.contains("error[boundary]") && stderr.contains("failed the §15 gates"), "{stderr}");
    // and nothing is emitted
    let out = Command::new(bin()).args(["emit"]).arg(&d).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn check_fails_on_unprovable_obligations() {
    // the `basic` sample has genuinely unprovable overflows (e.g. `pow2`)
    let out = Command::new(bin()).args(["check"]).arg(samples().join("basic/mod.rs")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("status: NOT VERIFIED"), "{stdout}");
    assert!(stderr.contains("error[obligation]: unproven obligation [overflow] in `crate::pow2`"), "{stderr}");
    assert!(stderr.contains("goal:"), "the goal is printed: {stderr}");
}

#[test]
fn check_crate_dir_via_build_rs() {
    let d = tmp("cli-crate");
    std::fs::create_dir_all(d.join("dsl")).unwrap();
    std::fs::write(d.join("build.rs"), "fn main() { sandblaster::build::compile(\"dsl/root.rs\"); }\n").unwrap();
    std::fs::write(d.join("dsl/root.rs"), GOOD_ROOT).unwrap();
    std::fs::write(d.join("dsl/m.rs"), GOOD_M).unwrap();
    std::fs::write(d.join("dsl/spec.rs"), GOOD_SPEC).unwrap();
    // the root is found through build.rs; its lock is `SPEC.root.lock`
    // (one lock per root, DESIGN.md §15.6)
    let out = Command::new(bin()).args(["check"]).arg(&d).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("dsl/SPEC.root.lock"), "{}", String::from_utf8_lossy(&out.stderr));
    let out = Command::new(bin()).args(["spec", "--accept"]).arg(&d).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(d.join("dsl/SPEC.root.lock").is_file() && !d.join("dsl/SPEC.lock").exists());
    let out = Command::new(bin()).args(["check"]).arg(&d).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    // --target: the lock holds one target at a time until it is accepted
    // for the other one too
    let out = Command::new(bin()).args(["check", "--target", "x86_64"]).arg(&d).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("target: x86_64"));
    let out = Command::new(bin()).args(["spec", "--accept", "--target", "x86_64"]).arg(&d).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for t in ["x86_64", "aarch64"] {
        let out = Command::new(bin()).args(["check", "--target", t]).arg(&d).output().unwrap();
        assert!(out.status.success(), "{t}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn check_reports_front_end_errors_and_fails() {
    let d = tmp("cli-bad");
    std::fs::write(d.join("mod.rs"), "#![forbid(unsafe_code)]\npub fn f(k: u32) -> u64 { (1 << k) as u64 }\n").unwrap();
    let out = Command::new(bin()).args(["check"]).arg(&d).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("mod.rs:2:28: error[literal]: unsuffixed literal in the operand of `as`"), "{err}");
    assert!(err.contains("^"), "snippet with caret: {err}");
    let out = Command::new(bin()).args(["emit"]).arg(&d).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn emit_prints_verified_code_only() {
    let d = good_crate("cli-emit");
    let out = Command::new(bin()).args(["emit"]).arg(&d).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let code = String::from_utf8_lossy(&out.stdout);
    assert!(code.starts_with("// @generated by sandblaster"));
    // the build's output: verified, every gate passed, optimized,
    // round-tripped
    assert!(code.lines().nth(1).is_some_and(|l| l.starts_with("// STATUS: VERIFIED + OPTIMIZED (phase 3)")), "{code}");
    assert!(!code.contains("UNVERIFIED") && !code.contains("STAGE OUTPUT"), "{code}");
    assert!(code.contains("mod __sandblaster {"));
    assert!(code.contains("pub use __sandblaster::m::pick as pick;"), "{code}");
    // unprovable obligations: nothing is emitted
    let out = Command::new(bin()).args(["emit"]).arg(samples().join("basic")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn report_is_json_with_obligations() {
    let d = good_crate("cli-report");
    let out = Command::new(bin()).args(["report"]).arg(&d).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.trim_start().starts_with('{') && s.trim_end().ends_with('}'));
    // the build's report: verified and optimized, with the gates
    assert!(s.contains("\"status\": \"VERIFIED + OPTIMIZED (phase 3)\""), "{s}");
    assert!(s.contains("\"obligations\""), "{s}");
    assert!(s.contains("\"by_kind\""), "{s}");
    assert!(s.contains("\"gates\""), "{s}");
    // without a verdict the report still explains, and the exit status is 1
    let d = unspecified_crate("cli-report-bad");
    let out = Command::new(bin()).args(["report"]).arg(&d).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"status\": \"NOT VERIFIED\"") && !s.contains("VERIFIED +"), "{s}");
}

#[test]
fn eval_uses_the_kernel_evaluator() {
    // a stage tool: it prints a value, never a verdict, on any crate whose
    // exec code verifies
    let d = unspecified_crate("cli-eval");
    let out = Command::new(bin()).args(["eval"]).arg(&d).args(["sum", "[\"0x01020304ff\", 3]"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "6");
    let out = Command::new(bin()).args(["eval"]).arg(&d).args(["crate::pick", "[{\"Some\": 9}, 4]"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "5");
    let out = Command::new(bin()).args(["eval"]).arg(&d).args(["pick", "[null, 4]"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "4");
    // wrong arity
    let out = Command::new(bin()).args(["eval"]).arg(&d).args(["pick", "[1]"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("takes 2 argument(s)"));
}

#[test]
fn usage_errors() {
    let out = Command::new(bin()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin()).args(["eval", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin()).args(["check", "/nonexistent/dir"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    // there is no flag to skip proofs
    let out = Command::new(bin()).args(["check", "--no-proofs", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
