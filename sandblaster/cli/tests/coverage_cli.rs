//! `sandblaster coverage` (DESIGN.md §15.10): the crate path (exit 0 only
//! with a crate verdict), then the per-function report of an exploration
//! run of the counterexample engine (§15.9), as text and JSON, on a crate
//! directory on disk. The fixture specifies `verify` by soundness only, so
//! it fails the gates (and the exploration run shows why).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandblaster")
}

fn tmp(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const ROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// The reference verdict.
#[cfg(sandblaster)]
#[spec]
#[example(verify_spec(3, 4))]
#[example(!verify_spec(3, 5))]
fn verify_spec(key: Nat, tag: Nat) -> bool { tag == key + 1 }

pub fn verify(key: u32, tag: u64) -> bool { if tag == (key as u64) + 1 { true } else { false } }

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const LAWS: &str = r#"use sandblaster::prelude::*;
use super::{verify, verify_spec};

/// Sound: `verify` accepts only the key's checksum.
#[law]
fn verified_tags_are_checksums(key: u32, tag: u64) {
    requires(verify(key, tag));
    ensures(verify_spec(key as Nat, tag as Nat));
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
use super::{verify, verify_spec};

#[proof]
fn verified_tags_are_checksums(key: u32, tag: u64) { follows(); }
"#;

fn crate_dir(name: &str) -> PathBuf {
    let d = tmp(name);
    for (f, t) in [("mod.rs", ROOT), ("LAWS.rs", LAWS), ("PROOF.rs", PROOF)] {
        std::fs::write(d.join(f), t).unwrap();
    }
    d
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).env("SANDBLASTER_MEM_LIMIT_GB", "6").output().expect("run sandblaster")
}

fn text(o: &Output) -> (String, String) {
    (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

/// JSON: every function with its status, obligations and mutants; the
/// `λ_. false` counterexample of the soundness-only `verify`; the gate's
/// `error[spec-incomplete]` on stderr.
#[test]
fn coverage_json_reports_the_counterexample() {
    let d = crate_dir("cov-json");
    let o = run(&["coverage", d.to_str().unwrap(), "--json", "--no-sheet", "--only", "crate::verify"]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "no crate verdict: stdout:\n{out}\nstderr:\n{err}");
    assert!(err.contains("failed the §15 gates"), "{err}");
    assert!(out.contains("\"path\": \"crate::verify\""), "{out}");
    assert!(out.contains("\"path\": \"crate::verify_spec\""), "{out}");
    assert!(out.contains("\"verdict\": \"counterexample\""), "{out}");
    assert!(out.contains("\"status\": \"complete\""), "{out}");
    assert!(out.contains("\"kill_rate_proofs\""), "{out}");
    assert!(out.contains("\"discharged_by\""), "{out}");
    assert!(out.contains("\"spec_sheet\": null"), "{out}");
    assert!(out.contains("partially constrained"), "{out}");
    assert!(err.contains("error[spec-incomplete]"), "{err}");
    assert!(err.contains("the mutant returns: false"), "{err}");
}

/// Text: per-function lines, the law-sensitivity table and the spec sheet.
#[test]
fn coverage_text_with_the_spec_sheet() {
    let d = crate_dir("cov-text");
    let o = run(&["coverage", d.to_str().unwrap(), "--mutants-max", "8"]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "no crate verdict: stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("exec `crate::verify`"), "{out}");
    assert!(out.contains("status: partially constrained"), "{out}");
    assert!(out.contains("kill rate: proofs"), "{out}");
    assert!(out.contains("spec `crate::verify_spec`"), "{out}");
    assert!(out.contains("examples: 2"), "{out}");
    assert!(out.contains("SPECIFICATION SHEET"), "{out}");
    // 8 of the enumerated mutants: a sample, so the run is incomplete
    assert!(out.contains("INCOMPLETE"), "{out}");
    assert!(err.contains("error[mutation-incomplete]"), "{err}");
    // a progress line per batch on stderr
    assert!(err.contains("sandblaster coverage: batch 1 ("), "{err}");
}

/// `--only` with an item that names nothing is a usage error with the
/// closest item, never a clean empty report; `--time-budget` stops the
/// run cleanly as incomplete.
#[test]
fn coverage_only_and_time_budget() {
    let d = crate_dir("cov-only");
    let o = run(&["coverage", d.to_str().unwrap(), "--no-sheet", "--only", "crate::verfy"]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "stdout:\n{out}\nstderr:\n{err}");
    assert!(err.contains("`--only crate::verfy` names no function or constant of the crate (closest: crate::verify"), "{err}");
    assert!(!out.contains("complete"), "{out}");
    let o = run(&["coverage", d.to_str().unwrap(), "--no-sheet", "--time-budget", "0"]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("INCOMPLETE") && out.contains("wall-clock budget"), "{out}");
    assert!(err.contains("error[mutation-incomplete]"), "{err}");
}

/// The coverage options belong to `coverage` only.
#[test]
fn coverage_flags_on_other_commands_are_usage_errors() {
    let d = crate_dir("cov-usage");
    let o = run(&["check", d.to_str().unwrap(), "--json"]);
    assert_eq!(o.status.code(), Some(2), "{:?}", text(&o));
}

/// A fully specified crate with its accepted lock: `coverage` exits 0,
/// and the exploration options never change the gate (the gate's spec
/// mutation ignores `--mutants-max` and `SANDBLASTER_MUTANTS_*`).
#[test]
fn coverage_of_a_verified_crate_exits_zero() {
    let d = tmp("cov-good");
    let files = [
        ("mod.rs", "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\nmod m;\n\npub use m::clamp_add;\n\n#[cfg(sandblaster)]\n#[spec]\n#[path = \"spec.rs\"]\nmod spec;\n"),
        ("m.rs", "use sandblaster::prelude::*;\n\n/// `a + b`, saturating at 255.\n#[refines(crate::spec::saturating_sum)]\npub fn clamp_add(a: u8, b: u8) -> u8 {\n    let s = a as u16 + b as u16;\n    if s > 255 { 255 } else { s as u8 }\n}\n"),
        ("spec.rs", "//! The reference.\n\n/// `a + b`, capped at 255.\n#[example(saturating_sum(1, 2) == 3)]\n#[example(saturating_sum(200, 100) == 255)]\n#[example(saturating_sum(255, 0) == 255)]\npub fn saturating_sum(a: Nat, b: Nat) -> Nat {\n    (a + b).min(255)\n}\n"),
    ];
    for (f, t) in files {
        std::fs::write(d.join(f), t).unwrap();
    }
    let o = run(&["spec", "--accept", d.to_str().unwrap()]);
    assert!(o.status.success(), "{:?}", text(&o));
    let o = Command::new(bin()).args(["coverage", d.to_str().unwrap(), "--no-sheet", "--mutants-max", "1"]).env("SANDBLASTER_MUTANTS_MAX", "0").env("SANDBLASTER_MUTANTS_TIME_BUDGET", "0").output().unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    // the exploration run is capped (and says so); the gate is not
    assert!(out.contains("INCOMPLETE"), "{out}");
    assert!(!err.contains("failed the §15 gates"), "{err}");
}
