//! `sandblaster coverage` (DESIGN.md §15.10): the crate path (exit 0 only
//! with a crate verdict), then the per-function report of an exploration
//! run of the counterexample engine (§15.9), as text and JSON, on a crate
//! directory on disk. The fixture specifies `verify` by soundness only, so
//! it fails the gates (and the exploration run shows why).
//!
//! `sandblaster mutate` (DESIGN.md §15.7): the on-demand spec-mutation
//! tool reports a surviving spec mutant of an under-pinned vocabulary
//! function (exit 1) and none once a known answer pins it (exit 0).

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

/// Runs the CLI with the verdict cache off (hermetic: no user cache).
fn run(args: &[&str]) -> Output {
    run_env(args, &[("SANDBLASTER_CACHE", "off")])
}

fn run_env(args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut c = Command::new(bin());
    c.args(args).env("SANDBLASTER_MEM_LIMIT_GB", "6").env_remove("SANDBLASTER_CACHE").env_remove("SANDBLASTER_CACHE_DIR");
    for (k, v) in vars {
        c.env(k, v);
    }
    c.output().expect("run sandblaster")
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

// ---------------------------------------------------------------------
// `sandblaster mutate`: the spec-mutation tool (not a gate)
// ---------------------------------------------------------------------

/// A crate whose law puts `checksum` on the review surface, with the known
/// answers `examples`.
fn checksum_dir(name: &str, examples: &str) -> PathBuf {
    let d = tmp(name);
    let root = format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n/// The checksum of two values.\n#[cfg(sandblaster)]\n#[spec]\n{examples}fn checksum(a: Nat, b: Nat) -> Nat {{ a + 2 * b }}\n\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    let laws = "use sandblaster::prelude::*;\nuse super::checksum;\n\n/// The checksum covers its first value.\n#[law]\nfn checksum_covers_a(a: Nat, b: Nat) {\n    ensures(checksum(a, b) >= a);\n}\n";
    let proof = "use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::checksum;\n\n#[proof]\nfn checksum_covers_a(a: Nat, b: Nat) {\n    follows();\n}\n";
    for (f, t) in [("mod.rs", root.as_str()), ("LAWS.rs", laws), ("PROOF.rs", proof)] {
        std::fs::write(d.join(f), t).unwrap();
    }
    d
}

/// One known answer leaves `checksum` under-pinned: `sandblaster mutate`
/// reports the surviving mutant and the example that kills it, and exits
/// 1 (it needs no lock: it states no verdict). Negative twin: with a
/// second known answer nothing survives and it exits 0.
#[test]
fn mutate_reports_a_survivor_and_passes_a_pinned_crate() {
    let d = checksum_dir("mutate-underpinned", "#[example(checksum(1, 2) == 5)]\n");
    let o = run(&["mutate", d.to_str().unwrap()]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("a review tool, not a gate") && out.contains("survived: #") && out.contains("`crate::checksum`"), "{out}");
    assert!(out.contains("law `crate::laws::checksum_covers_a`: kills"), "{out}");
    assert!(err.contains("error[spec-mutant-survived]") && err.contains("#[example(checksum("), "{err}");
    // the engine's report as JSON
    let o = run(&["mutate", d.to_str().unwrap(), "--json"]);
    let (out, _) = text(&o);
    assert_eq!(o.status.code(), Some(1));
    assert!(out.contains("\"counts\"") && out.contains("\"counterexample\": ") && !out.contains("\"counterexample\": 0"), "{out}");
    // the exploration options belong to `coverage`
    let o = run(&["mutate", d.to_str().unwrap(), "--mutants-max", "3"]);
    assert_eq!(o.status.code(), Some(2), "{:?}", text(&o));
    // pinned
    let d = checksum_dir("mutate-pinned", "#[example(checksum(1, 2) == 5)]\n#[example(checksum(0, 0) == 0)]\n");
    let o = run(&["mutate", d.to_str().unwrap()]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains(" 0 survived") && !out.contains("survived: #") && !err.contains("error["), "{out}\n{err}");
}

/// `sandblaster mutate` caches each mutant's verdict (its toolchain
/// identity from `build.rs`, the per-mutant keys of the verdict cache): a
/// repeated run on unchanged inputs reuses every verdict and reports the
/// same findings; a run with the cache off runs every mutant.
#[test]
fn mutate_reuses_cached_mutant_verdicts() {
    let d = checksum_dir("mutate-cached", "#[example(checksum(1, 2) == 5)]\n");
    let cache = tmp("mutate-cache-store");
    let vars = [("SANDBLASTER_CACHE_DIR", cache.to_str().unwrap()), ("SANDBLASTER_CACHE_KEY", "test-key")];
    let first = run_env(&["mutate", d.to_str().unwrap()], &vars);
    let (out1, err1) = text(&first);
    assert_eq!(first.status.code(), Some(1), "stdout:\n{out1}\nstderr:\n{err1}");
    assert!(out1.contains("verdict cache: 0 hit(s), "), "{out1}");
    let second = run_env(&["mutate", d.to_str().unwrap()], &vars);
    let (out2, err2) = text(&second);
    assert_eq!(second.status.code(), Some(1), "stdout:\n{out2}\nstderr:\n{err2}");
    assert!(out2.contains(" hit(s), 0 run") && !out2.contains("verdict cache: 0 hit(s)"), "{out2}");
    // the same survivors and findings either way
    let survivors = |o: &str| o.lines().filter(|l| l.contains("survived: #")).map(String::from).collect::<Vec<_>>();
    assert_eq!(survivors(&out1), survivors(&out2));
    assert!(err2.contains("error[spec-mutant-survived]"), "{err2}");
    // with the cache off: no cache line, every mutant runs
    let off = run(&["mutate", d.to_str().unwrap()]);
    let (out3, _) = text(&off);
    assert!(!out3.contains("verdict cache:"), "{out3}");
    assert_eq!(survivors(&out1), survivors(&out3));
}
