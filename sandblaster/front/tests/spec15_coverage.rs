//! §15 S4: `sandblaster coverage` (DESIGN.md §15.10) at the library level,
//! and the engine's resource behaviour (§15.9): per function, the safety
//! obligations and how they were discharged, the spec it refines and the
//! laws that mention it, its section and status (determined by its
//! refinement / fully specified / partially constrained / unspecified /
//! not required), the kill rates against the proofs and the specification
//! alone, examples and outcome coverage; sequential batches (re-elaborated
//! from scratch) that give the same verdicts whatever their size; the
//! memguard-aware limit; the review run of the spec-mutation tool on the
//! MMR (`sandblaster mutate`; recorded, never failed on, ignored by
//! default).

use std::path::Path;

use sandblaster_front::driver;
use sandblaster_front::hir::Crate;
use sandblaster_front::loader::{MemFs, RealFs};
use sandblaster_front::mutate::{self, MutateOptions, MutationReport, Verdict};
use sandblaster_front::span::SourceMap;
use sandblaster_front::target::TargetInfo;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

fn check(files: &[(&str, &str)]) -> (Crate, SourceMap) {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front-end errors:\n{}", c.render());
    (c.krate.clone().unwrap(), c.sm.clone())
}

const CRATE: &str = r#"
/// The reference verdict.
#[cfg(sandblaster)]
#[spec]
#[example(verify_spec(3, 4))]
#[example(!verify_spec(3, 5))]
fn verify_spec(key: Nat, tag: Nat) -> bool { tag == key + 1 }

/// Determined by its refinement.
#[refines(verify_spec)]
pub fn verify(key: u32, tag: u64) -> bool { if tag == (key as u64) + 1 { true } else { false } }

fn low(x: u32) -> u32 { x & 255u32 }

/// Only soundness is stated about `check` (see LAWS.rs).
pub fn check(x: u32, y: u32) -> bool { low(x) == low(y) }

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const LAWS: &str = r#"use sandblaster::prelude::*;
use super::check;

/// Accepted pairs agree on their low byte.
#[law]
fn check_sound(x: u32, y: u32) {
    requires(check(x, y));
    ensures(x % 256u32 == y % 256u32);
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
use super::check;

#[proof]
fn check_sound(x: u32, y: u32) { follows(); }
"#;

fn opts() -> MutateOptions {
    MutateOptions { max_mutants: 80, batch: 16, inputs: 200, ..MutateOptions::default() }
}

fn s_id(cov: &mutate::coverage::CoverageReport, p: &str) -> sandblaster_front::hir::ItemId {
    cov.functions.iter().find(|f| f.path == p).map(|f| f.item).expect("function")
}

fn verdicts(r: &MutationReport) -> Vec<(String, String, &'static str, Option<String>)> {
    r.mutants.iter().map(|(m, o)| (m.path.clone(), m.desc.clone(), o.verdict.word(), o.witness.as_ref().map(|w| format!("{} {} {}", w.input, w.original, w.mutant)))).collect()
}

/// The per-function report (statuses, obligations, refinements, laws,
/// sections, examples, kill rates) and its JSON.
#[test]
fn per_function_coverage() {
    let (k, sm) = check(&[("r/mod.rs", CRATE), ("r/LAWS.rs", LAWS), ("r/PROOF.rs", PROOF)]);
    let cov = mutate::coverage::coverage(&k, &sm, &opts(), None);
    let r = &cov.mutation;
    assert!(r.baseline_verified && r.complete, "{:?} {:?}", r.baseline_problems, r.incomplete_reasons);
    let f = |p: &str| cov.functions.iter().find(|f| f.path == p).unwrap_or_else(|| panic!("no `{p}`: {:#?}", cov.functions.iter().map(|f| &f.path).collect::<Vec<_>>()));
    let v = f("crate::verify");
    assert_eq!(v.status, "determined by its refinement", "{v:?}");
    assert!(v.refines.as_deref().is_some_and(|x| x.contains("crate::verify_spec") && x.contains("determines")), "{v:?}");
    assert!(v.obligations.iter().any(|(k, _, how)| k == "refines" && !how.contains_key("UNPROVEN")), "{v:?}");
    // a determined function has no counterexample: every surviving mutant is
    // equivalent where it matters
    assert!(v.counterexamples.is_empty(), "{v:?}");
    assert!(v.kill_rate_proofs.is_some_and(|(k, d)| k >= 1 && d >= k), "{v:?}");
    // its mutants are killed by the refinement lemma of the clone
    assert!(r.of_item(v.item).any(|(_, o)| o.verdict == Verdict::KilledBySpec && o.by.iter().any(|b| b.contains("refines"))), "{:#?}", r.of_item(v.item).map(|(m, o)| (&m.desc, o.verdict, &o.by)).collect::<Vec<_>>());
    // a spec mutant of `verify_spec` is not killed by `verify`'s refinement
    // (§15.7): at most noted
    for (_, o) in r.of_item(s_id(&cov, "crate::verify_spec")) {
        assert!(o.by.iter().all(|b| !b.contains("refines")), "{o:?}");
    }
    let c = f("crate::check");
    assert!(c.status.starts_with("partially constrained"), "{c:?}");
    assert_eq!(c.laws, vec!["crate::laws::check_sound".to_string()], "{c:?}");
    assert!(c.section.as_deref().is_some_and(|s| s.starts_with("section #")), "{c:?}");
    assert!(!c.counterexamples.is_empty(), "{c:?}");
    // an internal helper: its status names the functions its surviving
    // mutants change
    let l = f("crate::low");
    assert!(l.status.starts_with("not required") || l.status.starts_with("internal (not required itself); its surviving mutants change `crate::check`"), "{l:?}");
    let s = f("crate::verify_spec");
    assert_eq!(s.kind, "spec");
    assert_eq!(s.examples, (2, 0), "{s:?}");
    assert!(s.outcomes.as_ref().is_some_and(|(need, seen)| need.len() == 2 && seen.len() == 2), "{s:?}");
    // JSON and text
    let j = mutate::coverage::to_json(&cov).render();
    for key in ["\"functions\"", "\"obligations\"", "\"discharged_by\"", "\"kill_rate_spec\"", "\"law_sensitivity\"", "\"mutation\"", "\"outcomes\""] {
        assert!(j.contains(key), "{key} missing:\n{j}");
    }
    let t = mutate::coverage::render_text(&cov);
    assert!(t.contains("exec `crate::check`") && t.contains("counterexample (mutant #"), "{t}");
}

/// Sequential batches re-elaborate from scratch; their size changes the
/// number of elaborations, never a verdict or a witness (deterministic).
#[test]
fn batches_are_deterministic() {
    let (k, sm) = check(&[("r/mod.rs", CRATE), ("r/LAWS.rs", LAWS), ("r/PROOF.rs", PROOF)]);
    let only = vec!["crate::check".to_string()];
    let small = mutate::run(&k, &sm, &MutateOptions { batch: 2, only: only.clone(), ..opts() });
    let large = mutate::run(&k, &sm, &MutateOptions { batch: 64, only, ..opts() });
    assert!(small.batches.len() > large.batches.len() && large.batches.len() == 1, "{} vs {}", small.batches.len(), large.batches.len());
    assert!(small.batches.iter().all(|b| b.mutants <= 2));
    assert_eq!(verdicts(&small), verdicts(&large));
}

/// Memory-aware: no batch starts above the memguard fraction; the mutants
/// left are not run and the run is incomplete, never a pass.
#[test]
fn memory_limit_stops_batches_as_incomplete() {
    let (k, sm) = check(&[("r/mod.rs", CRATE), ("r/LAWS.rs", LAWS), ("r/PROOF.rs", PROOF)]);
    let r = mutate::run(&k, &sm, &MutateOptions { mem_fraction: 0.0, ..opts() });
    assert!(r.baseline_verified);
    assert!(!r.mutants.is_empty() && r.mutants.iter().all(|(_, o)| o.verdict == Verdict::NotRun));
    assert!(!r.complete && r.incomplete_reasons.iter().any(|x| x.contains("memory")), "{:?}", r.incomplete_reasons);
}

/// The spec-mutation tool's review run (`driver::stage::mutate`,
/// `sandblaster mutate`) on commonware-storage's MMR
/// (`storage/sandblaster/mmr`): the verdicts, findings and batches are
/// recorded in `$CARGO_TARGET_TMPDIR/mmr-mutants.{txt,json}`, not asserted
/// (it replaced the bounded run on the former QMDB fixture, removed
/// 2026-10-05). Only that the engine ran on a verified baseline is
/// checked. Run with `--ignored --test-threads=1`.
#[test]
#[ignore = "slow: the review run of the spec-mutation tool on the MMR (an elaboration of the root, then every spec mutant of its review surface); a measurement"]
fn the_mmr_review_run_is_recorded() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../storage/sandblaster/mmr/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let run = driver::stage::mutate(&c);
    let r = run.report.as_ref().unwrap_or_else(|| panic!("the MMR does not verify:\n{}", run.v.diags.render(&c.sm)));
    let mut s = format!("MMR: baseline verified {}, {} mutants enumerated, {} run, complete {}, {:.1} s, {} batch(es), {} finding(s)\n", r.baseline_verified, r.enumerated, r.mutants.iter().filter(|(_, o)| o.verdict != Verdict::NotRun).count(), r.complete, r.elapsed.as_secs_f64(), r.batches.len(), run.findings.list.len());
    for v in Verdict::ALL {
        s.push_str(&format!("  {}: {}\n", v.word(), r.count(v)));
    }
    for (m, o) in &r.mutants {
        s.push_str(&format!("  #{} {} [{}] {} -> {} ({} items) {}\n", m.id, m.path, m.family, m.desc, o.verdict.word(), o.closure, o.by.first().cloned().or_else(|| o.witness.as_ref().map(|w| format!("at `{}` on {}: {} vs {}", w.function, w.input, w.original, w.mutant))).or_else(|| o.notes.first().cloned()).unwrap_or_default()));
    }
    for b in &r.batches {
        s.push_str(&format!("  batch: {} mutant(s), {} items, {:.1} s, heap {} MiB\n", b.mutants, b.items, b.elapsed.as_secs_f64(), b.heap >> 20));
    }
    s.push_str(&run.findings.render(&c.sm));
    eprintln!("{s}");
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::write(dir.join("mmr-mutants.txt"), &s);
    let _ = std::fs::write(dir.join("mmr-mutants.json"), mutate::report_json(r).render());
    // recorded, not asserted: only that the engine ran on a verified baseline
    assert!(r.baseline_verified, "{s}");
}

const TABLE: &str = r#"
/// The round constants.
const K: [u32; 2] = [0x428a_2f98, 0x7137_4491];

/// XORs the low bits of the first round constant into a word.
fn mix_round_low(x: u32) -> u32 { x ^ (K[0] & 0xffffu32) }

/// Mixes a word with the round constants.
pub fn mix(x: u32) -> u32 { x ^ K[0] ^ K[1] }

/// Mixes a word with the low bits of the first round constant, rotated.
pub fn mix_low(x: u32) -> u32 { mix_round_low(x).rotate_left(8u32) }
"#;

/// Every counterexample line names the function the difference was seen
/// at; a constant or helper says which functions its surviving mutants
/// change; a function's status counts the mutants seen at it, and its
/// counterexample lines are exactly those.
#[test]
fn counterexamples_name_where_they_were_seen() {
    let (k, sm) = check(&[("r/mod.rs", TABLE)]);
    let cov = mutate::coverage::coverage(&k, &sm, &opts(), None);
    assert!(cov.mutation.baseline_verified, "{:?}", cov.mutation.baseline_problems);
    let f = |p: &str| cov.functions.iter().find(|f| f.path == p).unwrap();
    let kc = f("crate::K");
    assert!(kc.status.starts_with("internal (not required itself); its surviving mutants change") && kc.status.contains("`crate::mix`"), "{kc:?}");
    assert!(!kc.counterexamples.is_empty() && kc.counterexamples.iter().all(|x| x.at == "crate::mix" || x.at == "crate::mix_low"), "{kc:?}");
    let helper = f("crate::mix_round_low");
    assert!(helper.counterexamples.iter().all(|x| x.at == "crate::mix_low"), "{helper:?}");
    for p in ["crate::mix", "crate::mix_low"] {
        let m = f(p);
        let here = m.counterexamples.iter().filter(|x| x.at == p).count();
        assert!(here > 0 && m.status.starts_with(&format!("partially constrained: {here} surviving mutant(s) (of it or of the code it uses)")), "{m:?}");
    }
    let t = mutate::coverage::render_text(&cov);
    for line in t.lines().filter(|l| l.trim_start().starts_with("counterexample")) {
        assert!(line.contains(") at `crate::"), "{line}");
    }
    assert!(t.contains("mutants of this item:"), "{t}");
    let j = mutate::coverage::to_json(&cov).render();
    assert!(j.contains("\"at\": \"crate::mix\"") && j.contains("\"mutant_of\": \"crate::K\""), "{j}");
}

/// A function none of whose mutants ran says so instead of claiming a
/// success.
#[test]
fn a_function_without_mutants_run_claims_nothing() {
    let (k, sm) = check(&[("r/mod.rs", CRATE), ("r/LAWS.rs", LAWS), ("r/PROOF.rs", PROOF)]);
    let cov = mutate::coverage::coverage(&k, &sm, &MutateOptions { only: vec!["crate::check".into()], ..opts() }, None);
    let s = cov.functions.iter().find(|f| f.path == "crate::verify_spec").unwrap();
    assert!(s.status.starts_with("no mutants run"), "{s:?}");
    assert!(s.kill_rate_proofs.is_none(), "{s:?}");
}
