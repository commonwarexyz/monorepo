//! §15 S4: the counterexample engine (DESIGN.md §15.9), spec mutation
//! (§15.7) and law sensitivity (§15.1 LR8) on in-memory crates.
//!
//! * a soundness-only `verify`: the `λ_. false` mutant satisfies the law
//!   and is reported as a definite counterexample with an input and both
//!   outputs (`error[spec-incomplete]`); with the completeness law too,
//!   nothing survives with a counterexample;
//! * a codec whose laws miss canonicity: the engine finds the
//!   non-canonical decode; the canonicity law kills that mutant;
//! * an equivalent mutant (`x * 1` → `x / 1`) is possibly equivalent and
//!   never an error; safety kills (overflow) are never specification kills;
//! * budget exhaustion (caps, a deadline, an unverified baseline) reports
//!   `incomplete` (`error[mutation-incomplete]`), never a pass;
//! * spec mutants must be killed by examples or by definite law
//!   counterexamples; the survivor comes with the example that kills it;
//! * docs/qmdb-spec-design.md §2.10(b) in the tool: a law catches the
//!   spec mutant that breaks the construction; only a known answer catches
//!   the one wrong the same way on both sides; an insensitive law is
//!   `warning[law-insensitive]`.
//!
//! Each run is bounded (explicit caps) and deterministic.

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Diagnostics, Severity};
use sandblaster_front::driver;
use sandblaster_front::hir::Crate;
use sandblaster_front::loader::MemFs;
use sandblaster_front::mutate::{self, MutateOptions, MutationReport, Target, Verdict};
use sandblaster_front::target::TargetInfo;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

struct Run {
    rep: MutationReport,
    #[allow(dead_code)]
    krate: Crate,
    /// What the §15.8 gate reports: `(severity is error, kind, message, notes)`.
    gate: Vec<(bool, DiagKind, String, Vec<String>)>,
}

impl Run {
    fn explain(&self) -> String {
        let mut s = format!("complete={} enumerated={} reasons={:?}\n", self.rep.complete, self.rep.enumerated, self.rep.incomplete_reasons);
        for p in &self.rep.baseline_problems {
            s.push_str(&format!("baseline: {p}\n"));
        }
        for (m, o) in &self.rep.mutants {
            s.push_str(&format!("#{} {} [{}] {} -> {} by={:?} notes={:?}\n", m.id, m.path, m.family, m.desc, o.verdict.word(), o.by, o.notes));
            if let Some(w) = &o.witness {
                s.push_str(&format!("    witness at {} on {}: {} vs {} ({})\n", w.function, w.input, w.original, w.mutant, w.evaluator));
            }
        }
        for l in &self.rep.laws {
            s.push_str(&format!("law {}: in scope {:?}, kills {:?}, evaluable {}\n", l.path, l.in_scope, l.killed, l.evaluable));
        }
        for (e, k, m, n) in &self.gate {
            s.push_str(&format!("gate {} {k:?}: {m}\n", if *e { "error" } else { "warning" }));
            for x in n {
                s.push_str(&format!("   = {x}\n"));
            }
        }
        s
    }

    /// The mutants of `item` whose description contains `desc`.
    #[track_caller]
    fn mutant(&self, item: &str, desc: &str) -> &(mutate::Mutant, mutate::Outcome) {
        self.rep.mutants.iter().find(|(m, _)| m.path == item && m.desc.contains(desc)).unwrap_or_else(|| panic!("no mutant of `{item}` with `{desc}`:\n{}", self.explain()))
    }

    fn gate_has(&self, error: bool, kind: DiagKind, needle: &str) -> bool {
        self.gate.iter().any(|(e, k, m, n)| *e == error && *k == kind && (m.contains(needle) || n.iter().any(|x| x.contains(needle))))
    }
}

fn opts() -> MutateOptions {
    MutateOptions { max_mutants: 60, batch: 8, inputs: 300, ..MutateOptions::default() }
}

fn run_with(files: &[(&str, &str)], o: &MutateOptions) -> Run {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front-end errors:\n{}", c.render());
    let krate = c.krate.clone().unwrap();
    let rep = mutate::run(&krate, &c.sm, o);
    let mut d = Diagnostics::new();
    mutate::spec15_gate_mutants(&rep, &krate, &mut d);
    let gate = d.list.iter().map(|x| (x.severity == Severity::Error, x.kind, x.msg.clone(), x.notes.iter().map(|n| n.1.clone()).collect())).collect();
    let r = Run { rep, krate, gate };
    if std::env::var_os("SANDBLASTER_TEST_EXPLAIN").is_some() {
        eprintln!("{}", r.explain());
    }
    r
}

/// A crate with a root, a `LAWS.rs` and a `PROOF.rs` (a `follows()` proof
/// for every law); both modules import `uses` from the root.
fn with_laws(root: &str, uses: &str, laws: &str, o: &MutateOptions) -> Run {
    let root = format!("{root}\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    let mut proof = format!("use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::{{{uses}}};\n");
    for part in laws.split("#[law]").skip(1) {
        let r = part.trim_start().strip_prefix("fn ").unwrap();
        let name = r.split('(').next().unwrap().trim();
        let sig = &r[r.find('(').unwrap()..=r.find(')').unwrap()];
        proof.push_str(&format!("\n#[proof]\nfn {name}{sig} {{\n    follows();\n}}\n"));
    }
    let laws = format!("use sandblaster::prelude::*;\nuse super::{{{uses}}};\n{laws}");
    run_with(&[("r/mod.rs", &root), ("r/LAWS.rs", &laws), ("r/PROOF.rs", &proof)], o)
}

const MINI_SPEC: &str = r#"
/// The reference verdict: a tag is accepted exactly when it is the key's
/// successor.
#[cfg(sandblaster)]
#[spec]
#[example(verify_spec(3, 4))]
#[example(!verify_spec(3, 5))]
fn verify_spec(key: Nat, tag: Nat) -> bool { tag == key + 1 }

pub fn verify(key: u32, tag: u64) -> bool { if tag == (key as u64) + 1 { true } else { false } }
"#;

const SOUND: &str = r#"
/// Sound: `verify` accepts only the key's checksum.
#[law]
fn verified_tags_are_checksums(key: u32, tag: u64) {
    requires(verify(key, tag));
    ensures(verify_spec(key as Nat, tag as Nat));
}
"#;

const COMPLETE: &str = r#"
/// Complete: `verify` accepts the key's checksum.
#[law]
fn checksums_verify(key: u32, tag: u64) {
    requires(verify_spec(key as Nat, tag as Nat));
    ensures(verify(key, tag));
}
"#;

// ---------------------------------------------------------------------
// §15.9: definite counterexamples to an unproven completeness statement
// ---------------------------------------------------------------------

/// Soundness alone does not determine `verify`: `λ_. false` satisfies the
/// law, and the engine shows it with an input where it differs.
#[test]
fn soundness_only_verify_lambda_false_is_a_definite_counterexample() {
    let o = MutateOptions { only: vec!["crate::verify".into()], ..opts() };
    let r = with_laws(MINI_SPEC, "verify, verify_spec", SOUND, &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (m, out) = r.mutant("crate::verify", "returns `false`");
    assert_eq!(out.verdict, Verdict::Counterexample, "{}", r.explain());
    let w = out.witness.as_ref().unwrap();
    assert_eq!(w.function, "crate::verify");
    assert_eq!((w.original.as_str(), w.mutant.as_str()), ("true", "false"), "{}", r.explain());
    assert!(w.evaluator.contains("eval_closed"), "a boundary function is evaluated by the kernel: {}", r.explain());
    // the optional kernel-checked refutation of `complete_verify`
    assert!(matches!(&w.refutation, Some(Ok(t)) if t.contains("complete_crate::verify(R) → Empty")), "{:?}\n{}", w.refutation, r.explain());
    assert!(m.diff.iter().any(|l| l.starts_with("+ ") && l.contains("{ false }")), "the diff prints the mutant: {:?}", m.diff);
    // the gate: error[spec-incomplete] with the diff, the input and both outputs
    assert!(r.gate_has(true, DiagKind::SpecIncomplete, "`crate::verify` is not determined by its specification"), "{}", r.explain());
    assert!(r.gate_has(true, DiagKind::SpecIncomplete, &format!("input: {}", w.input)), "{}", r.explain());
    assert!(r.gate_has(true, DiagKind::SpecIncomplete, "{ false }"), "{}", r.explain());
    // `λ_. true` breaks soundness: killed by the law
    let (_, t) = r.mutant("crate::verify", "returns `true`");
    assert_eq!(t.verdict, Verdict::KilledBySpec, "{}", r.explain());
}

/// With the completeness law as well the section is fully specified: no
/// mutant survives with a counterexample (a surviving mutant would satisfy
/// `H(R)`, so `complete_verify` makes it equal), and the gate is silent
/// about `spec-incomplete`.
#[test]
fn sound_and_complete_verify_has_no_counterexample() {
    let o = MutateOptions { only: vec!["crate::verify".into()], ..opts() };
    let r = with_laws(MINI_SPEC, "verify, verify_spec", &format!("{SOUND}{COMPLETE}"), &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    assert_eq!(r.rep.count(Verdict::Counterexample), 0, "{}", r.explain());
    let (_, f) = r.mutant("crate::verify", "returns `false`");
    assert_eq!(f.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(!r.gate.iter().any(|(_, k, _, _)| *k == DiagKind::SpecIncomplete), "{}", r.explain());
}

const CODEC: &str = r#"
/// Encodes a byte as the byte followed by a zero byte.
pub fn encode(x: u8) -> [u8; 2] { [x, 0u8] }

/// Decodes an encoding; only the canonical one (a zero second byte) is
/// accepted.
pub fn decode(b: [u8; 2]) -> Option<u8> {
    if b[1] != 0u8 {
        return None;
    }
    Some(b[0])
}
"#;

const ROUND_TRIP: &str = r#"
/// Decoding an encoding gives the value back.
#[law]
fn round_trip(x: u8) {
    ensures(decode(encode(x)) == Some(x));
}
"#;

const CANONICAL: &str = r#"
/// Only canonical encodings decode: a decoded input has a zero second byte.
#[law]
fn canonical(b: [u8; 2], x: u8) {
    requires(decode(b) == Some(x));
    ensures(b[1] == 0u8 && b[0] == x);
}
"#;

/// A codec specified only by its round trip: the decoder may accept
/// non-canonical encodings. The engine finds the non-canonical decode.
#[test]
fn codec_without_canonicity_has_a_non_canonical_decode() {
    let o = MutateOptions { only: vec!["crate::decode".into()], ..opts() };
    let r = with_laws(CODEC, "encode, decode", ROUND_TRIP, &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (_, g) = r.mutant("crate::decode", "never runs");
    assert_eq!(g.verdict, Verdict::Counterexample, "the deleted canonicity check survives the round trip:\n{}", r.explain());
    let w = g.witness.as_ref().unwrap();
    assert_eq!(w.function, "crate::decode");
    assert_eq!(w.original, "None", "{}", r.explain());
    assert!(w.mutant.starts_with("Some("), "the mutant accepts the non-canonical input {}: {}", w.input, r.explain());
    assert!(r.gate_has(true, DiagKind::SpecIncomplete, "`crate::decode` is not determined"), "{}", r.explain());
    // rejecting everything breaks the round trip
    let (_, n) = r.mutant("crate::decode", "returns `None`");
    assert_eq!(n.verdict, Verdict::KilledBySpec, "{}", r.explain());

    // with canonicity stated, the non-canonical decoder is killed by it
    let r = with_laws(CODEC, "encode, decode", &format!("{ROUND_TRIP}{CANONICAL}"), &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (_, g) = r.mutant("crate::decode", "never runs");
    assert_eq!(g.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(g.by.iter().any(|b| b.contains("canonical")), "{}", r.explain());
}

/// An equivalent mutant is never an error, and a mutant killed by its own
/// safety obligations (overflow) is never counted as a specification kill.
#[test]
fn equivalent_mutant_is_never_an_error_and_safety_kills_are_separate() {
    let r = run_with(&[("r/mod.rs", "/// Scales by one.\npub fn scale(x: u32) -> u32 { x * 1u32 }\n")], &opts());
    assert!(r.rep.baseline_verified, "{}", r.explain());
    // `x * 1` → `x / 1`: equivalent
    let (eq, e) = r.mutant("crate::scale", "`*` → `/`");
    assert_eq!(e.verdict, Verdict::PossiblyEquivalent, "{}", r.explain());
    assert!(e.witness.is_none());
    assert!(!r.gate.iter().any(|(err, _, m, n)| *err && (m.contains(&format!("#{} ", eq.id)) || n.iter().any(|x| x.contains(&format!("mutant #{} ", eq.id))))), "an equivalent mutant is never an error:\n{}", r.explain());
    // `x * 1` → `x + 1`: overflow — a safety kill, not a specification kill
    let (_, s) = r.mutant("crate::scale", "`*` → `+`");
    assert_eq!(s.verdict, Verdict::KilledBySafety, "{}", r.explain());
    assert!(s.by.iter().any(|b| b.contains("[overflow]")), "{}", r.explain());
    assert_eq!(r.rep.count(Verdict::KilledBySpec), 0, "no specification: nothing is a specification kill\n{}", r.explain());
    // `x * 0` differs: `scale` has no specification at all
    let (_, z) = r.mutant("crate::scale", "constant `1u32` → `0u32`");
    assert_eq!(z.verdict, Verdict::Counterexample, "{}", r.explain());
    // coverage: the kill rate against the specification excludes safety kills
    let cov = mutate::coverage::build(&r.krate, r.rep.clone(), None);
    let f = cov.functions.iter().find(|f| f.path == "crate::scale").unwrap();
    let (spec, decided) = f.kill_rate_spec.unwrap();
    let (proofs, _) = f.kill_rate_proofs.unwrap();
    assert_eq!(spec, 0, "{f:?}");
    assert!(proofs >= 1 && decided >= proofs, "{f:?}");
    assert!(f.status.starts_with("unspecified") || f.status.starts_with("partially constrained"), "{f:?}");
}

// ---------------------------------------------------------------------
// budgets: `incomplete`, never a pass
// ---------------------------------------------------------------------

/// A capped run is incomplete: the gate says so (an error), and the
/// verdicts it has are not a pass.
#[test]
fn a_capped_run_is_incomplete() {
    let o = MutateOptions { only: vec!["crate::verify".into()], max_mutants: 3, ..opts() };
    let r = with_laws(MINI_SPEC, "verify, verify_spec", &format!("{SOUND}{COMPLETE}"), &o);
    assert!(!r.rep.complete, "{}", r.explain());
    assert_eq!(r.rep.mutants.len(), 3, "{}", r.explain());
    assert!(r.rep.incomplete_reasons.iter().any(|x| x.contains("3 of 12")), "{}", r.explain());
    assert!(r.gate_has(true, DiagKind::MutationIncomplete, "incomplete"), "{}", r.explain());
    let j = mutate::report_json(&r.rep).render();
    assert!(j.contains("\"status\": \"incomplete\""), "{j}");
}

/// A run stopped by its deadline decides nothing: every mutant is not run,
/// none is counted as killed, and the run is incomplete.
#[test]
fn a_deadline_decides_nothing() {
    let o = MutateOptions { only: vec!["crate::verify".into()], deadline: Some(std::time::Duration::ZERO), ..opts() };
    let r = with_laws(MINI_SPEC, "verify, verify_spec", SOUND, &o);
    assert!(r.rep.mutants.iter().all(|(_, x)| x.verdict == Verdict::NotRun), "{}", r.explain());
    assert!(!r.rep.complete);
    assert!(r.gate_has(true, DiagKind::MutationIncomplete, "not run"), "{}", r.explain());
    assert!(!r.gate.iter().any(|(_, k, _, _)| *k == DiagKind::SpecIncomplete), "nothing is claimed about mutants that did not run");
}

/// A mutant whose re-verification only fails for budget (a law's search
/// ran out of steps) and has no definite counterexample (no inputs are
/// searched here) is killed by budget: reported separately, never a
/// specification kill, and the run is incomplete.
#[test]
fn budget_limited_failures_are_not_specification_kills() {
    let o = MutateOptions { only: vec!["crate::verify".into()], inputs: 0, ..opts() };
    let r = with_laws(MINI_SPEC, "verify, verify_spec", SOUND, &o);
    let budget: Vec<_> = r.rep.mutants.iter().filter(|(_, x)| x.verdict == Verdict::KilledByBudget).collect();
    assert!(!budget.is_empty(), "{}", r.explain());
    for (_, x) in &budget {
        assert!(x.by.iter().all(|b| !b.is_empty()), "{}", r.explain());
    }
    assert!(!r.rep.complete, "{}", r.explain());
    assert!(r.gate_has(true, DiagKind::MutationIncomplete, "killed only by budget"), "{}", r.explain());
    // without inputs no counterexample is claimed either
    assert_eq!(r.rep.count(Verdict::Counterexample), 0, "{}", r.explain());
}

/// A crate that does not verify gets no verdicts at all.
#[test]
fn an_unverified_baseline_is_not_run() {
    let r = run_with(&[("r/mod.rs", "pub fn f(x: u32) -> u32 { x + 1u32 }\n")], &opts());
    assert!(!r.rep.baseline_verified, "{}", r.explain());
    assert!(r.rep.mutants.is_empty());
    assert!(r.gate_has(true, DiagKind::MutationIncomplete, "does not verify"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// §15.7 spec mutation
// ---------------------------------------------------------------------

const CHECKSUM: &str = r#"
/// The checksum of two values.
#[cfg(sandblaster)]
#[spec]
#[example(checksum(1, 2) == 5)]
fn checksum(a: Nat, b: Nat) -> Nat { a + 2 * b }
"#;

/// A spec mutant must be killed by an example: `a + 2 * b` → `a + (2 + b)`
/// agrees with the only example, so it survives, and the gate names the
/// example that kills it. An ill-formed spec mutant (`Nat` underflow) is a
/// safety kill, not an example kill.
#[test]
fn spec_mutant_survives_one_example_and_is_killed_by_two() {
    let r = run_with(&[("r/mod.rs", CHECKSUM)], &opts());
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (m, s) = r.mutant("crate::checksum", "`*` → `+`");
    assert_eq!(m.target, Target::Spec);
    assert_eq!(s.verdict, Verdict::Counterexample, "{}", r.explain());
    let w = s.witness.as_ref().unwrap();
    assert!(w.evaluator.contains("eval_closed"), "{}", r.explain());
    assert!(r.gate_has(true, DiagKind::SpecMutantSurvived, "a mutant of `crate::checksum` survives every example and law"), "{}", r.explain());
    // the example to add: the bare name (examples resolve in the function's
    // module), the expected value left to an independent source
    assert!(r.gate_has(true, DiagKind::SpecMutantSurvived, &format!("#[example(checksum{} == <expected>)]", w.input)), "{}", r.explain());
    let (_, k) = r.mutant("crate::checksum", "constant `2` → `3`");
    assert_eq!(k.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(k.by.iter().any(|b| b.starts_with("example #0")), "{}", r.explain());
    let (_, u) = r.mutant("crate::checksum", "`+` → `-`");
    assert_eq!(u.verdict, Verdict::KilledBySafety, "a `Nat` underflow makes the mutated spec ill-formed: {}", r.explain());

    // a second, independent known answer kills it
    let r = run_with(&[("r/mod.rs", &CHECKSUM.replace("#[example(checksum(1, 2) == 5)]", "#[example(checksum(1, 2) == 5)]\n#[example(checksum(0, 0) == 0)]"))], &opts());
    let (_, s) = r.mutant("crate::checksum", "`*` → `+`");
    assert_eq!(s.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(!r.gate.iter().any(|(_, k, _, _)| *k == DiagKind::SpecMutantSurvived), "{}", r.explain());
}

const SIDES: &str = r#"
/// The position of leaf `i` in the tree.
#[cfg(sandblaster)]
#[spec]
fn pos(i: Nat) -> Nat { 2 * i }

/// The database side: where the database puts leaf `i`'s digest.
#[cfg(sandblaster)]
#[spec]
fn db_leaf(i: Nat) -> Nat { pos(i) + 1 }

/// The proof side: where a proof looks for leaf `i`'s digest.
#[cfg(sandblaster)]
#[spec]
fn proof_leaf(i: Nat) -> Nat { pos(i) + 1 }
"#;

const SIDES_LAWS: &str = r#"
/// A proof looks for a leaf where the database put it.
#[law]
fn sides_agree(i: Nat) {
    ensures(db_leaf(i) == proof_leaf(i));
}

/// Positions are natural numbers.
#[law]
fn positions_are_natural(i: Nat) {
    ensures(pos(i) >= 0);
}
"#;

/// docs/qmdb-spec-design.md §2.10(b) in the tool: the law catches a spec
/// mutant that breaks the construction (one side changed), but a spec
/// wrong the same way on both sides (the shared `pos`) passes every law and
/// is caught only by a known answer. LR8: `sides_agree` kills the one-sided
/// mutants; `positions_are_natural` kills none (`warning[law-insensitive]`).
#[test]
fn laws_catch_one_sided_spec_mutants_and_known_answers_the_rest() {
    let r = with_laws(SIDES, "pos, db_leaf, proof_leaf", SIDES_LAWS, &opts());
    assert!(r.rep.baseline_verified, "{}", r.explain());
    // one side wrong: a definite counterexample to the law
    let (db, k) = r.mutant("crate::db_leaf", "constant `1` → `2`");
    assert_eq!(k.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(k.by.iter().any(|b| b.contains("law `crate::laws::sides_agree` is false for the mutant at")), "{}", r.explain());
    // both sides wrong the same way: every law still holds
    let (_, p) = r.mutant("crate::pos", "constant `2` → `3`");
    assert_eq!(p.verdict, Verdict::Counterexample, "only a known answer can catch a spec wrong on both sides:\n{}", r.explain());
    assert!(r.gate_has(true, DiagKind::SpecMutantSurvived, "a mutant of `crate::pos`"), "{}", r.explain());
    // LR8
    let agree = r.rep.laws.iter().find(|l| l.path == "crate::laws::sides_agree").unwrap();
    assert!(agree.killed.contains(&db.id), "{}", r.explain());
    let nat = r.rep.laws.iter().find(|l| l.path == "crate::laws::positions_are_natural").unwrap();
    assert!(!nat.in_scope.is_empty() && nat.killed.is_empty(), "{}", r.explain());
    assert!(r.gate_has(false, DiagKind::LawInsensitive, "law `crate::laws::positions_are_natural` kills none"), "{}", r.explain());
    assert!(!r.gate_has(false, DiagKind::LawInsensitive, "crate::laws::sides_agree"), "{}", r.explain());

    // the known answer kills the two-sided mutant
    let r = with_laws(&SIDES.replace("fn pos(i: Nat)", "#[example(pos(3) == 6)]\nfn pos(i: Nat)"), "pos, db_leaf, proof_leaf", SIDES_LAWS, &opts());
    let (_, p) = r.mutant("crate::pos", "constant `2` → `3`");
    assert_eq!(p.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(p.by.iter().any(|b| b.starts_with("example #0 of `crate::pos`")), "{}", r.explain());
}

const TABLE: &str = r#"
/// The round constants.
const K: [u32; 2] = [0x428a_2f98, 0x7137_4491];

/// The reference mixing step.
#[cfg(sandblaster)]
#[spec]
#[example(mix_spec(0) == 0x428a_2f98 ^ 0x7137_4491)]
fn mix_spec(x: u32) -> u32 { x ^ 0x428a_2f98 ^ 0x7137_4491 }
"#;

/// A wrong round constant (the motivating example of DESIGN.md §15):
/// killed by the refinement when the function refines its reference; a
/// definite counterexample when nothing pins the function down.
#[test]
fn a_wrong_constant_is_killed_by_the_refinement_and_found_without_it() {
    let o = MutateOptions { only: vec!["crate::K".into()], ..opts() };
    let r = run_with(&[("r/mod.rs", &format!("{TABLE}\n#[refines(mix_spec)]\npub fn mix(x: u32) -> u32 {{ x ^ K[0] ^ K[1] }}\n"))], &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    assert!(!r.rep.mutants.is_empty());
    for (m, x) in &r.rep.mutants {
        assert_eq!(m.target, Target::Impl);
        assert!(matches!(x.verdict, Verdict::KilledBySpec | Verdict::KilledBySafety), "{}", r.explain());
    }
    assert!(r.rep.mutants.iter().any(|(_, x)| x.by.iter().any(|b| b.contains("refines"))), "{}", r.explain());
    // without the refinement: `mix` is unspecified, a wrong constant shows
    let r = run_with(&[("r/mod.rs", &format!("{TABLE}\npub fn mix(x: u32) -> u32 {{ x ^ K[0] ^ K[1] }}\n"))], &o);
    let (m, x) = r.mutant("crate::K", "0x428a_2f98");
    assert_eq!(x.verdict, Verdict::Counterexample, "{}", r.explain());
    assert_eq!(x.witness.as_ref().unwrap().function, "crate::mix");
    assert!(m.diff.iter().any(|l| l.starts_with("- ") && l.contains("0x428a_2f98")), "{:?}", m.diff);
}

// ---------------------------------------------------------------------
// review regressions (S4 fixes)
// ---------------------------------------------------------------------

impl Run {
    /// The mutant of `item` whose description is exactly `desc`.
    #[track_caller]
    fn mutant_exact(&self, item: &str, desc: &str) -> &(mutate::Mutant, mutate::Outcome) {
        self.rep.mutants.iter().find(|(m, _)| m.path == item && m.desc == desc).unwrap_or_else(|| panic!("no mutant of `{item}` described `{desc}`:\n{}", self.explain()))
    }
}

const P2_SPEC: &str = r#"
/// The successor.
#[cfg(sandblaster)]
#[spec]
fn g(x: Nat) -> Nat { x + 1 }

/// The predecessor of the successor.
#[cfg(sandblaster)]
#[spec]
fn h(x: Nat) -> Nat { g(x) - 1 }
"#;

const P2_LAWS: &str = r#"
/// `h` is one below `g` on positive inputs.
#[law]
fn h_below_g(x: Nat) {
    requires(x > 0);
    ensures(h(x) + 1 == g(x));
}
"#;

/// A clone that did not verify is a placeholder with a default body: a law
/// checker that reaches it evaluates the default, not the mutant. A spec
/// mutant that makes a spec function using it ill-formed (`g(x) - 1`
/// underflows) is killed by well-formedness, and the law gets no LR8
/// credit for it.
#[test]
fn law_counterexamples_never_evaluate_a_placeholder() {
    let o = MutateOptions { only: vec!["crate::g".into()], ..opts() };
    let r = with_laws(P2_SPEC, "g, h", P2_LAWS, &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (m, k) = r.mutant_exact("crate::g", "constant `1` → `0`");
    assert_eq!(k.verdict, Verdict::KilledBySafety, "{}", r.explain());
    assert!(k.by.iter().any(|b| b.contains("ill-formed") && b.contains("crate::h")), "{}", r.explain());
    assert!(k.law_counterexamples.is_empty(), "{}", r.explain());
    let law = r.rep.laws.iter().find(|l| l.path == "crate::laws::h_below_g").unwrap();
    assert!(!law.killed.contains(&m.id) && !law.in_scope.contains(&m.id), "an ill-formed mutant is out of LR8's scope:\n{}", r.explain());
    // `x + 1` → `x + 2`: the law holds (`h' = x + 1`), so nothing refutes it
    let (_, s) = r.mutant_exact("crate::g", "constant `1` → `2`");
    assert!(s.law_counterexamples.is_empty(), "{}", r.explain());
}

/// A mutant whose own proof runs out of budget is a placeholder: the laws
/// over it are never "false" for it (`x * 2 + 1` and `x / 1 + 1` satisfy
/// `half(x) >= 1`).
#[test]
fn a_budget_failure_is_never_upgraded_through_a_placeholder() {
    let mut o = MutateOptions { only: vec!["crate::half".into()], ..opts() };
    o.elab.goal_budget = 10_000;
    let r = with_laws("/// Halves and bumps.\npub fn half(x: u8) -> u8 { x / 2u8 + 1u8 }\n", "half", "\n/// Never zero.\n#[law]\nfn half_positive(x: u8) {\n    ensures(half(x) >= 1u8);\n}\n", &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    for d in ["`/` → `*` in `x / 2u8`", "constant `2u8` → `1u8`"] {
        let (_, k) = r.mutant_exact("crate::half", d);
        assert!(k.law_counterexamples.is_empty() && !k.by.iter().any(|b| b.contains("is false for the mutant")), "{}", r.explain());
        assert_ne!(k.verdict, Verdict::KilledBySpec, "{}", r.explain());
    }
    if r.rep.count(Verdict::KilledByBudget) > 0 {
        assert!(!r.rep.complete, "{}", r.explain());
    }
}

/// A blocked example (it reaches a clone that did not verify) is a
/// consequence of that failure, never a specification kill: the caller's
/// overflow decides; a budget-limited own failure stays killed by budget.
#[test]
fn blocked_examples_are_consequences_never_kills() {
    let src = "/// Halves.\nfn half(x: u8) -> u8 { x / 2u8 }\n\n/// Lifts into the upper half.\n#[example(lift(0) == 128)]\npub fn lift(x: u8) -> u8 { half(x) + 128u8 }\n";
    let r = run_with(&[("r/mod.rs", src)], &MutateOptions { only: vec!["crate::half".into()], ..opts() });
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (_, k) = r.mutant_exact("crate::half", "constant `2u8` → `1u8`");
    assert_eq!(k.verdict, Verdict::KilledBySafety, "{}", r.explain());
    assert!(k.by.iter().any(|b| b.contains("[overflow]") && b.contains("crate::lift")), "{}", r.explain());

    let mut o = MutateOptions { only: vec!["crate::half".into()], ..opts() };
    o.elab.goal_budget = 10_000;
    let r = run_with(&[("r/mod.rs", "/// Halves and bumps.\n#[example(half(0) == 1)]\npub fn half(x: u8) -> u8 { x / 2u8 + 1u8 }\n")], &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    for (_, x) in &r.rep.mutants {
        assert!(!x.by.iter().any(|b| b.contains("did not verify")), "a blocked example is never a reason:\n{}", r.explain());
        if x.verdict == Verdict::KilledBySpec {
            // an evaluated example (`left: …; right: …`), never a blocked one
            assert!(x.by.iter().any(|b| b.contains("left: ") || b.contains("evaluates to") || b.contains("is false for the mutant")), "{}", r.explain());
        }
    }
    // `x * 2 + 1` satisfies the example
    let (_, k) = r.mutant_exact("crate::half", "`/` → `*` in `x / 2u8`");
    assert_ne!(k.verdict, Verdict::KilledBySpec, "{}", r.explain());
    if r.rep.count(Verdict::KilledByBudget) > 0 {
        assert!(!r.rep.complete && r.gate_has(true, DiagKind::MutationIncomplete, "killed only by budget"), "{}", r.explain());
    }
}

/// A constant whose value the typechecker put into a type (an array
/// length) is not mutated: its mutant could not follow it into the types.
/// Neither is one a type-level constant is computed from.
#[test]
fn constants_used_in_types_are_not_mutated() {
    let src = "const N: usize = 2;\nconst K: u8 = 7u8;\nconst BASE: usize = 3;\nconst LEN: usize = BASE * 2;\n/// The last byte, masked.\npub fn last(b: [u8; N]) -> u8 { b[N - 1] ^ K }\n/// The block width.\npub fn width(b: [u8; LEN]) -> usize { b.len() }\n";
    let o = MutateOptions { only: vec!["crate::N".into(), "crate::K".into(), "crate::BASE".into()], ..opts() };
    let r = run_with(&[("r/mod.rs", src)], &o);
    assert!(r.rep.baseline_verified, "{}", r.explain());
    for c in ["crate::N", "crate::BASE"] {
        assert!(r.rep.mutants.iter().all(|(m, _)| m.path != c), "{}", r.explain());
        assert!(r.rep.excluded.iter().any(|(p, why)| p == c && why.contains("array length")), "{:?}", r.rep.excluded);
    }
    assert!(r.rep.excluded.iter().any(|(p, why)| p == "crate::BASE" && why.contains("crate::LEN")), "{:?}", r.rep.excluded);
    assert!(r.rep.mutants.iter().any(|(m, _)| m.path == "crate::K"), "a constant used as a value is mutated:\n{}", r.explain());
    let j = mutate::report_json(&r.rep).render();
    assert!(j.contains("\"excluded\"") && j.contains("crate::N"), "{j}");
}

/// Every cap that leaves a mutant out makes the run incomplete: the
/// per-item cap (counted in `enumerated`, named in the reasons) as well as
/// the global one; the global sample is round-robin over the items.
#[test]
fn every_cap_that_drops_mutants_makes_the_run_incomplete() {
    let base = with_laws(CODEC, "encode, decode", ROUND_TRIP, &MutateOptions { only: vec!["crate::decode".into()], ..opts() });
    let all = base.rep.enumerated;
    assert_eq!(base.rep.mutants.len(), all, "no per-item cap by default:\n{}", base.explain());
    let o = MutateOptions { only: vec!["crate::decode".into()], max_per_item: 2, ..opts() };
    let r = with_laws(CODEC, "encode, decode", ROUND_TRIP, &o);
    assert_eq!(r.rep.enumerated, all, "{}", r.explain());
    assert!(r.rep.mutants.len() < all && !r.rep.complete, "{}", r.explain());
    assert!(r.rep.incomplete_reasons.iter().any(|x| x.contains(&format!("of {all} mutants of `crate::decode`")) && x.contains("SANDBLASTER_MUTANTS_PER_ITEM")), "{}", r.explain());
    assert!(r.gate_has(true, DiagKind::MutationIncomplete, "SANDBLASTER_MUTANTS_PER_ITEM"), "{}", r.explain());
    // the global cap: both items get mutants, nothing is left unsampled
    let r = with_laws(CODEC, "encode, decode", ROUND_TRIP, &MutateOptions { max_mutants: 4, ..opts() });
    assert!(r.rep.mutants.iter().any(|(m, _)| m.path == "crate::encode") && r.rep.mutants.iter().any(|(m, _)| m.path == "crate::decode"), "{}", r.explain());
    assert!(r.rep.not_sampled.is_empty() && !r.rep.complete, "{}", r.explain());
}

const P3: &str = r#"
/// A helper with a proof-only parameter.
#[ensures(|r: bool| true)]
fn h(x: u32, #[ghost] k: Int) -> bool { x < 10u32 }

/// Small.
#[ensures(|r: bool| r == h(x, 0))]
pub fn f(x: u32) -> bool { h(x, ghost!(0)) }
"#;

/// `complete_f` is proven relative to the unspecified `h` (a section that
/// is not well founded): a surviving mutant of `h` that changes `f` shows
/// that `h` is not determined — never a counterexample to the proven
/// `complete_f`.
#[test]
fn a_proven_completeness_statement_is_never_refuted() {
    let r = run_with(&[("r/mod.rs", P3)], &MutateOptions { only: vec!["crate::h".into()], ..opts() });
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let cex: Vec<_> = r.rep.mutants.iter().filter(|(_, o)| o.verdict == Verdict::Counterexample).collect();
    assert!(!cex.is_empty(), "{}", r.explain());
    for (_, o) in &cex {
        let w = o.witness.as_ref().unwrap();
        assert_eq!(w.section, None, "{}", r.explain());
        assert!(matches!(&w.dependency, Some((_, d)) if d == "crate::h"), "{}", r.explain());
        assert!(w.refutation.is_none(), "{}", r.explain());
    }
    assert!(r.gate_has(true, DiagKind::SpecIncomplete, "`crate::h` is not determined by its specification"), "{}", r.explain());
    assert!(!r.gate_has(true, DiagKind::SpecIncomplete, "which is not proven"), "{}", r.explain());
}

const READER_ROOT: &str = "mod codec;\n\n#[cfg(sandblaster)]\n#[spec]\n#[path = \"spec/mod.rs\"]\nmod spec;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use codec::read_u32_be;\n";

const READER_SPEC: &str = r#"
/// The value of the first four bytes, big-endian, and the rest.
#[example(read_u32_be(seq![1u8, 2u8, 3u8, 4u8, 5u8]) == Some((16909060, seq![5u8])))]
#[example(read_u32_be(seq![1u8, 2u8, 3u8]) == None)]
pub fn read_u32_be(xs: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    if xs.len() < 4 {
        None
    } else {
        Some(((xs[0] as Nat) * 16777216 + (xs[1] as Nat) * 65536 + (xs[2] as Nat) * 256 + (xs[3] as Nat), xs.skip(4)))
    }
}
"#;

const READER: &str = r#"use sandblaster::prelude::*;

/// A big-endian `u32` reader: the value and the rest, `None` when short.
#[refines(crate::spec::codec::read_u32_be)]
pub fn read_u32_be(xs: &[u8]) -> Option<(u32, &[u8])> {
    if xs.len() < 4 {
        None
    } else {
        Some((u32::from_be_bytes([xs[0], xs[1], xs[2], xs[3]]), &xs[4..]))
    }
}
"#;

const READER_PROOF: &str = r#"
/// `u32::from_be_bytes` is the positional value of its bytes.
#[lemma]
fn be_word(a: u8, b: u8, c: u8, d: u8) {
    ensures(u32::from_be_bytes([a, b, c, d]) == (a as u32) * 16777216u32 + (b as u32) * 65536u32 + (c as u32) * 256u32 + (d as u32));
    bv();
}

/// The reader refines the positional reference.
#[proof(refines = crate::codec::read_u32_be)]
fn read_u32_be(xs: &[u8]) {
    unfold(crate::codec::read_u32_be);
    if xs.len() < 4 {
        follows();
    } else {
        be_word(xs[0], xs[1], xs[2], xs[3]);
        follows();
    }
}
"#;

/// A function established by its refinement (an injective view): a mutant
/// whose refinement proof fails — by budget or not — is decided by
/// comparing it with the function the refinement determines. A difference
/// is a definite counterexample to the refinement (a specification kill);
/// killed-by-budget mutants are not counted in the kill rates.
#[test]
fn refinement_failures_are_decided_by_evaluation() {
    let files = [("r/mod.rs", READER_ROOT), ("r/codec.rs", READER), ("r/spec/mod.rs", "pub mod codec;\n"), ("r/spec/codec.rs", READER_SPEC), ("r/PROOF.rs", READER_PROOF)];
    let r = run_with(&files, &MutateOptions { only: vec!["crate::codec::read_u32_be".into()], ..opts() });
    assert!(r.rep.baseline_verified, "{}", r.explain());
    for d in ["returns `None`", "`from_be_bytes` → `from_le_bytes`"] {
        let (_, k) = r.mutant("crate::codec::read_u32_be", d);
        assert_eq!(k.verdict, Verdict::KilledBySpec, "{d}:\n{}", r.explain());
        assert!(k.by.iter().any(|b| b.contains("the refinement `crate::codec::read_u32_be` refines `crate::spec::codec::read_u32_be` is false for the mutant at")), "{}", r.explain());
    }
    let cov = mutate::coverage::build(&r.krate, r.rep.clone(), None);
    let f = cov.functions.iter().find(|f| f.path == "crate::codec::read_u32_be").unwrap();
    let (spec, decided) = f.kill_rate_spec.unwrap();
    assert!(spec > 0, "{f:?}");
    let budget = r.rep.count(Verdict::KilledByBudget);
    assert_eq!(f.budget, budget);
    assert_eq!(decided, r.rep.mutants.iter().filter(|(_, o)| o.verdict.decided()).count(), "{f:?}");
}

const HELPER: &str = r#"
/// The low byte of a word.
fn low(x: u32) -> u32 { x & 255u32 }

/// Whether two words agree on their low byte (only soundness is stated).
pub fn same_low(x: u32, y: u32) -> bool { low(x) == low(y) }
"#;

const HELPER_LAW: &str = r#"
/// Accepted pairs agree on their low byte.
#[law]
fn same_low_sound(x: u32, y: u32) {
    requires(same_low(x, y));
    ensures(x % 256u32 == y % 256u32);
}
"#;

/// An implementation mutant whose law proof fails without a counterexample
/// (`x ^ 255`: the law still holds, `auto` cannot re-prove it) is killed
/// by the proofs, not by the specification; one with a counterexample
/// (`x | 255`) is a specification kill.
#[test]
fn a_law_proof_failing_without_a_counterexample_is_not_a_spec_kill() {
    let r = with_laws(HELPER, "same_low", HELPER_LAW, &MutateOptions { only: vec!["crate::low".into()], ..opts() });
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (_, x) = r.mutant_exact("crate::low", "`&` → `^` in `x & 255u32`");
    assert!(matches!(x.verdict, Verdict::KilledByProofs | Verdict::Counterexample), "{}", r.explain());
    if x.verdict == Verdict::KilledByProofs {
        assert!(x.by.iter().any(|b| b.contains("no counterexample to the law was found")), "{}", r.explain());
        assert!(x.notes.iter().any(|n| n.contains("it differs from `crate::same_low`")), "{}", r.explain());
    }
    let (_, o) = r.mutant_exact("crate::low", "`&` → `|` in `x & 255u32`");
    assert_eq!(o.verdict, Verdict::KilledBySpec, "{}", r.explain());
    assert!(o.by.iter().any(|b| b.contains("law `crate::laws::same_low_sound` is false for the mutant at")), "{}", r.explain());
    // every specification kill through a law has its counterexample
    for (_, o) in &r.rep.mutants {
        if o.verdict == Verdict::KilledBySpec {
            assert!(!o.law_counterexamples.is_empty(), "{}", r.explain());
        }
    }
    let cov = mutate::coverage::build(&r.krate, r.rep.clone(), None);
    let f = cov.functions.iter().find(|f| f.path == "crate::low").unwrap();
    assert_eq!(f.kill_rate_spec.unwrap().0, r.rep.count(Verdict::KilledBySpec), "{f:?}");
}

const PRECEDENCE: &str = r#"
const C: u32 = 7u32 * 3u32 + 2u32;
/// Precedence-sensitive expressions.
pub fn p1(a: u8, b: u8, c: u8, d: u8) -> u8 { a ^ b ^ c ^ d }
pub fn p2(a: u32, b: u32, c: u32) -> u32 { c - a * b }
pub fn p3(a: u32, b: u32, c: u32) -> u32 { (a ^ b) | c }
pub fn p4(x: u32, y: u32, z: u32) -> u32 { x - y - z }
pub fn p5(a: bool, b: bool, c: bool) -> bool { !(a || b) && c }
pub fn p6(a: u32, b: u32) -> u32 { a | b & 7u32 }
pub fn p7(a: u32, b: u32, c: u32) -> bool { a + b < c && a > 3u32 || b == c }
pub fn p8(xs: [u32; 8], j: usize) -> u32 { xs[j >> 1usize] }
pub fn p9(a: u32, b: u32) -> u32 { (a | b).rotate_left(3u32) }
pub fn p10(a: u64, b: u32) -> u64 { a * (b as u64) + 1u64 }
pub fn p11(a: u32, b: u32, c: u32) -> u32 { a / (b % c) }
pub fn p12(a: bool, b: bool) -> bool { !a || b }

/// A spec function.
#[cfg(sandblaster)]
#[spec]
fn s1(a: Nat, b: Nat) -> bool { a + 1 == b && b > 2 || a == 0 }
"#;

/// Every printed diff, applied to the source and checked again, gives the
/// mutant the engine evaluates (compared as fully parenthesized
/// de-elaborated text): an operator whose binding power changes is
/// parenthesized (`a ^ b ^ c ^ d` → `(a ^ b | c) ^ d`).
#[test]
fn printed_diffs_parse_as_the_mutant() {
    let src = format!("{HEADER}{PRECEDENCE}");
    let check = |text: &str| {
        let fs = MemFs::from_files([("r/mod.rs", text)]);
        driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin())
    };
    let c = check(&src);
    assert!(c.ok(), "{}", c.render());
    let krate = c.krate.clone().unwrap();
    let ms = mutate::enumerate_mutants(&krate, &c.sm, &MutateOptions::default());
    assert!(ms.len() > 60, "{}", ms.len());
    let show = |k: &Crate, it: &sandblaster_front::hir::Item| -> String {
        match &it.kind {
            sandblaster_front::hir::ItemKind::Fn(f) => match &f.body {
                sandblaster_front::hir::FnBody::Exec(e) | sandblaster_front::hir::FnBody::Spec(e) => sandblaster_front::deelab::DeElab::new(k, &f.locals).expr(e),
                _ => String::new(),
            },
            sandblaster_front::hir::ItemKind::Const(cd) => sandblaster_front::deelab::DeElab::new(k, &cd.locals).expr(&cd.init),
            _ => String::new(),
        }
    };
    let mut bad = Vec::new();
    for m in &ms {
        let e = m.edit.as_ref().unwrap_or_else(|| panic!("no edit for {}", m.desc));
        let mut lines: Vec<String> = src.lines().map(str::to_string).collect();
        let i0 = (e.first_line - 1) as usize;
        assert_eq!(&lines[i0..i0 + e.old.len()], &e.old[..], "{}", m.desc);
        lines.splice(i0..i0 + e.old.len(), e.new.iter().cloned());
        let text = lines.join("\n") + "\n";
        let c2 = check(&text);
        if !c2.ok() {
            bad.push(format!("{} ({}): the printed mutant does not check:\n{}\n{}", m.path, m.desc, m.diff.join("\n"), c2.render()));
            continue;
        }
        let k2 = c2.krate.clone().unwrap();
        let id2 = k2.find(&m.path).expect("item");
        let want = show(&krate, &mutate::mutated_item(&krate, m));
        let got = show(&k2, k2.item(id2));
        if want != got {
            bad.push(format!("{} ({}):\n{}\n  evaluated: {want}\n  printed:   {got}", m.path, m.desc, m.diff.join("\n")));
        }
    }
    assert!(bad.is_empty(), "{} of {} diffs do not parse as their mutant:\n{}", bad.len(), ms.len(), bad.join("\n\n"));
    // the reviewer's case, printed with the parentheses the parse needs
    let m = ms.iter().find(|m| m.path == "crate::p1" && m.desc == "`^` → `|` in `a ^ b ^ c`").unwrap();
    assert!(m.diff.iter().any(|l| l.contains("(a ^ b | c) ^ d")), "{:?}", m.diff);
}

const RANGE: &str = r#"
/// A half-open range.
#[derive(Clone, Copy)]
pub struct Range { pub lo: u32, pub hi: u32 }

/// The width of a range (zero when empty).
#[cfg(sandblaster)]
#[spec]
#[example(width(Range { lo: 2, hi: 5 }) == 3)]
fn width(r: Range) -> Nat { if r.hi > r.lo { (r.hi - r.lo) as Nat } else { 0 } }

/// A helper without known answers.
#[cfg(sandblaster)]
#[spec]
fn inner(x: u32) -> u32 { x ^ 0x55u32 }

/// Known answers are published for this one.
#[cfg(sandblaster)]
#[spec]
#[example(outer(0) == 0x54)]
fn outer(x: u32) -> u32 { inner(x) ^ 1u32 }
"#;

/// The suggested example compiles as printed (the bare name, named-field
/// structs in their own syntax), and pasted with a known answer it kills
/// the mutant; a helper's survivor also points at the nearest spec
/// function with known answers.
#[test]
fn suggested_examples_compile_and_kill_the_mutant() {
    let r = run_with(&[("r/mod.rs", RANGE)], &opts());
    assert!(r.rep.baseline_verified, "{}", r.explain());
    // `else { 0 }` → `else { 1 }`: survives the one example
    let (_, s) = r.mutant_exact("crate::width", "constant `0` → `1`");
    assert_eq!(s.verdict, Verdict::Counterexample, "{}", r.explain());
    let w = s.witness.as_ref().unwrap();
    assert!(w.input.contains("Range { lo: ") && w.input.contains(", hi: "), "{}", w.input);
    let call = mutate::example_call(&r.krate, w);
    assert!(r.gate_has(true, DiagKind::SpecMutantSurvived, &format!("#[example({call} == <expected>)]")), "{}", r.explain());
    // pasted with the known answer (here the specification is right)
    let fixed = RANGE.replace("#[example(width(Range { lo: 2, hi: 5 }) == 3)]", &format!("#[example(width(Range {{ lo: 2, hi: 5 }}) == 3)]\n#[example({call} == {})]", w.original));
    let r2 = run_with(&[("r/mod.rs", &fixed)], &MutateOptions { only: vec!["crate::width".into()], ..opts() });
    let (_, s2) = r2.mutant_exact("crate::width", "constant `0` → `1`");
    assert_eq!(s2.verdict, Verdict::KilledBySpec, "{}", r2.explain());
    // a helper's survivor: the known answer site
    let (_, h) = r.mutant_exact("crate::inner", "`^` → `|` in `x ^ 0x55u32`");
    assert_eq!(h.verdict, Verdict::Counterexample, "{}", r.explain());
    let sug = h.suggestion.as_ref().unwrap_or_else(|| panic!("{}", r.explain()));
    assert_eq!(sug.function, "crate::outer");
    assert!(r.gate_has(true, DiagKind::SpecMutantSurvived, "`#[example(outer("), "{}", r.explain());
}

/// An `only` entry that names nothing is not a clean run: the report says
/// so, with the closest item.
#[test]
fn an_only_entry_naming_nothing_is_incomplete() {
    let r = with_laws(MINI_SPEC, "verify, verify_spec", SOUND, &MutateOptions { only: vec!["crate::verfy".into()], ..opts() });
    assert!(!r.rep.complete, "{}", r.explain());
    assert!(r.rep.unknown_only.iter().any(|(o, close)| o == "crate::verfy" && close.contains(&"crate::verify".to_string())), "{:?}", r.rep.unknown_only);
    assert!(r.gate_has(true, DiagKind::MutationIncomplete, "closest: `crate::verify`"), "{}", r.explain());
}

const XOR4: &str = r#"
/// The XOR of four bytes.
#[cfg(sandblaster)]
#[spec]
#[example(check_spec(1u8, 2u8, 4u8, 8u8) == 15u8)]
#[example(check_spec(255u8, 255u8, 0u8, 0u8) == 0u8)]
fn check_spec(a: u8, b: u8, c: u8, d: u8) -> u8 { a ^ b ^ c ^ d }

/// Eight words from one.
#[cfg(sandblaster)]
#[spec]
#[example(spread(0)[0] == 0)]
fn spread(x: u32) -> [u32; 8] { [x, x ^ 1u32, x ^ 2u32, x ^ 3u32, x ^ 4u32, x ^ 5u32, x ^ 6u32, x ^ 7u32] }
"#;

/// A distinguishing input is shrunk while the difference persists, and a
/// compound output says where it differs (word arrays in hex).
#[test]
fn counterexamples_are_shrunk_and_show_where_outputs_differ() {
    let r = run_with(&[("r/mod.rs", XOR4)], &opts());
    assert!(r.rep.baseline_verified, "{}", r.explain());
    let (m, x) = r.mutant_exact("crate::check_spec", "`^` → `|` in `a ^ b ^ c`");
    assert!(m.diff.iter().any(|l| l.contains("(a ^ b | c) ^ d")), "{:?}", m.diff);
    assert_eq!(x.verdict, Verdict::Counterexample, "{}", r.explain());
    let w = x.witness.as_ref().unwrap();
    let sum: u64 = w.input.replace("u8", "").split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap()).sum();
    assert!(sum <= 3, "the input is shrunk: {}", w.input);
    let (_, y) = r.mutant_exact("crate::spread", "constant `3u32` → `2u32`");
    assert_eq!(y.verdict, Verdict::Counterexample, "{}", r.explain());
    let w = y.witness.as_ref().unwrap();
    assert_eq!(w.input, "(0u32)", "{}", r.explain());
    assert_eq!(w.differs_at, vec!["[3]: 0x00000003 vs 0x00000002".to_string()], "{}", r.explain());
    assert!(w.original.starts_with("[0x00000000, 0x00000001"), "{}", w.original);
    // the gate's first survivor of `spread` (`λ_. [0u32; 8]`) lists where
    assert!(r.gate_has(true, DiagKind::SpecMutantSurvived, "they differ at [1]: 0x00000001 vs 0x00000000, [2]: 0x00000002 vs 0x00000000"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// gate mode (the crate gate's run, `mutate::run_gate`)
// ---------------------------------------------------------------------

/// The gate's run of the engine on `files`: the crate's own elaboration as
/// the baseline, fixed options (`MutateOptions::gate`).
fn gate_run(files: &[(&str, &str)]) -> (MutationReport, Crate) {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "front-end errors:\n{}", c.render());
    let krate = c.krate.clone().unwrap();
    let sm = &c.sm;
    let rep = sandblaster_front::elab::with_big_stack(|| {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(&krate, &mut chain, &Default::default());
        mutate::run_gate(&krate, sm, &out)
    });
    (rep, krate)
}

/// A verdict class: what the gate decides from it.
fn class(v: Verdict) -> &'static str {
    match v {
        Verdict::KilledBySpec | Verdict::KilledBySafety => "killed",
        Verdict::Counterexample => "survived with a counterexample",
        Verdict::PossiblyEquivalent => "possibly equivalent",
        other => other.word(),
    }
}

/// Gate mode re-checks only a spec mutant's spec closure, its examples and
/// the law checkers (no proofs, no implementation), one known answer at a
/// time, stopping at the first kill. It decides every spec mutant exactly
/// as the full engine does (the red-team question of PLAN §6: a survivor
/// hidden by what the gate skips), including LR8.
#[test]
fn gate_mode_decides_spec_mutants_as_the_full_engine() {
    let full_opts = MutateOptions { max_mutants: usize::MAX, impl_mutants: false, ..MutateOptions::default() };
    let sides_root = format!("{SIDES}\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    let sides_laws = format!("use sandblaster::prelude::*;\nuse super::{{pos, db_leaf, proof_leaf}};\n{SIDES_LAWS}");
    let sides_proof = "use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::{pos, db_leaf, proof_leaf};\n#[proof]\nfn sides_agree(i: Nat) {\n    follows();\n}\n#[proof]\nfn positions_are_natural(i: Nat) {\n    follows();\n}\n";
    let two_examples = CHECKSUM.replace("#[example(checksum(1, 2) == 5)]", "#[example(checksum(1, 2) == 5)]\n#[example(checksum(0, 0) == 0)]");
    let fixtures: Vec<Vec<(&str, &str)>> = vec![vec![("r/mod.rs", CHECKSUM)], vec![("r/mod.rs", &two_examples)], vec![("r/mod.rs", &sides_root), ("r/LAWS.rs", &sides_laws), ("r/PROOF.rs", sides_proof)]];
    for files in &fixtures {
        let full = run_with(files, &full_opts);
        let (gate, krate) = gate_run(files);
        assert!(gate.complete, "{:?}", gate.incomplete_reasons);
        let spec: Vec<&(mutate::Mutant, mutate::Outcome)> = full.rep.mutants.iter().filter(|(m, _)| m.target == Target::Spec).collect();
        assert_eq!(gate.mutants.len(), spec.len(), "the gate runs every spec mutant (and no implementation mutant: no section is unproven):\n{}", full.explain());
        for ((fm, fo), (gm, go)) in spec.iter().map(|x| (&x.0, &x.1)).zip(gate.mutants.iter().map(|x| (&x.0, &x.1))) {
            assert_eq!((fm.path.as_str(), fm.desc.as_str()), (gm.path.as_str(), gm.desc.as_str()));
            assert_eq!(class(fo.verdict), class(go.verdict), "{} {}: full {:?} ({:?}), gate {:?} ({:?})", fm.path, fm.desc, fo.verdict, fo.by, go.verdict, go.by);
        }
        // LR8 from the law checkers
        for l in &full.rep.laws {
            let g = gate.laws.iter().find(|x| x.path == l.path).unwrap_or_else(|| panic!("law {} not in the gate's LR8", l.path));
            assert_eq!(l.killed.is_empty(), g.killed.is_empty(), "LR8 of {}", l.path);
        }
        // the diagnostics agree
        let mut a = Diagnostics::new();
        mutate::spec15_gate_mutants(&gate, &krate, &mut a);
        let kinds = |d: &Diagnostics| d.list.iter().map(|x| format!("{:?} {}", x.kind, x.msg)).collect::<std::collections::BTreeSet<_>>();
        let full_kinds: std::collections::BTreeSet<String> = full.gate.iter().map(|(_, k, m, _)| format!("{k:?} {m}")).collect();
        assert_eq!(kinds(&a), full_kinds);
    }
}

/// The gate's options are fixed (`MutateOptions::gate` reads no
/// environment variable; `SANDBLASTER_MUTANTS_*` shape only `from_env`, the
/// exploration run of `sandblaster coverage`, which `coverage_cli` checks with
/// the variables set): every spec mutant, no deadline.
#[test]
fn gate_mode_ignores_the_mutation_environment() {
    let g = MutateOptions::gate();
    assert_eq!(g.max_mutants, usize::MAX);
    assert_eq!(g.max_per_item, usize::MAX);
    assert!(g.deadline.is_none() && g.gate && g.spec_mutants);
    let (rep, _) = gate_run(&[("r/mod.rs", CHECKSUM)]);
    assert!(rep.complete && rep.enumerated > 0);
    assert!(rep.incomplete_reasons.is_empty());
}
