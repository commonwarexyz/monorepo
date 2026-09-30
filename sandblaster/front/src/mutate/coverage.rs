//! `sandblaster coverage` (DESIGN.md §15.10): per function, what is proven
//! about it and how well its specification pins it down.
//!
//! For every exec function, exec constant, spec function and spec constant:
//! its safety obligations and how each was discharged (evaluation, the
//! development prover, `auto`, a script), the spec it refines and the laws
//! that mention it, its section and status (**determined by its
//! refinement**, **fully specified**, or — for a section whose completeness
//! is not proven — **partially constrained** when surviving mutants (of it,
//! or of code it uses) differ from it on some input, **unspecified** when
//! nothing constrains it; an internal helper or constant says which
//! functions its surviving mutants change), the mutation kill rates of the
//! counterexample engine ([`super::run`]) against the proofs and by the
//! specification alone (mutants killed only by budget are not counted, and
//! shown separately), every definite counterexample with the function it
//! was seen at, its example count and the outcome coverage of a
//! `bool`/`Option` spec function; then the law-sensitivity table (LR8) and
//! the spec sheet. Rendered as text or as JSON.

use std::collections::{BTreeMap, BTreeSet};

use super::{MutateOptions, MutationReport, Target, Verdict};
use crate::hir::*;
use crate::json::Json;
use crate::span::SourceMap;

/// A definite counterexample, as listed under a function.
#[derive(Clone, Debug)]
pub struct CexLine {
    pub mutant: usize,
    /// The mutated item.
    pub mutated: String,
    /// Where the difference was seen.
    pub at: String,
    pub input: String,
    pub original: String,
    pub mutant_output: String,
    pub differs_at: Vec<String>,
}

/// One function's coverage.
#[derive(Clone, Debug)]
pub struct FunctionCoverage {
    pub item: ItemId,
    pub path: String,
    /// `exec`, `spec`, `const`, `spec const`.
    pub kind: &'static str,
    /// Obligations by kind: `(kind, total, how discharged → count)`.
    pub obligations: Vec<(String, usize, BTreeMap<String, usize>)>,
    pub refines: Option<String>,
    pub laws: Vec<String>,
    pub section: Option<String>,
    pub status: String,
    /// Mutants of this item by verdict.
    pub mutants: BTreeMap<&'static str, usize>,
    /// `killed by proofs / decided`, `killed by the spec alone / decided`
    /// (decided: every verdict but not-run, invalid and killed-by-budget).
    pub kill_rate_proofs: Option<(usize, usize)>,
    pub kill_rate_spec: Option<(usize, usize)>,
    /// Mutants of this item killed only by budget (not in the rates).
    pub budget: usize,
    /// `(examples, failed)`.
    pub examples: (usize, usize),
    /// `(outcomes needed, seen)` of a `bool`/`Option` spec function.
    pub outcomes: Option<(Vec<String>, Vec<String>)>,
    /// Definite counterexamples of this item's mutants (wherever seen) and
    /// of other items' mutants seen at this function.
    pub counterexamples: Vec<CexLine>,
    /// Why the item was not mutated (see [`MutationReport::excluded`]).
    pub not_mutated: Option<String>,
}

/// The whole report.
#[derive(Clone, Debug)]
pub struct CoverageReport {
    pub functions: Vec<FunctionCoverage>,
    pub mutation: MutationReport,
    /// The spec sheet (`sandblaster spec`), when requested.
    pub sheet: Option<String>,
}

fn kind_of(krate: &Crate, id: ItemId) -> Option<&'static str> {
    let it = krate.item(id);
    match &it.kind {
        ItemKind::Fn(f) => match f.kind {
            FnKind::Exec if !it.ghost => Some("exec"),
            FnKind::Spec => Some("spec"),
            _ => None,
        },
        ItemKind::Const(_) if it.ghost || krate.in_spec_module(id) => Some("spec const"),
        ItemKind::Const(_) => Some("const"),
        _ => None,
    }
}

fn list(xs: &BTreeMap<String, usize>) -> String {
    xs.iter().map(|(p, n)| format!("`{p}` ({n})")).collect::<Vec<_>>().join(", ")
}

/// Builds the per-function coverage from a finished mutation report.
pub fn build(krate: &Crate, rep: MutationReport, sheet: Option<String>) -> CoverageReport {
    let mut functions = Vec::new();
    for (id, b) in &rep.base {
        let Some(kind) = kind_of(krate, *id) else { continue };
        let path = krate.item(*id).path.to_string();
        let mut obls: BTreeMap<String, (usize, BTreeMap<String, usize>)> = BTreeMap::new();
        for (k, how) in &b.obligations {
            let e = obls.entry(k.clone()).or_default();
            e.0 += 1;
            *e.1.entry(how.clone()).or_default() += 1;
        }
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (_, o) in rep.of_item(*id) {
            *counts.entry(o.verdict.word()).or_default() += 1;
        }
        // counterexamples: this item's mutants (wherever seen), and other
        // mutants seen at this function
        let mut cexs = Vec::new();
        let mut seen_ids = BTreeSet::new();
        // functions this item's surviving mutants change (not itself)
        let mut affects: BTreeMap<String, usize> = BTreeMap::new();
        // implementation mutants that differ from this function
        let mut observed_here = 0usize;
        // implementation mutants seen elsewhere, attributed to this item as
        // an unspecified dependency
        let mut as_dependency: BTreeMap<String, usize> = BTreeMap::new();
        for (m, o) in &rep.mutants {
            let (Verdict::Counterexample, Some(w)) = (o.verdict, &o.witness) else { continue };
            let mine = m.item == *id;
            let here = w.item == *id && w.dependency.is_none();
            let dep = w.dependency.as_ref().is_some_and(|d| d.0 == *id);
            if mine && w.item != *id {
                *affects.entry(w.function.clone()).or_default() += 1;
            }
            if here && m.target == Target::Impl {
                observed_here += 1;
            }
            if dep {
                *as_dependency.entry(w.function.clone()).or_default() += 1;
            }
            if (mine || here || dep) && seen_ids.insert(m.id) {
                cexs.push(CexLine { mutant: m.id, mutated: m.path.clone(), at: w.function.clone(), input: w.input.clone(), original: w.original.clone(), mutant_output: w.mutant.clone(), differs_at: w.differs_at.clone() });
            }
        }
        let decided = rep.of_item(*id).filter(|(_, o)| o.verdict.decided()).count();
        let proofs = rep.of_item(*id).filter(|(_, o)| o.verdict.killed_by_proofs()).count();
        let spec = rep.of_item(*id).filter(|(_, o)| o.verdict == Verdict::KilledBySpec).count();
        let budget = rep.of_item(*id).filter(|(_, o)| o.verdict == Verdict::KilledByBudget).count();
        let run = rep.of_item(*id).filter(|(_, o)| o.verdict != Verdict::NotRun).count();
        let not_mutated = rep.excluded.iter().find(|(p, _)| *p == path).map(|(_, why)| why.clone());
        let refines = b.refines.as_ref().map(|(s, checked, det, up_to)| {
            let mut t = format!("refines `{s}`");
            if !checked {
                t.push_str(" (NOT proven)");
            } else if *det {
                t.push_str(" (determines it)");
            } else if let Some(u) = up_to {
                t.push_str(&format!(" ({u})"));
            }
            t
        });
        let section = b.section.as_ref().map(|(i, w, _, published)| format!("section #{i}: {w}{}", if *published { "" } else { " (not published)" }));
        let no_mutants = || match &not_mutated {
            Some(_) => "not mutated (see below)".to_string(),
            None => "no mutants run (sampled out, filtered by `--only`, or no mutation site): nothing is claimed".to_string(),
        };
        let status = match kind {
            "exec" | "const" => {
                if b.refines.as_ref().is_some_and(|r| r.1 && r.2) {
                    "determined by its refinement".to_string()
                } else if let Some((i, w, fully, _)) = &b.section {
                    if *fully {
                        format!("fully specified (section #{i})")
                    } else if observed_here > 0 {
                        format!("partially constrained: {observed_here} surviving mutant(s) (of it or of the code it uses) differ from it on some input (section #{i}: {w})")
                    } else if !as_dependency.is_empty() {
                        format!("not determined: surviving mutants of it change {} (section #{i}: {w})", list(&as_dependency))
                    } else if b.laws.is_empty() && b.refines.is_none() && !krate.fn_def(*id).is_some_and(|f| f.ensures.is_some()) {
                        format!("unspecified: no law, contract or refinement constrains it (section #{i})")
                    } else {
                        format!("not determined (section #{i}: {w})")
                    }
                } else if !as_dependency.is_empty() {
                    format!("not determined: the completeness of {} is proven only relative to it, and surviving mutants of it change them", list(&as_dependency))
                } else if !affects.is_empty() {
                    format!("internal (not required itself); its surviving mutants change {}", list(&affects))
                } else if run == 0 && decided == 0 {
                    format!("not required (internal: not exported, and no law or exported contract mentions it); {}", no_mutants())
                } else {
                    "not required (internal: not exported, and no law or exported contract mentions it)".to_string()
                }
            }
            _ => {
                let surv = rep.of_item(*id).filter(|(_, o)| o.verdict == Verdict::Counterexample).count();
                if surv > 0 {
                    format!("{surv} spec mutant(s) survive every example and law")
                } else if decided == 0 {
                    no_mutants()
                } else {
                    format!("every decided spec mutant ({decided}) is killed by an example or a law, or is ill-formed")
                }
            }
        };
        functions.push(FunctionCoverage {
            item: *id,
            path,
            kind,
            obligations: obls.into_iter().map(|(k, (n, h))| (k, n, h)).collect(),
            refines,
            laws: b.laws.clone(),
            section,
            status,
            mutants: counts,
            kill_rate_proofs: (decided > 0).then_some((proofs, decided)),
            kill_rate_spec: (decided > 0).then_some((spec, decided)),
            budget,
            examples: b.examples,
            outcomes: b.coverage.as_ref().map(|(_, n, s)| (n.clone(), s.clone())),
            counterexamples: cexs,
            not_mutated,
        });
    }
    CoverageReport { functions, mutation: rep, sheet }
}

/// Runs the engine and builds the coverage report.
pub fn coverage(krate: &Crate, sm: &SourceMap, opts: &MutateOptions, sheet: Option<String>) -> CoverageReport {
    let rep = super::run(krate, sm, opts);
    build(krate, rep, sheet)
}

fn pct((a, b): (usize, usize)) -> String {
    if b == 0 { "n/a".into() } else { format!("{a}/{b} ({:.0}%)", 100.0 * a as f64 / b as f64) }
}

/// The report as text.
pub fn render_text(c: &CoverageReport) -> String {
    let r = &c.mutation;
    let mut s = String::new();
    s.push_str(&format!(
        "sandblaster coverage: {} function(s); counterexample engine {} ({} of {} mutant(s) run in {} batch(es), {:.1} s)\n",
        c.functions.len(),
        if !r.baseline_verified { "NOT RUN (the crate does not verify)" } else if r.complete { "complete" } else { "INCOMPLETE" },
        r.mutants.iter().filter(|(_, o)| o.verdict != Verdict::NotRun).count(),
        r.enumerated,
        r.batches.len(),
        r.elapsed.as_secs_f64()
    ));
    for why in &r.incomplete_reasons {
        s.push_str(&format!("  incomplete: {why}\n"));
    }
    if !r.not_sampled.is_empty() {
        s.push_str(&format!("  not sampled ({}): {}\n", r.not_sampled.len(), r.not_sampled.iter().map(|p| format!("`{p}`")).collect::<Vec<_>>().join(", ")));
    }
    for (p, why) in &r.excluded {
        s.push_str(&format!("  not mutated: `{p}`: {why}\n"));
    }
    for f in &c.functions {
        s.push_str(&format!("\n{} `{}`\n", f.kind, f.path));
        s.push_str(&format!("  status: {}\n", f.status));
        if let Some(x) = &f.refines {
            s.push_str(&format!("  spec: {x}\n"));
        }
        if !f.laws.is_empty() {
            s.push_str(&format!("  laws: {}\n", f.laws.join(", ")));
        }
        if let Some(x) = &f.section {
            s.push_str(&format!("  {x}\n"));
        }
        if !f.obligations.is_empty() {
            let parts: Vec<String> = f.obligations.iter().map(|(k, n, how)| format!("{k} {n} ({})", how.iter().map(|(h, c)| format!("{h} {c}")).collect::<Vec<_>>().join(", "))).collect();
            s.push_str(&format!("  obligations: {}\n", parts.join("; ")));
        }
        if f.examples.0 > 0 || f.outcomes.is_some() {
            let mut t = format!("  examples: {}", f.examples.0);
            if f.examples.1 > 0 {
                t.push_str(&format!(" ({} failing)", f.examples.1));
            }
            if let Some((need, seen)) = &f.outcomes
                && !need.is_empty()
            {
                t.push_str(&format!("; outcomes {} of {} ({})", seen.len(), need.len(), need.iter().map(|o| if seen.contains(o) { o.clone() } else { format!("{o}: MISSING") }).collect::<Vec<_>>().join(", ")));
            }
            s.push_str(&t);
            s.push('\n');
        }
        if let Some(why) = &f.not_mutated {
            s.push_str(&format!("  not mutated: {why}\n"));
        }
        if !f.mutants.is_empty() {
            let v: Vec<String> = f.mutants.iter().map(|(k, n)| format!("{k} {n}")).collect();
            s.push_str(&format!("  mutants of this item: {}\n", v.join(", ")));
            if let Some(k) = f.kill_rate_proofs {
                let mut t = format!("  kill rate: proofs {}, specification alone {}", pct(k), pct(f.kill_rate_spec.unwrap_or((0, 0))));
                if f.budget > 0 {
                    t.push_str(&format!("; {} killed only by budget (not counted)", f.budget));
                }
                s.push_str(&t);
                s.push('\n');
            } else if f.budget > 0 {
                s.push_str(&format!("  kill rate: n/a ({} killed only by budget, not counted)\n", f.budget));
            }
        }
        for x in &f.counterexamples {
            let whose = if x.mutated == f.path { "of this item".to_string() } else { format!("of `{}`", x.mutated) };
            let mut t = format!("  counterexample (mutant #{} {whose}) at `{}`: input {}: {} (original) vs {} (mutant)", x.mutant, x.at, x.input, x.original, x.mutant_output);
            if !x.differs_at.is_empty() {
                t.push_str(&format!("; differs at {}", x.differs_at.join(", ")));
            }
            s.push_str(&t);
            s.push('\n');
        }
    }
    if !r.laws.is_empty() {
        s.push_str("\nlaw sensitivity (§15.1 LR8): law | spec mutants in scope | killed\n");
        for l in &r.laws {
            s.push_str(&format!("  {} | {} | {}{}\n", l.path, l.in_scope.len(), l.killed.len(), if l.killed.is_empty() && !l.in_scope.is_empty() { "  (insensitive)" } else { "" }));
        }
    }
    s.push_str(&format!("\ntests against mutated emitted code: {}\n", r.tests_note));
    if let Some(sheet) = &c.sheet {
        s.push('\n');
        s.push_str(sheet);
    }
    s
}

/// The report as JSON.
pub fn to_json(c: &CoverageReport) -> Json {
    let strs = |v: &[String]| Json::Arr(v.iter().map(|x| Json::string(x)).collect());
    let rate = |r: Option<(usize, usize)>| match r {
        Some((a, b)) => {
            let mut j = Json::obj();
            j.num("killed", a as i64);
            j.num("decided", b as i64);
            j
        }
        None => Json::Null,
    };
    let mut o = Json::obj();
    o.put(
        "functions",
        Json::Arr(
            c.functions
                .iter()
                .map(|f| {
                    let mut j = Json::obj();
                    j.str("path", &f.path);
                    j.str("kind", f.kind);
                    j.str("status", &f.status);
                    match &f.refines {
                        Some(r) => j.str("refines", r),
                        None => j.put("refines", Json::Null),
                    }
                    j.put("laws", strs(&f.laws));
                    match &f.section {
                        Some(x) => j.str("section", x),
                        None => j.put("section", Json::Null),
                    }
                    j.put(
                        "obligations",
                        Json::Arr(
                            f.obligations
                                .iter()
                                .map(|(k, n, how)| {
                                    let mut x = Json::obj();
                                    x.str("kind", k);
                                    x.num("count", *n as i64);
                                    let mut h = Json::obj();
                                    for (p, c) in how {
                                        h.num(p, *c as i64);
                                    }
                                    x.put("discharged_by", h);
                                    x
                                })
                                .collect(),
                        ),
                    );
                    let mut m = Json::obj();
                    for (k, n) in &f.mutants {
                        m.num(k, *n as i64);
                    }
                    j.put("mutants", m);
                    j.put("kill_rate_proofs", rate(f.kill_rate_proofs));
                    j.put("kill_rate_spec", rate(f.kill_rate_spec));
                    j.num("killed_by_budget", f.budget as i64);
                    j.num("examples", f.examples.0 as i64);
                    j.num("examples_failing", f.examples.1 as i64);
                    match &f.outcomes {
                        Some((need, seen)) => {
                            let mut x = Json::obj();
                            x.put("needed", strs(need));
                            x.put("seen", strs(seen));
                            j.put("outcomes", x);
                        }
                        None => j.put("outcomes", Json::Null),
                    }
                    match &f.not_mutated {
                        Some(w) => j.str("not_mutated", w),
                        None => j.put("not_mutated", Json::Null),
                    }
                    j.put(
                        "counterexamples",
                        Json::Arr(
                            f.counterexamples
                                .iter()
                                .map(|x| {
                                    let mut y = Json::obj();
                                    y.num("mutant", x.mutant as i64);
                                    y.str("mutant_of", &x.mutated);
                                    y.str("at", &x.at);
                                    y.str("input", &x.input);
                                    y.str("original", &x.original);
                                    y.str("mutant_output", &x.mutant_output);
                                    y.put("differs_at", strs(&x.differs_at));
                                    y
                                })
                                .collect(),
                        ),
                    );
                    j
                })
                .collect(),
        ),
    );
    o.put("mutation", super::report_json(&c.mutation));
    match &c.sheet {
        Some(s) => o.str("spec_sheet", s),
        None => o.put("spec_sheet", Json::Null),
    }
    o
}
