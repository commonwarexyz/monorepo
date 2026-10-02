//! The crate gate (DESIGN.md §15.8): the only path to a crate verdict.
//!
//! [`build_crate`] runs, on one elaboration and in this order:
//!
//! 1. the proofs: every definition kernel-checked, every obligation and law
//!    proven, the law non-vacuity audit and the resource gate;
//! 2. the specification surface and its `SPEC.lock` status (with every
//!    difference classified in the kernel);
//! 3. **every §15 gate**: the boundary ([`crate::validate::spec15_gate`]),
//!    examples, coverage and spec closure
//!    ([`crate::elab::examples::spec15_gate_s1`]), sections
//!    ([`crate::elab::complete::spec15_gate_s3`]), the law rules
//!    ([`crate::elab::law_rules::spec15_gate_laws`]), the lock
//!    ([`crate::lock::enforce`]; not for [`LockUse::Accepting`], which is
//!    writing it) and spec mutation ([`crate::mutate::run_gate`],
//!    [`crate::mutate::spec15_gate_mutants`]). Spec mutation, by far the
//!    most expensive, runs when the other gates passed: when one of them
//!    failed the crate has already failed, and the report says the
//!    mutation gate did not run;
//! 4. with [`LockUse::Enforce`] and every gate passed: the optimizer, the
//!    printer with the verdict header, the round trip, the check of the
//!    printed `SANDBLASTER_SPEC_ROOT`, the emission-chain cross-check
//!    ([`emission_chain`]) and the resource gate again.
//!
//! Only when all of it succeeds does it make a [`CrateVerdict`] (a type
//! with private fields and no other constructor). With
//! [`LockUse::Accepting`] and every gate but the lock passed it makes an
//! [`AcceptPermit`], which [`crate::lock::accept`] requires. Nothing in
//! the signature selects gates: the lock use is the only input besides
//! the checked crate, and it only decides whether the lock is compared
//! (a build) or written (`sandblaster spec --accept`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::canon;
use crate::diag::{Diagnostics, Severity};
use crate::elab::{self, DefStatus};
use crate::json::Json;
use crate::lock::LockStatus;
use crate::surface::{hex, sha256, Hash, Surface};

use super::{apply_law_audit, def_status_str, optimize_emit_rooted, proof_summary, render_report, resource_gate, spec15_report, timing_json_with, Checked, LawAudit, OptimizedEmit, Spec15Report, Verification, VerifyOptions};

/// What the crate path does with `SPEC.lock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockUse {
    /// The lock must match the computed surface (every build and every
    /// CLI command that states a verdict).
    Enforce,
    /// `sandblaster spec --accept`: the lock is being written, so it is not
    /// compared; every other gate runs, and nothing is optimized, printed
    /// or verified — the result is an [`AcceptPermit`], never a verdict.
    Accepting,
}

/// Every §15 gate passed with [`LockUse::Enforce`]: what lets the printer
/// write the verdict header. Private fields: only this module makes one,
/// and it never leaves the crate path.
pub struct GatesPassed {
    _seal: (),
}

/// Every §15 gate but the lock passed with [`LockUse::Accepting`]:
/// required by [`crate::lock::accept`]. Private fields: only
/// [`build_crate`] makes one.
pub struct AcceptPermit {
    target: String,
    surface_root: Hash,
}

impl AcceptPermit {
    /// The target the gates ran for.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// The root of the lock that accepting the whole surface would write.
    pub fn surface_root(&self) -> Hash {
        self.surface_root
    }
}

/// A crate verdict: the proofs checked, every §15 gate passed, the code
/// was optimized, printed with the verdict header and round-tripped, and
/// the emission chain checked. Only [`build_crate`] makes one.
pub struct CrateVerdict {
    _gates: GatesPassed,
    code: String,
    code_sha256: Hash,
    summary: String,
    /// The file is a lifted module's source as-is ([`super::lifted`]),
    /// not the printed, optimized crate.
    lifted: bool,
}

impl CrateVerdict {
    /// The generated file (`OUT_DIR/sandblaster.rs`, header
    /// `STATUS: VERIFIED + OPTIMIZED`).
    pub fn code(&self) -> &str {
        &self.code
    }
    /// SHA-256 of [`CrateVerdict::code`] (also in the report).
    pub fn code_sha256(&self) -> String {
        hex(&self.code_sha256)
    }
    /// One line for the build's `cargo::warning`.
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

/// One gate's outcome in the report.
#[derive(Clone, Debug)]
pub struct GateResult {
    /// `boundary`, `examples`, `sections`, `law-rules`, `lock`, `mutation`.
    pub gate: &'static str,
    pub ran: bool,
    pub errors: usize,
    pub warnings: usize,
    /// Why it did not run, or a one-line summary.
    pub note: String,
}

/// The gates of one crate build.
#[derive(Clone, Debug, Default)]
pub struct GateReport {
    pub results: Vec<GateResult>,
    /// Every gate diagnostic, in gate order.
    pub diags: Diagnostics,
    /// The spec-mutation gate's engine run (when it ran).
    pub mutation: Option<crate::mutate::MutationReport>,
    /// Findings of the emission-chain cross-check ([`emission_chain`]);
    /// any is an error.
    pub chain: Vec<String>,
    /// SHA-256 of the emitted file (with a verdict).
    pub emitted_sha256: Option<String>,
    /// The emitted file's name in `OUT_DIR`; empty means `sandblaster.rs`
    /// (crate mode). Module mode (DESIGN.md §2.1) names `<module>.rs`.
    pub emitted_file: String,
    /// Wall-clock time of the gates (`sandblaster-timing.json` only).
    pub elapsed: Duration,
    /// The lift conformance check of a lifted module ([`crate::conform`]).
    pub conformance: Option<crate::conform::Report>,
    /// The theorems of the lifted functions read from rustc's MIR
    /// ([`theorem_gate`]), per lifted MIR module.
    pub theorems: Vec<crate::mir::checked::ModuleTheorems>,
}

impl GateReport {
    /// The emitted file's name in `OUT_DIR` ([`GateReport::emitted_file`]).
    pub fn file_name(&self) -> &str {
        if self.emitted_file.is_empty() { "sandblaster.rs" } else { &self.emitted_file }
    }

    /// Every gate ran and none reported an error.
    pub fn passed(&self) -> bool {
        !self.diags.has_errors() && self.chain.is_empty() && self.conformance.as_ref().is_none_or(|r| r.passed())
    }

    /// The report's `gates` section (deterministic: no times).
    pub fn json(&self) -> Json {
        let mut j = Json::obj();
        j.bool("passed", self.passed());
        j.put(
            "results",
            Json::Arr(
                self.results
                    .iter()
                    .map(|r| {
                        let mut o = Json::obj();
                        o.str("gate", r.gate);
                        o.bool("ran", r.ran);
                        o.num("errors", r.errors as i64);
                        o.num("warnings", r.warnings as i64);
                        o.str("note", &r.note);
                        o
                    })
                    .collect(),
            ),
        );
        if let Some(m) = &self.mutation {
            let mut o = Json::obj();
            o.str("mode", "gate: every spec mutant, no cap, no deadline; implementation mutants only when a section is not fully specified");
            o.num("enumerated", m.enumerated as i64);
            o.num("run", m.mutants.iter().filter(|(_, x)| x.verdict != crate::mutate::Verdict::NotRun).count() as i64);
            o.bool("complete", m.complete);
            let mut counts = Json::obj();
            for v in crate::mutate::Verdict::ALL {
                counts.num(v.word(), m.count(v) as i64);
            }
            o.put("counts", counts);
            o.put("incomplete_reasons", Json::Arr(m.incomplete_reasons.iter().map(|x| Json::string(x)).collect()));
            o.put(
                "law_sensitivity",
                Json::Arr(
                    m.laws
                        .iter()
                        .map(|l| {
                            let mut x = Json::obj();
                            x.str("law", &l.path);
                            x.num("spec_mutants_in_scope", l.in_scope.len() as i64);
                            x.num("kills", l.killed.len() as i64);
                            x
                        })
                        .collect(),
                ),
            );
            j.put("mutation", o);
        }
        if let Some(r) = &self.conformance {
            j.put("lift_conformance", r.json());
        }
        if !self.theorems.is_empty() {
            j.put("mir_theorems", theorems_json(&self.theorems));
        }
        j.put("emission_chain", Json::Arr(self.chain.iter().map(|x| Json::string(x)).collect()));
        let mut e = Json::obj();
        e.str("file", self.file_name());
        match &self.emitted_sha256 {
            Some(h) => e.str("sha256", h),
            None => e.put("sha256", Json::Null),
        }
        j.put("emitted", e);
        j
    }
}

/// Everything the crate path produced.
pub struct CrateBuild {
    /// The proofs.
    pub v: Verification,
    pub law_audit: Vec<LawAudit>,
    /// `SPEC.lock` against the computed surface.
    pub spec: LockStatus,
    pub spec15: Spec15Report,
    /// The specification surface (when the proofs checked).
    pub surface: Option<Surface>,
    /// The differences against the lock, classified in the kernel.
    pub changes: Vec<crate::specdiff::Change>,
    pub gates: GateReport,
    /// The optimizer's results (after every gate passed). Its `code` is
    /// always empty: the printed file exists only inside a verdict.
    pub emit: Option<OptimizedEmit>,
    /// Why the optimizer could not run (an internal error).
    pub emit_error: Option<String>,
    /// `sandblaster-report.json`.
    pub report: String,
    /// `sandblaster-timing.json`.
    pub timing: String,
    /// The verdict ([`LockUse::Enforce`], everything passed).
    pub verdict: Option<CrateVerdict>,
    /// The accept permit ([`LockUse::Accepting`], every gate but the lock
    /// passed).
    pub permit: Option<AcceptPermit>,
    /// A lifted module: what the optimizer's residuals became in the
    /// emitted source ([`super::lowered`]; after every gate passed).
    pub lowered: Option<super::lowered::LoweredModule>,
    /// A lifted module: the optimizer's warnings.
    pub lifted_opt_warnings: Vec<String>,
    /// The verdict is the record of in-place lifted modules
    /// (`Emission::InPlace`).
    pub in_place: bool,
    /// In-place lifted modules: every host file lowered by the optimizer
    /// ([`super::lowered::lower_in_place`]; run once every proof checked,
    /// after the §15 gates ran). The lowered copies are written beside the
    /// record, marked with the build's status; rustc compiles a copy where
    /// the host declares it (`driver::in_place`).
    pub lowered_in_place: Vec<super::lowered::LoweredModule>,
}

impl CrateBuild {
    /// The status line: `VERIFIED + OPTIMIZED (phase 3)` with a verdict.
    pub fn status(&self) -> String {
        if self.in_place && self.verdict.as_ref().is_some_and(|v| v.lifted) {
            super::lifted::LIFTED_IN_PLACE.to_string()
        } else if self.verdict.as_ref().is_some_and(|v| v.lifted) {
            if self.lowered.as_ref().is_some_and(|l| l.lowered() > 0) { super::lifted::LIFTED_OPTIMIZED.to_string() } else { super::lifted::LIFTED.to_string() }
        } else if self.verdict.is_some() {
            canon::OPTIMIZED.to_string()
        } else if self.permit.is_some() {
            "NOT VERIFIED (spec --accept: every gate but the lock passed; the lock may be written)".to_string()
        } else {
            "NOT VERIFIED".to_string()
        }
    }

    /// Every diagnostic: the proofs', then the gates'.
    pub fn diagnostics(&self) -> Diagnostics {
        let mut d = self.v.diags.clone();
        d.extend(self.gates.diags.clone());
        d
    }

    /// The optimizer's warnings.
    pub fn optimizer_warnings(&self) -> Vec<String> {
        let mut w = self.emit.as_ref().map(|e| e.opt.warnings.clone()).unwrap_or_default();
        w.extend(self.lifted_opt_warnings.iter().cloned());
        w
    }

    /// Public API differences found by the round trip.
    pub fn api_differences(&self) -> Vec<String> {
        self.emit.as_ref().map(|e| e.roundtrip_stats.api_differences.clone()).unwrap_or_default()
    }

    /// The human summary of `sandblaster check`: the proof counts, each
    /// gate's outcome and the status line.
    pub fn summary(&self, c: &Checked) -> String {
        let mut v = self.v.clone();
        v.diags.extend(self.gates.diags.clone());
        let mut s = proof_summary(c, &v, &self.status());
        let status_at = s.rfind("status: ").unwrap_or(s.len());
        let mut gates = String::new();
        for r in &self.gates.results {
            let what = if !r.ran {
                format!("not run ({})", r.note)
            } else if r.errors == 0 && r.warnings == 0 {
                if r.note.is_empty() { "passed".to_string() } else { format!("passed ({})", r.note) }
            } else {
                format!("{} error(s), {} warning(s){}", r.errors, r.warnings, if r.note.is_empty() { String::new() } else { format!(" ({})", r.note) })
            };
            gates.push_str(&format!("gate {}: {what}\n", r.gate));
        }
        if !self.gates.chain.is_empty() {
            gates.push_str(&format!("emission chain: {} finding(s)\n", self.gates.chain.len()));
        }
        if let Some(h) = &self.gates.emitted_sha256 {
            gates.push_str(&format!("emitted: {} sha256 {h}\n", self.gates.file_name()));
        }
        s.insert_str(status_at, &gates);
        s
    }

    /// What a failed crate build prints on stderr: the diagnostics and a
    /// closing line with the reason.
    pub fn render_failure(&self, c: &Checked, root: &str) -> String {
        let mut out = String::new();
        let d = self.diagnostics().render(&c.sm);
        out.push_str(&d);
        if !self.v.proofs_ok {
            let st = self.v.stats();
            let failed_defs = self.v.failed_defs();
            out.push_str(&format!(
                "\nerror: sandblaster: verification of `{root}` failed: {} of {} obligation(s) unproven, {} definition(s) not checked{}\n",
                st.failed + st.todo,
                st.total,
                failed_defs.len(),
                if self.v.laws.iter().any(|l| l.status != DefStatus::Checked) { ", some laws unproven" } else if self.law_audit.iter().any(|a| a.kind == "law" && a.vacuous.is_some()) { ", some laws vacuous" } else { "" }
            ));
            for d in failed_defs.iter().take(40) {
                out.push_str(&format!("  - {}: {}\n", d.name, def_status_str(&d.status)));
            }
            return out;
        }
        if let Some(r) = self.gates.conformance.as_ref().filter(|r| !r.passed()) {
            out.push_str(&format!("\nerror: sandblaster: the lift conformance check of `{root}` failed: the proofs and every §15 gate passed, but the lifted model and rustc's build of the source differ (a misreading by the lift, DESIGN.md §1.1 item 8) or the check could not run; no code was emitted\n"));
            for f in r.failures() {
                out.push_str(&format!("error[lift-conformance]: {f}\n"));
            }
            return out;
        }
        if !self.gates.passed() {
            let failed: Vec<&str> = self.gates.results.iter().filter(|r| r.errors > 0).map(|r| r.gate).collect();
            if failed.is_empty() && !self.gates.diags.has_errors() {
                out.push_str(&format!("\nerror: sandblaster: the emission chain of `{root}` failed ({} finding(s)): the proofs and every §15 gate passed, but the printed file was not emitted (a printer, optimizer or relocation bug)\n", self.gates.chain.len()));
            } else {
                out.push_str(&format!("\nerror: sandblaster: `{root}` failed the §15 gates ({}): the proofs checked, but the crate is not fully specified, locked and mutation-tested (DESIGN.md §15.8); no code was emitted\n", failed.join(", ")));
            }
            for f in &self.gates.chain {
                out.push_str(&format!("error[emission-chain]: {f}\n"));
            }
            return out;
        }
        if let Some(e) = &self.emit_error {
            out.push_str(&format!("error[build]: internal error: optimization failed: {e}\n"));
        }
        if let Some(em) = &self.emit {
            for e in &em.opt.errors {
                out.push_str(&format!("error[optimizer]: {e}\n"));
            }
            for e in &em.roundtrip {
                out.push_str(&format!("error[round-trip]: {e}\n"));
            }
        }
        out.push_str(&format!("\nerror: sandblaster: the optimized code of `{root}` was not emitted (optimizer errors in strict mode, a round-trip mismatch or an emission-chain finding: a printer, optimizer or elaborator bug)\n"));
        out
    }
}

/// Runs the crate path on a checked crate (see the module docs). The
/// optimizer options come from the environment (`SANDBLASTER_STRICT_OPT`
/// only makes optimizer failures errors) and the crate's checked-in
/// profile ([`Checked::profile`], an input of the checked crate: it steers
/// which loop summaries are tried, never what is admitted); nothing else
/// is configurable.
pub fn build_crate(c: &Checked, lock: LockUse, root_display: &str) -> CrateBuild {
    build_crate_emitting(c, lock, root_display, &Emission::Crate)
}

/// Where the verdict's file goes: the whole generated crate, or one module
/// of a host crate (DESIGN.md §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Emission {
    /// Crate mode: `src/lib.rs` is exactly the `include!` of
    /// `OUT_DIR/sandblaster.rs`.
    Crate,
    /// Module mode: the host's module file `module_file` (as displayed in
    /// the file's note) is exactly the `include!` of `OUT_DIR/<out>`; the
    /// printed, round-tripped file is relocated ([`crate::relocate`]) —
    /// position-independent paths, internals visible only inside the file.
    /// A lifted module is emitted only after the lift conformance check
    /// ([`crate::conform`], configured by `conform`) passed.
    Module { module_file: String, out: String, conform: crate::conform::Config },
    /// In-place lifted modules (`#[lift(in_place)]`, DESIGN.md §2.1): the
    /// host compiles its own files, which are the lifted sources; the
    /// verdict's file is the record `OUT_DIR/<out>` of what was verified,
    /// written only after the lift conformance check of every in-place
    /// module passed.
    InPlace { out: String, conform: crate::conform::Config },
}

/// [`build_crate`] with the verdict's file placed by `emission`. Every
/// proof and gate is the same in both modes; module mode adds the
/// relocation (and its check) after the round trip and the emission-chain
/// cross-check, as one more emission-chain step: a refusal emits no code.
pub fn build_crate_emitting(c: &Checked, lock: LockUse, root_display: &str, emission: &Emission) -> CrateBuild {
    let t = Instant::now();
    let opts = VerifyOptions::default();
    let mut oopts = crate::opt::OptOptions::from_env();
    if let Some(p) = &c.profile {
        oopts.loops.profile = p.loop_samples();
    }
    let file = c.lock_path.display().to_string();
    let provers: Vec<String> = opts.chain().provers.iter().map(|(n, _)| n.clone()).collect();
    let empty = |why: &str| CrateBuild {
        v: Verification::empty(false),
        law_audit: vec![],
        spec: LockStatus::not_computed(&file, "", why),
        spec15: Spec15Report::default(),
        surface: None,
        changes: vec![],
        gates: GateReport::default(),
        emit: None,
        emit_error: None,
        report: String::new(),
        timing: String::new(),
        verdict: None,
        permit: None,
        lowered: None,
        lifted_opt_warnings: vec![],
        in_place: false,
        lowered_in_place: vec![],
    };
    let krate = match c.krate.as_ref() {
        Some(k) if c.ok() => k,
        _ => {
            let mut b = empty("front-end errors");
            b.report = render_report(c, &b.v, &[], root_display, None, None, None, "NOT VERIFIED", None);
            return b;
        }
    };
    let mut b = elab::with_big_stack(|| {
        let mut chain = opts.chain();
        let mut out = elab::elaborate(krate, &mut chain, &opts.elab_options());
        let spec15 = spec15_report(&out, krate);
        let mut v = Verification::of(&out, false);
        let law_audit = apply_law_audit(&mut v, &out, krate, &c.sm);
        resource_gate(&mut v);
        let mut b = CrateBuild { v, law_audit, spec15, ..empty("the crate did not verify") };
        b.spec = LockStatus::not_computed(&file, krate.target.arch.name(), "the crate did not verify");
        if !b.v.proofs_ok {
            return b;
        }
        // the specification surface, the lock and the classification of
        // every difference (for the lock gate's messages and the sheet)
        let (surface, terms) = crate::surface::compute_with_terms(&out, krate, &c.sm, &crate::surface::SurfaceOptions::default());
        b.spec = crate::lock::compare(c.spec_lock.as_deref(), &surface, &file);
        if !b.spec.matches() && surface.errors.is_empty() {
            let old: Vec<crate::lock::LockEntry> = c.spec_lock.as_deref().and_then(|t| crate::lock::Lock::parse(t).ok()).map(|l| l.entries_for(&surface.target).cloned().collect()).unwrap_or_default();
            b.changes = crate::specdiff::Classifier::new(&out, &surface, &terms, old).changes();
        }
        let tg = Instant::now();
        run_gates(&out, krate, c, &b.spec, &b.changes, lock, &mut b.gates);
        // the theorem of every lifted function read from MIR, in this very
        // environment (after the other gates: it extends the environment
        // with the literal reading and the theorems)
        theorem_gate(&mut out, krate, c, &mut b.gates);
        // a safety net that tripped while the gates ran (examples of
        // mutants, law checkers) fails the build like any other
        resource_gate(&mut b.v);
        b.gates.elapsed = tg.elapsed();
        let surface_root = b.spec.computed_root;
        let target = surface.target.clone();
        b.surface = Some(surface);
        // in place: the optimizer and the lowering of the host's files (the
        // host compiles its own files; the lowered copies carry the build's
        // status, `driver::in_place`)
        if b.v.proofs_ok && lock != LockUse::Accepting && matches!(emission, Emission::InPlace { .. }) && c.lifted.iter().any(|l| l.in_place && !l.ghost) {
            let t_opt = Instant::now();
            let o = crate::opt::optimize(&mut out, krate, &oopts);
            let optimizer_ms = t_opt.elapsed().as_millis();
            resource_gate(&mut b.v);
            if !b.v.proofs_ok {
                return b;
            }
            if o.errors.is_empty() {
                let t_low = Instant::now();
                let mut lows = super::lowered::lower_in_place(c, std::path::Path::new(root_display), &mut out, &o, &oopts);
                let lowering_ms = t_low.elapsed().as_millis();
                for l in lows.iter_mut() {
                    l.optimizer_ms = optimizer_ms;
                    l.lowering_ms = lowering_ms;
                }
                resource_gate(&mut b.v);
                if !b.v.proofs_ok {
                    return b;
                }
                b.lowered_in_place = lows;
            } else {
                b.lifted_opt_warnings.extend(o.errors.iter().map(|e| format!("optimizer: {e}")));
            }
        }
        if !b.v.proofs_ok || !b.gates.passed() {
            return b;
        }
        if lock == LockUse::Accepting {
            b.permit = Some(AcceptPermit { target, surface_root });
            return b;
        }
        // in-place lifted modules (`driver::lifted::in_place_record`): the
        // host's own files are the verified sources; nothing is emitted but
        // the record of what was verified
        if c.lifted.iter().any(|l| l.in_place && !l.ghost) {
            let seal = GatesPassed { _seal: () };
            let (out_name, cfg) = match emission {
                Emission::InPlace { out, conform } => (out.clone(), conform.clone()),
                _ => {
                    b.gates.chain.push("in-place lifted modules (`#[lift(in_place)]`) are verified by `sandblaster::build::compile_lifted` (the host compiles its own files)".into());
                    return b;
                }
            };
            if let Some(other) = c.lifted.iter().find(|l| !l.ghost && !l.host && !l.in_place && !l.opt) {
                b.gates.chain.push(format!("lifted module `{}` is neither in place nor a host model: a crate verified in place emits no module", other.name));
                return b;
            }
            b.gates.emitted_file = out_name.clone();
            // the lift conformance check (DESIGN.md §1.1 item 8) of every
            // in-place module, before the record is sealed
            let infos: Vec<&crate::lift::LiftedInfo> = c.lifted.iter().filter(|l| l.in_place && !l.ghost).collect();
            let conf = crate::conform::check_in_place(&mut out, krate, c, &infos, &cfg);
            b.gates.results.push(GateResult { gate: "lift-conformance", ran: true, errors: conf.failures().len(), warnings: 0, note: conf.summary() });
            let conf_ok = conf.passed();
            let conf_summary = conf.header_line();
            b.gates.conformance = Some(conf);
            if !conf_ok {
                return b;
            }
            let st = b.v.stats();
            let summary = format!(
                "{} obligation(s) proven, {} definition(s) kernel-checked; every §15 gate passed (spec mutants: {}); {conf_summary}; lifted in place (the proven optimizer's rewrites are in the lowered copies; rustc compiles a copy where the host declares it, else the host's own file); SPEC.lock: {}",
                st.proven,
                b.v.defs.len(),
                b.gates.mutation.as_ref().map(|m| format!("{} killed of {}", m.count(crate::mutate::Verdict::KilledBySpec), m.mutants.len())).unwrap_or_else(|| "none".into()),
                b.spec.summary(),
            );
            let files: Vec<(String, String)> = c.lifted.iter().filter(|l| l.in_place && !l.ghost).filter_map(|l| c.sm.get(l.file).map(|f| (f.path.display().to_string(), hex(&sha256(f.text.as_bytes()))))).collect();
            let rec = super::lifted::InPlaceInfo {
                root_display,
                files,
                boundary: krate.boundary.iter().map(|e| format!("`{}`", e.name)).collect(),
                host_models: c.lifted.iter().filter(|l| l.host).map(|l| format!("`{}` ({})", l.name, c.sm.path(l.file).display())).collect(),
                spec_root: hex(&b.spec.root),
                summary: &summary,
            };
            let code = super::lifted::in_place_record(&rec, &c.lift_facts);
            let digest = sha256(code.as_bytes());
            b.gates.emitted_sha256 = Some(hex(&digest));
            let summary = format!("{summary}; {} sha256 {}", b.gates.file_name(), hex(&digest));
            b.verdict = Some(CrateVerdict { _gates: seal, code, code_sha256: digest, summary, lifted: true });
            b.in_place = true;
            return b;
        }
        // a crate of lifted Rust emits its lifted module's source as-is
        // (`driver::lifted`): the printed lifted items are the buffer
        // model's state passing, not the host's code
        match super::lifted::emitted_module(&c.lifted) {
            Err(e) => {
                b.gates.chain.push(e);
                return b;
            }
            Ok(Some(info)) => {
                let seal = GatesPassed { _seal: () };
                let (module_file, conform) = match emission {
                    Emission::Module { module_file, out, conform } => {
                        b.gates.emitted_file = out.clone();
                        (module_file.clone(), Some(conform.clone()))
                    }
                    Emission::Crate | Emission::InPlace { .. } => ("(none: crate mode cannot include a lifted module)".to_string(), None),
                };
                let Some(src) = c.sm.get(info.file) else {
                    b.gates.chain.push(format!("lifted module `{}`: internal error: its source is not in the source map", info.name));
                    return b;
                };
                // the lift conformance check (DESIGN.md §1.1 item 8): the
                // lifted model against rustc's build of the source
                let Some(cfg) = conform else {
                    b.gates.chain.push(format!("lifted module `{}`: crate mode cannot emit a lifted module", info.name));
                    return b;
                };
                let conf = crate::conform::check(&mut out, krate, c, info, &cfg);
                b.gates.results.push(GateResult { gate: "lift-conformance", ran: true, errors: conf.failures().len(), warnings: 0, note: conf.summary() });
                let conf_ok = conf.passed();
                let conf_summary = conf.header_line();
                b.gates.conformance = Some(conf);
                if !conf_ok {
                    return b;
                }
                // the always-on optimizer on the lifted meaning; cheaper
                // residuals are lowered into the source text and checked by
                // the lifted round trip (`driver::lowered`)
                let t_opt = Instant::now();
                let o = crate::opt::optimize(&mut out, krate, &oopts);
                let optimizer_ms = t_opt.elapsed().as_millis();
                resource_gate(&mut b.v);
                if !b.v.proofs_ok {
                    return b;
                }
                b.lifted_opt_warnings = o.warnings.clone();
                if !o.errors.is_empty() {
                    b.gates.chain.extend(o.errors.iter().map(|e| format!("optimizer: {e}")));
                    return b;
                }
                let t_low = Instant::now();
                let mut low = super::lowered::lower_lifted(c, std::path::Path::new(root_display), &mut out, &o, &oopts, info);
                low.optimizer_ms = optimizer_ms;
                low.lowering_ms = t_low.elapsed().as_millis();
                resource_gate(&mut b.v);
                if !b.v.proofs_ok {
                    return b;
                }
                let st = b.v.stats();
                let opt_note = lowering_note(&low);
                let summary = format!(
                    "{} obligation(s) proven, {} definition(s) kernel-checked; every §15 gate passed (spec mutants: {}); {conf_summary}; {opt_note}; SPEC.lock: {}",
                    st.proven,
                    b.v.defs.len(),
                    b.gates.mutation.as_ref().map(|m| format!("{} killed of {}", m.count(crate::mutate::Verdict::KilledBySpec), m.mutants.len())).unwrap_or_else(|| "none".into()),
                    b.spec.summary(),
                );
                let h = super::lifted::HeaderInfo {
                    root_display,
                    module_file: &module_file,
                    source_display: &src.path.display().to_string(),
                    boundary: krate.boundary.iter().map(|e| format!("`{}`", e.name)).collect(),
                    host_models: c.lifted.iter().filter(|l| l.host).map(|l| format!("`{}` ({})", l.name, c.sm.path(l.file).display())).collect(),
                    spec_root: hex(&b.spec.root),
                    summary: &summary,
                };
                let code = super::lifted::module_code_with(&src.text, info, &c.lift_facts, &h, Some(&low));
                b.lowered = Some(low);
                match code {
                    Ok(code) => {
                        let digest = sha256(code.as_bytes());
                        b.gates.emitted_sha256 = Some(hex(&digest));
                        let summary = format!("{summary}; {} sha256 {}", b.gates.file_name(), hex(&digest));
                        b.verdict = Some(CrateVerdict { _gates: seal, code, code_sha256: digest, summary, lifted: true });
                    }
                    Err(es) => b.gates.chain.extend(es),
                }
                return b;
            }
            Ok(None) => {}
        }
        // every gate passed: optimize, print with the verdict header,
        // round-trip, cross-check the emission chain
        let seal = GatesPassed { _seal: () };
        let em = optimize_emit_rooted(c, &mut out, root_display, "", &oopts, false, b.spec.root, Some(&seal));
        resource_gate(&mut b.v);
        let mut em = match em {
            Ok(em) => em,
            Err(e) => {
                b.emit_error = Some(e);
                return b;
            }
        };
        if em.roundtrip_stats.spec_root.is_some_and(|r| r != b.spec.root) {
            em.roundtrip.push(format!("the printed `{}` is not the root of the matching SPEC.lock", canon::SPEC_ROOT_NAME));
        }
        b.gates.chain = emission_chain(&out, &em);
        if !em.code.starts_with(&canon::verdict_header_first_lines(root_display)) {
            b.gates.chain.push("the printed file does not start with the verdict header".into());
        }
        let mut code = std::mem::take(&mut em.code);
        if let Emission::Module { module_file, out, .. } = emission {
            b.gates.emitted_file = out.clone();
            if em.opt.errors.is_empty() && em.roundtrip.is_empty() && b.gates.chain.is_empty() {
                let report = format!("`{}-report.json`", out.trim_end_matches(".rs"));
                match crate::relocate::relocate(&code, &crate::relocate::module_note(module_file, &report)) {
                    Ok(m) => code = m,
                    Err(es) => b.gates.chain.extend(es),
                }
            }
        }
        let clean = b.v.proofs_ok && em.opt.errors.is_empty() && em.roundtrip.is_empty() && b.gates.chain.is_empty();
        if clean {
            let digest = sha256(code.as_bytes());
            b.gates.emitted_sha256 = Some(hex(&digest));
            let st = b.v.stats();
            let spec = em.opt.fns.iter().filter(|f| matches!(f.outcome, crate::opt::Outcome::Specialized { .. })).count();
            let summary = format!(
                "{} obligation(s) proven, {} definition(s) kernel-checked; every §15 gate passed (spec mutants: {}); optimized: {spec}/{} function(s) specialized, variant sets [{}], round trip {} definition(s); SPEC.lock: {}; {} sha256 {}",
                st.proven,
                b.v.defs.len(),
                b.gates.mutation.as_ref().map(|m| format!("{} killed of {}", m.count(crate::mutate::Verdict::KilledBySpec), m.mutants.len())).unwrap_or_else(|| "none".into()),
                em.opt.fns.len(),
                em.opt.sets.iter().map(|s| format!("{{{}}}", s.name)).collect::<Vec<_>>().join(", "),
                em.roundtrip_stats.compared,
                b.spec.summary(),
                b.gates.file_name(),
                hex(&digest),
            );
            b.verdict = Some(CrateVerdict { _gates: seal, code, code_sha256: digest, summary, lifted: false });
        }
        b.emit = Some(em);
        b
    });
    b.v.elapsed = t.elapsed();
    b.v.provers = provers;
    let status = b.status();
    b.report = render_report(c, &b.v, &b.law_audit, root_display, b.emit.as_ref(), Some(&b.spec), Some(&b.spec15), &status, Some(&b.gates));
    b.timing = timing_json_with(&b.v, b.emit.as_ref(), Some(&b.gates));
    if !b.lowered_in_place.is_empty() {
        let arr = crate::json::Json::Arr(b.lowered_in_place.iter().map(|l| l.json()).collect());
        b.report = splice_json_field(&b.report, "lifted_optimizer", &arr.render());
        let ms = b.lowered_in_place.first().map(|l| (l.optimizer_ms, l.lowering_ms)).unwrap_or_default();
        b.timing = splice_json_field(&b.timing, "lifted_optimizer_ms", &ms.0.to_string());
        b.timing = splice_json_field(&b.timing, "lifted_lowering_ms", &ms.1.to_string());
    }
    if let Some(l) = &b.lowered {
        b.report = splice_json_field(&b.report, "lifted_optimizer", &l.json().render());
        b.timing = splice_json_field(&b.timing, "lifted_optimizer_ms", &l.optimizer_ms.to_string());
        b.timing = splice_json_field(&b.timing, "lifted_lowering_ms", &l.lowering_ms.to_string());
    }
    b
}

/// `text` (a rendered JSON object) with the field `key: value` added last.
pub(super) fn splice_json_field(text: &str, key: &str, value: &str) -> String {
    let Some(at) = text.rfind('}') else { return text.to_string() };
    let (head, tail) = text.split_at(at);
    let head = head.trim_end();
    let sep = if head.ends_with('{') { "" } else { "," };
    let value = value.trim_end().replace('\n', "\n  ");
    format!("{head}{sep}\n  \"{key}\": {value}\n{tail}")
}

/// The theorem gate (`docs/checked-structuring.md`, amendment (e)): every
/// lifted exec function whose body was read from rustc's MIR must have its
/// theorem `L::thm::f` kernel-checked — the literal reading of its MIR
/// returns, at sufficient fuel, exactly the structured reading's value —
/// or the build has an error and the module is not verified. A crate with
/// no lifted MIR module records nothing.
pub fn theorem_gate(out: &mut elab::Output, krate: &crate::hir::Crate, c: &Checked, rep: &mut GateReport) {
    if c.lift_facts.mir_loaded.is_empty() || c.lift_facts.mir_contracts.is_empty() {
        return;
    }
    let t = Instant::now();
    // (the lifted round trip's copies call the module's functions: their
    // lemmas are needed later, so they are walked even when cached)
    let mut keep_keys = Vec::new();
    for info in c.lifted.iter() {
        let Some(rt_path) = &info.mir_roundtrip else { continue };
        let Some(text) = c.sm.files().find(|(_, f)| f.path == *rt_path).map(|(_, f)| f.text.clone()) else { continue };
        let Ok(rt) = crate::mir::ir::parse(&text) else { continue };
        for k in rt.fns.keys().filter(|k| k.contains(super::lowered::HELPER_PREFIX) || k.contains(super::lowered::CHECK_PREFIX)) {
            keep_keys.extend(crate::mir::checked::mir_closure(&rt, k));
        }
    }
    let opts = crate::mir::checked::GateOptions { cache: c.cache.as_deref(), keep_keys, ..Default::default() };
    let mut reports = crate::mir::checked::prove_lifted(out, &c.lift_facts, &opts);
    // the verdict: the trusted check against what the kernel holds
    // (crate::mir::gate); the walks' reports only explain a refusal
    let tv = Instant::now();
    let verdicts = out.mir_gate.ledger.verdicts(&out.env, krate, &c.lift_facts);
    let trusted_secs = tv.elapsed().as_secs_f64();
    crate::mir::checked::annotate(&mut reports, &verdicts);
    let mut d = Diagnostics::new();
    let span_of = |g: &str| krate.items.iter().find(|it| format!("crate::{}", it.path.0.join("::")) == g).map(|it| it.span).unwrap_or(crate::span::Span::DUMMY);
    for v in &verdicts {
        let Err(trusted) = &v.result else { continue };
        let why = reports.iter().flat_map(|r| &r.missing).find(|(g, _)| *g == v.global).map_or(trusted, |(_, w)| w);
        let mut msg = format!("`{}` has no kernel-checked theorem relating rustc's MIR (`{}`) to the structured reading its laws and proofs are about: {}", v.global, v.key, trunc_msg(why, 4000));
        msg.push_str(" (docs/checked-structuring.md: without it the reading of the body is not checked, and the module is not verified)");
        d.push(crate::diag::Diagnostic::error(crate::diag::DiagKind::MirTheorem, span_of(&v.global), msg));
    }
    let (total, proven, cached) = (verdicts.len(), verdicts.iter().filter(|v| v.result.is_ok()).count(), reports.iter().map(|r| r.cached()).sum::<usize>());
    let note = format!("{proven} of {total} lifted function(s) read from MIR with a kernel-checked theorem ({cached} from the verdict cache), {:.1}s, the trusted check {trusted_secs:.1}s", t.elapsed().as_secs_f64());
    let warnings = 0;
    rep.results.push(GateResult { gate: "mir-theorems", ran: true, errors: d.error_count(), warnings, note });
    rep.diags.extend(d);
    rep.theorems = reports;
}

fn trunc_msg(s: &str, n: usize) -> String {
    if s.len() > n { format!("{}..", &s[..s.floor_char_boundary(n)]) } else { s.to_string() }
}

/// The report's `mir_theorems` section (deterministic: no times).
fn theorems_json(reports: &[crate::mir::checked::ModuleTheorems]) -> Json {
    Json::Arr(
        reports
            .iter()
            .map(|r| {
                let mut o = Json::obj();
                o.str("module", &r.dsl);
                o.num("functions", r.functions() as i64);
                o.num("proven", r.proven() as i64);
                o.num("literal_functions", r.literal_fns as i64);
                o.num("literal_items", r.literal_items as i64);
                o.put(
                    "theorems",
                    Json::Arr(
                        r.outcomes
                            .iter()
                            .map(|x| {
                                let mut t = Json::obj();
                                t.str("function", &x.global);
                                t.str("mir", &x.key);
                                t.str("kind", x.kind);
                                match &x.result {
                                    Ok(_) => t.bool("proven", true),
                                    Err(e) => {
                                        t.bool("proven", false);
                                        t.str("why", &trunc_msg(e, 600));
                                    }
                                }
                                t
                            })
                            .collect(),
                    ),
                );
                o.put("missing", Json::Arr(r.missing.iter().map(|(g, _)| Json::string(g)).collect()));
                o
            })
            .collect(),
    )
}

/// Runs the six §15 gates in order (see the module docs) and records each
/// one's outcome.
fn run_gates(out: &elab::Output, krate: &crate::hir::Crate, c: &Checked, spec: &LockStatus, changes: &[crate::specdiff::Change], lock: LockUse, rep: &mut GateReport) {
    let record = |rep: &mut GateReport, gate: &'static str, d: Diagnostics, note: String| {
        let warnings = d.list.iter().filter(|x| x.severity == Severity::Warning).count();
        rep.results.push(GateResult { gate, ran: true, errors: d.error_count(), warnings, note });
        rep.diags.extend(d);
    };
    let mut d = Diagnostics::new();
    crate::validate::spec15_gate(krate, &mut d);
    record(rep, "boundary", d, String::new());
    let mut d = Diagnostics::new();
    elab::examples::spec15_gate_s1(out, krate, &mut d);
    record(rep, "examples", d, format!("{} example(s) and vector record(s) checked", out.examples.iter().filter(|e| e.status == DefStatus::Checked).count()));
    let mut d = Diagnostics::new();
    elab::complete::spec15_gate_s3(out, krate, &mut d);
    record(rep, "sections", d, format!("{} section(s)", out.sections.len()));
    let mut d = Diagnostics::new();
    elab::law_rules::spec15_gate_laws(out, krate, &mut d);
    record(rep, "law-rules", d, String::new());
    match lock {
        LockUse::Enforce => {
            let mut d = Diagnostics::new();
            crate::lock::enforce(spec, &crate::specdiff::classes(changes), &mut d);
            record(rep, "lock", d, spec.summary());
        }
        // accepting: the lock is not compared (it is being written), but a
        // surface that cannot be locked still fails
        LockUse::Accepting if spec.state == crate::lock::LockState::SurfaceErrors => {
            let mut d = Diagnostics::new();
            crate::lock::enforce(spec, &Default::default(), &mut d);
            record(rep, "lock", d, "the surface cannot be locked".into());
        }
        LockUse::Accepting => rep.results.push(GateResult { gate: "lock", ran: false, errors: 0, warnings: 0, note: "`sandblaster spec --accept` is writing the lock".into() }),
    }
    if rep.diags.has_errors() {
        let failed: Vec<&str> = rep.results.iter().filter(|r| r.errors > 0).map(|r| r.gate).collect();
        rep.results.push(GateResult { gate: "mutation", ran: false, errors: 0, warnings: 0, note: format!("the crate already failed the {} gate(s); spec mutation runs once they pass", failed.join(", ")) });
        return;
    }
    // with the verdict cache of the build entry point, a spec mutant whose
    // inputs did not change keeps its stored verdict (`mutate::cache`)
    let m = crate::mutate::run_gate_cached(krate, &c.sm, out, c.cache.as_deref());
    let mut d = Diagnostics::new();
    crate::mutate::spec15_gate_mutants(&m, krate, &mut d);
    let note = format!("{} mutant(s), {} killed by the specification, {} possibly equivalent", m.mutants.len(), m.count(crate::mutate::Verdict::KilledBySpec) + m.count(crate::mutate::Verdict::KilledBySafety), m.count(crate::mutate::Verdict::PossiblyEquivalent));
    record(rep, "mutation", d, note);
    rep.mutation = Some(m);
}

/// The optimizer's part of a lifted module's summary (the emitted header,
/// the build's warning line): how many source functions were rewritten
/// and, for every other one, **why it kept its source text**, grouped by
/// reason ([`kept_reason_class`]) and counted, most frequent first; the
/// report's `lifted_optimizer` lists each function with its full reason.
/// (It used to say "no residual … is cheaper and printable" whatever the
/// reason, although many functions of a real module are never candidates:
/// methods, other state passing, generic functions outside the per-type
/// dispatch.)
pub fn lowering_note(low: &super::lowered::LoweredModule) -> String {
    let n = low.records.len();
    let mut s = if low.lowered() == 0 {
        format!("optimized: none of the {n} source function(s) rewritten, the source is emitted as-is")
    } else {
        format!("optimized: {} of {n} source function(s) rewritten to their residuals (lifted round trip: {} definition(s) compared{})", low.lowered(), low.compared, if low.shipped.is_empty() { String::new() } else { format!("; the shipped MIR's theorems: {}", low.shipped.join("; ")) })
    };
    let mut groups: BTreeMap<String, usize> = BTreeMap::new();
    for r in &low.records {
        if let super::lowered::LowerOutcome::Kept(why) = &r.outcome {
            *groups.entry(kept_reason_class(why)).or_default() += 1;
        }
    }
    let mut groups: Vec<(String, usize)> = groups.into_iter().collect();
    groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if !groups.is_empty() {
        let listed: Vec<String> = groups.iter().map(|(c, k)| format!("{k} {c}")).collect();
        s.push_str(&format!("; source kept: {}", listed.join(", ")));
    }
    if let Some(note) = &low.note {
        s.push_str(&format!("; nothing lowered: {}", note.replace('\n', " ")));
    }
    s
}

/// The reason class of a kept function's reason (`driver::lowered`): the
/// known reasons in a few words that still say what is missing, the
/// optimizer's own reason for an unspecialized function, a generic
/// function's failed instance by the instance's reason, and any other
/// reason up to its details (the first `: ` or ` (`). Generic functions
/// over one sealed trait (per-type dispatch) and `impl Buf` readers are
/// lowered; the classes name only what is still refused.
pub fn kept_reason_class(why: &str) -> String {
    let known: &[(&str, &str)] = &[
        ("a generic function with buffer state", "generic with buffer state (the per-type dispatch does not thread the state yet)"),
        ("a generic function without a by-value parameter", "generic without a by-value parameter of its type (the per-type dispatch needs one as its receiver)"),
        ("a generic function", "generic beyond one type parameter bounded by one trait (no per-type dispatch)"),
        ("a parameter with state other than", "other state passing (`&mut` or `dyn` parameters, two buffers, a `BufMut` writer with a result; lowering not built yet)"),
        ("a method", "methods (receivers are not lowered yet)"),
        ("the residual is not 3% cheaper", "residual not 3% cheaper"),
        ("the residual cannot be printed", "residual not printable as Rust"),
        ("the residual calls", "residual calls an item the lowered code cannot name"),
        ("the lifted round trip", "rejected by the lifted round trip"),
        ("no lifted item of this name", "dropped by the lift"),
    ];
    let head = |t: &str| -> String {
        let cut = [": ", " ("].iter().filter_map(|p| t.find(p)).min().unwrap_or(t.len());
        t[..cut].to_string()
    };
    if let Some(r) = why.strip_prefix("not specialized: ") {
        return format!("not specialized ({})", head(r));
    }
    // a generic function's instance (`instance `u8`: <reason>`): by the
    // instance's reason, not per type
    if let Some(r) = why.strip_prefix("instance `").and_then(|r| r.split_once("`: ")).map(|(_, r)| r) {
        return format!("generic instance: {}", kept_reason_class(r));
    }
    for (prefix, class) in known {
        if why.starts_with(prefix) {
            return class.to_string();
        }
    }
    head(why)
}

/// The emission-chain cross-check (DESIGN.md §15.2, §15.8): a read-only
/// check of the optimizer's records against the kernel environment it
/// extended. Every clone of a dispatched variant set has passed its
/// relation check and has its equality lemma in the kernel; every
/// dispatched hardware variant has its proven `VariantEquiv` lemma in the
/// kernel; every specialized function has its residual-equality record
/// (a conversion, or a lemma in the kernel). The optimizer enforces all of
/// it itself; this is an independent second reading of its output.
pub fn emission_chain(out: &elab::Output, em: &OptimizedEmit) -> Vec<String> {
    let o = &em.opt;
    let mut bad = Vec::new();
    let known = |name: &str| out.env.lookup_global(name).is_some();
    let dispatched: BTreeSet<&str> = o.dispatchers.iter().flat_map(|d| d.variants.iter().map(|(s, _)| s.name.as_str())).collect();
    for cl in o.clones.iter().filter(|c| dispatched.contains(c.set.as_str())) {
        if let Err(e) = &cl.related {
            bad.push(format!("clone `{}` of `{}` (set {{{}}}) is dispatched, but its relation check failed: {e}", cl.clone, cl.original, cl.set));
        }
        match &cl.lemma {
            None => bad.push(format!("clone `{}` of `{}` (set {{{}}}) is dispatched without a kernel-checked equality lemma", cl.clone, cl.original, cl.set)),
            Some(l) if !known(l) => bad.push(format!("the equality lemma `{l}` of clone `{}` is not in the kernel environment", cl.clone)),
            Some(_) => {}
        }
    }
    for v in o.variants.iter().filter(|v| v.dispatched) {
        match &v.equivalence {
            Err(e) => bad.push(format!("variant `{}` of `{}` is dispatched without a proven equivalence: {e}", v.variant, v.implements)),
            Ok((lemma, _, _)) if !known(lemma) => bad.push(format!("the equivalence lemma `{lemma}` of variant `{}` is not in the kernel environment", v.variant)),
            Ok(_) => {}
        }
    }
    for f in &o.fns {
        if !matches!(f.outcome, crate::opt::Outcome::Specialized { .. }) {
            continue;
        }
        match &f.link {
            None => bad.push(format!("`{}` is specialized without a residual-equality record", f.name)),
            Some(crate::opt::Link::Lemma(l)) if !known(l) => bad.push(format!("the residual-equality lemma `{l}` of `{}` is not in the kernel environment", f.name)),
            Some(_) => {}
        }
    }
    bad
}
