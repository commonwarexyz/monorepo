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
//!    ([`crate::elab::law_rules::spec15_gate_laws`], every rule but LR8)
//!    and the lock ([`crate::lock::enforce`]; not for
//!    [`LockUse::Accepting`], which is writing it). Spec mutation and LR8
//!    law sensitivity are not gates: they are an on-demand tool for law
//!    authors and reviewers (`sandblaster mutate`,
//!    [`super::stage::mutate`]; DESIGN.md §15.7), and no build runs them;
//! 4. the theorem gate ([`theorem_gate`]) of every lifted function read
//!    from rustc's MIR, and the resource gate again;
//! 5. with [`LockUse::Enforce`] and every gate passed: for lifted Rust the
//!    lift conformance check, then the verdict's file (the record of the
//!    in-place files, or the lifted module's source as-is). A crate written
//!    in sandblaster's own dialect gets a verdict with no file: nothing of
//!    it is compiled by rustc.
//!
//! Only when all of it succeeds does it make a [`CrateVerdict`] (a type
//! with private fields and no other constructor). With
//! [`LockUse::Accepting`] and every gate but the lock passed it makes an
//! [`AcceptPermit`], which [`crate::lock::accept`] requires. Nothing in
//! the signature selects gates: the lock use is the only input besides
//! the checked crate, and it only decides whether the lock is compared
//! (a build) or written (`sandblaster spec --accept`).

use std::time::{Duration, Instant};

use crate::diag::{Diagnostics, Severity};
use crate::elab::{self, DefStatus};
use crate::json::Json;
use crate::lock::LockStatus;
use crate::surface::{hex, sha256, Hash, Surface};

use super::{apply_law_audit, def_status_str, proof_summary, render_report, resource_gate, spec15_report, timing_json_with, Checked, LawAudit, Spec15Report, Verification, VerifyOptions};

/// What the crate path does with `SPEC.lock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockUse {
    /// The lock must match the computed surface (every build and every
    /// CLI command that states a verdict).
    Enforce,
    /// `sandblaster spec --accept`: the lock is being written, so it is not
    /// compared; every other gate runs, and nothing is emitted or verified —
    /// the result is an [`AcceptPermit`], never a verdict.
    Accepting,
}

/// Every §15 gate passed with [`LockUse::Enforce`]: what lets a verdict be
/// made. Private fields: only this module makes one, and it never leaves the
/// crate path.
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

/// A crate verdict: the proofs checked, every §15 gate passed (and, for
/// lifted Rust, the theorem gate and the lift conformance check). Only
/// [`build_crate`] makes one.
pub struct CrateVerdict {
    _gates: GatesPassed,
    code: String,
    code_sha256: Hash,
    summary: String,
    kind: VerdictKind,
}

/// What a verdict's file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerdictKind {
    /// The record of in-place lifted modules ([`super::lifted::in_place_record`]).
    InPlace,
    /// A lifted module's source as-is ([`super::lifted::module_code`]).
    Lifted,
    /// A crate in sandblaster's own dialect: no file (nothing of it is
    /// compiled by rustc).
    Dialect,
}

/// The status line of a verified crate written in sandblaster's own dialect.
pub const DIALECT_VERIFIED: &str = "VERIFIED (sandblaster's own dialect: proofs and every §15 gate; no code is emitted)";

impl CrateVerdict {
    /// The verdict's file (the lifted module, or the in-place record);
    /// empty for a crate in sandblaster's own dialect.
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
    /// `boundary`, `examples`, `sections`, `law-rules`, `lock` (then
    /// `mir-theorems`, `lift-conformance`).
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
    /// Why no file could be emitted (a crate shape the build mode refuses,
    /// a lifted source an `include!` cannot carry); any is an error.
    pub chain: Vec<String>,
    /// SHA-256 of the emitted file (with a verdict that has one).
    pub emitted_sha256: Option<String>,
    /// The emitted file's name in `OUT_DIR` (module mode: `<module>.rs`;
    /// in place: `<name>-verified.txt`); empty: no file.
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
    /// The emitted file's name in `OUT_DIR` ([`GateReport::emitted_file`]),
    /// `(none)` without one.
    pub fn file_name(&self) -> &str {
        if self.emitted_file.is_empty() { "(none)" } else { &self.emitted_file }
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
    /// `sandblaster-report.json`.
    pub report: String,
    /// `sandblaster-timing.json`.
    pub timing: String,
    /// The verdict ([`LockUse::Enforce`], everything passed).
    pub verdict: Option<CrateVerdict>,
    /// The accept permit ([`LockUse::Accepting`], every gate but the lock
    /// passed).
    pub permit: Option<AcceptPermit>,
    /// The verdict is the record of in-place lifted modules
    /// (`Emission::InPlace`).
    pub in_place: bool,
}

impl CrateBuild {
    /// The status line: `VERIFIED ..` with a verdict.
    pub fn status(&self) -> String {
        if let Some(v) = &self.verdict {
            match v.kind {
                VerdictKind::InPlace => super::lifted::LIFTED_IN_PLACE.to_string(),
                VerdictKind::Lifted => super::lifted::LIFTED.to_string(),
                VerdictKind::Dialect => DIALECT_VERIFIED.to_string(),
            }
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
            gates.push_str(&format!("emission: {} finding(s)\n", self.gates.chain.len()));
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
                out.push_str(&format!("\nerror: sandblaster: `{root}` was not emitted ({} finding(s)): the proofs and every §15 gate passed, but the build mode cannot emit this crate\n", self.gates.chain.len()));
            } else {
                out.push_str(&format!("\nerror: sandblaster: `{root}` failed the §15 gates ({}): the proofs checked, but the crate is not fully specified and locked (DESIGN.md §15.8); no code was emitted\n", failed.join(", ")));
            }
            for f in &self.gates.chain {
                out.push_str(&format!("error[emission]: {f}\n"));
            }
            return out;
        }
        out.push_str(&format!("\nerror: sandblaster: `{root}` has no verdict (the proofs and every gate passed, but no verdict was made: `spec --accept` writes the lock, it does not verify)\n"));
        out
    }
}

/// Runs the crate path on a checked crate (see the module docs). Nothing
/// is configurable.
pub fn build_crate(c: &Checked, lock: LockUse, root_display: &str) -> CrateBuild {
    build_crate_emitting(c, lock, root_display, &Emission::Crate)
}

/// Where the verdict's file goes (DESIGN.md §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Emission {
    /// No file: a crate written in sandblaster's own dialect gets a verdict
    /// with no code (the CLI's `check`, the toolchain's tests); a lifted
    /// module is refused (it is emitted in module mode).
    Crate,
    /// Module mode: the host's module file `module_file` (as displayed in
    /// the file's note) is exactly the `include!` of `OUT_DIR/<out>`, the
    /// lifted module's source as-is, emitted only after the lift conformance
    /// check ([`crate::conform`], configured by `conform`) passed.
    Module { module_file: String, out: String, conform: crate::conform::Config },
    /// In-place lifted modules (`#[lift(in_place)]`, DESIGN.md §2.1): the
    /// host compiles its own files, which are the lifted sources; the
    /// verdict's file is the record `OUT_DIR/<out>` of what was verified,
    /// written only after the lift conformance check of every in-place
    /// module passed.
    InPlace { out: String, conform: crate::conform::Config },
}

/// [`build_crate`] with the verdict's file placed by `emission`. Every
/// proof and gate is the same in every mode; a refusal emits no code.
pub fn build_crate_emitting(c: &Checked, lock: LockUse, root_display: &str, emission: &Emission) -> CrateBuild {
    let t = Instant::now();
    let opts = VerifyOptions::default();
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
        report: String::new(),
        timing: String::new(),
        verdict: None,
        permit: None,
        in_place: false,
    };
    let krate = match c.krate.as_ref() {
        Some(k) if c.ok() => k,
        _ => {
            let mut b = empty("front-end errors");
            b.report = render_report(c, &b.v, &[], root_display, None, None, "NOT VERIFIED", None);
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
        run_gates(&out, krate, &b.spec, &b.changes, lock, &mut b.gates);
        // the theorem of every lifted function read from MIR, in this very
        // environment (after the other gates: it extends the environment
        // with the literal reading and the theorems)
        theorem_gate(&mut out, krate, c, &mut b.gates);
        // a safety net that tripped while the gates ran (examples, the
        // theorem gate) fails the build like any other
        resource_gate(&mut b.v);
        b.gates.elapsed = tg.elapsed();
        let surface_root = b.spec.computed_root;
        let target = surface.target.clone();
        b.surface = Some(surface);
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
            if let Some(other) = c.lifted.iter().find(|l| !l.ghost && !l.host && !l.in_place) {
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
                "{} obligation(s) proven, {} definition(s) kernel-checked; every §15 gate passed; {conf_summary}; lifted in place (rustc compiles the host's own files, as verified); SPEC.lock: {}",
                st.proven,
                b.v.defs.len(),
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
            b.verdict = Some(CrateVerdict { _gates: seal, code, code_sha256: digest, summary, kind: VerdictKind::InPlace });
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
                    Emission::Crate | Emission::InPlace { .. } => ("(none: only module mode emits a lifted module)".to_string(), None),
                };
                let Some(src) = c.sm.get(info.file) else {
                    b.gates.chain.push(format!("lifted module `{}`: internal error: its source is not in the source map", info.name));
                    return b;
                };
                // the lift conformance check (DESIGN.md §1.1 item 8): the
                // lifted model against rustc's build of the source
                let Some(cfg) = conform else {
                    b.gates.chain.push(format!("lifted module `{}`: only module mode (`compile_module`) emits a lifted module", info.name));
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
                let st = b.v.stats();
                let summary = format!(
                    "{} obligation(s) proven, {} definition(s) kernel-checked; every §15 gate passed; {conf_summary}; SPEC.lock: {}",
                    st.proven,
                    b.v.defs.len(),
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
                match super::lifted::module_code(&src.text, info, &c.lift_facts, &h) {
                    Ok(code) => {
                        let digest = sha256(code.as_bytes());
                        b.gates.emitted_sha256 = Some(hex(&digest));
                        let summary = format!("{summary}; {} sha256 {}", b.gates.file_name(), hex(&digest));
                        b.verdict = Some(CrateVerdict { _gates: seal, code, code_sha256: digest, summary, kind: VerdictKind::Lifted });
                    }
                    Err(es) => b.gates.chain.extend(es),
                }
                return b;
            }
            Ok(None) => {}
        }
        // a crate in sandblaster's own dialect: every gate passed; nothing
        // of it is compiled by rustc, so the verdict has no file
        if let Emission::Module { .. } | Emission::InPlace { .. } = emission {
            b.gates.chain.push("module mode and in-place builds emit lifted Rust (`#[lift] mod m;`): a crate written in sandblaster's own dialect has no code to emit".into());
            return b;
        }
        let st = b.v.stats();
        let summary = format!(
            "{} obligation(s) proven, {} definition(s) kernel-checked; every §15 gate passed; no code emitted (sandblaster's own dialect); SPEC.lock: {}",
            st.proven,
            b.v.defs.len(),
            b.spec.summary(),
        );
        b.verdict = Some(CrateVerdict { _gates: GatesPassed { _seal: () }, code: String::new(), code_sha256: sha256(b""), summary, kind: VerdictKind::Dialect });
        b
    });
    b.v.elapsed = t.elapsed();
    b.v.provers = provers;
    let status = b.status();
    b.report = render_report(c, &b.v, &b.law_audit, root_display, Some(&b.spec), Some(&b.spec15), &status, Some(&b.gates));
    b.timing = timing_json_with(&b.v, Some(&b.gates));
    b
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
    let opts = crate::mir::checked::GateOptions { cache: c.cache.as_deref(), ..Default::default() };
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

/// Runs the five §15 gates in order (see the module docs) and records each
/// one's outcome. Spec mutation is not among them: it is the on-demand
/// tool [`super::stage::mutate`] (`sandblaster mutate`).
fn run_gates(out: &elab::Output, krate: &crate::hir::Crate, spec: &LockStatus, changes: &[crate::specdiff::Change], lock: LockUse, rep: &mut GateReport) {
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
}
