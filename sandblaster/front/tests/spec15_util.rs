//! Shared helpers of the §15 S1 tests (`spec15_refines`, `spec15_examples`,
//! `spec15_closure`, `spec15_worked`): the whole pipeline (ghost items
//! included, the build's prover chain) on in-memory crates, with the S1
//! records of the elaboration (refinements, examples, coverage, closure
//! findings) summarized for assertions.
#![allow(dead_code)]

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Severity};
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::elab::examples::{ClosureKind, ExampleMethod, ExampleSource};
use sandblaster_front::elab::refines::RefinesForm;
use sandblaster_front::elab::{DefStatus, OblStatus};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

/// The standard header of test roots.
pub const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// A refinement record, by display paths.
#[derive(Clone, Debug)]
pub struct Ref {
    pub item: String,
    pub spec: String,
    pub checked: bool,
    pub proof: String,
    pub form: RefinesForm,
    pub up_to: Option<String>,
    /// Why it determines the function (S2), when it does.
    pub determined_by: Option<String>,
    pub statement: String,
}

/// An example record, by display path.
#[derive(Clone, Debug)]
pub struct Ex {
    pub item: String,
    pub file: bool,
    pub index: u32,
    pub checked: bool,
    pub method: Option<ExampleMethod>,
    pub counts: bool,
    pub detail: String,
}

/// A coverage record.
#[derive(Clone, Debug)]
pub struct Cov {
    pub spec: String,
    pub exercised: bool,
    pub needed: Vec<String>,
    pub seen: Vec<String>,
}

type Summary = (bool, String, Vec<(DiagKind, String)>, Vec<(DiagKind, String)>, Vec<Ref>, Vec<Ex>, Vec<Cov>, Vec<(String, ClosureKind, String)>, Vec<String>, Vec<(String, String)>, Vec<(String, String, String)>, Vec<String>);

/// The outcome of a run.
pub struct Run {
    pub checked: Checked,
    pub front_ok: bool,
    pub verified: bool,
    pub rendered: String,
    pub errors: Vec<(DiagKind, String)>,
    pub warnings: Vec<(DiagKind, String)>,
    pub refs: Vec<Ref>,
    pub examples: Vec<Ex>,
    pub coverage: Vec<Cov>,
    pub closure: Vec<(String, ClosureKind, String)>,
    pub established: Vec<String>,
    /// Definitions that did not check: `(name, status)`.
    pub failed_defs: Vec<(String, String)>,
    /// Unproven obligations: `(def, kind, goal)`.
    pub unproven: Vec<(String, String, String)>,
    /// Every checked definition's name.
    pub checked_defs: Vec<String>,
}

impl Run {
    /// Everything, for assertion messages.
    pub fn explain(&self) -> String {
        let mut s = String::new();
        for (d, st) in &self.failed_defs {
            s.push_str(&format!("def {d}: {st}\n"));
        }
        for (d, k, g) in &self.unproven {
            s.push_str(&format!("unproven {d} [{k}]: {g}\n"));
        }
        for r in &self.refs {
            s.push_str(&format!("refines {} -> {}: checked={} proof={} up_to={:?}\n", r.item, r.spec, r.checked, r.proof, r.up_to));
        }
        for e in &self.examples {
            s.push_str(&format!("example {}#{}{}: checked={} {:?} {}\n", e.item, if e.file { "file" } else { "" }, e.index, e.checked, e.method, e.detail));
        }
        s.push_str(&self.rendered);
        s
    }

    pub fn has_error(&self, kind: DiagKind, needle: &str) -> bool {
        self.errors.iter().any(|(k, m)| *k == kind && m.contains(needle))
    }

    pub fn refinement(&self, item: &str) -> &Ref {
        self.refs.iter().find(|r| r.item == item).unwrap_or_else(|| panic!("no refinement record for `{item}`:\n{}", self.explain()))
    }
}

/// Runs the whole pipeline on an in-memory crate; `files[0]` is the root
/// (its text gets [`HEADER`] prepended).
pub fn run_files(files: &[(&str, &str)]) -> Run {
    run_files_with(files, sandblaster_front::elab::Options::default())
}

/// [`run_files`] with explicit elaboration options (e.g. a small example
/// budget).
pub fn run_files_with(files: &[(&str, &str)], eopts: sandblaster_front::elab::Options) -> Run {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let refs: Vec<(&str, &str)> = owned.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    run_files_raw(&refs, eopts)
}

/// [`run_files_with`] without the header.
pub fn run_files_raw(files: &[(&str, &str)], eopts: sandblaster_front::elab::Options) -> Run {
    let owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    let front_ok = c.ok();
    if !front_ok {
        let rendered = c.render();
        let errors = c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect();
        let warnings = c.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| (d.kind, d.msg.clone())).collect();
        return Run { checked: c, front_ok, verified: false, rendered, errors, warnings, refs: vec![], examples: vec![], coverage: vec![], closure: vec![], established: vec![], failed_defs: vec![], unproven: vec![], checked_defs: vec![] };
    }
    let k = c.krate.clone().unwrap();
    let _ = (VerifyOptions { provers: ProverSet::Standard, exec_only: false }, driver::stage::verify);
    let sm = &c.sm;
    let kr = &k;
    let eo = &eopts;
    let summarize = move |out: &sandblaster_front::elab::Output| -> Summary {
        let path = |id: sandblaster_front::hir::ItemId| kr.item(id).path.to_string();
        let gname = |g: sandblaster_kernel::term::GlobalId| out.env.global_name(g).map(|n| n.to_string()).unwrap_or_default();
        let refs = out.refinements.iter().map(|r| Ref { item: path(r.item), spec: path(r.spec), checked: r.status == DefStatus::Checked, proof: r.proof.clone(), form: r.form.clone(), up_to: r.up_to.clone(), determined_by: r.determined_by.clone(), statement: r.statement.clone() }).collect();
        let examples = out
            .examples
            .iter()
            .map(|e| {
                let (file, index) = match e.source {
                    ExampleSource::Attr { index } => (false, index),
                    ExampleSource::File { record, .. } => (true, record),
                };
                Ex { item: path(e.item), file, index, checked: e.status == DefStatus::Checked, method: e.method, counts: e.counts, detail: e.detail.clone() }
            })
            .collect();
        let coverage = out.coverage.iter().map(|c| Cov { spec: path(c.spec), exercised: c.exercised, needed: c.outcomes_needed.clone(), seen: c.outcomes_seen.clone() }).collect();
        let closure = out.spec_closure.iter().map(|c| (path(c.item), c.kind, c.msg.clone())).collect();
        let established = out.established.iter().map(|g| gname(*g)).collect();
        let failed_defs = out.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked)).map(|d| (d.name.clone(), format!("{:?}", d.status))).collect();
        let unproven = out.obligations.iter().filter(|o| !matches!(o.status, OblStatus::Proven { .. })).map(|o| (o.def.clone(), sandblaster_front::elab::obl::kind_name(&o.kind).to_string(), o.goal.clone())).collect();
        let checked_defs = out.defs.iter().filter(|d| d.status == DefStatus::Checked).map(|d| d.name.clone()).collect();
        let errors = out.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect::<Vec<_>>();
        let warnings = out.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| (d.kind, d.msg.clone())).collect::<Vec<_>>();
        (out.verified(), out.diags.render(sm), errors, warnings, refs, examples, coverage, closure, established, failed_defs, unproven, checked_defs)
    };
    let (verified, rendered, errors, warnings, refs, examples, coverage, closure, established, failed_defs, unproven, checked_defs) = sandblaster_front::elab::with_big_stack(move || {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, eo);
        summarize(&out)
    });
    // the front end's warnings (an accepted crate has no front-end error)
    // come first, as a build reports them
    let mut all_warnings: Vec<(DiagKind, String)> = c.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| (d.kind, d.msg.clone())).collect();
    all_warnings.extend(warnings);
    let rendered = format!("{}{rendered}", c.diags.render(&c.sm));
    Run { checked: c, front_ok, verified, rendered, errors, warnings: all_warnings, refs, examples, coverage, closure, established, failed_defs, unproven, checked_defs }
}

/// Runs the pipeline on a crate directory on disk (`root` is its
/// `mod.rs`, which carries its own header).
pub fn run_dir(root: &Path) -> Run {
    run_dir_edited(root, &|_, c| c.to_string())
}

/// [`run_dir`] with each file's text passed through `edit(path, text)`
/// (red-team mutations of a sample crate).
pub fn run_dir_edited(root: &Path, edit: &dyn Fn(&str, &str) -> String) -> Run {
    let files: Vec<(std::path::PathBuf, String)> = collect_dir(root.parent().unwrap()).into_iter().map(|(p, c)| {
        let rel = p.strip_prefix(root.parent().unwrap()).unwrap().display().to_string();
        let c2 = edit(&rel, &c);
        (p, c2)
    }).collect();
    let base = root.parent().unwrap();
    let owned: Vec<(String, String)> = files.iter().map(|(p, c)| (format!("r/{}", p.strip_prefix(base).unwrap().display()), c.clone())).collect();
    let mut ordered: Vec<(String, String)> = owned.iter().filter(|(p, _)| p == "r/mod.rs").cloned().collect();
    ordered.extend(owned.into_iter().filter(|(p, _)| p != "r/mod.rs"));
    // the root keeps its own header
    let refs: Vec<(&str, &str)> = ordered.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    run_files_raw(&refs, sandblaster_front::elab::Options::default())
}

fn collect_dir(d: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(collect_dir(&p));
        } else {
            out.push((p.clone(), std::fs::read_to_string(&p).unwrap()));
        }
    }
    out
}

/// [`run_files`] on a single-module crate.
pub fn run(body: &str) -> Run {
    run_files(&[("r/mod.rs", body)])
}

/// Asserts the crate verifies (front end, every definition, obligation and
/// §15 record) and returns the run.
#[track_caller]
pub fn verifies(body: &str) -> Run {
    let r = run(body);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    assert!(r.verified && r.errors.is_empty(), "not verified:\n{}", r.explain());
    r
}

/// [`verifies`] on several files.
#[track_caller]
pub fn verifies_files(files: &[(&str, &str)]) -> Run {
    let r = run_files(files);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    assert!(r.verified && r.errors.is_empty(), "not verified:\n{}", r.explain());
    r
}

/// Asserts the crate does not verify.
#[track_caller]
pub fn fails(body: &str) -> Run {
    let r = run(body);
    assert!(!r.verified || !r.errors.is_empty() || !r.front_ok, "expected a failure, but it verified:\n{}", r.explain());
    r
}
