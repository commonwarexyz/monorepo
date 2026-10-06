//! The sandblaster pipeline (DESIGN.md §1, §10).
//!
//! **Front end**: load → resolve → surface typecheck → subset validation →
//! HIR. [`check`] runs it on a DSL root and returns the source map, the HIR
//! (when every item lowered) and all diagnostics.
//!
//! **The crate path** ([`gates::build_crate`]): elaborate every item to
//! kernel definitions ([`crate::elab`], DESIGN.md §7) with every obligation
//! discharged by the prover chain and every definition kernel-checked, the
//! law audit and the resource gate, then **every §15 gate** (boundary,
//! examples and coverage, sections, law rules, `SPEC.lock`; DESIGN.md
//! §15.8), the theorem gate of the functions read from rustc's
//! MIR and, for lifted Rust, the lift conformance check. It is the only
//! producer of a [`gates::CrateVerdict`], and only a verdict reports
//! `VERIFIED`, lets the build entry points ([`build_module`],
//! [`build_lifted`]) write their verified output, and lets the CLI exit 0
//! on a verdict; the variant [`gates::LockUse::Accepting`] is the only
//! producer of the permit that `crate::lock::accept` needs. Nothing selects
//! which gates run.
//!
//! **Stage APIs** ([`stage`]): the toolchain's own steps (verify, spec,
//! conformance, evaluate) for its unit tests and the CLI's stage tools.
//! Their results are never a crate verdict: a stage report's status is
//! [`STAGE_RUN`] or `NOT VERIFIED`, never `VERIFIED`.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::elab::{self, DefStatus, OblStatus};
use crate::diag::{DiagKind, Diagnostic, Diagnostics, Severity};
use crate::hir::{self, Crate, ItemId, ItemKind, LawProof, ModId, Recursion};
use crate::json::Json;
use crate::loader::{self, FileProvider};
use crate::resolve::Resolver;
use crate::span::{SourceMap, Span};
use crate::target::TargetInfo;
use crate::typeck::{docs_of, Checker};
use crate::validate;

pub mod cache;
pub mod gates;
pub mod in_place;
pub mod lifted;
pub mod module;
pub mod stage;

pub use gates::{build_crate, build_crate_emitting, CrateBuild, CrateVerdict, Emission, LockUse};
pub use in_place::build_lifted;
pub use module::{build_module, module_file_ok, module_include_line, module_out_name};

/// Result of running the front end.
pub struct Checked {
    pub sm: SourceMap,
    pub krate: Option<Crate>,
    pub diags: Diagnostics,
    /// The lock of this root in its directory (DESIGN.md §15.6:
    /// `SPEC.lock` for a root named `mod.rs` or `lib.rs`, `SPEC.<stem>.lock`
    /// otherwise; [`crate::lock::lock_path`]): its path and its text
    /// (`None`: no lock), read through the file provider.
    pub lock_path: std::path::PathBuf,
    pub spec_lock: Option<String>,
    /// The `#[lift]` modules (existing Rust lifted as-is) and what the lift
    /// assumed: a crate with a lifted exec module that is not
    /// `#[lift(host)]` emits that module's source as-is in module mode
    /// ([`gates::Emission::Module`], DESIGN.md §2.1).
    pub lifted: Vec<crate::lift::LiftedInfo>,
    pub lift_facts: crate::lift::LiftFacts,
    /// The verdict cache ([`cache`]) the crate path may reuse the theorem
    /// gate's and the conformance check's verdicts from (and store them
    /// in), and the on-demand mutation tool ([`stage::mutate`]) its
    /// per-mutant verdicts: set by the build entry points that know the
    /// toolchain's identity ([`build_module`], [`build_lifted`]); `None`
    /// (never reuse) from [`check`].
    pub cache: Option<std::sync::Arc<cache::VerdictCache>>,
}

impl Checked {
    pub fn ok(&self) -> bool {
        !self.diags.has_errors() && self.krate.is_some()
    }
    /// Rendered diagnostics.
    pub fn render(&self) -> String {
        self.diags.render(&self.sm)
    }
}

/// Runs load, resolve, typecheck and validation on the DSL root `root`.
pub fn check(root: &Path, fs: &dyn FileProvider, target: &TargetInfo) -> Checked {
    let mut sm = SourceMap::new();
    let mut diags = Diagnostics::new();
    let lock_path = crate::lock::lock_path(root);
    let spec_lock = fs.read(&lock_path).ok();
    if target.pointer_width != 64 {
        diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, format!("sandblaster requires a 64-bit target (pointer width {})", target.pointer_width)));
    }
    let Some(loaded) = loader::load(root, fs, target, &mut sm, &mut diags) else {
        return Checked { sm, krate: None, diags, lock_path, spec_lock, lifted: vec![], lift_facts: Default::default(), cache: None };
    };
    let res = Resolver::new(&loaded, target, &mut diags);
    let mut ck = Checker::new(&res);
    ck.lower_signatures();
    ck.check_bodies();
    diags.extend(std::mem::take(&mut ck.diags));
    let mut krate = assemble(&res, &ck, target);
    // in-place lifted modules: their `pub` functions may carry `requires`
    // (host obligations, listed in the record)
    let in_place_files: std::collections::HashSet<crate::span::FileId> = loaded.lifted.iter().filter(|l| l.in_place).map(|l| l.file).collect();
    // a lifted crate's proof files: the ghost `#[lift]` modules other than
    // the laws file (never on the review surface, DESIGN.md §15.6)
    let proof_files: std::collections::HashSet<crate::span::FileId> = loaded.lifted.iter().filter(|l| l.ghost && l.name != crate::lift::LAWS_MODULE).map(|l| l.file).collect();
    // the non-ghost `#[lift]` sources (in place or copied)
    let lift_sources: std::collections::HashSet<crate::span::FileId> = loaded.lifted.iter().filter(|l| !l.ghost).map(|l| l.file).collect();
    // the ghost `#[lift]` modules (the laws file, the proof files)
    let lift_ghosts: std::collections::HashSet<crate::span::FileId> = loaded.lifted.iter().filter(|l| l.ghost).map(|l| l.file).collect();
    for m in krate.modules.iter_mut() {
        m.lift_source = !m.ghost && m.lifted && lift_sources.contains(&m.file);
        m.lift_ghost = m.ghost && lift_ghosts.contains(&m.file);
        m.lifted = m.lifted && in_place_files.contains(&m.file);
        m.proof_file = m.ghost && proof_files.contains(&m.file);
        if m.lifted {
            m.host_access = loaded.lift_facts.host_access.iter().find(|(f, _)| *f == m.file).map(|(_, a)| a.clone()).unwrap_or_default();
        }
    }
    // the text of `#[examples(file = ..)]` vector files (build inputs in
    // the source map; the elaborator reads their records, DESIGN.md §15.7)
    for it in &mut krate.items {
        if let hir::ItemKind::Fn(f) = &mut it.kind {
            for ef in &mut f.spec.example_files {
                ef.text = sm.get(ef.file).map(|s| s.text.clone()).unwrap_or_default();
            }
        }
    }
    validate::validate(&mut krate, &res, &mut diags);
    let (lifted, lift_facts) = (loaded.lifted.clone(), loaded.lift_facts.clone());
    Checked { sm, krate: Some(krate), diags, lock_path, spec_lock, lifted, lift_facts, cache: None }
}

fn assemble(res: &Resolver, ck: &Checker, target: &TargetInfo) -> Crate {
    let modules = res
        .mods
        .iter()
        .map(|m| {
            let mut docs = docs_of(&m.decl_attrs);
            docs.extend(docs_of(&m.inner_attrs));
            hir::Module {
                id: m.id,
                name: m.name.clone(),
                parent: m.parent,
                path: m.path.clone(),
                file: m.file,
                ghost: m.ghost,
                vis: m.vis,
                items: m.items.clone(),
                submodules: m.children.clone(),
                span: m.span,
                docs,
                cfg: m.cfg.clone(),
                spec: m.spec,
                model: m.model,
                bridges: m.bridges,
                lifted: m.lifted,
                proof_file: false,
                lift_source: false,
                lift_ghost: false,
                host_access: Default::default(),
            }
        })
        .collect();
    let items = res
        .items
        .iter()
        .map(|it| {
            let kind = ck.hir_items[it.id.0 as usize].clone().unwrap_or(ItemKind::TypeAlias(hir::TypeAliasDef { ty: hir::Ty::Error, lts: Default::default() }));
            let (docs, allow) = ck.item_docs.get(&it.id).cloned().unwrap_or_default();
            hir::Item { id: it.id, name: it.name.clone(), path: it.path.clone(), module: it.module, vis: it.vis, ghost: it.ghost, span: it.span, docs, allow, cfg: it.cfg.clone(), kind }
        })
        .collect();
    Crate { root: ModId(0), modules, items, target: target.clone(), boundary: vec![], reachable: vec![] }
}

pub(crate) fn kind_name(k: &ItemKind) -> &'static str {
    match k {
        ItemKind::Struct(_) => "struct",
        ItemKind::Enum(_) => "enum",
        ItemKind::Const(_) => "const",
        ItemKind::TypeAlias(_) => "type",
        ItemKind::Fn(f) => f.kind.name(),
    }
}

pub(crate) fn count_loops(f: &hir::FnDef) -> usize {
    struct V(usize);
    impl crate::visit::Visitor for V {
        fn loop_(&mut self, l: &hir::Loop) {
            self.0 += 1;
            crate::visit::walk_loop(self, l);
        }
    }
    let mut v = V(0);
    crate::visit::walk_fn(&mut v, f);
    v.0
}

/// A human summary (`sandblaster check`).
pub fn summary(c: &Checked) -> String {
    let mut s = String::new();
    let Some(k) = &c.krate else { return "no crate".into() };
    let count = |pred: &dyn Fn(&hir::Item) -> bool| k.items.iter().filter(|i| pred(i)).count();
    let exec = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == hir::FnKind::Exec) && !i.ghost);
    let spec = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == hir::FnKind::Spec));
    let lemmas = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == hir::FnKind::Lemma));
    let laws = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == hir::FnKind::Law));
    let proofs = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == hir::FnKind::Proof));
    let open = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.law_proof == Some(LawProof::Missing)));
    let types = count(&|i| matches!(&i.kind, ItemKind::Struct(_) | ItemKind::Enum(_)));
    let consts = count(&|i| matches!(&i.kind, ItemKind::Const(_)));
    let requires = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == hir::FnKind::Exec && f.has_requires()));
    let tail = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.recursion == Recursion::Tail));
    let nontail = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.recursion == Recursion::NonTail));
    let loops: usize = k.items.iter().filter_map(|i| match &i.kind {
        ItemKind::Fn(f) => Some(count_loops(f)),
        _ => None,
    }).sum();
    s.push_str(&format!("modules: {} ({} ghost)\n", k.modules.len(), k.modules.iter().filter(|m| m.ghost).count()));
    s.push_str(&format!("types: {types}, consts: {consts}\n"));
    s.push_str(&format!("exec fns: {exec} ({requires} with requires, {tail} tail-recursive, {nontail} depth-bounded recursive), loops: {loops}\n"));
    s.push_str(&format!("ghost: {spec} spec fns, {lemmas} lemmas, {laws} laws ({open} open claims), {proofs} proofs\n"));
    s.push_str(&format!("boundary: {}\n", k.boundary.iter().map(|e| e.name.clone()).collect::<Vec<_>>().join(", ")));
    s.push_str(&format!("target: {} [{}]\n", k.target.arch.name(), k.target.features.iter().cloned().collect::<Vec<_>>().join(",")));
    let (e, w) = (c.diags.error_count(), c.diags.list.iter().filter(|d| d.severity == Severity::Warning).count());
    s.push_str(&format!("diagnostics: {e} error(s), {w} warning(s)\n"));
    s.push_str(&format!("status: {UNVERIFIED} — front end only; proofs are not checked yet\n"));
    s
}

/// Pushes `cargo::rerun-if-changed` for each of `paths` that exists.
/// Cargo re-runs a build script on **every** invocation while a watched
/// path is missing, so a virtual source-map path (the lift prelude's
/// `<sandblaster lift prelude>/…`) or a lock not accepted yet would rebuild
/// the host crate and all its dependents each time; a missing lock is
/// still noticed when it appears, because the DSL root's directory is
/// watched.
pub fn watch_existing<'p>(o: &mut BuildOutcome, fs: &dyn FileProvider, paths: impl IntoIterator<Item = &'p Path>) {
    for p in paths {
        if fs.exists(p) {
            o.cargo.push(format!("cargo::rerun-if-changed={}", p.display()));
        }
    }
}

/// The status of the front end's output: proofs not checked.
pub const UNVERIFIED: &str = "UNVERIFIED (phase 1)";

/// The status of a stage run whose proofs checked ([`status_str`]).
pub const STAGE_RUN: &str = "PROOFS CHECKED (stage run, no crate verdict: the §15 gates did not run)";

/// Removes `//` and `/* */` comments and all whitespace.
pub(crate) fn strip_comments_ws(s: &str) -> String {
    let mut out = String::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && i + 1 < b.len() && b[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else {
            if !c.is_whitespace() {
                out.push(c);
            }
            i += 1;
        }
    }
    out
}

/// What a build script run produced (see `sandblaster::build`).
#[derive(Debug, Default)]
pub struct BuildOutcome {
    /// `cargo::...` directives to print on stdout.
    pub cargo: Vec<String>,
    /// Human diagnostics for stderr.
    pub stderr: String,
    /// Files to write in `OUT_DIR` (the verified module or record, the
    /// report, the timing).
    pub outputs: Vec<(std::path::PathBuf, String)>,
    pub ok: bool,
}

// ---------------------------------------------------------------------------
// Verified pipeline (phase 2)
// ---------------------------------------------------------------------------

/// Which provers discharge obligations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProverSet {
    /// The build's chain: the development prover, then `auto` (§8.1).
    #[default]
    Standard,
    /// The development prover only (faster; for tests).
    Basic,
}

/// Options of [`verify`]. None of them skips a proof: an unproven
/// obligation always makes verification fail.
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    pub provers: ProverSet,
    /// **Test-only**: elaborate exec code (and the types and constants it
    /// needs) but not spec functions, lemmas and laws. Never set by the
    /// build or the CLI.
    #[doc(hidden)]
    pub exec_only: bool,
}

impl VerifyOptions {
    fn elab_options(&self) -> elab::Options {
        elab::Options { exec_only: self.exec_only, ..Default::default() }
    }
    fn chain(&self) -> elab::ProverChain {
        match self.provers {
            ProverSet::Standard => elab::ProverChain::standard(),
            ProverSet::Basic => elab::ProverChain::basic(),
        }
    }
}

/// The result of [`verify`]: everything of [`elab::Output`] except the
/// kernel environment (which stays on the elaboration thread).
#[derive(Clone, Debug)]
pub struct Verification {
    pub defs: Vec<elab::DefRecord>,
    pub obligations: Vec<elab::ObligationRecord>,
    pub laws: Vec<elab::LawRecord>,
    /// Elaboration diagnostics (unproven obligations, unsupported
    /// constructs, kernel rejections, open laws).
    pub diags: Diagnostics,
    /// Items deferred to a later phase, with the reason.
    pub deferred: Vec<(ItemId, String)>,
    /// Every definition checked, every obligation proven, every law proven,
    /// the law audit and the resource gate passed: the crate's **proofs**
    /// checked. Not a crate verdict — the §15 gates are not part of it
    /// (only [`gates::build_crate`] makes a [`gates::CrateVerdict`]).
    pub proofs_ok: bool,
    pub elapsed: Duration,
    /// The provers of the chain, in order.
    pub provers: Vec<String>,
    /// Whether ghost items were skipped (test-only [`VerifyOptions::exec_only`]).
    pub exec_only: bool,
}

impl Verification {
    /// The records of an elaboration (`proofs_ok` from the elaboration
    /// alone; the law audit and the resource gate may still clear it).
    pub(crate) fn of(out: &elab::Output, exec_only: bool) -> Verification {
        Verification {
            defs: out.defs.clone(),
            obligations: out.obligations.clone(),
            laws: out.laws.clone(),
            diags: out.diags.clone(),
            deferred: out.deferred.clone(),
            proofs_ok: out.verified() && !exec_only,
            elapsed: Duration::ZERO,
            provers: Vec::new(),
            exec_only,
        }
    }

    /// No elaboration (front-end errors).
    pub(crate) fn empty(exec_only: bool) -> Verification {
        Verification { defs: vec![], obligations: vec![], laws: vec![], diags: Diagnostics::new(), deferred: vec![], proofs_ok: false, elapsed: Duration::ZERO, provers: vec![], exec_only }
    }
}

/// The statement of a proven law (or lemma) and whether its hypotheses were
/// found contradictory (red team RG-1: a law whose `requires` cannot hold
/// proves nothing, and must not be reported as a guarantee).
#[derive(Clone, Debug)]
pub struct LawAudit {
    pub item: ItemId,
    /// Display path.
    pub name: String,
    /// `law` or `lemma`.
    pub kind: &'static str,
    /// The statement as written: signature, `requires`, `ensures`.
    pub statement: String,
    /// The proven kernel type (bounded print).
    pub kernel_statement: String,
    /// `Some(prover)` when the prover chain refuted the hypotheses (proved
    /// `Empty` from them) and the kernel checked that refutation.
    pub vacuous: Option<String>,
    /// How the (bounded) refutation attempts ended when they did not
    /// refute: "no refutation found", the limit that stopped them, or why
    /// no attempt could be made ("not attempted: …"). Empty for refuted
    /// laws and laws without hypotheses.
    pub attempt: String,
}

/// The outcome of one refutation attempt ([`refute_hypotheses`]).
enum Refutation {
    /// The prover refuted the hypotheses and the kernel checked it.
    Refuted(String),
    /// The bounded attempt failed (with the reason).
    NotRefuted(String),
    /// No attempt was made (the hypotheses could not be evaluated).
    NotAttempted(String),
}

/// Kernel step budget of one non-vacuity check (a refutation attempt of a
/// law's hypotheses; failing to refute is the normal case).
pub const VACUITY_BUDGET: u64 = 2_000_000;
/// The same for lemmas (only a warning: ex-falso helper lemmas are legitimate).
pub const VACUITY_BUDGET_LEMMA: u64 = 500_000;
/// Budget of the second attempt for laws (small functions unfolded).
pub const VACUITY_BUDGET_TRANSPARENT: u64 = 200_000;
/// Functions whose body has at most this many term nodes are unfolded by
/// the second attempt.
pub const VACUITY_SMALL_FN: usize = 256;
/// Wall-clock limit of one refutation attempt (a backstop: the step budget
/// ends failing attempts first; running out means "not refuted").
pub const VACUITY_TIMEOUT: Duration = Duration::from_secs(5);

/// The prover of the non-vacuity audit: the development prover (linear
/// arithmetic, contradictory facts, bounded case splits) with a small
/// split bound — deterministic and cheap, every attempt bounded by its step
/// budget (kernel and front-end work) and [`VACUITY_TIMEOUT`]. `auto` is not
/// used: the audit runs on every law and lemma, and the development prover
/// finds the contradictions it targets (arithmetic and facts over atoms).
fn vacuity_chain() -> elab::ProverChain {
    let mut chain = elab::ProverChain::new(vec![("basic".into(), Box::new(elab::basic::BasicProver { max_splits: 2, max_split_nodes: 16, timeout: None }))]);
    chain.timeout = Some(VACUITY_TIMEOUT);
    chain
}

/// The statement of a law/lemma as written (for the report).
fn law_statement(sm: &SourceMap, it: &hir::Item, f: &hir::FnDef) -> String {
    let flat = |sp: Span| sm.snippet(sp).map(|t| t.split_whitespace().collect::<Vec<_>>().join(" "));
    let mut s = flat(f.sig_span).unwrap_or_else(|| format!("fn {}", it.name));
    // with the header `let`s where they are written
    s.push_str(&f.contract_text(&|sp| flat(sp).unwrap_or_else(|| "?".into())));
    s
}

/// Non-vacuity audit (red team RG-1): for every proven law and lemma with
/// hypotheses, tries — with a small budget and the development prover
/// ([`vacuity_chain`]) — to prove `Empty` from the
/// hypotheses alone (the law's parameters and `requires`, without its
/// conclusion). The hypotheses are evaluated with the crate's own functions
/// **opaque** (`verify(..)` stays an atom instead of unfolding the whole
/// verifier), so the attempt reasons about arithmetic and facts over atoms
/// (`len < 3 ∧ len > 5`, `1 == 2`); for laws a second attempt unfolds the
/// small leaf functions (body ≤ [`VACUITY_SMALL_FN`] nodes, no calls of
/// other crate functions), e.g. a function that returns a constant.
/// A kernel-checked refutation means the law is vacuously true. Laws are
/// then a verification error; lemmas a warning (an ex-falso helper lemma is
/// legitimate). Failing to refute is not evidence of consistency (the check
/// is incomplete: a contradiction that needs a function's definition is not
/// found), but it closes the gap of hypotheses that the automation
/// refutes on their face.
pub fn audit_laws(out: &elab::Output, krate: &Crate, sm: &SourceMap) -> (Vec<LawAudit>, Diagnostics) {
    use sandblaster_kernel::term::DefKind;
    let mut audits = Vec::new();
    let mut diags = Diagnostics::new();
    let mut chain = vacuity_chain();
    let user: std::collections::HashSet<sandblaster_kernel::term::GlobalId> = out.fn_globals.values().copied().collect();
    let opaque = |g: sandblaster_kernel::term::GlobalId| user.contains(&g);
    // the second attempt unfolds only small leaf functions (no calls of
    // other crate functions), so the unfolding is bounded; everything else
    // (the verifier) stays an atom
    let small_leaf = |g: sandblaster_kernel::term::GlobalId| {
        out.env.global_body(g).is_some_and(|b| elab::tm::size_capped(&b, VACUITY_SMALL_FN + 1) <= VACUITY_SMALL_FN && !elab::tm::any_node(&b, &mut |n| matches!(n, sandblaster_kernel::term::Term::Global(h) if *h != g && user.contains(h))))
    };
    let large: std::collections::HashSet<sandblaster_kernel::term::GlobalId> = user.iter().copied().filter(|g| !small_leaf(*g)).collect();
    let opaque_large = |g: sandblaster_kernel::term::GlobalId| large.contains(&g);
    for (i, d) in out.defs.iter().enumerate() {
        let (Some(item), Some(g)) = (d.item, d.global) else { continue };
        let kind = match d.kind {
            DefKind::Law => "law",
            DefKind::Lemma => "lemma",
            _ => continue,
        };
        if d.status != DefStatus::Checked {
            continue;
        }
        let it = krate.item(item);
        let Some(f) = krate.fn_def(item) else { continue };
        let Some(ty) = out.env.global_type(g) else { continue };
        let statement = law_statement(sm, it, f);
        let kernel_statement = sandblaster_kernel::syntax::printer::print_term_bounded(&out.env, &[], &ty, 2000);
        let mut audit = LawAudit { item, name: it.path.to_string(), kind, statement, kernel_statement, vacuous: None, attempt: String::new() };
        let nparams = f.generics.len() + f.params.len();
        if f.requires.iter().all(|r| r.is_true_lit()) {
            audits.push(audit);
            continue;
        }
        // two attempts: the crate's functions opaque (atoms), then — for
        // laws — with the small functions unfolded (a contradiction visible
        // after a little unfolding, e.g. a function returning a constant)
        let budget = if kind == "law" { VACUITY_BUDGET } else { VACUITY_BUDGET_LEMMA };
        let t0 = Instant::now();
        let mut r = refute_hypotheses(out, &mut chain, &ty, nparams, Some(&opaque), budget, u32::MAX - i as u32, d.span);
        if kind == "law" && !matches!(r, Refutation::Refuted(_)) {
            let r2 = refute_hypotheses(out, &mut chain, &ty, nparams, Some(&opaque_large), VACUITY_BUDGET_TRANSPARENT, u32::MAX - i as u32, d.span);
            r = match (r, r2) {
                (_, Refutation::Refuted(by)) => Refutation::Refuted(by),
                (Refutation::NotRefuted(a), Refutation::NotRefuted(b)) => Refutation::NotRefuted(format!("{a}; small functions unfolded: {b}")),
                (Refutation::NotRefuted(a), Refutation::NotAttempted(_)) | (Refutation::NotAttempted(_), Refutation::NotRefuted(a)) => Refutation::NotRefuted(a),
                (a @ Refutation::NotAttempted(_), Refutation::NotAttempted(_)) => a,
                (Refutation::Refuted(by), _) => Refutation::Refuted(by),
            };
        }
        if std::env::var_os("SANDBLASTER_TRACE_AUDIT").is_some() {
            let what = match &r {
                Refutation::Refuted(by) => format!("refuted by {by}"),
                Refutation::NotRefuted(why) => format!("not refuted ({why})"),
                Refutation::NotAttempted(why) => format!("not attempted ({why})"),
            };
            eprintln!("audit {kind} {}: {what} in {:?} (heap {} MiB)", it.path, t0.elapsed(), crate::memguard::allocated() >> 20);
        }
        let by = match r {
            Refutation::Refuted(by) => Some(by),
            Refutation::NotRefuted(why) => {
                audit.attempt = why;
                None
            }
            Refutation::NotAttempted(why) => {
                audit.attempt = format!("not attempted: {why}");
                None
            }
        };
        if let Some(by) = by {
            audit.vacuous = Some(by.clone());
            let sp = it.span;
            if kind == "law" {
                diags.push(
                    Diagnostic::error(DiagKind::Law, sp, format!("vacuous law: the hypotheses (`requires`) of law `{}` are contradictory, so it proves nothing", it.path))
                        .note(format!("the prover (`{by}`) derived `Empty` from the hypotheses alone, and the kernel checked the refutation"))
                        .note(format!("statement: {}", audit.statement))
                        .note("fix the `requires` so that they can hold together (a law must state a property of real inputs, DESIGN.md §4.5)"),
                );
            } else {
                diags.push(Diagnostic::warning(DiagKind::Law, sp, format!("lemma `{}` has contradictory hypotheses (vacuous; refuted by `{by}`)", it.path)).note(format!("statement: {}", audit.statement)));
            }
        }
        audits.push(audit);
    }
    (audits, diags)
}

/// The refutation goal of the hypotheses of the law/lemma of type `ty` (see
/// [`audit_laws`]): opens its Π telescope (the first `nparams` binders are
/// its parameters, the rest its hypotheses), evaluating the binder types
/// with the globals of `opaque` folded (all transparent for `None`), and
/// returns the goal `Empty` in that context together with the terms of its
/// target and facts (for [`elab::basic::set_goal_terms`]). `None` when there
/// is no hypothesis or an evaluation fails (budget `b`).
#[allow(clippy::too_many_arguments)]
pub fn hypotheses_goal(env: &sandblaster_kernel::api::Env, ty: &sandblaster_kernel::term::Tm, nparams: usize, opaque: Option<&dyn Fn(sandblaster_kernel::term::GlobalId) -> bool>, b: &mut sandblaster_kernel::value::Budget, id: u32, span: Span) -> Option<(crate::prover::Goal, elab::basic::GoalTerms)> {
    use sandblaster_kernel::api::{Ctx, CtxEntry};
    use sandblaster_kernel::term::Term;
    use crate::prover::{FactOrigin, FactRef, Goal, ObligationId, ObligationKind};
    let mut ctx = Ctx::default();
    let mut facts = Vec::new();
    let mut fact_terms: Vec<(u32, sandblaster_kernel::term::Tm)> = Vec::new();
    let mut t = ty.clone();
    let mut k = 0usize;
    while let Term::Pi { name, rel, dom, cod } = &*t {
        let venv = env.ctx_venv(&ctx);
        let dv = match opaque {
            Some(o) => env.eval_opaque(&venv, ctx.depth(), dom, o, b),
            None => env.eval(&venv, ctx.depth(), dom, b),
        }
        .ok()?;
        if k >= nparams {
            facts.push(FactRef { lvl: ctx.depth(), origin: FactOrigin::LemmaHyp, span });
            fact_terms.push((ctx.depth().0, dom.clone()));
        }
        ctx = ctx.push(CtxEntry { name: name.clone(), rel: *rel, ty: dv, def: None });
        t = cod.clone();
        k += 1;
    }
    if facts.is_empty() {
        return None;
    }
    let empty_tm = sandblaster_kernel::util::mk::ind(env.empty_ind(), vec![]);
    let venv = env.ctx_venv(&ctx);
    let target = env.eval(&venv, ctx.depth(), &empty_tm, b).ok()?;
    let goal = Goal { id: ObligationId(id), kind: ObligationKind::Assert, span, ctx, facts, target, hints: vec![] };
    Some((goal, elab::basic::GoalTerms { id, target: empty_tm, facts: fact_terms }))
}

/// One refutation attempt of the hypotheses of the law/lemma of type `ty`
/// (see [`audit_laws`], [`hypotheses_goal`]): asks `chain` for a proof of
/// `Empty` within `budget` kernel steps (every prover call is also bounded
/// by the per-goal deadline and the memory soft limit, [`crate::auto::meter`]).
/// `Refuted` only when the kernel checks the refutation; a failed,
/// exhausted or timed-out attempt is `NotRefuted` (with the reason), and a
/// goal that cannot be set up within the budget is `NotAttempted` — never
/// "refuted", and never reported as a completed attempt.
#[allow(clippy::too_many_arguments)]
fn refute_hypotheses(out: &elab::Output, chain: &mut elab::ProverChain, ty: &sandblaster_kernel::term::Tm, nparams: usize, opaque: Option<&dyn Fn(sandblaster_kernel::term::GlobalId) -> bool>, budget: u64, id: u32, span: Span) -> Refutation {
    use sandblaster_kernel::value::Budget;
    use crate::prover::Prover;
    let mut b = Budget { steps: budget };
    let Some((goal, terms)) = hypotheses_goal(&out.env, ty, nparams, opaque, &mut b, id, span) else {
        return Refutation::NotAttempted("the hypotheses could not be evaluated within the budget".into());
    };
    elab::basic::set_goal_terms(Some(terms));
    let res = chain.prove(&out.env, &goal, &mut b);
    elab::basic::set_goal_terms(None);
    let p = match res {
        Ok(p) => p,
        Err(f) => {
            // the limit that stopped the attempt, if any
            let limit = f.tried.iter().rev().find(|t| t.contains("budget exhausted") || t.contains("deadline exceeded") || t.contains("memory") || t.contains("too large")).cloned();
            return Refutation::NotRefuted(limit.unwrap_or_else(|| "no refutation found".into()));
        }
    };
    // the prover is untrusted: the refutation must check
    let p = elab::recert::recertify(&out.env, &goal.ctx, &p);
    let mut cb = Budget { steps: budget.saturating_mul(4) };
    match out.env.check(&goal.ctx, &p, &goal.target, &mut cb) {
        Ok(()) => Refutation::Refuted(chain.last_name()),
        Err(e) => Refutation::NotRefuted(format!("the prover's refutation was rejected by the kernel: {}", e.message.lines().next().unwrap_or(""))),
    }
}

/// Runs [`audit_laws`] (only on a fully proven elaboration: the audit
/// qualifies proven laws) and records its result in `v`: a vacuous law
/// makes the verification fail. Returns the audit (for the report).
pub(crate) fn apply_law_audit(v: &mut Verification, out: &elab::Output, krate: &Crate, sm: &SourceMap) -> Vec<LawAudit> {
    if !v.proofs_ok || v.exec_only {
        return Vec::new();
    }
    let (audit, diags) = audit_laws(out, krate, sm);
    if diags.has_errors() {
        v.proofs_ok = false;
    }
    v.diags.extend(diags);
    audit
}

/// Obligation statistics of a verification.
#[derive(Clone, Debug, Default)]
pub struct OblStats {
    pub total: usize,
    pub proven: usize,
    pub failed: usize,
    pub todo: usize,
    /// Proven without script hints.
    pub automated: usize,
    /// Proven with script hints.
    pub hinted: usize,
    /// `(kind, total, proven)`, sorted by kind.
    pub by_kind: Vec<(String, usize, usize)>,
    /// `(prover, proven)`, sorted by name (`eval` = closed by evaluation).
    pub by_prover: Vec<(String, usize)>,
}

impl Verification {
    /// Obligation statistics.
    pub fn stats(&self) -> OblStats {
        use std::collections::BTreeMap;
        let mut s = OblStats { total: self.obligations.len(), ..Default::default() };
        let mut kinds: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut provers: BTreeMap<String, usize> = BTreeMap::new();
        for o in &self.obligations {
            let e = kinds.entry(elab::obl::kind_name(&o.kind).to_string()).or_default();
            e.0 += 1;
            match &o.status {
                OblStatus::Proven { by } => {
                    s.proven += 1;
                    e.1 += 1;
                    *provers.entry(by.clone()).or_default() += 1;
                    if o.hinted {
                        s.hinted += 1;
                    } else {
                        s.automated += 1;
                    }
                }
                OblStatus::Failed(_) => s.failed += 1,
                OblStatus::Todo => s.todo += 1,
            }
        }
        s.by_kind = kinds.into_iter().map(|(k, (t, p))| (k, t, p)).collect();
        s.by_prover = provers.into_iter().collect();
        s
    }

    /// Definitions that did not end [`DefStatus::Checked`] (deferred ones
    /// excluded).
    pub fn failed_defs(&self) -> Vec<&elab::DefRecord> {
        self.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).collect()
    }
}

/// A definition status, as the report and the spec sheet print it.
pub fn def_status_str(s: &DefStatus) -> String {
    match s {
        DefStatus::Checked => "checked".into(),
        DefStatus::Unproven => "unproven".into(),
        DefStatus::Rejected(m) => format!("rejected by the kernel: {m}"),
        DefStatus::Unsupported(m) => format!("unsupported: {m}"),
        DefStatus::Blocked(m) => format!("blocked: {m}"),
        DefStatus::Deferred(m) => format!("deferred: {m}"),
        DefStatus::Open => "open claim (no proof)".into(),
    }
}

fn def_kind_str(k: sandblaster_kernel::term::DefKind) -> &'static str {
    use sandblaster_kernel::term::DefKind::*;
    match k {
        Exec => "exec",
        Spec => "spec",
        Lemma => "lemma",
        Law => "law",
        LoopHelper => "loop-helper",
        Ensures => "ensures",
        Prelude => "prelude",
        Intrinsic => "intrinsic",
    }
}

fn span_str(sm: &SourceMap, sp: Span) -> String {
    if sp.is_dummy() {
        return String::new();
    }
    format!("{}:{}:{}", sm.path(sp.file).display(), sp.lo.0, sp.lo.1 + 1)
}

/// Status line of a stage verification: never a crate verdict (only
/// [`gates::build_crate`] reports `VERIFIED`).
pub fn status_str(v: &Verification) -> String {
    if v.exec_only {
        "NOT VERIFIED (test-only exec-only elaboration)".to_string()
    } else if v.proofs_ok {
        STAGE_RUN.to_string()
    } else {
        "NOT VERIFIED".to_string()
    }
}

/// A human summary of a verification with the given status line (the
/// crate path's and [`stage::summary`]).
pub(crate) fn proof_summary(c: &Checked, v: &Verification, status: &str) -> String {
    let mut s = summary(c);
    // replace the phase-1 status line
    if let Some(i) = s.find("status: ") {
        s.truncate(i);
    }
    // count the verifier's diagnostics too, not only the front end's
    if let Some(i) = s.find("diagnostics: ") {
        let end = i + s[i..].find('\n').map_or(s.len() - i, |n| n + 1);
        let warnings = |d: &Diagnostics| d.list.iter().filter(|d| d.severity == Severity::Warning).count();
        let e = c.diags.error_count() + v.diags.error_count();
        let w = warnings(&c.diags) + warnings(&v.diags);
        s.replace_range(i..end, &format!("diagnostics: {e} error(s), {w} warning(s)\n"));
    }
    let st = v.stats();
    s.push_str(&format!(
        "definitions: {} ({} checked, {} not checked, {} deferred)\n",
        v.defs.len(),
        v.defs.iter().filter(|d| d.status == DefStatus::Checked).count(),
        v.failed_defs().len(),
        v.defs.iter().filter(|d| matches!(d.status, DefStatus::Deferred(_))).count()
    ));
    s.push_str(&format!("obligations: {} ({} proven: {} automated, {} hinted; {} failed, {} todo)\n", st.total, st.proven, st.automated, st.hinted, st.failed, st.todo));
    s.push_str(&format!("provers: {}\n", st.by_prover.iter().map(|(p, n)| format!("{p} {n}")).collect::<Vec<_>>().join(", ")));
    if !v.laws.is_empty() {
        let proven = v.laws.iter().filter(|l| l.status == DefStatus::Checked).count();
        s.push_str(&format!("laws: {} ({} proven, {} open or failed)\n", v.laws.len(), proven, v.laws.len() - proven));
    }
    s.push_str(&format!("time: {:.2}s\n", v.elapsed.as_secs_f64()));
    s.push_str(&format!("status: {status}\n"));
    s
}

/// Renders `sandblaster-timing.json`: the wall-clock times of a verified
/// build (elaboration, the §15 gates). They are kept out of
/// `sandblaster-report.json`, which is byte-identical across builds of the
/// same inputs.
pub fn timing_json(v: &Verification) -> String {
    timing_json_with(v, None)
}

/// [`timing_json`] with the time of the §15 gates (the crate path).
pub(crate) fn timing_json_with(v: &Verification, gates: Option<&gates::GateReport>) -> String {
    let mut j = Json::obj();
    j.num("elaborate_ms", v.elapsed.as_millis() as i64);
    if let Some(g) = gates {
        j.num("gates_ms", g.elapsed.as_millis() as i64);
    }
    j.render()
}

/// Renders `sandblaster-report.json`: the proofs, the `SPEC.lock` status,
/// the §15 records and, on the crate path, the gates and the emitted file. `status` is the verdict line: the crate
/// path's (only [`gates::build_crate`] passes `VERIFIED`) or a stage
/// status ([`status_str`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_report(c: &Checked, v: &Verification, law_audit: &[LawAudit], root_display: &str, spec: Option<&crate::lock::LockStatus>, s15: Option<&Spec15Report>, status: &str, gates: Option<&gates::GateReport>) -> String {
    let mut j = Json::obj();
    j.str("sandblaster", env!("CARGO_PKG_VERSION"));
    j.str("status", status);
    j.num("phase", 2);
    j.str("root", root_display);
    let files: Vec<Json> = c.sm.files().map(|(_, f)| Json::string(&f.path.display().to_string())).collect();
    j.put("files", Json::Arr(files));
    if let Some(k) = &c.krate {
        let mut t = Json::obj();
        t.str("arch", k.target.arch.name());
        t.put("features", Json::Arr(k.target.features.iter().map(|f| Json::string(f)).collect()));
        t.str("endian", if k.target.little_endian { "little" } else { "big" });
        t.num("pointer_width", k.target.pointer_width as i64);
        j.put("target", t);
        // definitions
        let defs: Vec<Json> = v
            .defs
            .iter()
            .map(|d| {
                let mut o = Json::obj();
                o.str("name", &d.name);
                o.str("kind", def_kind_str(d.kind));
                if let Some(it) = d.item {
                    o.str("item", &k.item(it).path.to_string());
                }
                o.str("status", &def_status_str(&d.status));
                o.str("span", &span_str(&c.sm, d.span));
                o
            })
            .collect();
        j.put("definitions", Json::Arr(defs));
        // obligations
        let st = v.stats();
        let mut ob = Json::obj();
        ob.num("total", st.total as i64);
        ob.num("proven", st.proven as i64);
        ob.num("failed", st.failed as i64);
        ob.num("todo", st.todo as i64);
        ob.num("automated", st.automated as i64);
        ob.num("hinted", st.hinted as i64);
        let mut bk = Json::obj();
        for (kind, total, proven) in &st.by_kind {
            let mut o = Json::obj();
            o.num("total", *total as i64);
            o.num("proven", *proven as i64);
            bk.put(kind, o);
        }
        ob.put("by_kind", bk);
        let mut bp = Json::obj();
        for (p, n) in &st.by_prover {
            bp.num(p, *n as i64);
        }
        ob.put("by_prover", bp);
        ob.put("provers", Json::Arr(v.provers.iter().map(|p| Json::string(p)).collect()));
        let list: Vec<Json> = v
            .obligations
            .iter()
            .map(|o| {
                let mut x = Json::obj();
                x.num("id", o.id as i64);
                x.str("kind", elab::obl::kind_name(&o.kind));
                x.str("def", &o.def);
                x.str("span", &span_str(&c.sm, o.span));
                x.bool("hinted", o.hinted);
                match &o.status {
                    OblStatus::Proven { by } => {
                        x.str("status", "proven");
                        x.str("by", by);
                    }
                    OblStatus::Failed(_) => {
                        x.str("status", "failed");
                        x.str("goal", &o.goal);
                    }
                    OblStatus::Todo => {
                        x.str("status", "todo");
                        x.str("goal", &o.goal);
                    }
                }
                x
            })
            .collect();
        ob.put("list", Json::Arr(list));
        j.put("obligations", ob);
        // laws
        let laws: Vec<Json> = v
            .laws
            .iter()
            .map(|l| {
                let mut o = Json::obj();
                o.str("law", &l.name);
                o.str("proof", &l.proof);
                let audit = law_audit.iter().find(|a| a.item == l.item);
                match audit.and_then(|a| a.vacuous.as_ref()) {
                    Some(by) => o.str("status", &format!("vacuous: its hypotheses are contradictory (refuted by `{by}`, kernel-checked); it proves nothing")),
                    None => o.str("status", &def_status_str(&l.status)),
                }
                let statement = audit.map(|a| a.statement.clone()).unwrap_or_else(|| {
                    let it = k.item(l.item);
                    k.fn_def(l.item).map(|f| law_statement(&c.sm, it, f)).unwrap_or_default()
                });
                o.str("statement", &statement);
                if let Some(a) = audit {
                    o.str("kernel_statement", &a.kernel_statement);
                    let nv = match (&a.vacuous, k.fn_def(l.item).is_some_and(|f| f.requires.iter().any(|r| !r.is_true_lit()))) {
                        (Some(_), _) => "refuted".to_string(),
                        (None, true) if a.attempt.starts_with("not attempted") => format!("unknown: the non-vacuity check was {}", a.attempt),
                        (None, true) => format!("hypotheses not refuted (bounded attempt of the development prover, crate functions opaque; small leaf functions unfolded for laws: {})", a.attempt),
                        (None, false) => "no hypotheses".to_string(),
                    };
                    o.str("non_vacuity", &nv);
                }
                o
            })
            .collect();
        j.put("laws", Json::Arr(laws));
        let vacuous_lemmas: Vec<Json> = law_audit.iter().filter(|a| a.kind == "lemma" && a.vacuous.is_some()).map(|a| Json::string(&format!("{}: {}", a.name, a.statement))).collect();
        j.put("vacuous_lemmas", Json::Arr(vacuous_lemmas));
        let deferred: Vec<Json> = v
            .deferred
            .iter()
            .map(|(id, why)| {
                let mut o = Json::obj();
                o.str("item", &k.item(*id).path.to_string());
                o.str("reason", why);
                o
            })
            .collect();
        j.put("deferred", Json::Arr(deferred));
        j.put("boundary", Json::Arr(k.boundary.iter().map(|e| Json::string(&e.name)).collect()));
        if let Some(st) = spec {
            j.put("spec", st.json());
        }
        if let Some(r) = s15 {
            j.put("refinements", refinements_json(&r.refinements));
            j.put("sections", sections_json(&r.sections));
            let vf: Vec<Json> = r
                .vector_files
                .iter()
                .map(|x| {
                    let mut o = Json::obj();
                    o.str("checker", &x.checker);
                    o.str("file", &x.file);
                    o.str("provenance", x.provenance);
                    o.num("records", x.records as i64);
                    o.num("checked", x.checked as i64);
                    o
                })
                .collect();
            j.put("vector_files", Json::Arr(vf));
            j.put("law_rules", law_rules_json(&r.law_rules));
            j.put("laws", laws_json(&r.laws));
        }
    }
    if let Some(g) = gates {
        j.put("gates", g.json());
    }
    // wall-clock times are in `sandblaster-timing.json` ([`timing_json`]): the
    // report is a pure function of the build's inputs (gate G1)
    j.put(
        "tcb",
        Json::Arr(
            [
                "sandblaster-kernel (checker, evaluator, linarith, bvnorm, axioms)",
                "elaboration semantics of the canonical dialect (SEMANTICS.md)",
                "prelude definitions (sandblaster/kernel/prelude/*.core)",
                "target semantics library: the intrinsic models (sandblaster/targets/core/*.core), validated natively",
                "rustc/LLVM",
                "the elaboration of the ghost language (SEMANTICS.md §13) and Env::abstract_section (DESIGN.md §1.1 item 6)",
                "assumptions (DESIGN.md §1.1 item 7): num-bigint/num-integer, the rustc that compiled the kernel, syn agreeing with rustc on the canonical dialect, the §3.7 stack assumption, host code calls a `#[target_feature]` function only on a CPU with those features, a process free of undefined behaviour",
            ]
            .iter()
            .map(|s| Json::string(s))
            // a crate with lifted modules also trusts the lift
            .chain((!c.lifted.is_empty()).then(|| Json::string("the lift (DESIGN.md §1.1 item 8): the item skeleton read from the lifted Rust source (crate::lift, SEMANTICS.md §19), the function bodies read from rustc's MIR (crate::mir and the printer sandblaster-mirx, docs/mir-lift.md §20), the buffer model (lift/model.rs) and the #[lift(host)] models; mitigated by the lift conformance check against rustc (crate::conform)")))
            .collect(),
        ),
    );
    let warnings: Vec<Json> = c.diags.list.iter().chain(v.diags.list.iter()).filter(|d| d.severity == Severity::Warning).map(|d| Json::string(&d.render(&c.sm))).collect();
    j.put("warnings", Json::Arr(warnings));
    j.render()
}

/// The §15 records of `sandblaster-report.json` (DESIGN.md §15.10).
#[derive(Clone, Debug, Default)]
pub struct Spec15Report {
    pub refinements: Vec<RefinementReport>,
    pub vector_files: Vec<VectorFileReport>,
    /// The computed sections (DESIGN.md §15.5, §15.10; S3).
    pub sections: Vec<SectionReport>,
    /// The findings of the law rules (DESIGN.md §15.1 LR1–LR10), enforced
    /// by the §15.8 gate ([`elab::law_rules::spec15_gate_laws`]).
    pub law_rules: Vec<LawRuleReport>,
    /// The law table (LR9): law, guarantee, assumptions, heading.
    pub laws: Vec<elab::law_rules::LawRow>,
}

/// One finding of the law rules in `sandblaster-report.json`.
#[derive(Clone, Debug)]
pub struct LawRuleReport {
    /// `LR1` … `LR10`.
    pub rule: &'static str,
    /// The diagnostic code (`law-mentions-internal`, …).
    pub kind: &'static str,
    /// `error` or `warning` (the §15.8 gate).
    pub severity: &'static str,
    pub item: String,
    pub message: String,
    pub notes: Vec<String>,
}

/// One computed section in `sandblaster-report.json` (DESIGN.md §15.10): its
/// members, `P(R)`, `H(R)`, `Deps(R)` (each with how it is specified), its
/// position in ≺, its status and each `complete_p`'s statement and outcome.
/// The §15.8 gate fails a build with a section that is not fully
/// specified.
#[derive(Clone, Debug)]
pub struct SectionReport {
    pub index: usize,
    pub members: Vec<String>,
    pub published: Vec<String>,
    pub hypotheses: Vec<(String, String)>,
    pub deps: Vec<(String, String)>,
    pub status: String,
    pub fully_specified: bool,
    pub merged: bool,
    /// `(function, statement in surface syntax, kernel statement, status, proof)`.
    pub complete: Vec<(String, String, String, String, String)>,
    pub problems: Vec<String>,
    /// `(function, goal)`: where `auto` got stuck on an unproven
    /// `complete_p` (surface syntax, the function unfolded once).
    pub stuck: Vec<(String, String)>,
}

/// The report records of the sections of an elaboration.
pub fn section_reports(out: &elab::Output, krate: &Crate) -> Vec<SectionReport> {
    use elab::complete::DepHow;
    let path = |id: hir::ItemId| krate.item(id).path.to_string();
    out.sections
        .iter()
        .map(|s| SectionReport {
            index: s.index,
            members: s.members.iter().map(|m| path(*m)).collect(),
            published: s.published.iter().map(|m| path(*m)).collect(),
            hypotheses: s.hyps.clone(),
            deps: s
                .dep_status
                .iter()
                .map(|(d, h)| {
                    let how = match h {
                        DepHow::Refines => "determined by its refinement".to_string(),
                        DepHow::Section(k) => format!("fully specified in section {k}"),
                        DepHow::Constant => "exec constant (value locked)".to_string(),
                        DepHow::Derived => "derived PartialEq (determined by its type)".to_string(),
                        DepHow::Prelude => "lift prelude function (a trusted primitive)".to_string(),
                        DepHow::UpToView(None) => "determined by its refinement only up to a lossy view (not accepted as a dependency)".to_string(),
                        DepHow::UpToView(Some(k)) => format!("fully specified in section {k} only up to a lossy view (not accepted as a dependency)"),
                        DepHow::Unspecified => "NOT fully specified in an earlier section".to_string(),
                    };
                    (path(*d), how)
                })
                .collect(),
            status: s.status.word().to_string(),
            fully_specified: s.fully_specified(),
            merged: s.merged,
            complete: s.statements.iter().map(|c| (path(c.item), c.surface.clone(), c.text.clone(), def_status_str(&c.status), c.proof.clone())).collect(),
            problems: s.problems.clone(),
            stuck: s.statements.iter().filter_map(|c| c.stuck.clone().map(|g| (path(c.item), g))).collect(),
        })
        .collect()
}

fn sections_json(ss: &[SectionReport]) -> Json {
    let strs = |v: &[String]| Json::Arr(v.iter().map(|x| Json::string(x)).collect());
    Json::Arr(
        ss.iter()
            .map(|s| {
                let mut o = Json::obj();
                o.num("index", s.index as i64);
                o.put("members", strs(&s.members));
                o.put("published", strs(&s.published));
                o.put(
                    "hypotheses",
                    Json::Arr(
                        s.hypotheses
                            .iter()
                            .map(|(k, n)| {
                                let mut h = Json::obj();
                                h.str("kind", k);
                                h.str("name", n);
                                h
                            })
                            .collect(),
                    ),
                );
                o.put(
                    "deps",
                    Json::Arr(
                        s.deps
                            .iter()
                            .map(|(d, how)| {
                                let mut h = Json::obj();
                                h.str("function", d);
                                h.str("specified", how);
                                h
                            })
                            .collect(),
                    ),
                );
                o.str("status", &s.status);
                o.bool("fully_specified", s.fully_specified);
                o.bool("merged", s.merged);
                o.put(
                    "complete",
                    Json::Arr(
                        s.complete
                            .iter()
                            .map(|(f, surf, core, st, proof)| {
                                let mut c = Json::obj();
                                c.str("function", f);
                                c.str("statement", surf);
                                c.str("kernel", core);
                                c.str("status", st);
                                c.str("proof", proof);
                                c
                            })
                            .collect(),
                    ),
                );
                o.put("problems", strs(&s.problems));
                o.put(
                    "stuck_goals",
                    Json::Arr(
                        s.stuck
                            .iter()
                            .map(|(f, g)| {
                                let mut c = Json::obj();
                                c.str("function", f);
                                c.str("goal", g);
                                c
                            })
                            .collect(),
                    ),
                );
                o
            })
            .collect(),
    )
}

fn law_rules_json(rs: &[LawRuleReport]) -> Json {
    Json::Arr(
        rs.iter()
            .map(|r| {
                let mut o = Json::obj();
                o.str("rule", r.rule);
                o.str("kind", r.kind);
                o.str("severity", r.severity);
                o.str("item", &r.item);
                o.str("message", &r.message);
                o.put("notes", Json::Arr(r.notes.iter().map(|n| Json::string(n)).collect()));
                o
            })
            .collect(),
    )
}

fn laws_json(rows: &[elab::law_rules::LawRow]) -> Json {
    use elab::law_rules::LawHeading;
    Json::Arr(
        rows.iter()
            .map(|r| {
                let mut o = Json::obj();
                o.str("law", &r.path);
                match &r.guarantee {
                    Some(g) => o.str("guarantee", g),
                    None => o.put("guarantee", Json::Null),
                }
                o.put(
                    "assumes",
                    Json::Arr(
                        r.assumes
                            .iter()
                            .map(|(p, info)| {
                                let mut a = Json::obj();
                                a.str("assumption", p);
                                match info {
                                    Some((class, cite)) => {
                                        a.str("class", class);
                                        a.str("cite", cite);
                                    }
                                    None => a.put("class", Json::Null),
                                }
                                a
                            })
                            .collect(),
                    ),
                );
                match &r.heading {
                    LawHeading::Guarantee => o.str("heading", "guarantee"),
                    LawHeading::Definitional(reason) => {
                        o.str("heading", "definitional");
                        o.str("reason", reason);
                    }
                    LawHeading::Corollary(of) => {
                        o.str("heading", "corollary");
                        o.put("of", Json::Arr(of.iter().map(|x| Json::string(x)).collect()));
                    }
                }
                o
            })
            .collect(),
    )
}

/// One vector file in the report (DESIGN.md §15.7): how many of its
/// records were evaluated and how many held.
#[derive(Clone, Debug)]
pub struct VectorFileReport {
    pub checker: String,
    pub file: String,
    pub provenance: &'static str,
    /// Records evaluated (checking stops after ten failures).
    pub records: usize,
    pub checked: usize,
}

/// The §15 report records of an elaboration.
pub fn spec15_report(out: &elab::Output, krate: &Crate) -> Spec15Report {
    let mut vector_files = Vec::new();
    for it in &krate.items {
        let ItemKind::Fn(f) = &it.kind else { continue };
        for file in &f.spec.example_files {
            let recs: Vec<&elab::examples::ExampleRecord> = out.examples.iter().filter(|e| e.item == it.id && matches!(e.source, elab::examples::ExampleSource::File { file: x, .. } if x == file.file)).collect();
            vector_files.push(VectorFileReport {
                checker: it.path.to_string(),
                file: file.path.clone(),
                provenance: match file.provenance {
                    hir::Provenance::Independent => "independent",
                    hir::Provenance::Production => "production",
                    hir::Provenance::SelfDerived => "self",
                },
                records: recs.len(),
                checked: recs.iter().filter(|e| e.status == DefStatus::Checked).count(),
            });
        }
    }
    let law_rules = out
        .law_rules
        .iter()
        .map(|r| LawRuleReport { rule: r.rule.code(), kind: r.rule.kind().code(), severity: if r.rule.hard() { "error" } else { "warning" }, item: krate.item(r.item).path.to_string(), message: r.msg.clone(), notes: r.notes.iter().map(|n| n.1.clone()).collect() })
        .collect();
    Spec15Report { refinements: refinement_reports(out, krate), vector_files, sections: section_reports(out, krate), law_rules, laws: elab::law_rules::law_table(krate) }
}

/// One `#[refines]` in `sandblaster-report.json` (DESIGN.md §15.10): the
/// spec it refines, the form of the statement, whether the lemma checked,
/// whether it determines the function (§15.2) and, when it does not, why
/// ("refines `s` up to view(T)", a domain, a representation relation, a
/// spec that is not spec-closed).
#[derive(Clone, Debug)]
pub struct RefinementReport {
    pub function: String,
    pub spec: String,
    /// `view` (plain, through the result's view coercion),
    /// `represents-constructor`, `represents-preserve`,
    /// `represents-state-passing`, `represents-observer`.
    pub form: &'static str,
    /// `walk` or the `#[proof(refines = ..)]` item.
    pub proof: String,
    pub status: String,
    pub checked: bool,
    pub determines: bool,
    pub up_to: Option<String>,
    /// Why the refinement determines the function (when it does, S2).
    pub determined_by: Option<String>,
    /// The de-elaborated refinement (`refines s(..)`, its meaning, the
    /// verdict), as on the spec sheet.
    pub statement: Vec<String>,
}

/// The report records of the refinements of an elaboration.
pub fn refinement_reports(out: &elab::Output, krate: &Crate) -> Vec<RefinementReport> {
    use elab::refines::RefinesForm;
    out.refinements
        .iter()
        .map(|r| {
            let it = krate.item(r.item);
            let statement = match krate.fn_def(r.item) {
                Some(f) => crate::deelab::DeElab::new(krate, &f.locals).contract_with("fn", it, f, Some(r)).into_iter().skip_while(|l| !l.trim_start().starts_with("refines ")).map(|l| l.trim().to_string()).collect(),
                None => vec![],
            };
            let checked = r.status == DefStatus::Checked;
            RefinementReport {
                function: it.path.to_string(),
                spec: krate.item(r.spec).path.to_string(),
                form: match r.form {
                    RefinesForm::Plain => "view",
                    RefinesForm::RepConstructor => "represents-constructor",
                    RefinesForm::RepPreserve => "represents-preserve",
                    RefinesForm::RepStatePassing => "represents-state-passing",
                    RefinesForm::RepObserver => "represents-observer",
                },
                proof: r.proof.clone(),
                status: def_status_str(&r.status),
                checked,
                determines: checked && r.up_to.is_none(),
                up_to: r.up_to.clone(),
                determined_by: r.determined_by.clone().filter(|_| checked && r.up_to.is_none()),
                statement,
            }
        })
        .collect()
}

fn refinements_json(rs: &[RefinementReport]) -> Json {
    Json::Arr(
        rs.iter()
            .map(|r| {
                let mut o = Json::obj();
                o.str("function", &r.function);
                o.str("spec", &r.spec);
                o.str("form", r.form);
                o.str("proof", &r.proof);
                o.str("status", &r.status);
                o.bool("checked", r.checked);
                o.bool("determines", r.determines);
                match &r.up_to {
                    Some(u) => o.str("up_to", u),
                    None => o.put("up_to", Json::Null),
                }
                match &r.determined_by {
                    Some(u) => o.str("determined_by", u),
                    None => o.put("determined_by", Json::Null),
                }
                o.put("statement", Json::Arr(r.statement.iter().map(|l| Json::string(l)).collect()));
                o
            })
            .collect(),
    )
}

/// DESIGN.md §15.8 "deterministic outcomes": if a resource safety net
/// (the per-goal wall-clock deadline, the memory soft limit or the per-goal
/// heap cap; [`crate::auto::meter`]) tripped on this thread since the last
/// call, the build fails with `error[resource]` — whatever the affected
/// goals' outcome, which the step budgets alone must decide (the law audit
/// falls back on a failed goal, so a trip could otherwise change what is
/// accepted). Reported once; per-obligation trips
/// are already `error[resource]` diagnostics of the elaborator.
pub fn resource_gate(v: &mut Verification) {
    let trips = crate::auto::meter::take_trips();
    let memory = crate::auto::meter::memory_soft_limit_reached();
    if trips.is_empty() && !memory {
        return;
    }
    v.proofs_ok = false;
    let mut d = Diagnostic::error(DiagKind::Resource, Span::DUMMY, format!("resource safety nets tripped during the build ({} goal(s) stopped{}): the build failed for resources; no outcome of it is a proof result", trips.len(), if memory { ", memory soft limit reached" } else { "" }))
        .note("proofs and the emitted code are decided by step budgets only (DESIGN.md §15.8); the wall-clock deadline and the memory limits are safety nets set well above them — rerun on a less loaded machine, or raise SANDBLASTER_GOAL_TIMEOUT_MS / SANDBLASTER_MEM_LIMIT_GB");
    let mut seen = std::collections::BTreeSet::new();
    for t in &trips {
        if seen.insert(format!("{:?}", t.reason)) {
            d = d.note(format!("tripped: {}", t.note));
        }
    }
    v.diags.push(d);
}

/// The lock status of a verified elaboration (reported by stage runs; the
/// crate gate computes its own, with kernel text, [`gates::build_crate`]).
pub(crate) fn spec_status(c: &Checked, out: &elab::Output, krate: &Crate, verified: bool) -> crate::lock::LockStatus {
    let file = c.lock_path.display().to_string();
    let target = krate.target.arch.name();
    if !verified {
        return crate::lock::LockStatus::not_computed(&file, target, "the crate did not verify");
    }
    let t = Instant::now();
    let opts = crate::surface::SurfaceOptions { kernel_text: false, ..Default::default() };
    let surface = crate::surface::compute(out, krate, &c.sm, &opts);
    let status = crate::lock::compare(c.spec_lock.as_deref(), &surface, &file);
    if std::env::var_os("SANDBLASTER_TRACE_SPEC").is_some() {
        eprintln!("spec surface: {} item(s), {} error(s), lock {} in {:?}", surface.items.len(), surface.errors.len(), status.summary(), t.elapsed());
    }
    status
}
