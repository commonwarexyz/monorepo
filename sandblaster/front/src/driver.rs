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
//! examples and coverage, sections, law rules, `SPEC.lock`, spec mutation;
//! DESIGN.md §15.8), then the optimizer, the printer, the round trip and
//! the emission-chain check. It is the only producer of a
//! [`gates::CrateVerdict`], and only a verdict prints
//! `STATUS: VERIFIED + OPTIMIZED`, reports `VERIFIED`, lets
//! [`build_verified`] (the logic of `sandblaster::build::compile`) write
//! `OUT_DIR/sandblaster.rs`, and lets the CLI exit 0 on a verdict; the
//! variant [`gates::LockUse::Accepting`] is the only producer of the
//! permit that `crate::lock::accept` needs. Nothing selects which gates
//! run.
//!
//! **Stage APIs** ([`stage`]): the toolchain's own steps (verify, optimize,
//! print, evaluate) for its unit tests, the optimizer corpus and
//! `sandblaster eval`. Their results are never a crate verdict: stage output
//! carries the header `STATUS: STAGE OUTPUT` ([`canon::STAGE`]) and every
//! consumer of crate output rejects it.
//!
//! **The profile** (`PROFILE.json`, optimizer design §10.4) is an input of
//! the checked crate like its lock: [`check`] reads it through the file
//! provider into [`Checked::profile`], and the crate path hands its loop
//! samples to the optimizer. It changes which loop summaries are tried,
//! never what is admitted; `sandblaster profile` (a stage tool) writes it.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::canon;
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
pub mod lowered;
pub mod module;
pub mod stage;

pub use gates::{build_crate, build_crate_emitting, CrateBuild, CrateVerdict, Emission, LockUse};
pub use in_place::{build_lifted, build_lifted_with, GateUse};
pub use module::{build_module, module_file_ok, module_include_line, module_out_name};

/// Result of running the front end.
pub struct Checked {
    pub sm: SourceMap,
    pub krate: Option<Crate>,
    pub diags: Diagnostics,
    /// The source's `pub use` re-exports outside the boundary (the HIR has
    /// no place for them): printed by `canon`, compared by the round trip.
    pub reexports: Vec<canon::ReExport>,
    /// The lock of this root in its directory (DESIGN.md §15.6:
    /// `SPEC.lock` for a root named `mod.rs` or `lib.rs`, `SPEC.<stem>.lock`
    /// otherwise; [`crate::lock::lock_path`]): its path and its text
    /// (`None`: no lock), read through the file provider.
    pub lock_path: std::path::PathBuf,
    pub spec_lock: Option<String>,
    /// The optimizer's checked-in profile (`PROFILE.json` in the parent of
    /// the root's directory, [`crate::opt::cost::profile::for_root`]), when
    /// the file exists: read through the file provider, like the lock.
    pub profile: Option<ProfileInput>,
    /// The `#[lift]` modules (existing Rust lifted as-is) and what the lift
    /// assumed: a crate with a lifted exec module that is not
    /// `#[lift(host)]` emits that module's source as-is in module mode
    /// ([`gates::Emission::Module`], DESIGN.md §2.1).
    pub lifted: Vec<crate::lift::LiftedInfo>,
    pub lift_facts: crate::lift::LiftFacts,
    /// The verdict cache ([`cache`]) the crate path may reuse per-mutant
    /// verdicts of the spec-mutation gate from (and store them in): set by
    /// the build entry points that know the toolchain's identity
    /// ([`build_module`], [`build_verified_with`]); `None` (never reuse)
    /// from [`check`].
    pub cache: Option<std::sync::Arc<cache::VerdictCache>>,
}

/// A checked-in `PROFILE.json` (optimizer design §10.4): its path (a build
/// input) and its parse (a file that does not parse is ignored with a
/// warning; the profile only steers the optimizer's choices).
pub struct ProfileInput {
    pub path: std::path::PathBuf,
    pub parsed: Result<crate::opt::cost::profile::Profile, String>,
}

impl ProfileInput {
    /// The loop samples Σ2 starts from (none when the file did not parse).
    pub fn loop_samples(&self) -> std::collections::BTreeMap<String, Vec<Vec<Option<u128>>>> {
        self.parsed.as_ref().map(|p| p.loop_samples()).unwrap_or_default()
    }
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
    let profile = crate::opt::cost::profile::for_root(fs, root).map(|(path, parsed)| ProfileInput { path, parsed });
    if target.pointer_width != 64 {
        diags.push(Diagnostic::error(DiagKind::Build, Span::DUMMY, format!("sandblaster requires a 64-bit target (pointer width {})", target.pointer_width)));
    }
    let Some(loaded) = loader::load(root, fs, target, &mut sm, &mut diags) else {
        return Checked { sm, krate: None, diags, reexports: vec![], lock_path, spec_lock, profile, lifted: vec![], lift_facts: Default::default(), cache: None };
    };
    check_reserved_names(&loaded, &mut diags);
    let res = Resolver::new(&loaded, target, &mut diags);
    let mut ck = Checker::new(&res);
    ck.lower_signatures();
    ck.check_bodies();
    diags.extend(std::mem::take(&mut ck.diags));
    let mut krate = assemble(&res, &ck, target);
    // in-place lifted modules: their `pub` functions may carry `requires`
    // (host obligations, listed in the record)
    let in_place_files: std::collections::HashSet<crate::span::FileId> = loaded.lifted.iter().filter(|l| l.in_place).map(|l| l.file).collect();
    for m in krate.modules.iter_mut() {
        m.lifted = m.lifted && in_place_files.contains(&m.file);
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
    let reexports = canon::source_reexports(&res, &krate);
    let (lifted, lift_facts) = (loaded.lifted.clone(), loaded.lift_facts.clone());
    Checked { sm, krate: Some(krate), diags, reexports, lock_path, spec_lock, profile, lifted, lift_facts, cache: None }
}

/// Names the generated code declares next to the source's items: the
/// modules `__sandblaster` and `__rt` (the checked-arithmetic helpers,
/// `crate::__rt::chk`) at the top level of the generated file (beside the
/// root's boundary exports) and the trusted glue modules `__arch` and
/// `__dispatch` inside `__sandblaster` (beside the root's items). A
/// module-level name of the source spelled like one (an item, a module, a
/// `use` binding) would be defined twice (rustc E0255/E0428) or change what
/// the glue paths name.
pub const GLUE_NAMES: &[&str] = &["__sandblaster", "__arch", "__dispatch", "__rt", canon::SPEC_ROOT_NAME];

/// Rejects module-level names of the source spelled like the generated
/// code's glue ([`GLUE_NAMES`]), in every non-ghost module (ghost items are
/// never printed).
fn check_reserved_names(loaded: &loader::Loaded, diags: &mut Diagnostics) {
    fn use_names(t: &syn::UseTree, out: &mut Vec<(String, proc_macro2::Span)>) {
        match t {
            syn::UseTree::Path(p) => use_names(&p.tree, out),
            syn::UseTree::Name(n) => out.push((n.ident.to_string(), n.ident.span())),
            syn::UseTree::Rename(r) => out.push((r.rename.to_string(), r.rename.span())),
            syn::UseTree::Glob(_) => {}
            syn::UseTree::Group(g) => g.items.iter().for_each(|t| use_names(t, out)),
        }
    }
    for m in loaded.modules.iter().filter(|m| !m.ghost) {
        for it in m.items.iter().filter(|it| !it.ghost) {
            let mut names: Vec<(String, proc_macro2::Span)> = Vec::new();
            match &it.item {
                syn::Item::Const(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Static(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Fn(x) => names.push((x.sig.ident.to_string(), x.sig.ident.span())),
                syn::Item::Struct(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Enum(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Union(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Type(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Trait(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::TraitAlias(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::Mod(x) => names.push((x.ident.to_string(), x.ident.span())),
                syn::Item::ExternCrate(x) => {
                    let id = x.rename.as_ref().map(|(_, r)| r).unwrap_or(&x.ident);
                    names.push((id.to_string(), id.span()));
                }
                syn::Item::Macro(x) => names.extend(x.ident.as_ref().map(|i| (i.to_string(), i.span()))),
                syn::Item::Use(u) => use_names(&u.tree, &mut names),
                _ => {}
            }
            for (n, sp) in names {
                if GLUE_NAMES.contains(&n.as_str()) {
                    let note = if n == canon::SPEC_ROOT_NAME {
                        "the generated crate exports `pub const SANDBLASTER_SPEC_ROOT: [u8; 32]`, the Merkle root of SPEC.lock, beside the root's boundary exports (DESIGN.md §15.6); rename it"
                    } else {
                        "the generated file declares `mod __sandblaster` (every DSL module, beside the root's boundary exports), the checked-arithmetic module `__rt` beside it and the trusted glue modules `__sandblaster::__arch` and `__sandblaster::__dispatch` (DESIGN.md §2, §8.3, §9.2, §9.3); rename it"
                    };
                    diags.push(Diagnostic::error(DiagKind::Resolve, Span::from_pm2(m.file, sp), format!("the name `{n}` is reserved for the generated code")).note(note));
                }
            }
        }
    }
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

/// The report's list of the source's re-exports outside the boundary
/// ([`canon::ReExport`]): where each is, what it names, or why the
/// generated crate cannot have it.
pub(crate) fn reexports_json(k: &Crate, reexports: &[canon::ReExport]) -> Json {
    Json::Arr(
        reexports
            .iter()
            .map(|r| {
                let mut j = Json::obj();
                j.str("path", &canon::reexport_site(k, r));
                match canon::reexport_target(k, r) {
                    Ok(target) => j.str("target", &target),
                    Err(why) => j.str("unsupported", &why),
                }
                j
            })
            .collect(),
    )
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
    let variants = count(&|i| matches!(&i.kind, ItemKind::Fn(f) if f.implements.is_some()));
    let loops: usize = k.items.iter().filter_map(|i| match &i.kind {
        ItemKind::Fn(f) => Some(count_loops(f)),
        _ => None,
    }).sum();
    s.push_str(&format!("modules: {} ({} ghost)\n", k.modules.len(), k.modules.iter().filter(|m| m.ghost).count()));
    s.push_str(&format!("types: {types}, consts: {consts}\n"));
    s.push_str(&format!("exec fns: {exec} ({requires} with requires, {variants} hardware variants, {tail} tail-recursive, {nontail} depth-bounded recursive), loops: {loops}\n"));
    s.push_str(&format!("ghost: {spec} spec fns, {lemmas} lemmas, {laws} laws ({open} open claims), {proofs} proofs\n"));
    s.push_str(&format!("boundary: {}\n", k.boundary.iter().map(|e| e.name.clone()).collect::<Vec<_>>().join(", ")));
    if !c.reexports.is_empty() {
        let names: Vec<String> = c.reexports.iter().map(|r| format!("{}{}", canon::reexport_site(k, r).trim_start_matches("crate::"), if matches!(r.target, canon::ReExportTarget::Unsupported(_)) { " (not reproducible)" } else { "" })).collect();
        s.push_str(&format!("re-exports: {}\n", names.join(", ")));
    }
    s.push_str(&format!("target: {} [{}]\n", k.target.arch.name(), k.target.features.iter().cloned().collect::<Vec<_>>().join(",")));
    let (e, w) = (c.diags.error_count(), c.diags.list.iter().filter(|d| d.severity == Severity::Warning).count());
    s.push_str(&format!("diagnostics: {e} error(s), {w} warning(s)\n"));
    s.push_str(&format!("status: {} — front end only; proofs are not checked yet\n", canon::UNVERIFIED));
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

/// The single line `src/lib.rs` must consist of (plus comments), §2.
pub const LIB_RS_LINE: &str = "include!(concat!(env!(\"OUT_DIR\"), \"/sandblaster.rs\"));";

/// Removes `//` and `/* */` comments and all whitespace.
fn strip_comments_ws(s: &str) -> String {
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

/// Whether `src/lib.rs` is exactly the `include!` line (plus comments).
pub fn lib_rs_ok(text: &str) -> bool {
    strip_comments_ws(text) == strip_comments_ws(LIB_RS_LINE)
}

/// What a build script run produced (see `sandblaster::build::compile`).
#[derive(Debug, Default)]
pub struct BuildOutcome {
    /// `cargo::...` directives to print on stdout.
    pub cargo: Vec<String>,
    /// Human diagnostics for stderr.
    pub stderr: String,
    /// Files to write (`OUT_DIR/sandblaster.rs`, `OUT_DIR/sandblaster-report.json`).
    pub outputs: Vec<(std::path::PathBuf, String)>,
    pub ok: bool,
    /// Outputs that rustc compiles and the build script watches (the
    /// lowered copies of in-place files, `driver::in_place`): the facade
    /// writes them read-only with the fixed old modification time
    /// [`GUARDED_MTIME_SECS`], so the watch does not re-run the build script
    /// by itself, while any later edit of the file (newer than the build
    /// script's run) re-runs it, which rewrites the file from the verified
    /// source.
    pub guarded: Vec<std::path::PathBuf>,
}

/// The modification time of guarded outputs ([`BuildOutcome::guarded`]):
/// 2000-01-01T00:00:00Z, older than any build script run.
pub const GUARDED_MTIME_SECS: u64 = 946_684_800;

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
        canon::STAGE_RUN.to_string()
    } else {
        "NOT VERIFIED".to_string()
    }
}

/// Header note of verified output: what later phases add.
pub(crate) fn deferred_note(c: &Crate, v: &Verification) -> String {
    let variants: Vec<String> = c.items.iter().filter(|i| matches!(&i.kind, ItemKind::Fn(f) if f.implements.is_some())).map(|i| i.path.to_string()).collect();
    let mut s = String::from("Not yet done by this phase: the optimizer, get_unchecked codegen and its round trip (phase 3).");
    if !variants.is_empty() {
        s.push_str(&format!("\nHardware variants ({}) are kernel-checked but their equivalence with the portable\nfunctions is deferred to phase 3; nothing dispatches to them (the portable code always runs).", variants.join(", ")));
    }
    for (id, why) in &v.deferred {
        s.push_str(&format!("\nDeferred: {} ({why}).", c.item(*id).path));
    }
    s
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

/// The optimizer's part of the report (DESIGN.md §2: specializations with
/// reasons, variants and model-validation evidence, the round trip).
fn optimizer_report(em: &OptimizedEmit) -> (Json, Json, Json) {
    let o = &em.opt;
    let specs: Vec<Json> = o
        .fns
        .iter()
        .map(|f| {
            let mut j = Json::obj();
            j.str("function", &f.name);
            if let Some(s) = &f.set {
                j.str("variant_set", s);
            }
            match &f.outcome {
                crate::opt::Outcome::Specialized { nodes, calls, .. } => {
                    j.str("result", "Specialized");
                    j.num("residual_nodes", *nodes as i64);
                    j.put("opaque_calls", Json::Arr(calls.iter().map(|c| Json::string(c)).collect()));
                }
                crate::opt::Outcome::Unspecialized { reason, failure } => {
                    j.str("result", "Unspecialized");
                    j.str("reason", reason);
                    j.bool("optimizer_failure", *failure);
                }
            }
            // the report schema of docs/optimizer-plan.md O1 (design §5):
            // link, rung, candidates, budgets_used, facts_exported. Every
            // value is deterministic (steps and nodes, never time: G1).
            j.put(
                "link",
                match &f.link {
                    Some(crate::opt::Link::Conversion) => Json::string("Conversion"),
                    Some(crate::opt::Link::Lemma(l)) => {
                        let mut o = Json::obj();
                        o.str("Lemma", l);
                        o
                    }
                    None => Json::Null,
                },
            );
            j.put("rung", f.rung.map_or(Json::Null, |r| Json::string(r.name())));
            j.put(
                "candidates",
                Json::Arr(
                    f.candidates
                        .iter()
                        .map(|c| {
                            let mut o = Json::obj();
                            o.str("rung", c.rung.name());
                            let mut cost = Json::obj();
                            for (set, v) in &c.cost {
                                cost.num(set, *v as i64);
                            }
                            o.put("cost", cost);
                            o.bool("chosen", c.chosen);
                            o.str("reason", &c.reason);
                            if let Some(r) = &c.rejected_by {
                                o.str("rejected_by", r);
                            }
                            if c.injected {
                                o.bool("injected", true);
                            }
                            o
                        })
                        .collect(),
                ),
            );
            let mut b = Json::obj();
            b.num("symex_steps", f.budgets_used.symex_steps as i64);
            b.num("check_steps", f.budgets_used.check_steps as i64);
            b.num("residual_nodes", f.budgets_used.residual_nodes as i64);
            b.num("loopsum_steps", f.budgets_used.loopsum_steps as i64);
            j.put("budgets_used", b);
            j.put("facts_exported", Json::Arr(f.facts_exported.iter().map(|x| Json::string(x)).collect()));
            j
        })
        .collect();
    let variants: Vec<Json> = o
        .variants
        .iter()
        .map(|v| {
            let mut j = Json::obj();
            j.str("variant", &v.variant);
            j.str("implements", &v.implements);
            j.put("features", Json::Arr(v.features.iter().map(|x| Json::string(x)).collect()));
            match &v.equivalence {
                Ok((lemma, rhs, _ms)) => {
                    j.str("equivalence", "proven (VariantEquiv, kernel-checked BvRefl)");
                    j.str("lemma", lemma);
                    j.str("right_hand_side", rhs);
                }
                Err(e) => j.str("equivalence", &format!("not proven: {e}")),
            }
            let ev: Vec<Json> = v
                .evidence
                .iter()
                .map(|(m, s)| {
                    let mut e = Json::obj();
                    e.str("model", m);
                    e.str("status", s);
                    e
                })
                .collect();
            j.put("model_evidence", Json::Arr(ev));
            j.bool("dispatched", v.dispatched);
            j.str("note", &v.note);
            j
        })
        .collect();
    let mut mv = Json::obj();
    mv.put("sets", Json::Arr(o.sets.iter().map(|s| {
        let mut j = Json::obj();
        j.str("name", &s.name);
        j.put("features", Json::Arr(s.feature_set.iter().map(|x| Json::string(x)).collect()));
        j
    }).collect()));
    mv.put("clones", Json::Arr(o.clones.iter().map(|cl| {
        let mut j = Json::obj();
        j.str("clone", &cl.clone);
        j.str("original", &cl.original);
        j.str("set", &cl.set);
        j.str("relation", &match &cl.related { Ok(()) => "α-equivalent modulo the renaming (kernel alpha_eq_relevant)".to_string(), Err(e) => format!("FAILED: {e}") });
        match &cl.lemma {
            Some(l) => j.str("equality", &format!("kernel-proven lemma {l}")),
            None => j.str("equality", "by the renaming argument (DESIGN.md §9.3)"),
        }
        j
    }).collect()));
    mv.put("dispatchers", Json::Arr(o.dispatchers.iter().map(|d| Json::string(&format!("{}::{}", o.print.module(d.module).path, d.name))).collect()));
    mv.put("not_cloned", Json::Arr(o.not_cloned.iter().map(|(f, set, why)| {
        let mut j = Json::obj();
        j.str("function", f);
        j.str("set", set);
        j.str("reason", why);
        j
    }).collect()));
    mv.put("not_emitted", Json::Arr(o.not_emitted.iter().map(|(f, why)| {
        let mut j = Json::obj();
        j.str("function", f);
        j.str("reason", why);
        j
    }).collect()));
    mv.put("warnings", Json::Arr(o.warnings.iter().map(|w| Json::string(w)).collect()));
    mv.put("errors", Json::Arr(o.errors.iter().map(|w| Json::string(w)).collect()));
    let mut rt = Json::obj();
    rt.num("definitions_compared", em.roundtrip_stats.compared as i64);
    rt.num("skeletons_compared", em.roundtrip_stats.skeletons as i64);
    rt.num("glue_items_compared", em.roundtrip_stats.glue as i64);
    rt.num("reexports_compared", em.roundtrip_stats.reexports as i64);
    rt.put("api_differences", Json::Arr(em.roundtrip_stats.api_differences.iter().map(|w| Json::string(w)).collect()));
    rt.put("failures", Json::Arr(em.roundtrip.iter().map(|w| Json::string(w)).collect()));
    (Json::Arr(specs), Json::Arr(variants), { let mut j = Json::obj(); j.put("multiversioning", mv); j.put("round_trip", rt); j })
}

/// Renders `sandblaster-timing.json`: the wall-clock times of a verified
/// build (elaboration, each function's optimization, each variant proof,
/// multiversioning, the printer and the round trip). They are kept out of
/// `sandblaster-report.json`, which is byte-identical across builds of the
/// same inputs (docs/optimizer-plan.md gate G1).
pub fn timing_json(v: &Verification, em: Option<&OptimizedEmit>) -> String {
    timing_json_with(v, em, None)
}

/// [`timing_json`] with the time of the §15 gates (the crate path).
pub(crate) fn timing_json_with(v: &Verification, em: Option<&OptimizedEmit>, gates: Option<&gates::GateReport>) -> String {
    let mut j = Json::obj();
    j.num("elaborate_ms", v.elapsed.as_millis() as i64);
    if let Some(g) = gates {
        j.num("gates_ms", g.elapsed.as_millis() as i64);
        if let Some(m) = &g.mutation {
            j.num("mutation_gate_ms", m.elapsed.as_millis() as i64);
            j.num("mutation_gate_batches", m.batches.len() as i64);
            // incremental spec mutation (`mutate::cache`): cache state, so
            // here and never in the deterministic report
            j.num("mutation_cache_hits", m.cache_hits as i64);
            j.num("mutation_cache_misses", m.cache_misses as i64);
            if let Some(n) = &m.cache_note {
                j.str("mutation_cache_note", n);
            }
        }
    }
    if let Some(em) = em {
        j.num("optimize_ms", em.opt.millis as i64);
        j.num("print_us", em.print_us as i64);
        j.num("round_trip_ms", em.roundtrip_stats.millis as i64);
        j.put(
            "functions",
            Json::Arr(
                em.opt
                    .fns
                    .iter()
                    .map(|f| {
                        let mut o = Json::obj();
                        o.str("function", &f.name);
                        o.num("ms", f.millis as i64);
                        o
                    })
                    .collect(),
            ),
        );
        j.put(
            "variants",
            Json::Arr(
                em.opt
                    .variants
                    .iter()
                    .filter_map(|v| v.equivalence.as_ref().ok().map(|(_, _, ms)| (v, ms)))
                    .map(|(v, ms)| {
                        let mut o = Json::obj();
                        o.str("variant", &v.variant);
                        o.num("ms", *ms as i64);
                        o
                    })
                    .collect(),
            ),
        );
    }
    j.render()
}

/// Renders `sandblaster-report.json`: the proofs, the optimizer's sections,
/// the `SPEC.lock` status, the §15 records and, on the crate path, the
/// gates and the emitted file. `status` is the verdict line: the crate
/// path's (only [`gates::build_crate`] passes `VERIFIED`) or a stage
/// status ([`status_str`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_report(c: &Checked, v: &Verification, law_audit: &[LawAudit], root_display: &str, em: Option<&OptimizedEmit>, spec: Option<&crate::lock::LockStatus>, s15: Option<&Spec15Report>, status: &str, gates: Option<&gates::GateReport>) -> String {
    let mut j = Json::obj();
    j.str("sandblaster", env!("CARGO_PKG_VERSION"));
    j.str("status", status);
    j.num("phase", if em.is_some() { 3 } else { 2 });
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
        // hardware variants
        let variants: Vec<Json> = k
            .items
            .iter()
            .filter_map(|it| match &it.kind {
                ItemKind::Fn(f) if f.implements.is_some() => {
                    let mut o = Json::obj();
                    o.str("variant", &it.path.to_string());
                    o.str("implements", &k.item(f.implements.unwrap()).path.to_string());
                    o.put("features", Json::Arr(f.feature_set.iter().map(|x| Json::string(x)).collect()));
                    let def = v.defs.iter().find(|d| d.item == Some(it.id));
                    o.str("definition", &def.map(|d| def_status_str(&d.status)).unwrap_or_else(|| "not elaborated".into()));
                    o.str("equivalence", "deferred (phase 3)");
                    o.str("dispatch", "none (the portable function always runs)");
                    Some(o)
                }
                _ => None,
            })
            .collect();
        match em {
            Some(em) => {
                let (specs, vars, extra) = optimizer_report(em);
                j.put("variants", vars);
                j.put("specializations", specs);
                j.put("optimizer", extra);
            }
            None => j.put("variants", Json::Arr(variants)),
        }
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
        j.put("reexports", reexports_json(k, &c.reexports));
        if em.is_none() {
            j.put("specializations", Json::Arr(vec![]));
        }
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
                "target semantics library (sandblaster/targets/core/*.core) and dispatch glue",
                "the elaboration semantics of the canonical dialect read back by the round trip (roundtrip.rs lowering)",
                "dispatch glue and load/store helpers (fixed templates)",
                "rustc/LLVM",
                "the elaboration of the ghost language (SEMANTICS.md §13) and Env::abstract_section (DESIGN.md §1.1 item 6)",
                "assumptions (DESIGN.md §1.1 item 7): num-bigint/num-integer, the rustc that compiled the kernel, syn agreeing with rustc on the canonical dialect, the §3.7 stack assumption, runtime feature detection, a process free of undefined behaviour",
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

/// The build logic of `sandblaster::build::compile` (DESIGN.md §10.1),
/// independent of the process environment: `env` reads build-script
/// environment variables, `fs` reads sources.
///
/// 1. reads `CARGO_MANIFEST_DIR`, `OUT_DIR` and the `CARGO_CFG_*` target;
/// 2. checks that `src/lib.rs` is exactly the `include!` line;
/// 3. runs the crate path on `root` ([`gates::build_crate`] with
///    [`LockUse::Enforce`]): front end, proofs, law audit, every §15 gate,
///    optimizer, printer, round trip, emission-chain check;
/// 4. with a [`CrateVerdict`] writes `OUT_DIR/sandblaster.rs` (marked
///    `VERIFIED + OPTIMIZED`), `OUT_DIR/sandblaster-report.json` and
///    `OUT_DIR/sandblaster-timing.json`; without one prints the diagnostics
///    and writes only the report and the timing (to diagnose the failure).
///
/// There is no option: no environment variable, flag or attribute skips
/// or weakens a proof or a gate (DESIGN.md §15.8).
pub fn build_verified(root: &str, env: &dyn Fn(&str) -> Option<String>, fs: &dyn FileProvider) -> BuildOutcome {
    build_verified_with(root, None, env, fs)
}

/// [`build_verified`] with the verifier's identity `context` (the facade
/// passes [`cache::verifier_context`]: the toolchain's content hash and
/// what else can change a result): the verdict is looked up in, and stored to, the shared
/// verdict cache ([`cache`]) under the verdict key of module mode
/// (`crate` as the emission), and the spec-mutation gate reuses the
/// per-mutant verdicts whose inputs did not change. `None`: nothing is
/// reused (as [`build_verified`]).
pub fn build_verified_with(root: &str, context: Option<&str>, env: &dyn Fn(&str) -> Option<String>, fs: &dyn FileProvider) -> BuildOutcome {
    let mut o = BuildOutcome::default();
    let fail = |mut o: BuildOutcome, msg: String| {
        o.stderr.push_str(&format!("error[build]: {msg}\n"));
        o.ok = false;
        o
    };
    let Some(manifest) = env("CARGO_MANIFEST_DIR") else { return fail(o, "CARGO_MANIFEST_DIR is not set (run from a build script)".into()) };
    let Some(out_dir) = env("OUT_DIR") else { return fail(o, "OUT_DIR is not set (run from a build script)".into()) };
    let manifest = std::path::PathBuf::from(manifest);
    let out_dir = std::path::PathBuf::from(out_dir);
    for k in ["CARGO_CFG_TARGET_ARCH", "CARGO_CFG_TARGET_FEATURE", "CARGO_CFG_TARGET_ENDIAN", "CARGO_CFG_TARGET_POINTER_WIDTH"] {
        o.cargo.push(format!("cargo::rerun-if-env-changed={k}"));
    }
    let target = match TargetInfo::from_cargo_env(env) {
        Ok(t) => t,
        Err(e) => return fail(o, e),
    };
    let lib = manifest.join("src/lib.rs");
    o.cargo.push(format!("cargo::rerun-if-changed={}", lib.display()));
    match fs.read(&lib) {
        Ok(text) if lib_rs_ok(&text) => {}
        Ok(_) => return fail(o, format!("`{}` must contain exactly `{LIB_RS_LINE}` (plus comments), so host code cannot live next to generated code (DESIGN.md §2)", lib.display())),
        Err(e) => return fail(o, format!("cannot read `{}`: {e}", lib.display())),
    }
    let root_path = manifest.join(root);
    if let Some(dir) = root_path.parent() {
        o.cargo.push(format!("cargo::rerun-if-changed={}", dir.display()));
    }
    let mut checked = check(&root_path, fs, &target);
    watch_existing(&mut o, fs, checked.sm.files().map(|(_, f)| f.path.as_path()));
    if checked.lifted.iter().any(|l| !l.ghost) {
        return fail(o, format!("`{}` lifts existing Rust (`#[lift]`): lifted code names host items through `crate::`, so it is emitted in module mode (`sandblaster::build::compile_module`), never as a whole crate (DESIGN.md §2.1)", root_path.display()));
    }
    // the lock is an input whether or not it exists yet (a missing lock is
    // noticed through the watched root directory)
    watch_existing(&mut o, fs, [checked.lock_path.as_path()]);
    let rendered = checked.render();
    if !checked.ok() {
        o.stderr.push_str(&rendered);
        o.stderr.push_str(&format!("\nerror: sandblaster: {} error(s) in `{}`\n", checked.diags.error_count(), root_path.display()));
        o.ok = false;
        return o;
    }
    if !rendered.is_empty() {
        o.stderr.push_str(&rendered);
    }
    // the checked-in profile is an input of the checked crate (optimizer
    // design §10.4): `build_crate` hands it to the optimizer
    if let Some(p) = &checked.profile {
        watch_existing(&mut o, fs, [p.path.as_path()]);
        if let Err(e) = &p.parsed {
            o.cargo.push(format!("cargo::warning=sandblaster: profile `{}` ignored: {}", p.path.display(), e.replace('\n', " ")));
        }
    }
    o.cargo.push("cargo::rerun-if-env-changed=SANDBLASTER_STRICT_OPT".into());
    o.cargo.push("cargo::rerun-if-env-changed=SANDBLASTER_MEM_LIMIT_GB".into());
    // the shared verdict cache (`driver::cache`)
    let key = context.map(|ctx| module::verdict_key(ctx, env, fs, &root_path, "crate", &checked));
    let cache = module::open_cache(context, env, &mut o);
    if let (Some(k), Some(vc)) = (&key, &cache) {
        match module::reuse_cached(vc, k, &out_dir.join("sandblaster.rs"), &[out_dir.join("sandblaster-report.json"), out_dir.join("sandblaster-timing.json")], &mut o) {
            Some(_) => {
                o.cargo.push(format!("cargo::warning=sandblaster: verified `{root}` unchanged (verdict key {}): reusing the verdict cache entry in `{}`", &k[..16], vc.store.dir().display()));
                o.ok = true;
                return o;
            }
            None => checked.cache = Some(std::sync::Arc::new(vc.clone())),
        }
    }
    let root_display = root_path.display().to_string();
    let b = build_crate(&checked, LockUse::Enforce, &root_display);
    for w in b.optimizer_warnings() {
        o.cargo.push(format!("cargo::warning=sandblaster optimizer: {}", w.replace('\n', " ")));
    }
    for w in b.api_differences() {
        o.cargo.push(format!("cargo::warning=sandblaster: public API difference: {}", w.replace('\n', " ")));
    }
    o.outputs.push((out_dir.join("sandblaster-report.json"), b.report.clone()));
    o.outputs.push((out_dir.join("sandblaster-timing.json"), b.timing.clone()));
    let Some(verdict) = &b.verdict else {
        o.stderr.push_str(&b.render_failure(&checked, &root_path.display().to_string()));
        o.ok = false;
        return o;
    };
    o.outputs.insert(0, (out_dir.join("sandblaster.rs"), verdict.code().to_string()));
    if let (Some(k), Some(vc)) = (&key, &cache) {
        module::store_cached(vc, k, verdict.code(), &b.report, &b.timing, &mut o);
    }
    o.cargo.push(format!("cargo::warning=sandblaster: verified `{root}`: {}", verdict.summary()));
    o.ok = true;
    o
}

// ---------------------------------------------------------------------------
// Optimized pipeline (phase 3)
// ---------------------------------------------------------------------------

/// The result of [`optimize_emit`].
pub struct OptimizedEmit {
    /// The generated file (only meaningful when `errors` is empty).
    pub code: String,
    pub opt: crate::opt::Optimized,
    /// Round-trip failures (DESIGN.md §8.3); non-empty is a build error.
    pub roundtrip: Vec<String>,
    /// Round-trip statistics (definitions compared, …).
    pub roundtrip_stats: crate::roundtrip::Stats,
    /// Wall-clock microseconds of the printer (`sandblaster-timing.json`).
    pub print_us: u128,
}

/// The `SAFETY:` comment tables of the printer: kernel definition of each
/// printed exec function and the obligations by source span.
pub(crate) fn opt_print<'a>(out: &crate::elab::Output, o: &'a crate::opt::Optimized, reexports: &'a [canon::ReExport]) -> canon::OptPrint<'a> {
    use std::collections::HashMap;
    let mut kernel_def = HashMap::new();
    for (item, (_, compare)) in &o.targets {
        if let Some(n) = out.env.global_name(*compare) {
            kernel_def.insert(*item, n.to_string());
        }
    }
    let mut obligations: HashMap<Span, Vec<(String, &'static str, u32)>> = HashMap::new();
    for ob in &out.obligations {
        obligations.entry(ob.span).or_default().push((ob.def.clone(), crate::elab::obl::kind_name(&ob.kind), ob.id));
    }
    canon::OptPrint { dispatchers: &o.dispatchers, sets: &o.sets, kernel_def, obligations, exec_only: false, reexports, spec_root: [0; 32], verdict: None }
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
/// goals' outcome, which the step budgets alone must decide (the optimizer
/// and the law audit fall back on a failed goal, so a trip could otherwise
/// change what is emitted or accepted). Reported once; per-obligation trips
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

/// Optimizes, prints and round-trips an elaboration whose proofs checked,
/// exporting `spec_root` as `SANDBLASTER_SPEC_ROOT` (DESIGN.md §15.6; zero
/// when the specification is not locked). The header is the crate
/// verdict's only with `seal` (which only the crate gate holds), the stage
/// header otherwise.
#[allow(clippy::too_many_arguments)]
pub(crate) fn optimize_emit_rooted(c: &Checked, out: &mut crate::elab::Output, root_display: &str, note: &str, opts: &crate::opt::OptOptions, exec_only: bool, spec_root: [u8; 32], seal: Option<&gates::GatesPassed>) -> Result<OptimizedEmit, String> {
    let k = c.krate.as_ref().ok_or("no crate")?;
    let mut o = crate::opt::optimize(out, k, opts);
    o.errors.extend(printed_name_collisions(k, &o, &c.reexports));
    let mut op = opt_print(out, &o, &c.reexports);
    op.exec_only = exec_only;
    op.spec_root = spec_root;
    op.verdict = seal;
    let t = Instant::now();
    let code = canon::print_crate_optimized(&o.print, &c.sm, root_display, note, op);
    let print_us = t.elapsed().as_micros();
    let (roundtrip, roundtrip_stats) = match crate::roundtrip::check(&code, &o, out, &c.sm, &c.reexports) {
        Ok(s) => (s.failures.clone(), s),
        Err(e) => (vec![e], Default::default()),
    };
    Ok(OptimizedEmit { code, opt: o, roundtrip, roundtrip_stats, print_us })
}

/// The namespaces a module-level name of the generated file occupies
/// (rustc's type and value namespaces; macros are never printed).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum PrintedNs {
    Type,
    Value,
}

/// Names the optimized output would bind twice in one namespace of one
/// scope (rustc E0428/E0255/E0252): the optimizer names multiversioned
/// clones `<f>__<set>` and portable functions `<f>__portable` in the
/// module of `f`, and boundary dispatchers `<f>`; the generated code
/// declares `__sandblaster` and `__rt` at the top level and `__arch` /
/// `__dispatch` in the root of `__sandblaster`. A source name spelled like one of them (an item, a module, a
/// `pub use`, renames included) is reported here with what to rename (red
/// team: `pub use self::K as top__sha2;` beside the clone `top__sha2`). The
/// round trip checks the same independently, from the printed text
/// (`roundtrip`, *Name resolution*).
fn printed_name_collisions(k: &Crate, o: &crate::opt::Optimized, reexports: &[canon::ReExport]) -> Vec<String> {
    use std::collections::BTreeMap;
    use canon::ReExportTarget as RT;
    use PrintedNs::{Type as T, Value as V};
    let pv = &o.print;
    fn item_ns(pv: &Crate, id: ItemId) -> &'static [PrintedNs] {
        match &pv.item(id).kind {
            ItemKind::Fn(_) | ItemKind::Const(_) => &[V],
            ItemKind::Struct(s) if s.shape != hir::Shape::Named => &[T, V],
            ItemKind::Struct(_) | ItemKind::Enum(_) | ItemKind::TypeAlias(_) => &[T],
        }
    }
    let reexport_ns = |r: &canon::ReExport| -> &'static [PrintedNs] {
        match &r.target {
            RT::Item(id) => item_ns(pv, *id),
            RT::Module(_) => &[T],
            RT::Variant(e, v) => match &pv.item(*e).kind {
                ItemKind::Enum(en) if en.variants.get(*v as usize).is_some_and(|x| x.shape == hir::Shape::Named) => &[T],
                _ => &[T, V],
            },
            RT::External { path, .. } => {
                let segs: Vec<&str> = path.trim_start_matches("::").split("::").collect();
                match segs.as_slice() {
                    [.., "Option", "Some" | "None"] => &[T, V],
                    ["core", "arch", _, name] if crate::intrinsics::lookup(&pv.target.arch, name).is_some() => &[V],
                    _ => &[T],
                }
            }
            RT::Unsupported(_) => &[],
        }
    };
    let generated = |id: ItemId| id.0 as usize >= k.items.len() || k.item(id).name != pv.item(id).name;
    let describe = |id: ItemId| {
        let it = pv.item(id);
        if id.0 as usize >= k.items.len() {
            format!("the optimizer's multiversioned clone `{}`", it.path)
        } else if k.item(id).name != it.name {
            format!("the optimizer's portable function `{}` (`{}` renamed)", it.path, k.item(id).path)
        } else {
            let what = match &it.kind {
                ItemKind::Fn(_) => "function",
                ItemKind::Const(_) => "constant",
                ItemKind::Struct(_) => "struct",
                ItemKind::Enum(_) => "enum",
                ItemKind::TypeAlias(_) => "type alias",
            };
            format!("the {what} `{}`", it.path)
        }
    };
    // (scope, name) → namespace → what binds it, and whether the optimizer
    // or the glue made it
    type Binders = BTreeMap<PrintedNs, Vec<(String, bool)>>;
    let mut binds: BTreeMap<(String, String), Binders> = BTreeMap::new();
    let mut add = |scope: &str, ns: &[PrintedNs], name: &str, what: String, generated: bool| {
        let e = binds.entry((scope.to_string(), name.to_string())).or_default();
        for n in ns {
            e.entry(*n).or_default().push((what.clone(), generated));
        }
    };
    let clean = |s: &str| s.strip_prefix("r#").unwrap_or(s).to_string();
    let exported_mods = canon::exported_modules_with(pv, reexports);
    let printed = |r: &canon::ReExport| canon::reexport_text(pv, &o.dispatchers, &exported_mods, r, 0).is_some();
    let top = "the top level of the generated file";
    add(top, &[T], "__sandblaster", "the generated module `__sandblaster`".into(), true);
    add(top, &[T], "__rt", "the checked-arithmetic glue module `__rt`".into(), true);
    add(top, &[V], canon::SPEC_ROOT_NAME, format!("the specification root `{}` (DESIGN.md §15.6)", canon::SPEC_ROOT_NAME), true);
    for e in &pv.boundary {
        let ns = match e.target {
            hir::ExportTarget::Item(i) => item_ns(pv, i),
            hir::ExportTarget::Module(_) => &[T],
        };
        add(top, ns, &clean(&e.name), format!("the boundary export `{}`", e.name), false);
    }
    for m in pv.modules.iter().filter(|m| !m.ghost) {
        let scope = format!("module `{}`", m.path);
        let root = m.id == pv.root;
        if root {
            for g in ["__arch", "__dispatch"] {
                add(&scope, &[T], g, format!("the trusted glue module `__sandblaster::{g}`"), true);
            }
        }
        for &id in &m.items {
            let it = pv.item(id);
            let printed_item = !it.ghost
                && match &it.kind {
                    ItemKind::Fn(f) => f.kind == hir::FnKind::Exec && f.owner.is_none(),
                    _ => true,
                };
            if printed_item {
                add(&scope, item_ns(pv, id), &clean(&it.name), describe(id), generated(id));
            }
        }
        for d in o.dispatchers.iter().filter(|d| d.module == m.id) {
            add(&scope, &[V], &clean(&d.name), format!("the optimizer's boundary dispatcher `{}`", m.path.child(&d.name)), true);
        }
        for &c in &m.submodules {
            let cm = pv.module(c);
            if !cm.ghost {
                add(&scope, &[T], &clean(&cm.name), format!("the module `{}`", cm.path), false);
            }
        }
        for r in reexports.iter().filter(|r| r.module == m.id && printed(r)) {
            let at = if root { top.to_string() } else { scope.clone() };
            add(&at, reexport_ns(r), &clean(&r.name), format!("the re-export `{}` (a `pub use` of the source)", canon::reexport_site(pv, r)), false);
        }
    }
    let mut out = Vec::new();
    for ((scope, name), by_ns) in &binds {
        let Some((ns, bs)) = by_ns.iter().find(|(_, bs)| bs.len() > 1) else { continue };
        let list: Vec<&str> = bs.iter().map(|(w, _)| w.as_str()).collect();
        let hint = if bs.iter().any(|(_, g)| *g) {
            format!("; the optimizer names multiversioned clones `<f>__<set>`, portable functions `<f>__portable` and boundary dispatchers `<f>`, and the generated code declares `__sandblaster`, `__rt`, `__arch` and `__dispatch`: rename the source's `{name}`")
        } else {
            String::new()
        };
        out.push(format!("{scope}: {} have the same name `{name}` in the {} namespace of the generated code (rustc E0428/E0255/E0252){hint}", list.join(" and "), if *ns == T { "type" } else { "value" }));
    }
    out
}
