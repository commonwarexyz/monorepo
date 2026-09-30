//! **Stage APIs** of the pipeline: the toolchain's own steps (verify,
//! optimize, print, evaluate a module), used by its unit tests, the
//! optimizer corpus and `sandblaster eval`.
//!
//! Nothing here is a crate verdict (DESIGN.md §15.8, stage boundary). No
//! function of this module runs the §15 gates, prints or returns
//! `VERIFIED`, writes `OUT_DIR` files or `SPEC.lock`, or produces a
//! [`super::gates::CrateVerdict`]: stage output carries the header
//! `STATUS: STAGE OUTPUT (not a crate verdict: the §15 gates did not run)`
//! ([`canon::STAGE`]), and every consumer of crate output (the `include!`
//! glue, the bench and oracle `build.rs` files, `cgen`) rejects it. The
//! crate paths — `sandblaster::build::compile`, every CLI command that prints
//! a crate verdict — go through [`super::gates::build_crate`], the only
//! constructor of a verdict.

use std::time::Instant;

use crate::canon;
use crate::diag::Severity;
use crate::elab::{self, DefStatus};
use crate::hir::{self, Crate, ItemId, ItemKind, LawProof, Recursion};
use crate::json::Json;
use crate::span::SourceMap;

use super::{apply_law_audit, count_loops, def_status_str, kind_name, optimize_emit_rooted, reexports_json, resource_gate, spec15_report, spec_status, Checked, LawAudit, OptimizedEmit, Spec15Report, Verification, VerifyOptions};

/// Prints the canonical code of an error-free crate, front end only
/// (header `UNVERIFIED (phase 1)`): a toolchain test of the printer.
pub fn emit(c: &Checked, root_display: &str) -> Option<String> {
    if !c.ok() {
        return None;
    }
    Some(canon::print_crate(c.krate.as_ref()?, &c.sm, root_display, &c.reexports))
}

/// The front-end report (status `UNVERIFIED (phase 1)`): a toolchain
/// test of the report's shape, never a crate report.
pub fn front_end_report_json(c: &Checked, root_display: &str) -> String {
    let mut j = Json::obj();
    j.str("sandblaster", env!("CARGO_PKG_VERSION"));
    j.str("status", canon::UNVERIFIED);
    j.num("phase", 1);
    j.str("root", root_display);
    let files: Vec<Json> = c.sm.files().map(|(_, f)| Json::string(&f.path.display().to_string())).collect();
    j.put("files", Json::Arr(files));
    let mut warnings = Vec::new();
    for d in &c.diags.list {
        if d.severity == Severity::Warning {
            warnings.push(Json::string(&d.render(&c.sm)));
        }
    }
    if let Some(k) = &c.krate {
        let mut t = Json::obj();
        t.str("arch", k.target.arch.name());
        t.put("features", Json::Arr(k.target.features.iter().map(|f| Json::string(f)).collect()));
        t.str("endian", if k.target.little_endian { "little" } else { "big" });
        t.num("pointer_width", k.target.pointer_width as i64);
        j.put("target", t);
        let reach: std::collections::HashSet<ItemId> = k.reachable.iter().copied().collect();
        let mut defs = Vec::new();
        let mut laws = Vec::new();
        let mut variants = Vec::new();
        for it in &k.items {
            let mut d = Json::obj();
            d.str("path", &it.path.to_string());
            d.str("kind", kind_name(&it.kind));
            d.bool("ghost", it.ghost);
            d.bool("boundary", reach.contains(&it.id) && it.vis == hir::Vis::Public);
            if let ItemKind::Fn(f) = &it.kind {
                d.num("requires", f.requires.len() as i64);
                d.bool("ensures", f.ensures.is_some());
                match &f.decreases {
                    Some(dec) => {
                        let mut o = Json::obj();
                        if let Some(m) = dec.max {
                            o.num("max", m as i64);
                        }
                        d.put("decreases", o);
                    }
                    None => d.put("decreases", Json::Null),
                }
                d.str("recursion", match f.recursion {
                    Recursion::None => "none",
                    Recursion::Tail => "tail",
                    Recursion::NonTail => "non-tail",
                });
                d.num("loops", count_loops(f) as i64);
                d.put("target_features", Json::Arr(f.target_features.iter().map(|x| Json::string(x)).collect()));
                d.put("implements", f.implements.map(|i| Json::string(&k.item(i).path.to_string())).unwrap_or(Json::Null));
                d.bool("specialize", f.specialize);
                if let Some(target) = f.implements {
                    let mut v = Json::obj();
                    v.str("variant", &it.path.to_string());
                    v.str("implements", &k.item(target).path.to_string());
                    v.put("features", Json::Arr(f.feature_set.iter().map(|x| Json::string(x)).collect()));
                    v.str("equivalence", "not proven (phase 1)");
                    v.str("model_validation", "not checked (phase 1)");
                    variants.push(v);
                }
                if let Some(lp) = f.law_proof {
                    let mut l = Json::obj();
                    l.str("law", &it.path.to_string());
                    l.str("proof", &match lp {
                        LawProof::Inline => "inline".to_string(),
                        LawProof::Item(p) => k.item(p).path.to_string(),
                        LawProof::Missing => "missing (open claim)".to_string(),
                    });
                    l.str("status", "not checked (phase 1)");
                    laws.push(l);
                }
            }
            defs.push(d);
        }
        j.put("definitions", Json::Arr(defs));
        j.put("laws", Json::Arr(laws));
        j.put("boundary", Json::Arr(k.boundary.iter().map(|e| Json::string(&e.name)).collect()));
        j.put("reexports", reexports_json(k, &c.reexports));
        let mut ob = Json::obj();
        ob.str("note", "obligations are generated by the elaborator (phase 2); none were checked");
        j.put("obligations", ob);
        j.put("specializations", Json::Arr(vec![]));
        j.put("variants", Json::Arr(variants));
    }
    j.put(
        "tcb",
        Json::Arr(
            ["sandblaster-kernel (checker, evaluator, linarith, bvnorm, axioms)", "elaboration semantics of the canonical dialect", "prelude definitions (sandblaster/kernel/prelude/*.core)", "target semantics library and dispatch glue", "rustc/LLVM"]
                .iter()
                .map(|s| Json::string(s))
                .collect(),
        ),
    );
    j.put("warnings", Json::Arr(warnings));
    j.render()
}



/// Runs `f` on the elaboration of `krate`, on the big-stack elaboration
/// thread (the kernel environment is not `Send`; everything `f` needs from
/// it must be computed inside).
pub fn with_elaboration<T: Send>(krate: &Crate, opts: &VerifyOptions, f: impl FnOnce(&elab::Output) -> T + Send) -> T {
    elab::with_big_stack(|| {
        let mut chain = opts.chain();
        let out = elab::elaborate(krate, &mut chain, &opts.elab_options());
        f(&out)
    })
}

/// Elaborates and checks the crate: every definition, obligation and law,
/// the law audit and the resource gate (the proofs of a crate; no §15
/// gate). Without a source map, law statements in the audit are printed
/// from the kernel only.
pub fn verify(krate: &Crate, opts: &VerifyOptions) -> Verification {
    verify_with_sources(krate, opts, &SourceMap::new())
}

/// [`verify`] with the source map (law statements as written).
pub fn verify_with_sources(krate: &Crate, opts: &VerifyOptions, sm: &SourceMap) -> Verification {
    verify_audited(krate, opts, sm).0
}

/// [`verify_with_sources`], also returning the law audit
/// ([`super::audit_laws`]).
pub fn verify_audited(krate: &Crate, opts: &VerifyOptions, sm: &SourceMap) -> (Verification, Vec<LawAudit>) {
    let t = Instant::now();
    let provers: Vec<String> = opts.chain().provers.iter().map(|(n, _)| n.clone()).collect();
    let mut v = with_elaboration(krate, opts, |out| {
        let mut v = Verification::of(out, opts.exec_only);
        let audit = apply_law_audit(&mut v, out, krate, sm);
        resource_gate(&mut v);
        (v, audit)
    });
    v.0.elapsed = t.elapsed();
    v.0.provers = provers;
    v
}

/// Prints the (unoptimized) canonical code of a crate whose proofs
/// checked, with the stage header (`None` unless
/// [`Verification::proofs_ok`]).
pub fn emit_stage(c: &Checked, v: &Verification, root_display: &str) -> Option<String> {
    if !c.ok() || !v.proofs_ok {
        return None;
    }
    let k = c.krate.as_ref()?;
    Some(canon::print_crate_stage(k, &c.sm, root_display, &super::deferred_note(k, v), &c.reexports))
}

/// Evaluates `f(args)` with the kernel evaluator on an elaboration (the
/// reference semantics, DESIGN.md §10.2): `fn_path` is the item's display
/// path (`crate::m::f`, or `m::f`), `args` a JSON array with one value per
/// parameter (formats in [`elab::value`]). Irrelevant arguments (proofs
/// of `requires`) are erased; the caller is responsible for supplying
/// arguments that satisfy the preconditions (evaluation of a checked
/// primitive outside its domain is stuck and reported). Every definition
/// must have been checked (a placeholder would evaluate to garbage).
pub fn eval_in(out: &elab::Output, krate: &Crate, fn_path: &str, args: &str) -> Result<String, String> {
    use sandblaster_kernel::term::{Lvl, Rel, Term, Tm};
    use sandblaster_kernel::util::mk;
    use sandblaster_kernel::value::{Budget, VEnv};
    let path = if fn_path.starts_with("crate::") { fn_path.to_string() } else { format!("crate::{fn_path}") };
    let id = krate.find(&path).ok_or_else(|| format!("no item `{path}`"))?;
    let f = krate.fn_def(id).ok_or_else(|| format!("`{path}` is not a function"))?;
    if !f.generics.is_empty() {
        return Err(format!("`{path}` is generic; eval needs a monomorphic function"));
    }
    let bad: Vec<String> = out.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).map(|d| format!("{} ({})", d.name, def_status_str(&d.status))).collect();
    if !bad.is_empty() {
        return Err(format!("eval needs every definition checked; not checked: {}", bad.join(", ")));
    }
    let g = *out.fn_globals.get(&id).ok_or_else(|| format!("`{path}` was not elaborated"))?;
    let rels = out.env.global_param_rels(g).ok_or("no parameter list")?;
    let j = elab::value::J::parse(args)?;
    let elab::value::J::Arr(vals) = j else { return Err("arguments must be a JSON array".into()) };
    // `#[ghost]` parameters (`Irr` binders, DESIGN.md §15.3) take no value
    let vparams: Vec<&crate::hir::Param> = f.params.iter().filter(|p| !p.ghost).collect();
    let nrel = rels.iter().filter(|r| **r == Rel::Rel).count();
    if nrel != vparams.len() || vals.len() != vparams.len() {
        return Err(format!("`{path}` takes {} argument(s), got {}", vparams.len(), vals.len()));
    }
    let conv = elab::value::Conv { env: &out.env, krate, adts: &out.adts };
    let mut rel_args = vparams.iter().zip(&vals).map(|(p, x)| conv.term(&p.ty, x));
    let mut args: Vec<(Rel, Tm)> = Vec::new();
    for r in rels {
        let a = match r {
            Rel::Rel => rel_args.next().ok_or("argument mismatch")??,
            Rel::Irr => std::rc::Rc::new(Term::Erased),
        };
        args.push((r, a));
    }
    let term = mk::apps(mk::global(g), args);
    let mut b = Budget { steps: 50_000_000_000 };
    let t = Instant::now();
    let v = out.env.eval_opaque(&VEnv::default(), Lvl(0), &term, &|_| false, &mut b).map_err(|e| format!("evaluation failed: {e:?}"))?;
    // The kernel unfolds a recursive global only when a speculative
    // evaluation of its body is not stuck on a match (DESIGN.md §5.6) — a
    // policy made for conversion checking, under which non-tail recursion
    // that inspects its own result (`match path(..) { .. }`) stays folded.
    // The reference evaluator unfolds such applications itself (see
    // [`Unfolder`]).
    let mut u = Unfolder { env: &out.env, rounds: 0, b: &mut b };
    let v = u.deep(v)?;
    let rounds = u.rounds;
    let t_eval = t.elapsed();
    let r = conv.json(&f.ret, &v)?.render();
    if std::env::var_os("SANDBLASTER_TRACE_EVAL").is_some() {
        eprintln!("eval {path}: evaluated in {t_eval:?} ({rounds} manual unfolding(s)), read back in {:?}", t.elapsed() - t_eval);
    }
    Ok(r)
}

/// Maximum number of manual unfoldings of stuck recursive applications in
/// one [`eval_in`].
const MAX_UNFOLDS: u32 = 1 << 20;

/// The reference evaluation of a closed term, as [`eval_in`] does it (the
/// kernel's evaluator with every definition transparent, then the
/// completion of stuck recursive applications), with a step budget: for the
/// lift conformance check ([`crate::conform`]) on arguments that carry
/// erased proofs (invariant fields), which `Env::eval_closed` rejects.
pub(crate) fn eval_reference(env: &sandblaster_kernel::api::Env, term: &sandblaster_kernel::term::Tm, steps: u64) -> Result<sandblaster_kernel::value::V, String> {
    use sandblaster_kernel::term::Lvl;
    use sandblaster_kernel::value::{Budget, VEnv};
    let mut b = Budget { steps };
    let v = env.eval_opaque(&VEnv::default(), Lvl(0), term, &|_| false, &mut b).map_err(|e| format!("evaluation failed: {e:?}"))?;
    let mut u = Unfolder { env, rounds: 0, b: &mut b };
    u.deep(v)
}

/// Completes an evaluation on closed arguments (the reference semantics):
/// a neutral headed by a recursive global applied to values is unfolded —
/// its body is evaluated in the environment of its arguments, exactly what
/// the kernel does when its policy allows — and the neutral's eliminators
/// are then applied to the result (a `match` on a constructor picks its
/// arm). Constructor fields and pair components are completed recursively.
/// Only public kernel operations are used (`eval_opaque` of terms in value
/// environments); nothing is quoted.
struct Unfolder<'e, 'b> {
    env: &'e sandblaster_kernel::api::Env,
    rounds: u32,
    b: &'b mut sandblaster_kernel::value::Budget,
}

impl Unfolder<'_, '_> {
    fn eval(&mut self, entries: Vec<sandblaster_kernel::value::EnvEntry>, t: &sandblaster_kernel::term::Tm) -> Result<sandblaster_kernel::value::V, String> {
        use sandblaster_kernel::term::Lvl;
        use sandblaster_kernel::value::VEnv;
        self.env.eval_opaque(&VEnv(std::rc::Rc::new(entries)), Lvl(0), t, &|_| false, self.b).map_err(|e| format!("evaluation failed: {e:?}"))
    }

    fn entry(a: &sandblaster_kernel::value::Arg) -> sandblaster_kernel::value::EnvEntry {
        use sandblaster_kernel::value::{Arg, EnvEntry};
        match a {
            Arg::Rel(v) => EnvEntry::Rel(v.clone()),
            Arg::Irr(c) => EnvEntry::Irr(c.clone()),
        }
    }

    /// Unfolds the head of `v` while it is a stuck recursive application.
    fn force(&mut self, v: sandblaster_kernel::value::V) -> Result<sandblaster_kernel::value::V, String> {
        use sandblaster_kernel::term::{Rel, Term};
        use sandblaster_kernel::util::mk;
        use sandblaster_kernel::value::{Arg, Elim, EnvEntry, Head, Value};
        let mut v = v;
        loop {
            let Value::Neu(n) = &*v else { return Ok(v) };
            let Head::Global { def, args } = &n.head else { return Ok(v) };
            let Some(body) = self.env.global_body(*def) else { return Ok(v) };
            let arity = self.env.global_arity(*def).unwrap_or(0) as usize;
            if args.len() != arity || self.rounds >= MAX_UNFOLDS {
                return Ok(v);
            }
            // strip the λ-telescope
            let mut inner = body;
            for _ in 0..arity {
                let next = match &*inner {
                    Term::Lam { body, .. } => body.clone(),
                    _ => return Ok(v),
                };
                inner = next;
            }
            self.rounds += 1;
            let mut hv = self.eval(args.iter().map(Self::entry).collect(), &inner)?;
            for e in &n.spine {
                hv = self.force(hv)?;
                hv = match e {
                    Elim::App(a) => {
                        let rel = if matches!(a, Arg::Rel(_)) { Rel::Rel } else { Rel::Irr };
                        self.eval(vec![EnvEntry::Rel(hv), Self::entry(a)], &mk::apps(mk::var(1), [(rel, mk::var(0))]))?
                    }
                    Elim::Fst => self.eval(vec![EnvEntry::Rel(hv)], &mk::fst(mk::var(0)))?,
                    Elim::Snd => self.eval(vec![EnvEntry::Rel(hv)], &mk::snd(mk::var(0)))?,
                    Elim::Match { arms, .. } => match &*hv {
                        Value::Ctor { ctor, args: fields, .. } => {
                            let arm = arms.get(*ctor as usize).ok_or("bad match arm")?;
                            let mut es: Vec<EnvEntry> = (*arm.env.0).clone();
                            es.extend(fields.iter().map(Self::entry));
                            self.eval(es, &arm.body)?
                        }
                        _ => return Err("evaluation is stuck on a match".into()),
                    },
                };
            }
            v = hv;
        }
    }

    /// [`Self::force`], then completes constructor fields and pairs.
    fn deep(&mut self, v: sandblaster_kernel::value::V) -> Result<sandblaster_kernel::value::V, String> {
        use sandblaster_kernel::value::{Arg, Value};
        let v = self.force(v)?;
        Ok(match &*v {
            Value::Ctor { ind, ctor, params, args } => {
                let mut new_args = Vec::with_capacity(args.len());
                for a in args {
                    new_args.push(match a {
                        Arg::Rel(x) => Arg::Rel(self.deep(x.clone())?),
                        Arg::Irr(c) => Arg::Irr(c.clone()),
                    });
                }
                std::rc::Rc::new(Value::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: new_args })
            }
            Value::Pair { fst, snd } => {
                let fst = self.deep(fst.clone())?;
                let snd = match snd {
                    Arg::Rel(x) => Arg::Rel(self.deep(x.clone())?),
                    Arg::Irr(c) => Arg::Irr(c.clone()),
                };
                std::rc::Rc::new(Value::Pair { fst, snd })
            }
            _ => v,
        })
    }
}


/// `sandblaster eval`: elaborates the crate's exec code and evaluates
/// `fn_path(args)` with the kernel evaluator (see [`eval_in`]). Prints a
/// value, never a verdict.
pub fn eval_json(c: &Checked, fn_path: &str, args: &str) -> Result<String, String> {
    let k = c.krate.as_ref().ok_or("the crate has front-end errors")?;
    if !c.ok() {
        return Err("the crate has front-end errors".into());
    }
    let opts = VerifyOptions { exec_only: true, ..Default::default() };
    with_elaboration(k, &opts, |out| eval_in(out, k, fn_path, args))
}

/// The result of [`verify_and_optimize`]: proofs and, when they checked,
/// the optimized stage output (header [`canon::STAGE`]).
pub struct StageBuild {
    pub v: Verification,
    /// `None` when the proofs did not check.
    pub emit: Option<Result<OptimizedEmit, String>>,
    /// Law statements and their non-vacuity check ([`super::audit_laws`]).
    pub law_audit: Vec<LawAudit>,
    /// `SPEC.lock` against the computed specification surface (DESIGN.md
    /// §15.6): reported only; the crate gate enforces it.
    pub spec: crate::lock::LockStatus,
    /// Every `#[refines]` with its form and determinacy, every vector file,
    /// the sections and the law-rule findings (DESIGN.md §15.10).
    pub spec15: Spec15Report,
}

/// Elaborates and checks the crate ([`verify`]) and, if every definition,
/// obligation and law is proven, optimizes, prints (stage header) and
/// round-trips it ([`optimize_emit`]). The §15 gates do not run.
pub fn verify_and_optimize(c: &Checked, opts: &VerifyOptions, oopts: &crate::opt::OptOptions, root_display: &str) -> StageBuild {
    let t = Instant::now();
    let Some(krate) = c.krate.as_ref() else {
        let spec = crate::lock::LockStatus::not_computed(&c.lock_path.display().to_string(), "", "front-end errors");
        return StageBuild { v: Verification::empty(opts.exec_only), emit: None, law_audit: vec![], spec, spec15: Spec15Report::default() };
    };
    let provers: Vec<String> = opts.chain().provers.iter().map(|(n, _)| n.clone()).collect();
    let exec_only = opts.exec_only;
    let (mut v, emit, law_audit, spec, spec15) = elab::with_big_stack(|| {
        let mut chain = opts.chain();
        let mut out = elab::elaborate(krate, &mut chain, &opts.elab_options());
        let spec15 = spec15_report(&out, krate);
        let mut v = Verification::of(&out, exec_only);
        let audit = apply_law_audit(&mut v, &out, krate, &c.sm);
        resource_gate(&mut v);
        let spec = spec_status(c, &out, krate, v.proofs_ok && !exec_only);
        // the test-only exec-only path still optimizes (its proofs never
        // count: `proofs_ok` stays false)
        if !out.verified() || (!exec_only && !v.proofs_ok) {
            return (v, None, audit, spec, spec15);
        }
        let mut em = optimize_emit_rooted(c, &mut out, root_display, "", oopts, exec_only, spec.root, None);
        resource_gate(&mut v);
        if let Ok(em) = &mut em
            && em.roundtrip_stats.spec_root.is_some_and(|r| r != spec.root)
        {
            em.roundtrip.push(format!("the printed `{}` is not the root of the matching SPEC.lock (or zero)", canon::SPEC_ROOT_NAME));
        }
        (v, Some(em), audit, spec, spec15)
    });
    v.elapsed = t.elapsed();
    v.provers = provers;
    StageBuild { v, emit, law_audit, spec, spec15 }
}

/// What [`spec_run`] classifies the computed surface against.
#[derive(Clone, Debug)]
pub enum SpecBaseline {
    /// Nothing (the surface of an old revision is being computed).
    None,
    /// The crate's own lock.
    Lock,
    /// The entries of an old revision's surface (`--diff`).
    Old(Vec<crate::lock::LockEntry>),
}

/// The result of [`spec_run`].
pub struct SpecRun {
    pub v: Verification,
    /// `None` unless the proofs checked.
    pub surface: Option<crate::surface::Surface>,
    pub status: crate::lock::LockStatus,
    /// The differences against the baseline, classified in the kernel.
    pub changes: Vec<crate::specdiff::Change>,
}

/// The specification surface of a crate and its classification against
/// `baseline` (bounded kernel attempts, [`crate::specdiff`]): what
/// `sandblaster spec --diff` prints. Proofs and the law audit run; the §15
/// gates do not, and nothing here is a verdict. Writes nothing.
pub fn spec_run(c: &Checked, baseline: &SpecBaseline, classify: bool) -> SpecRun {
    let file = c.lock_path.display().to_string();
    let t = Instant::now();
    let opts = VerifyOptions::default();
    let provers: Vec<String> = opts.chain().provers.iter().map(|(n, _)| n.clone()).collect();
    let Some(krate) = c.krate.as_ref() else {
        let mut v = Verification::empty(false);
        v.provers = provers;
        return SpecRun { v, surface: None, status: crate::lock::LockStatus::not_computed(&file, "", "front-end errors"), changes: vec![] };
    };
    let mut run = elab::with_big_stack(|| {
        let mut chain = opts.chain();
        let out = elab::elaborate(krate, &mut chain, &opts.elab_options());
        let mut v = Verification::of(&out, false);
        let _ = apply_law_audit(&mut v, &out, krate, &c.sm);
        if !v.proofs_ok {
            let status = crate::lock::LockStatus::not_computed(&file, krate.target.arch.name(), "the crate did not verify");
            return SpecRun { v, surface: None, status, changes: vec![] };
        }
        let (surface, terms) = crate::surface::compute_with_terms(&out, krate, &c.sm, &crate::surface::SurfaceOptions::default());
        let status = crate::lock::compare(c.spec_lock.as_deref(), &surface, &file);
        let old: Option<Vec<crate::lock::LockEntry>> = match baseline {
            SpecBaseline::None => None,
            SpecBaseline::Lock => c.spec_lock.as_deref().and_then(|t| crate::lock::Lock::parse(t).ok()).map(|l| l.entries_for(&surface.target).cloned().collect()),
            SpecBaseline::Old(e) => Some(e.clone()),
        };
        // against the lock only a lockable surface is classified; `--diff`
        // classifies regardless
        let lockable = surface.errors.is_empty() || matches!(baseline, SpecBaseline::Old(_));
        let changes = match old {
            Some(old) if classify && lockable => crate::specdiff::Classifier::new(&out, &surface, &terms, old).changes(),
            _ => vec![],
        };
        SpecRun { v, surface: Some(surface), status, changes }
    });
    run.v.elapsed = t.elapsed();
    run.v.provers = provers;
    run
}

/// Optimizes an elaboration whose proofs checked (`out`, of `c`'s crate),
/// prints the optimized crate with the stage header and checks the round
/// trip (DESIGN.md §8.2, §8.3).
pub fn optimize_emit(c: &Checked, out: &mut crate::elab::Output, root_display: &str, note: &str, opts: &crate::opt::OptOptions) -> Result<OptimizedEmit, String> {
    optimize_emit_mode(c, out, root_display, note, opts, false)
}

/// [`optimize_emit`]; `exec_only` marks output of the test-only exec-only
/// elaboration in the header.
pub fn optimize_emit_mode(c: &Checked, out: &mut crate::elab::Output, root_display: &str, note: &str, opts: &crate::opt::OptOptions, exec_only: bool) -> Result<OptimizedEmit, String> {
    optimize_emit_rooted(c, out, root_display, note, opts, exec_only, [0; 32], None)
}

/// A human summary of a stage verification: the front-end summary plus
/// the proof counts, with a status line that never states a crate verdict.
pub fn summary(c: &Checked, v: &Verification) -> String {
    super::proof_summary(c, v, &super::status_str(v))
}

/// The report of a stage verification (the shape of
/// `sandblaster-report.json`, status [`super::status_str`]: never a crate
/// verdict).
pub fn report_json(c: &Checked, v: &Verification, law_audit: &[LawAudit], root_display: &str, em: Option<&OptimizedEmit>, spec: Option<&crate::lock::LockStatus>, s15: Option<&Spec15Report>) -> String {
    super::render_report(c, v, law_audit, root_display, em, spec, s15, &super::status_str(v), None)
}

/// Stage API of the optimizer on a lifted module (`driver::lowered`):
/// elaborates (`opts.exec_only` for tests), optimizes and lowers the
/// cheaper residuals of the crate's emitted lifted module into its source
/// text, with the lifted round trip. `root` is the DSL root `c` was read
/// from. Not a verdict: no §15 gate runs. Returns the proofs, the
/// optimizer's per-function reports and the lowering.
pub fn lower_lifted(c: &Checked, root: &std::path::Path, opts: &VerifyOptions, oopts: &crate::opt::OptOptions) -> Result<(Verification, Vec<crate::opt::FnReport>, super::lowered::LoweredModule), String> {
    lower_lifted_stage(c, root, opts, oopts, &|c, root, out, o, oopts, info| super::lowered::lower_lifted(c, root, out, o, oopts, info))
}

/// [`lower_lifted`] with a simulated lowering-printer fault (the
/// must-reject suite; test builds only).
#[cfg(any(test, feature = "opt-test-hooks"))]
pub fn lower_lifted_with_fault(c: &Checked, root: &std::path::Path, opts: &VerifyOptions, oopts: &crate::opt::OptOptions, fault: super::lowered::LowerFault) -> Result<(Verification, Vec<crate::opt::FnReport>, super::lowered::LoweredModule), String> {
    lower_lifted_stage(c, root, opts, oopts, &|c, root, out, o, oopts, info| super::lowered::lower_lifted_with_fault(c, root, out, o, oopts, info, fault))
}

/// [`lower_lifted`] for a crate verified in place (`#[lift(in_place)]`):
/// every in-place file lowered and round-tripped (DESIGN.md §2.1). Not a
/// verdict: no §15 gate runs.
pub fn lower_in_place(c: &Checked, root: &std::path::Path, opts: &VerifyOptions, oopts: &crate::opt::OptOptions) -> Result<(Verification, Vec<super::lowered::LoweredModule>), String> {
    let krate = c.krate.as_ref().ok_or("front-end errors")?;
    let exec_only = opts.exec_only;
    elab::with_big_stack(|| {
        let mut chain = opts.chain();
        let mut out = elab::elaborate(krate, &mut chain, &opts.elab_options());
        let v = Verification::of(&out, exec_only);
        if !out.verified() && !exec_only {
            let failed: Vec<String> = out.obligations.iter().filter(|o| !o.proven()).take(12).map(|o| format!("{} [{:?}] {}:{:?}: {:?}\n    goal: {}", o.def, o.kind, c.sm.path(o.span.file).display(), o.span.lo, o.status, o.goal.chars().take(1500).collect::<String>())).collect();
            let defs: Vec<String> = out.defs.iter().filter(|d| !matches!(d.status, elab::DefStatus::Checked)).take(12).map(|d| format!("{}: {:?}", d.name, d.status)).collect();
            let diags: Vec<String> = out.diags.list.iter().filter(|d| d.severity == Severity::Error).take(12).map(|d| d.render(&c.sm)).collect();
            return Err(format!("the crate did not verify: {}\n{}\n{}\n{}", super::status_str(&v), failed.join("\n"), defs.join("\n"), diags.join("\n")));
        }
        let o = crate::opt::optimize(&mut out, krate, oopts);
        if !o.errors.is_empty() {
            return Err(format!("optimizer errors: {:?}", o.errors));
        }
        let low = super::lowered::lower_in_place(c, root, &mut out, &o, oopts);
        Ok((v, low))
    })
}

type LowerStep<'a> = dyn Fn(&Checked, &std::path::Path, &mut elab::Output, &crate::opt::Optimized, &crate::opt::OptOptions, &crate::lift::LiftedInfo) -> super::lowered::LoweredModule + Sync + 'a;

fn lower_lifted_stage(c: &Checked, root: &std::path::Path, opts: &VerifyOptions, oopts: &crate::opt::OptOptions, step: &LowerStep<'_>) -> Result<(Verification, Vec<crate::opt::FnReport>, super::lowered::LoweredModule), String> {
    let krate = c.krate.as_ref().ok_or("front-end errors")?;
    let info = super::lifted::emitted_module(&c.lifted)?.ok_or("no lifted module")?.clone();
    let exec_only = opts.exec_only;
    elab::with_big_stack(|| {
        let mut chain = opts.chain();
        let mut out = elab::elaborate(krate, &mut chain, &opts.elab_options());
        let v = Verification::of(&out, exec_only);
        if !out.verified() && !exec_only {
            return Err(format!("the crate did not verify: {}", super::status_str(&v)));
        }
        let o = crate::opt::optimize(&mut out, krate, oopts);
        if !o.errors.is_empty() {
            return Err(format!("optimizer errors: {:?}", o.errors));
        }
        let low = step(c, root, &mut out, &o, oopts, &info);
        Ok((v, o.fns.clone(), low))
    })
}
