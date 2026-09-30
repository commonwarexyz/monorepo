//! The proof builder (optimizer design §11.3): kernel-checked equality
//! lemmas `Π x̄ (h̄ :Irr Req). Eq(R, a x̄ h̄, b x̄ h̄)` linking an emitted
//! function `a` to the source function `b` it replaces (the emission chain
//! of design §3.1).
//!
//! Two kinds of links share this API:
//!
//! * **driven residuals** ([`prove_driven`]): the residual of the Σ1
//!   driver against its source, built by replaying the process tree
//!   ([`build`], [`steps`]) — `Link::Lemma`;
//! * **multiversioned clones** ([`prove_clone`]): a clone `f__<set>`
//!   against its original, by mirroring the two α-equal bodies
//!   (`opt::mirror`) — `clone_equiv`.
//!
//! Every lemma is committed with `Env::add_def` (kind `Lemma`, opaque), so
//! the kernel checks it; a failure is reported and the function falls back.

pub mod build;
pub mod steps;

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Recursion, Rel, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

pub use build::ProofStats;
use crate::auto::AutoConfig;
use crate::auto::lemmas::LemmaDb;
use crate::auto::search::Engine;
use crate::opt::drive::tree::Node;
use crate::opt::drive::Driven;

/// The link statement `Π x̄. Eq(R, a x̄, b x̄)` over `a`'s telescope, and
/// its arity.
pub fn link_statement(env: &Env, a: GlobalId, b: GlobalId) -> Result<(Tm, u32), String> {
    let tele = super::symex::telescope(env, a).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let mut ty = mk::eq(tele.ret.clone(), mk::apps(mk::global(a), args.clone()), mk::apps(mk::global(b), args));
    for (nm, rel, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    Ok((ty, n as u32))
}

/// Commits `name : Π x̄. Eq(R, a x̄, b x̄) := λ x̄. body` (`body` a term in
/// the telescope's context).
pub fn commit(env: &mut Env, a: GlobalId, b: GlobalId, body: Tm, recursion: &Recursion, name: &str, budget: u64) -> Result<GlobalId, String> {
    commit_counted(env, a, b, body, recursion, name, budget).map(|(g, _)| g)
}

/// [`commit`], also returning the kernel steps the check took.
pub fn commit_counted(env: &mut Env, a: GlobalId, b: GlobalId, body: Tm, recursion: &Recursion, name: &str, budget: u64) -> Result<(GlobalId, u64), String> {
    let (ty, arity) = link_statement(env, a, b)?;
    let tele = super::symex::telescope(env, a).ok_or("no telescope")?;
    let mut lam = body;
    for (nm, rel, dom) in tele.binders.iter().rev() {
        lam = mk::lam(nm, *rel, dom.clone(), lam);
    }
    let d = DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body: lam, recursion: recursion.clone(), arity, opaque: true };
    let mut bud = Budget { steps: budget };
    let g = env.add_def(d, &mut bud).map_err(|e| e.to_string().chars().take(900).collect::<String>())?;
    Ok((g, budget - bud.steps))
}

/// A committed specialization helper (design §6.5): its global and its
/// lemma `Π dyn̄. Eq(R, helper dyn̄, def(statics, dyn̄))`.
#[derive(Clone, Copy, Debug)]
pub struct SpecLemma {
    pub helper: GlobalId,
    pub lemma: GlobalId,
}

/// The helpers available to a proof, by specialization key.
pub type Specs = std::collections::BTreeMap<crate::opt::drive::tree::SpecKey, SpecLemma>;

/// The fold helpers available to a proof, by the recursion they fold:
/// `(helper, lemma)` (design §6.6).
pub type Folds = HashMap<GlobalId, (GlobalId, GlobalId)>;

/// The step budgets of one equality lemma: the whole proof, and the
/// `auto` search at one leaf of the process tree (taken out of the
/// former; see `DriveConfig::leaf_auto_steps`).
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    pub steps: u64,
    pub leaf_steps: u64,
}

impl Budgets {
    pub fn of(cfg: &crate::opt::drive::DriveConfig) -> Budgets {
        Budgets { steps: cfg.proof_steps, leaf_steps: cfg.leaf_auto_steps }
    }
}

/// The equality lemma of a driven residual `res` of `src` (see the module
/// docs), committed as `name`. Returns the lemma and the proof's
/// statistics.
#[allow(clippy::too_many_arguments)]
pub fn prove_driven(env: &mut Env, res: GlobalId, src: GlobalId, driven: &Driven, specs: &Specs, folds: &Folds, folded: &HashSet<GlobalId>, trust: bool, budgets: Budgets, name: &str, outl: &mut super::outline::Outlines, cache: Option<&super::cache::Cache>) -> Result<(GlobalId, ProofStats), String> {
    let budget = budgets.steps;
    let tele = super::symex::telescope(env, res).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let src_app = mk::apps(mk::global(src), args);
    let mut stats = ProofStats::default();
    // a trivial process tree (the root unfolded, then only the source's own
    // splits): the residual is the source up to evaluation, and conversion
    // alone may prove the lemma (`refl`: no proof inside either side is
    // re-checked, conversion skips them); otherwise the replayed proof
    let c = driven.tree.counts();
    let timing = std::env::var_os("SANDBLASTER_OPT_TIMING").is_some();
    let t0 = std::time::Instant::now();
    if !trust && c.trivial() {
        let body = mk::refl(tele.ret.clone(), src_app.clone());
        let r = commit(env, res, src, body, &Recursion::None, name, budget);
        if timing {
            eprintln!("opt: timing {name}: refl {} in {:?}", if r.is_ok() { "admitted" } else { "refused" }, t0.elapsed());
        }
        if let Ok(g) = r {
            stats.leaves_refl = 1;
            return Ok((g, stats));
        }
    }
    // the outlined definitions first: a cached proof mentions their lemmas
    let t1 = std::time::Instant::now();
    let outlined = outl.table(env, unfolded_defs(&driven.tree, res));
    if timing {
        eprintln!("opt: timing {name}: outlined in {:?} ({} lemmas so far, {} refused)", t1.elapsed(), outl.lemmas, outl.refused);
    }
    // a proof of a previous build (a hint: the kernel checks it; a rejected
    // hit is a forged or corrupt entry, R25: recorded and removed by the
    // cache, reported by the optimizer, and the proof is built below as on
    // a miss — the build emits what a cold build emits)
    let key = match cache {
        Some(c) => Some(c.key(env, name, &link_statement(env, res, src)?.0)),
        None => None,
    };
    if let (Some(c), Some(k)) = (cache, &key)
        && let Some(body) = c.load(env, k)
    {
        let r = commit(env, res, src, body, &Recursion::None, name, budget);
        if timing {
            eprintln!("opt: timing {name}: cached proof {} in {:?}", if r.is_ok() { "admitted" } else { "REJECTED" }, t0.elapsed());
        }
        match r {
            Ok(g) => return Ok((g, stats)),
            Err(e) => c.reject(k, name, &e),
        }
    }
    let body = {
        let envr: &Env = env;
        let r = build_body(envr, res, &src_app, &driven.tree, &driven.root, specs, folded, trust, budgets, &mut stats, &outlined, folds, None);
        if timing {
            eprintln!("opt: timing {name}: proof built in {:?} ({})", t1.elapsed(), if r.is_ok() { "ok" } else { "failed" });
        }
        r?
    };
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        eprintln!("opt: proof: committing `{name}` ({} term nodes, heap {} MiB)", crate::elab::tm::size_capped(&body, 100_000_000), crate::memguard::allocated() >> 20);
    }
    let t2 = std::time::Instant::now();
    let g = commit(env, res, src, body.clone(), &Recursion::None, name, budget);
    if timing {
        eprintln!("opt: timing {name}: committed in {:?} ({})", t2.elapsed(), if g.is_ok() { "ok" } else { "refused" });
    }
    if g.is_ok()
        && let (Some(c), Some(k)) = (cache, &key)
    {
        c.store(env, k, &body);
    }
    Ok((g?, stats))
}

/// The lemma of a fold helper `h` of the recursion `def` (design §6.6):
/// `name : Π x̄ (h̄ :Irr Req). Eq(R, h x̄ h̄, entry x̄ h̄)`, where `entry` (the
/// same telescope) is `def x̄ …` by definition. The lemma is measure
/// recursive (`measure`, a term over the telescope): the process tree's
/// back-edges are its induction hypothesis. `trust`: a simulated fault
/// (R10) — an unproven decrease is claimed, for the kernel to judge.
#[allow(clippy::too_many_arguments)]
pub fn prove_fold(env: &mut Env, h: GlobalId, entry: GlobalId, def: GlobalId, measure: Tm, driven: &Driven, specs: &Specs, folds: &Folds, folded: &HashSet<GlobalId>, trust: bool, budgets: Budgets, name: &str, outl: &mut super::outline::Outlines) -> Result<GlobalId, String> {
    let mut stats = ProofStats::default();
    let tele = super::symex::telescope(env, h).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let src_app = mk::apps(mk::global(entry), args.clone());
    let mut ty = mk::eq(tele.ret.clone(), mk::apps(mk::global(h), args), src_app.clone());
    for (nm, rel, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let outlined = outl.table(env, unfolded_defs(&driven.tree, h));
    let own = build::OwnFold { def, measure: measure.clone(), arity: n as u32 };
    let body = {
        let envr: &Env = env;
        build_body(envr, h, &src_app, &driven.tree, &driven.root, specs, folded, trust, budgets, &mut stats, &outlined, folds, Some(own))?
    };
    let mut lam = body;
    for (nm, rel, dom) in tele.binders.iter().rev() {
        lam = mk::lam(nm, *rel, dom.clone(), lam);
    }
    let d = DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body: lam, recursion: Recursion::Measure { measure }, arity: n as u32, opaque: true };
    let mut bud = Budget { steps: budgets.steps };
    env.add_def(d, &mut bud).map_err(|e| e.to_string().chars().take(900).collect::<String>())
}

/// The definitions a proof unfolds (the process tree's `Unfold` steps) and
/// the residual itself: the ones worth outlining (`opt::outline`).
pub(crate) fn unfolded_defs(tree: &Node, res: GlobalId) -> Vec<GlobalId> {
    fn go(n: &Node, out: &mut std::collections::BTreeSet<GlobalId>) {
        for s in &n.steps {
            if let crate::opt::drive::tree::Step::Unfold { def, .. } = s {
                out.insert(*def);
            }
        }
        match &n.kind {
            crate::opt::drive::tree::NodeKind::Leaf(_) => {}
            crate::opt::drive::tree::NodeKind::Split { arms, .. } => arms.iter().for_each(|a| go(&a.body, out)),
            crate::opt::drive::tree::NodeKind::Bind { value, body, .. } => {
                go(value, out);
                go(body, out);
            }
        }
    }
    let mut out = std::collections::BTreeSet::new();
    go(tree, &mut out);
    out.insert(res);
    out.into_iter().collect()
}

/// The lemma of a specialization helper `h` of `def` at the static
/// arguments of `src_app` (a term over `h`'s telescope):
/// `name : Π dyn̄. Eq(R, h dyn̄, src_app)`.
#[allow(clippy::too_many_arguments)]
pub fn prove_helper(env: &mut Env, h: GlobalId, src_app: &Tm, driven: &Driven, specs: &Specs, folds: &Folds, folded: &HashSet<GlobalId>, budgets: Budgets, name: &str, outl: &mut super::outline::Outlines, cache: Option<&super::cache::Cache>) -> Result<(GlobalId, ProofStats), String> {
    let mut stats = ProofStats::default();
    let budget = budgets.steps;
    let tele = super::symex::telescope(env, h).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    // over the helper's whole telescope (trailing `requires` binders
    // included, see `build_body`)
    let k = n.saturating_sub(driven.root.depth() as usize);
    let mut ty = mk::eq(tele.ret.clone(), mk::apps(mk::global(h), args), crate::auto::util::shift(src_app, k as i64));
    for (nm, rel, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let lemma = |env: &mut Env, body: Tm| -> Result<GlobalId, String> {
        let mut lam = body;
        for (nm, rel, dom) in tele.binders.iter().rev() {
            lam = mk::lam(nm, *rel, dom.clone(), lam);
        }
        let d = DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty: ty.clone(), body: lam, recursion: Recursion::None, arity: n as u32, opaque: true };
        let mut bud = Budget { steps: budget };
        env.add_def(d, &mut bud).map_err(|e| e.to_string().chars().take(900).collect::<String>())
    };
    // a proof of a previous build (a hint; see `prove_driven`: a rejected
    // hit is recorded, removed and rebuilt below), after the outlined
    // definitions its proof may mention
    let outlined = outl.table(env, unfolded_defs(&driven.tree, h));
    let key = cache.map(|c| c.key(env, name, &ty));
    if let (Some(c), Some(k)) = (cache, &key)
        && let Some(body) = c.load(env, k)
    {
        match lemma(env, body) {
            Ok(g) => return Ok((g, stats)),
            Err(e) => c.reject(k, name, &e),
        }
    }
    let body = {
        let envr: &Env = env;
        build_body(envr, h, src_app, &driven.tree, &driven.root, specs, folded, false, budgets, &mut stats, &outlined, folds, None)?
    };
    let g = lemma(env, body.clone())?;
    if let (Some(c), Some(k)) = (cache, &key) {
        c.store(env, k, &body);
    }
    Ok((g, stats))
}

/// The proof term (in the telescope's context) of `Eq(R, res x̄, src_app)`:
/// `transport(R, B, res x̄, sym(Delta(res; x̄)), z. Eq(R, z, src_app), P)`
/// where `B` is the residual's committed body and `P : Eq(R, B, src_app)`
/// is built by walking `B` along the process tree ([`build`]).
#[allow(clippy::too_many_arguments)]
pub fn build_body(env: &Env, res: GlobalId, src_app: &Tm, tree: &Node, root: &crate::auto::state::St, specs: &Specs, folded: &HashSet<GlobalId>, trust: bool, budgets: Budgets, stats: &mut ProofStats, outlined: &HashMap<GlobalId, Rc<(Tm, Tm)>>, folds: &Folds, own_fold: Option<build::OwnFold>) -> Result<Tm, String> {
    let mut b = Budget { steps: budgets.steps };
    let _scope = crate::auto::meter::Scope::enter(Some(std::time::Duration::from_secs(600)), &b);
    build::clear_shift_memo();
    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            build::clear_shift_memo();
        }
    }
    let _clear = ClearOnDrop;
    let cfg = AutoConfig { self_check: false, max_split_depth: 2, max_nodes: 20_000, lin_rounds: crate::opt::drive::process::LIN_ROUNDS, deep_enrich: true, goal_timeout: Some(std::time::Duration::from_secs(600)), ..AutoConfig::default() };
    let mut db = LemmaDb::default();
    db.refresh(env);
    let mut st = root.clone();
    let tele = super::symex::telescope(env, res).ok_or("no telescope")?;
    let n = tele.binders.len();
    // trailing irrelevant binders of the residual (a helper's `requires`)
    // that the driver's root does not have: bound, unused
    let mut src_app = src_app.clone();
    if (st.depth() as usize) < n && tele.binders[st.depth() as usize..].iter().all(|(_, rel, _)| *rel == Rel::Irr) {
        let k = n - st.depth() as usize;
        for (nm, _, dom) in &tele.binders[st.depth() as usize..] {
            let mut bb = Budget { steps: 10_000_000 };
            let venv = env.ctx_venv(&st.ctx);
            let tv = env.eval(&venv, sandblaster_kernel::term::Lvl(st.depth()), dom, &mut bb).map_err(|e| format!("a requires binder: {e:?}"))?;
            st.push_raw(env, nm.clone(), Rel::Irr, tv);
        }
        src_app = crate::auto::util::shift(&src_app, k as i64);
    }
    let src_app = &src_app;
    if st.depth() as usize != n {
        return Err("the driver's root context is not the residual's telescope".into());
    }
    // the residual's body at the parameters
    let mut body = match outlined.get(&res) {
        Some(o) => o.1.clone(),
        None => env.global_body(res).ok_or("the residual has no body")?,
    };
    for _ in 0..n {
        body = match &*body {
            sandblaster_kernel::term::Term::Lam { body, .. } => body.clone(),
            _ => return Err("a residual body without its parameter λs".into()),
        };
    }
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let arg_tms: Vec<Tm> = args.iter().map(|(_, t)| t.clone()).collect();
    let res_app = mk::apps(mk::global(res), args.clone());
    let r = tele.ret.clone();
    let mut e = Engine::new(env, &mut b, &cfg, &db, vec![], n as u32);
    let mut walk = build::Walk { stats: ProofStats::default(), lvl: (0..n as u32).map(|l| (l, l)).collect(), specs: specs.clone(), let_terms: HashMap::new(), folded: folded.clone(), trust, leaf_steps: budgets.leaf_steps, fact_terms: HashMap::new(), cond_tm: None, outlined: outlined.clone(), folds: folds.clone(), own_fold, res, slice_mk: env.lookup_global("slice::mk") };
    let p = walk.node(&mut e, &st, steps::Goal { r: r.clone(), l: body.clone(), s: src_app.clone() }, tree);
    *stats = walk.stats.clone();
    let p = match p {
        Ok(p) => p,
        Err(why) => {
            if crate::auto::meter::exhausted().is_some() {
                return Err(format!("{why} ({})", crate::auto::meter::failure_note()));
            }
            return Err(why);
        }
    };
    // res x̄ = B (Delta), so Eq(R, B, src_app) gives Eq(R, res x̄, src_app)
    let delta: Tm = Rc::new(sandblaster_kernel::term::Term::Delta { def: res, args: arg_tms });
    let sym = e.sym(&r, &res_app, &body, &delta);
    let motive = mk::eq(crate::auto::util::shift(&r, 1), mk::var(0), crate::auto::util::shift(src_app, 1));
    Ok(Rc::new(sandblaster_kernel::term::Term::Transport { ty: r, lhs: body, rhs: res_app, eq: sym, motive, val: p }))
}

/// The clone lemma `name : Π x̄. Eq(R, clone x̄, orig x̄)` (see
/// `opt::mirror`): the renaming turned into a proof.
#[allow(clippy::too_many_arguments)]
pub fn prove_clone(env: &mut Env, clone: GlobalId, orig: GlobalId, pre: &Tm, recursion: &Recursion, lemmas: &HashMap<GlobalId, (GlobalId, GlobalId)>, eq: super::mirror::EqIds, name: &str, budget: u64) -> Result<GlobalId, String> {
    super::mirror::prove_clone(env, clone, orig, pre, recursion, lemmas, eq, name, budget)
}
