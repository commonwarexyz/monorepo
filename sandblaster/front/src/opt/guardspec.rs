//! Guard specialization (optimizer design §6.5 "facts enter σ only if they
//! decide a branch of g"; plan O6: the `nb + na ≥ 62` check of
//! `reconstruct_finish`, decided by the facts `shape` exports).
//!
//! A kept call `g ā` in tail position of a driven function whose path has
//! imported facts (`opt::facts`) is inspected: the **early-return guards**
//! of `g`'s body — boolean tests one of whose arms is a constant exit such
//! as `None` — met along its continuing path are decided at `ā` by the
//! caller's facts (linear arithmetic, then `auto` with case splits). When
//! some are decided in the continuing direction, the call becomes a call of
//! the **guard helper** `g__g<n>`: `g`'s source with those `if c { return …;
//! }` statements removed and `!c` added to its `requires`. The helper is an
//! ordinary exec function, elaborated (every obligation of the pruned body
//! re-proven from the new `requires`), and linked by the kernel-checked
//!
//! ```text
//! <g__g<n>>::equiv : Π x̄ h̄ h̄g. Eq(R, g__g<n> x̄ h̄ h̄g, g x̄ h̄)
//! ```
//!
//! proven in lockstep: both bodies unfold; a test the facts (the new
//! `requires`) decide is rewritten on the source's side, a test both sides
//! share is split, and each leaf closes by conversion (`opt::facts` has
//! the helper's shape; nothing here is trusted). At the call site the
//! residual prints the helper call; the proof builder rewrites the source's
//! call to the helper's through the lemma, the helper's new `requires`
//! proven there from the facts (`Step::GuardSpec`).
//!
//! This is the certified fallback for callees whose driven residual cannot
//! be printed (their buffers are `seq` terms): the facts still reach their
//! checks.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, EnvEntry, Head, Neutral, V, VEnv, Value};

use crate::auto::search::{Engine, R};
use crate::auto::state::St;
use crate::auto::util::{apps, as_eq, entry_arg};
use crate::hir::*;
use crate::opt::drive::step::{Eval, HeadKind, head_of};

/// A guard specialization: the callee and the indices of its early-return
/// guards (in the order they are met) that the call site decides.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuardKey {
    pub def: GlobalId,
    pub guards: Vec<u32>,
}

/// A committed guard helper.
#[derive(Clone, Copy, Debug)]
pub struct GuardHelper {
    pub item: ItemId,
    pub global: GlobalId,
    /// `Π x̄ h̄ h̄g. Eq(R, H x̄ h̄ h̄g, g x̄ h̄)`.
    pub lemma: GlobalId,
}

#[derive(Default)]
struct Reg {
    helpers: BTreeMap<GuardKey, GuardHelper>,
    failed: BTreeMap<GuardKey, String>,
    count: BTreeMap<GlobalId, u32>,
}

thread_local! {
    static REG: RefCell<Reg> = RefCell::new(Reg::default());
}

/// Forgets the helpers (one crate's optimization).
pub fn reset() {
    REG.with(|r| *r.borrow_mut() = Reg::default());
}

pub fn helper(k: &GuardKey) -> Option<GuardHelper> {
    REG.with(|r| r.borrow().helpers.get(k).copied())
}

pub fn failed(k: &GuardKey) -> Option<String> {
    REG.with(|r| r.borrow().failed.get(k).cloned())
}

// ---------------------------------------------------------------------------
// The guards of a callee's body.
// ---------------------------------------------------------------------------

/// An early-return guard met along the continuing path of a body.
#[derive(Clone, Debug)]
pub struct Guard {
    pub cond: V,
    /// The test's value that exits.
    pub exit_on: bool,
    /// The test mentions only the caller's context (no field of a match
    /// passed on the way).
    pub closed: bool,
}

/// Whether an arm's value is a constant exit (a constructor of closed
/// values, e.g. `None`).
fn is_exit(v: &V, depth: u32) -> bool {
    let mut fuel = 1usize << 10;
    matches!(&**v, Value::Ctor { .. }) && crate::opt::drive::step::closed_below(v, depth, &mut fuel)
}

/// [`crate::opt::drive::step::closed_below`] over the value's DAG (each
/// shared node visited once: a condition over a caller's values captures
/// its whole environment in its closures), within `fuel` nodes.
fn closed_shared(v: &V, depth: u32, fuel: usize) -> bool {
    use sandblaster_kernel::value::{Closure, Elim};
    let mut seen: std::collections::HashSet<*const Value> = std::collections::HashSet::new();
    let mut stack: Vec<V> = vec![v.clone()];
    let mut fuel = fuel;
    let push_closure = |c: &Closure, stack: &mut Vec<V>| {
        for e in c.env.0.iter() {
            if let EnvEntry::Rel(x) = e {
                stack.push(x.clone());
            }
        }
    };
    while let Some(x) = stack.pop() {
        if !seen.insert(Rc::as_ptr(&x)) {
            continue;
        }
        if fuel == 0 {
            return false;
        }
        fuel -= 1;
        match &*x {
            Value::Sort(_) | Value::IntTy(_) | Value::Lit { .. } => {}
            Value::Pi { dom, cod, .. } | Value::Lam { dom, body: cod, .. } => {
                stack.push(dom.clone());
                push_closure(cod, &mut stack);
            }
            Value::Sigma { fst, snd, .. } => {
                stack.push(fst.clone());
                push_closure(snd, &mut stack);
            }
            Value::Pair { fst, snd } => {
                stack.push(fst.clone());
                if let Arg::Rel(y) = snd {
                    stack.push(y.clone());
                }
            }
            Value::Eq { ty, lhs, rhs } => stack.extend([ty.clone(), lhs.clone(), rhs.clone()]),
            Value::Refl { ty, val } => stack.extend([ty.clone(), val.clone()]),
            Value::Ind { params, .. } => stack.extend(params.iter().cloned()),
            Value::Ctor { params, args, .. } => {
                stack.extend(params.iter().cloned());
                stack.extend(args.iter().filter_map(|a| if let Arg::Rel(y) = a { Some(y.clone()) } else { None }));
            }
            Value::Neu(n) => {
                match &n.head {
                    Head::Var(l) => {
                        if l.0 >= depth {
                            return false;
                        }
                    }
                    Head::Global { args, .. } => stack.extend(args.iter().filter_map(|a| if let Arg::Rel(y) = a { Some(y.clone()) } else { None })),
                    Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                    _ => return false,
                }
                for e in &n.spine {
                    match e {
                        Elim::App(Arg::Rel(y)) => stack.push(y.clone()),
                        Elim::App(Arg::Irr(_)) | Elim::Fst | Elim::Snd => {}
                        Elim::Match { params, motive, arms, .. } => {
                            stack.extend(params.iter().cloned());
                            push_closure(motive, &mut stack);
                            for c in arms {
                                push_closure(c, &mut stack);
                            }
                        }
                    }
                }
            }
        }
    }
    true
}

/// The guards of `body` (the callee's body at the call's arguments,
/// evaluated in the driver's mode at depth `depth`): boolean tests with a
/// constant-exit arm, following the continuing arm (through matches with
/// one continuing arm, e.g. `x?`, whose fields are fresh), at most `max`.
pub fn walk(env: &Env, ev: &Eval<'_>, body: V, depth: u32, max: usize) -> Vec<Guard> {
    let bi = env.bool_ind();
    let mut out = Vec::new();
    let mut v = body;
    let mut d = depth;
    let mut b = Budget { steps: 2_000_000 };
    for _ in 0..4 * max {
        if out.len() >= max {
            break;
        }
        let (scrut, ind, params, arms, rest) = match head_of(&v) {
            HeadKind::Stuck { scrut, ind, params, arms, rest } => (scrut, ind, params.to_vec(), arms.to_vec(), rest.iter().map(crate::auto::util::clone_elim).collect::<Vec<_>>()),
            // a match on a kept call (`peak?` of a callee's result): its
            // scrutinee is the folded call
            HeadKind::Folded { .. } => {
                let Value::Neu(n) = &*v else { break };
                let Some(i) = n.spine.iter().position(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. })) else { break };
                let sandblaster_kernel::value::Elim::Match { ind, params, arms, .. } = &n.spine[i] else { break };
                (crate::auto::util::prefix(n, i), *ind, params.clone(), arms.clone(), n.spine[i + 1..].iter().map(crate::auto::util::clone_elim).collect::<Vec<_>>())
            }
            _ => break,
        };
        let Some(decl) = env.inductive_decl(ind) else { break };
        let mut vals: Vec<(V, u32)> = Vec::new();
        for (k, c) in decl.ctors.iter().enumerate() {
            let mut fenv: Vec<EnvEntry> = params.iter().map(|x| EnvEntry::Rel(x.clone())).collect();
            let mut fes = Vec::new();
            let mut dk = d;
            let mut ok = true;
            for (_, frel, fty) in &c.fields {
                let Ok(ftv) = env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(dk), fty, &mut b) else {
                    ok = false;
                    break;
                };
                let e = env.fresh_var(Lvl(dk), *frel, &ftv);
                dk += 1;
                fes.push(e.clone());
                fenv.push(e);
            }
            if !ok {
                return out;
            }
            let Some(arm) = arms.get(k) else { return out };
            // (the dependent-match idiom's path-equation argument: the
            // continuation does not read it)
            let Ok(w) = ev.inst(arm, fes, dk, &mut b).and_then(|w| ev.elims(w, &rest, dk, &mut b)) else { return out };
            vals.push((w, dk));
        }
        let exits: Vec<bool> = vals.iter().map(|(w, _)| is_exit(w, d)).collect();
        let cont: Vec<usize> = (0..vals.len()).filter(|k| !exits[*k]).collect();
        if cont.len() != 1 || exits.iter().all(|x| !*x) {
            break;
        }
        let k = cont[0];
        if ind == bi {
            let closed = closed_shared(&scrut, depth, 1 << 16);
            out.push(Guard { cond: scrut, exit_on: k == 0, closed });
        }
        let (w, dk) = vals.swap_remove(k);
        v = w;
        d = dk;
    }
    out
}

/// A proof of `Eq(Bool, c, want)` in `st` (its facts, the imported ones
/// included by the caller): linear arithmetic, then `auto` with case
/// splits (a callee's slice lengths through its own matches).
pub fn decide(env: &Env, st: &St, c: &V, want: bool, budget: u64) -> Option<Tm> {
    let bi = env.bool_ind();
    let bt: V = Rc::new(Value::Ind { ind: bi, params: vec![] });
    let g: V = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: Rc::new(Value::Ctor { ind: bi, ctor: want as u32, params: vec![], args: vec![] }) });
    // (linear arithmetic over the facts only: a guard the facts decide
    // this way is one the call site's proof and the residual's
    // elaboration discharge too; an undecided one costs one query)
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(10)), lin_rounds: 3, ..crate::auto::AutoConfig::default() };
    let db = crate::auto::lemmas::LemmaDb::default();
    let mut b = Budget { steps: budget };
    let _scope = crate::auto::meter::Scope::enter(Some(std::time::Duration::from_secs(10)), &b);
    let mut e = Engine::new(env, &mut b, &cfg, &db, vec![], st.depth());
    if let Some(p) = crate::opt::loopsum::lemmas::trivial(env, &st.ctx, &g, &mut Budget { steps: 5_000_000 }) {
        return Some(p);
    }
    match e.lin_prove(st, &g, true) {
        Ok(Some(p)) => Some(e.promote(st, &g, p)),
        _ => None,
    }
}

/// A proof of the proposition `g` in `st` (see [`decide`]).
pub fn prove(env: &Env, st: &St, g: &V, budget: u64) -> Option<Tm> {
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(60)), deep_enrich: true, lin_rounds: 3, ..crate::auto::AutoConfig::default() };
    let mut db = crate::auto::lemmas::LemmaDb::default();
    db.refresh(env);
    let mut b = Budget { steps: budget };
    let _scope = crate::auto::meter::Scope::enter(Some(std::time::Duration::from_secs(60)), &b);
    let mut e = Engine::new(env, &mut b, &cfg, &db, vec![], st.depth());
    if let Some(p) = crate::opt::loopsum::lemmas::trivial(env, &st.ctx, g, &mut Budget { steps: 5_000_000 }) {
        return Some(p);
    }
    if let Ok(Some(p)) = e.lin_prove(st, g, true) {
        return Some(e.promote(st, g, p));
    }
    match e.solve(st, g.clone(), true) {
        Ok(Some(p)) => Some(p),
        _ => None,
    }
}

/// [`prove`] with the imported facts of `st` (`opt::facts`): a proof at
/// `st`'s depth.
pub fn prove_with_imports(env: &Env, st: &St, g: &V, budget: u64, lets: &dyn Fn(u32) -> Option<V>) -> Option<Tm> {
    match crate::opt::facts::with_imports_by(env, st, lets) {
        Some(st2) => prove(env, &st2, g, budget).map(|p| crate::opt::facts::close(&st2, p)),
        None => prove(env, st, g, budget),
    }
}

// ---------------------------------------------------------------------------
// The helper.
// ---------------------------------------------------------------------------

/// Whether an expression is pure (no return, `?`, or call of a user
/// function).
fn pure(e: &Expr) -> bool {
    struct V(bool);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Return(_) | ExprKind::Try(_) => self.0 = false,
                ExprKind::Call { callee: Callee::Item(..), .. } => self.0 = false,
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(true);
    crate::visit::Visitor::expr(&mut v, e);
    v.0
}

/// A block whose statements end in a `return`.
fn returns(b: &Block) -> bool {
    match (&b.tail, b.stmts.last()) {
        (Some(t), _) => matches!(&t.kind, ExprKind::Return(_)),
        (None, Some(s)) => matches!(&s.kind, StmtKind::Expr(e) if matches!(&e.kind, ExprKind::Return(_))),
        _ => false,
    }
}

/// The early-return guards of a function's body block, in order: the
/// statement index and the condition over the parameters (pure `let`s
/// substituted); the scan stops at the first other statement.
pub fn hir_guards(f: &FnDef) -> Vec<(usize, Expr)> {
    let FnBody::Exec(body) = &f.body else { return Vec::new() };
    let ExprKind::Block(b) = &body.kind else { return Vec::new() };
    let mut lets: HashMap<LocalId, Expr> = HashMap::new();
    let mut out = Vec::new();
    for (i, s) in b.stmts.iter().enumerate() {
        match &s.kind {
            StmtKind::Let { pat, init, els: None } => {
                if matches!(&init.kind, ExprKind::Try(_)) {
                    continue;
                }
                let PatKind::Binding { local, sub: None, .. } = &pat.kind else { break };
                if !pure(init) {
                    break;
                }
                let Some(v) = crate::opt::loopsum::subst_locals(init, &lets) else { break };
                lets.insert(*local, v);
            }
            StmtKind::Expr(e) => match &e.kind {
                ExprKind::If { cond, then, els: None } if pure(cond) => {
                    let ExprKind::Block(tb) = &then.kind else { break };
                    if !returns(tb) {
                        break;
                    }
                    let Some(c) = crate::opt::loopsum::subst_locals(cond, &lets) else { break };
                    out.push((i, c));
                }
                _ => break,
            },
            _ => break,
        }
    }
    out
}

/// Commits the helpers of `keys` not built yet; a failure is recorded and
/// returned (the caller drives again with the call kept).
#[allow(clippy::too_many_arguments)]
pub(super) fn ensure(cx: &mut super::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, keys: &[GuardKey], user_globals: &HashMap<GlobalId, ItemId>) -> Result<(), String> {
    let mut first: Option<String> = None;
    for key in keys {
        if helper(key).is_some() {
            continue;
        }
        if let Some(why) = failed(key) {
            first.get_or_insert(why);
            continue;
        }
        match build(cx, ext, chain, eopts, key, user_globals) {
            Ok(h) => REG.with(|r| {
                r.borrow_mut().helpers.insert(key.clone(), h);
            }),
            Err(e) => {
                if e.contains("kernel rejected") {
                    cx.failure(format!("the guard helper of `{}` was rejected: {}", cx.out.env.global_name(key.def).unwrap_or_default(), e.chars().take(400).collect::<String>()));
                }
                REG.with(|r| {
                    r.borrow_mut().failed.insert(key.clone(), e.clone());
                });
                first.get_or_insert(e);
            }
        }
    }
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn build(cx: &mut super::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, key: &GuardKey, user_globals: &HashMap<GlobalId, ItemId>) -> Result<GuardHelper, String> {
    let fid = *user_globals.get(&key.def).ok_or("the callee is not a user function")?;
    let fd = ext.fn_def(fid).cloned().ok_or("the callee is not a function")?;
    if !fd.generics.is_empty() || fd.params.iter().any(|p| p.ghost) {
        return Err("a generic callee or one with ghost parameters".into());
    }
    let guards = hir_guards(&fd);
    let mut drop: Vec<usize> = Vec::new();
    let mut reqs: Vec<Expr> = Vec::new();
    for &g in &key.guards {
        let (si, c) = guards.get(g as usize).cloned().ok_or("a decided guard the source does not have")?;
        drop.push(si);
        let sp = c.span;
        let not = Expr::new(ExprKind::Unary(UnOp::Not, Box::new(c)), Ty::Bool, sp);
        reqs.push(Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(not)), Ty::Prop, sp));
    }
    let FnBody::Exec(body) = &fd.body else { return Err("no exec body".into()) };
    let ExprKind::Block(b) = &body.kind else { return Err("the body is not a block".into()) };
    let mut nb = b.clone();
    nb.stmts = b.stmts.iter().enumerate().filter(|(i, _)| !drop.contains(i)).map(|(_, s)| s.clone()).collect();
    let mut hf = fd.clone();
    hf.body = FnBody::Exec(Expr::new(ExprKind::Block(nb), body.ty.clone(), body.span));
    hf.requires.extend(reqs);
    hf.ensures = None;
    hf.specialize = false;
    hf.implements = None;
    hf.inline = None;
    let orig = ext.item(fid).clone();
    let n = REG.with(|r| {
        let mut r = r.borrow_mut();
        let c = r.count.entry(key.def).or_insert(0);
        let n = *c;
        *c += 1;
        n
    });
    let hname = format!("{}__g{n}", orig.name);
    let hid = super::push_elaborate(cx, ext, chain, eopts, &orig, hname.clone(), hf, false).map_err(|(why, _)| format!("the guard helper `{hname}` did not elaborate: {why}"))?;
    let Some(hg) = cx.out.fn_globals.get(&hid).copied() else {
        super::pop_driven(cx, ext, hid);
        return Err("the guard helper has no global".into());
    };
    match link_lemma(&mut cx.out.env, key.def, hg) {
        Ok(lemma) => {
            cx.set_aside_obligations(hid);
            Ok(GuardHelper { item: hid, global: hg, lemma })
        }
        Err(e) => {
            ext.items[hid.0 as usize].ghost = true;
            super::pop_driven(cx, ext, hid);
            Err(format!("the guard helper `{hname}`'s link: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// The link lemma (lockstep).
// ---------------------------------------------------------------------------

/// The first stuck match of a value: scrutinee, inductive, parameters.
fn first_match(v: &V) -> Option<(V, IndId, Vec<V>)> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. }))?;
    let sandblaster_kernel::value::Elim::Match { ind, params, .. } = &n.spine[i] else { return None };
    Some((crate::auto::util::prefix(n, i), *ind, params.clone()))
}

struct Lock {
    /// The two functions (unfolded by `delta` where opaque: a callee
    /// that builds buffers is opaque in proofs).
    unfold: [GlobalId; 2],
    failure: Option<String>,
}

impl Lock {
    fn note(&mut self, env: &Env, st: &St, what: &str, v: &V) {
        if self.failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.failure = Some(format!("{what}: {}", crate::elab::show::value(env, &names, v, 600)));
        }
    }

    /// `goal` with the opaque application `side` (of one of the two
    /// functions) replaced by its body: `transport` along `sym(delta)`.
    fn delta(&self, env: &Env, st: &St, goal: &V, side: &V) -> Option<(V, crate::opt::loopsum::lemmas::Wrap)> {
        let Value::Neu(Neutral { head: Head::Global { def, args }, spine }) = &**side else { return None };
        if !spine.is_empty() || !self.unfold.contains(def) || env.global_opaque(*def) != Some(true) {
            return None;
        }
        let n = args.len();
        let app = st.quote(env, side);
        let mut targs: Vec<Tm> = Vec::new();
        let mut cur = &app;
        while let Term::App { fun, arg, .. } = &**cur {
            targs.push(arg.clone());
            cur = fun;
        }
        if targs.len() != n || !matches!(&**cur, Term::Global(g) if g == def) {
            return None;
        }
        targs.reverse();
        let delta: Tm = Rc::new(Term::Delta { def: *def, args: targs });
        let ty = env.infer(&st.ctx, &delta, &mut Budget { steps: 50_000_000 }).ok()?;
        let Value::Eq { ty: r_ty, rhs, .. } = &*ty else { return None };
        let (r_tm, body) = (st.quote(env, r_ty), st.quote(env, rhs));
        let sym = env.lookup_global("eq::sym")?;
        let eq = apps(mk::global(sym), [(Rel::Rel, r_tm.clone()), (Rel::Rel, app.clone()), (Rel::Rel, body.clone()), (Rel::Rel, delta)]);
        crate::opt::loopsum::lemmas::rewrite(env, st, goal, &app, &body, r_tm, eq)
    }

    fn go(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = crate::opt::loopsum::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 50_000_000 }) {
            return Ok(Some(p));
        }
        // a rewrite's motive with its equation binder: introduced
        if let Value::Pi { name, rel, dom, cod } = &**goal {
            let mut ch = st.child();
            let is_prop = e.is_prop(dom, st.depth());
            let entry = ch.push_lam(env, name.clone(), *rel, dom.clone(), is_prop);
            let Some(body) = e.inst(cod, vec![entry], ch.depth())? else { return Ok(None) };
            return Ok(self.go(e, &mut ch, &body, depth)?.map(|p| ch.finish(p)));
        }
        let Some((_, l, r)) = as_eq(goal) else {
            self.note(env, st, "not an equation", goal);
            return Ok(None);
        };
        let (l, r) = (l.clone(), r.clone());
        let bi = env.bool_ind();
        // an opaque side (one of the two functions): its body, by `delta`
        for side in [&l, &r] {
            if let Some((t2, w)) = self.delta(env, st, goal, side) {
                return Ok(self.go(e, st, &t2, depth)?.map(w));
            }
        }
        // the source's test decided by the facts: rewritten
        if let Some((c, ind, _)) = first_match(&r)
            && ind == bi
        {
            for want in [false, true] {
                let bt: V = Rc::new(Value::Ind { ind: bi, params: vec![] });
                let g: V = Rc::new(Value::Eq { ty: bt, lhs: c.clone(), rhs: Rc::new(Value::Ctor { ind: bi, ctor: want as u32, params: vec![], args: vec![] }) });
                let lin = match e.lin_prove(st, &g, true)? {
                    Some(p) => Some(e.promote(st, &g, p)),
                    None => None,
                };
                let p = match lin {
                    Some(p) => Some(p),
                    None => {
                        let mut ch = st.child();
                        // (the requires as a negation: determined by saturation)
                        match e.solve_in(&mut ch, g.clone(), true)? {
                            Some(p) => Some(ch.finish(p)),
                            None => None,
                        }
                    }
                };
                if let Some(p) = p {
                    // the engine's checked motive: the dependent-match
                    // idiom's `refl(Bool, c)` path equation abstracted
                    // consistently with the motive
                    let bt: V = Rc::new(Value::Ind { ind: bi, params: vec![] });
                    let lit: V = Rc::new(Value::Ctor { ind: bi, ctor: want as u32, params: vec![], args: vec![] });
                    if let Some((t2, k)) = e.rewrite(st, goal, &bt, &c, &lit, p)? {
                        let d = st.depth();
                        return Ok(self.go(e, st, &t2, depth)?.map(|q| k.apply(d, q)));
                    }
                }
            }
        }
        // a test both sides share: split
        if depth > 0
            && let Some((c, ind, params)) = first_match(&l).or_else(|| first_match(&r))
        {
            let d = st.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
                let mut ch = a2.child();
                if let Ok(Some(p)) = e2.contradiction(&mut ch) {
                    return Ok(Some(e2.absurd(a2, &tk, ch.finish(p))));
                }
                self.go(e2, a2, &tk, depth - 1)
            };
            return e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn);
        }
        self.note(env, st, "the two bodies differ", goal);
        Ok(None)
    }
}

/// `Π x̄ h̄ h̄g. Eq(R, H x̄ h̄ h̄g, g x̄ h̄)` (see the module docs).
pub fn link_lemma(env: &mut Env, g: GlobalId, h: GlobalId) -> Result<GlobalId, String> {
    let tele_h = crate::opt::symex::telescope(env, h).ok_or("the helper has no telescope")?;
    let tele_g = crate::opt::symex::telescope(env, g).ok_or("the callee has no telescope")?;
    let n = tele_h.binders.len();
    let ng = tele_g.binders.len();
    if ng > n {
        return Err("the helper has fewer binders than the callee".into());
    }
    let var = |b: usize| mk::var((n - 1 - b) as u32);
    let h_app = apps(mk::global(h), (0..n).map(|b| (tele_h.binders[b].1, var(b))));
    let g_app = apps(mk::global(g), (0..ng).map(|b| (tele_g.binders[b].1, var(b))));
    let mut ty = mk::eq(tele_h.ret.clone(), h_app, g_app);
    for (nm, rel, dom) in tele_h.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let body = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut sb = Budget { steps: 200_000_000 };
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 32);
        let goal = crate::opt::loopsum::lemmas::open(&mut e, &mut st, &ty)?;
        let mut lk = Lock { unfold: [h, g], failure: None };
        let p = lk.go(&mut e, &mut st, &goal, 12).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("the lockstep proof: {}", lk.failure.clone().unwrap_or_default()))?;
        st.finish(p)
    };
    let name = format!("{}::equiv", env.global_name(h).map(|s| s.to_string()).unwrap_or_default());
    let (lemma, _) = crate::opt::loopsum::lemmas::add_lemma(env, &name, ty, body, 400_000_000).map_err(|e| format!("kernel rejected {e}"))?;
    Ok(lemma)
}

// ---------------------------------------------------------------------------
// The call site.
// ---------------------------------------------------------------------------

/// The process tree with every guard-specialized leaf call replaced by its
/// helper's (what the residual prints; the proof builder rewrites the
/// source's call through the helper's lemma, `Step::GuardSpec`).
pub fn for_printing(t: &crate::opt::drive::tree::Node) -> crate::opt::drive::tree::Node {
    use crate::opt::drive::tree::{NodeKind, Step};
    let mut n = t.clone();
    fn go(n: &mut crate::opt::drive::tree::Node) {
        let spec = n.steps.iter().find_map(|s| match s {
            Step::GuardSpec { def, key } => Some((*def, key.clone())),
            _ => None,
        });
        match &mut n.kind {
            NodeKind::Leaf(v) => {
                if let Some((def, key)) = spec
                    && let Some(h) = helper(&key)
                    && let Value::Neu(Neutral { head: Head::Global { def: d, args }, spine }) = &**v
                    && *d == def
                    && spine.is_empty()
                {
                    let mut args = args.clone();
                    let dummy = sandblaster_kernel::value::Closure { env: VEnv::default(), body: Rc::new(Term::Erased) };
                    for _ in 0..key.guards.len() {
                        args.push(Arg::Irr(dummy.clone()));
                    }
                    *v = Rc::new(Value::Neu(Neutral { head: Head::Global { def: h.global, args }, spine: vec![] }));
                }
            }
            NodeKind::Split { arms, .. } => arms.iter_mut().for_each(|a| go(&mut a.body)),
            NodeKind::Bind { value, body, .. } => {
                go(value);
                go(body);
            }
        }
    }
    go(&mut n);
    n
}

/// The helper's application at the source call `g ā` (terms at `st`'s
/// depth, `ā` the call's arguments with their relevance) and the lemma's
/// instance `Eq(R, H ā h̄g, g ā)`: the helper's new `requires` proven from
/// the facts of `st` and the imported ones.
pub fn call_site(env: &Env, st: &St, key: &GuardKey, args: &[(Rel, Tm)], lets: &dyn Fn(u32) -> Option<V>) -> Result<(Tm, Tm), String> {
    let h = helper(key).ok_or("a guard specialization without its helper")?;
    let tele = crate::opt::symex::telescope(env, h.global).ok_or("the helper has no telescope")?;
    if tele.binders.len() != args.len() + key.guards.len() {
        return Err("the helper's telescope does not extend the callee's".into());
    }
    let mut full: Vec<(Rel, Tm)> = args.to_vec();
    let mut vals: Vec<EnvEntry> = Vec::new();
    let mut b = Budget { steps: 20_000_000 };
    for (i, (r, t)) in args.iter().enumerate() {
        let _ = i;
        match r {
            Rel::Rel => vals.push(EnvEntry::Rel(env.eval(&env.ctx_venv(&st.ctx), st.ctx.depth(), t, &mut b).map_err(|e| format!("{e:?}"))?)),
            Rel::Irr => vals.push(crate::auto::util::irr_entry(&st.venv, t)),
        }
    }
    for (_, _, dom) in &tele.binders[args.len()..] {
        let goal = env.eval(&VEnv(Rc::new(vals.clone())), Lvl(st.depth()), dom, &mut b).map_err(|e| format!("the helper's requires: {e:?}"))?;
        let p = prove_with_imports(env, st, &goal, 20_000_000, lets).ok_or("the guard helper's requires is not proven at the call")?;
        vals.push(crate::auto::util::irr_entry(&st.venv, &p));
        full.push((Rel::Irr, p));
    }
    let to = apps(mk::global(h.global), full.clone());
    let inst = apps(mk::global(h.lemma), full);
    let _ = entry_arg;
    Ok((to, inst))
}
