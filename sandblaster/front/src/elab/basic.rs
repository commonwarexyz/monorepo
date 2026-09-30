//! `BasicProver`: a small, deterministic development prover (DESIGN.md §8.1
//! subset). The real prover is `crate::auto::Auto`; this one exists so the
//! elaborator can be developed and tested independently, and runs first in
//! the driver's [`ProverChain`](super::ProverChain) because it is cheap.
//!
//! Steps, in order, each bounded:
//! 1. `refl` (an equation whose sides convert), trivial targets (`Unit`);
//! 2. assumption (a fact, or a component of a conjunction fact, whose type
//!    converts with the target; irrelevant equational facts are promoted
//!    with `eq::promote` so the proof is valid in relevant positions);
//! 3. goal connectives: `Σ` (dependent conjunction) is split, `Π`
//!    (implication, `forall`) is introduced;
//! 4. contradictions: an `Empty` fact, constructor clashes (one fact, or two
//!    facts equating the same term to different constructors), a
//!    disequality whose negation linear arithmetic proves;
//! 5. linear arithmetic: facts of the §5.8 forms plus the facts carried by
//!    the proof slots of checked primitives in the statements, the kernel's
//!    linearization and a Fourier–Motzkin certificate ([`super::fm`]);
//!    equational facts `t = v` (`v` a constructor/literal) first add
//!    `A = A[t := v]` for every atom `A` containing `t`;
//! 6. bound facts for the piecewise atoms of the failed system, each
//!    proven locally (never nested): `min(a, c) ≤ a, c`, `a, c ≤ max(a,
//!    c)`, `sat_sub(a, c) ≤ a` (one-level split with the §5.10 axiom),
//!    `count_ones(a) ≤ w`, `a & c ≤ a, c`, `a >> s ≤ a`, `a ^ c ≤ a | c`
//!    (unconditional axioms), `x · y ≤ X · Y` for factors with evident
//!    bounds (`mul_mono`), and `m ≤ ub` for a stuck `match` whose arms are
//!    all evidently at most `ub` — e.g. the join value of `match o {
//!    Some(x) => x as u32, None => 0 }` (a match on its scrutinee with the
//!    atom generalized in the motive);
//! 7. case splits (depth ≤ [`BasicProver::max_splits`], at most
//!    [`BasicProver::max_split_nodes`] per goal) on the atoms that blocked
//!    linarith: `min/max/sat_sub/sat_add` atoms get the matching §5.10
//!    axiom instance in each branch of their comparison; stuck `Bool`
//!    matches and disequalities are split on their scrutinee; a scrutinee
//!    already decided by a fact is not split again. A split does **not**
//!    rewrite the goal: the facts and atoms mentioning the scrutinee `c` are
//!    **generalized** in the split's motive (`c ↦ y`; the dependent-match
//!    idiom `(match c … λ(e : Eq(Bool, c, y')). …) .refl` becomes `(match
//!    y …) .e` with the split's own path equation `e`, which keeps it
//!    well-typed), so each branch receives them with the scrutinee's value,
//!    where they compute.
//!
//! All kernel work (evaluation, type checks of generalized facts, bound
//! proofs, linearization) is charged to the goal's budget, and so is the
//! front-end work — quoting, shifting, generalization and abstraction
//! traversals, fact scans, Fourier–Motzkin pivots, re-certification
//! ([`crate::auto::meter`]). Every call also has a wall-clock deadline
//! ([`BasicProver::timeout`]) and stops at the memory soft limit;
//! exhaustion is a failure, never a success.
//!
//! **Terms, not quotes.** Terms quoted from values can be unfit for
//! re-checking (instantiated proofs of unfolded definitions, `pair(_, ..)`
//! for slices inside closures, `absurd(T, _)`). The elaborator therefore
//! passes the terms of the goal and of its facts through
//! [`set_goal_terms`]; this prover builds its proofs from them and quotes
//! only atoms and fall-back cases. Every returned term is closed in
//! `goal.ctx` and re-checked by the kernel.

use std::cell::RefCell;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::axioms::{axiom_id, Schema};
use sandblaster_kernel::term::{IndId, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use crate::auto::meter;
use crate::auto::util::{occurs, shift};
use sandblaster_kernel::value::{Budget, EnvEntry, Head, Neutral, VEnv, Value, V};

use crate::prover::{AutoFailure, Goal, Prover};

/// The development prover (see the module docs).
#[derive(Clone, Debug)]
pub struct BasicProver {
    /// Maximum nesting of case splits.
    pub max_splits: u32,
    /// Maximum number of case splits per goal (all levels together).
    pub max_split_nodes: u32,
    /// Wall-clock limit of one call (`None`: [`meter::goal_timeout`]); an
    /// enclosing scope (the prover chain's per-goal deadline) may be
    /// shorter.
    pub timeout: Option<std::time::Duration>,
}

impl Default for BasicProver {
    fn default() -> Self {
        BasicProver { max_splits: 3, max_split_nodes: 48, timeout: None }
    }
}

/// Terms of a goal and of its facts, supplied by the elaborator (see the
/// module docs).
#[derive(Clone, Debug)]
pub struct GoalTerms {
    pub id: u32,
    /// The target, a term in the goal context.
    pub target: Tm,
    /// Fact binder level ↦ its type term (in the context of depth `lvl`).
    pub facts: Vec<(u32, Tm)>,
}

thread_local! {
    static GOAL_TERMS: RefCell<Option<GoalTerms>> = const { RefCell::new(None) };
}

/// Registers (or clears) the terms of the goal about to be proven.
pub fn set_goal_terms(g: Option<GoalTerms>) {
    GOAL_TERMS.with(|c| *c.borrow_mut() = g);
}

fn goal_terms(id: u32) -> Option<GoalTerms> {
    GOAL_TERMS.with(|c| c.borrow().as_ref().filter(|g| g.id == id).cloned())
}

/// A usable fact: a proof term and its stated type (both built at `depth`).
#[derive(Clone)]
struct Fact {
    tm: Tm,
    depth: u32,
    ty: V,
    /// The stated type as a term (at `depth`), when known.
    ty_tm: Option<Tm>,
}

type SplitCand = (Tm, Option<(Schema, Schema, Width, Tm, Tm)>);

/// Atoms larger than this (term nodes) are not used for rewriting and
/// splitting.
const MAX_ATOM_SIZE: usize = 4000;

/// At most this many facts are generalized in one case split's motive.
const MAX_GEN_FACTS: usize = 6;

struct PCx<'e> {
    env: &'e Env,
    ctx: Ctx,
    venv: VEnv,
    facts: Vec<Fact>,
    tried: Vec<String>,
    stuck: Vec<String>,
    bool_: IndId,
    promote: Option<sandblaster_kernel::term::GlobalId>,
    sym: Option<sandblaster_kernel::term::GlobalId>,
    trans: Option<sandblaster_kernel::term::GlobalId>,
    false_ne_true: Option<sandblaster_kernel::term::GlobalId>,
    /// Atoms whose bound facts were already added (by debug key).
    bounded: Vec<String>,
    /// Case splits left for this goal (all nesting levels together).
    split_budget: u32,
    /// Set while proving a bound fact (no nested bound facts).
    in_bounds: bool,
    /// A restricted closing statement (`by_arithmetic()`,
    /// `by_unfolding(..)`, [`crate::prover::Hint::Only`]): no case splits,
    /// so no `match` bounds either (step 6 keeps the axiom bounds).
    restricted: bool,
    /// Read-backs by (value address, depth): the same value at the same
    /// depth reads back to the same term (the variables it mentions are
    /// bound by the context it was built in). Keeps the values alive so
    /// their addresses are not reused.
    qcache: RefCell<std::collections::HashMap<(usize, u32), (V, Tm)>>,
}

impl Prover for BasicProver {
    fn prove(&mut self, env: &Env, g: &Goal, b: &mut Budget) -> Result<Tm, AutoFailure> {
        let _scope = meter::Scope::enter(self.timeout, b);
        // `by_arithmetic()` / `by_unfolding(..)`: arithmetic and equality
        // reasoning only (this prover never unfolds a definition)
        let restricted = g.reasoning().is_some();
        let max_splits = if restricted { 0 } else { self.max_splits };
        let venv = env.ctx_venv(&g.ctx);
        let mut cx = PCx {
            env,
            ctx: g.ctx.clone(),
            venv,
            facts: vec![],
            tried: vec![],
            stuck: vec![],
            bool_: env.bool_ind(),
            promote: env.lookup_global("eq::promote"),
            sym: env.lookup_global("eq::sym"),
            trans: env.lookup_global("eq::trans"),
            false_ne_true: env.lookup_global("bool::false_ne_true"),
            bounded: Vec::new(),
            split_budget: if restricted { 0 } else { self.max_split_nodes },
            in_bounds: false,
            restricted,
            qcache: RefCell::new(std::collections::HashMap::new()),
        };
        let terms = goal_terms(g.id.0);
        let depth = cx.depth();
        let mut lvls: Vec<u32> = g.facts.iter().map(|f| f.lvl.0).collect();
        for (i, e) in g.ctx.entries.iter().enumerate() {
            if !lvls.contains(&(i as u32)) && is_prop_type(&e.ty) {
                lvls.push(i as u32);
            }
        }
        lvls.sort();
        lvls.dedup();
        for l in lvls {
            if super::fact_hidden(l) {
                continue;
            }
            let Some(e) = g.ctx.entries.get(l as usize) else { continue };
            let tm = mk::var(depth - 1 - l);
            let ty_tm = terms.as_ref().and_then(|t| t.facts.iter().find(|(fl, _)| *fl == l)).map(|(fl, t)| shift(t, (depth - fl) as i64));
            cx.add_fact(tm, e.rel == Rel::Irr, e.ty.clone(), ty_tm, b, 0);
        }
        let tgt = terms.map(|t| t.target);
        let r = cx.prove(&g.target, tgt.as_ref(), max_splits, b);
        // exhaustion (budget, deadline, memory) is a failure, even when a
        // term was built at the last moment (it may contain placeholders of
        // refused read-backs)
        let exhausted = !meter::settle(b) || meter::exhausted().is_some();
        match r {
            Some(t) if !exhausted => Ok(t),
            _ => {
                let goal = cx.show(&g.target);
                let facts = cx.facts.iter().take(64).map(|f| cx.show(&f.ty)).collect();
                let mut tried = cx.tried;
                if exhausted {
                    tried.push(meter::failure_note());
                }
                Err(AutoFailure { goal, facts, stuck: cx.stuck, tried })
            }
        }
    }
}

/// Whether a type value looks like a proposition (equation, conjunction
/// of propositions).
fn is_prop_type(v: &V) -> bool {
    match &**v {
        Value::Eq { .. } => true,
        Value::Sigma { fst, snd, .. } => is_prop_type(fst) && matches!(&*snd.body, Term::Eq { .. } | Term::Sigma { .. }),
        _ => false,
    }
}

/// Linear-arithmetic proof term for `goal` from `hyps` (proof, stated
/// proposition) in `ctx`, using the kernel's linearization and a
/// Fourier–Motzkin certificate.
pub fn linarith_term(env: &Env, ctx: &Ctx, hyps: Vec<(Tm, Tm)>, goal: Tm) -> Result<Tm, String> {
    let mut b = Budget { steps: 50_000_000 };
    linarith_term_b(env, ctx, hyps, goal, &mut b)
}

/// [`linarith_term`] charged to the budget `b` (the linearization; the
/// certificate search is charged through [`meter`]).
pub fn linarith_term_b(env: &Env, ctx: &Ctx, hyps: Vec<(Tm, Tm)>, goal: Tm, b: &mut Budget) -> Result<Tm, String> {
    meter::settle(b);
    let sys = env.linearize(ctx, &hyps, &goal, b).map_err(|e| e.to_string())?;
    let cert = super::fm::certificate(&sys).ok_or_else(|| "no certificate found".to_string())?;
    Ok(Rc::new(Term::Linarith { hyps, goal, cert }))
}

fn is_cmp(op: PrimOp) -> bool {
    matches!(op, PrimOp::Eq(_) | PrimOp::Ne(_) | PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_))
}

fn as_bool_lit(v: &V, bool_: IndId) -> Option<bool> {
    match &**v {
        Value::Ctor { ind, ctor, .. } if *ind == bool_ => Some(*ctor == 1),
        _ => None,
    }
}

fn prim_head(v: &V) -> Option<PrimOp> {
    match &**v {
        Value::Neu(Neutral { head: Head::Prim { op, .. }, spine }) if spine.is_empty() => Some(*op),
        _ => None,
    }
}

fn closed_val(v: &V) -> bool {
    matches!(&**v, Value::Ctor { .. } | Value::Lit { .. })
}

impl<'e> PCx<'e> {
    fn depth(&self) -> u32 {
        self.ctx.entries.len() as u32
    }

    fn names(&self) -> Vec<sandblaster_kernel::term::Name> {
        self.ctx.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// Bounded display for diagnostics (never quotes the value: see
    /// [`super::show`]).
    fn show(&self, v: &V) -> String {
        super::show::value(self.env, &self.names(), v, 600)
    }

    /// Reads a value back (charged; an unaffordable read-back exhausts the
    /// goal and yields `Erased`, see [`meter::charge_quote`]).
    fn quote(&self, v: &V) -> Tm {
        self.quote_in(&self.ctx, v)
    }

    /// [`PCx::quote`] in `ctx` (the current context or a prefix of it),
    /// memoized.
    fn quote_in(&self, ctx: &Ctx, v: &V) -> Tm {
        let key = (Rc::as_ptr(v) as *const () as usize, ctx.entries.len() as u32);
        if let Some((_, t)) = self.qcache.borrow().get(&key) {
            return t.clone();
        }
        let t = quote_at(self.env, ctx, v);
        if !matches!(&*t, Term::Erased) {
            self.qcache.borrow_mut().insert(key, (v.clone(), t.clone()));
        }
        t
    }

    fn eval(&self, t: &Tm, b: &mut Budget) -> Option<V> {
        meter::settle(b);
        self.env.eval(&self.venv, Lvl(self.depth()), t, b).ok()
    }

    fn conv(&self, a: &V, c: &V, b: &mut Budget) -> bool {
        if Rc::ptr_eq(a, c) {
            return true;
        }
        meter::settle(b);
        self.env.conv(Lvl(self.depth()), a, c, b).unwrap_or(false)
    }

    /// Pushes a relevant binder of type `ty` (a fresh variable).
    fn push(&mut self, name: &str, ty: V) {
        let entry = self.env.fresh_var(Lvl(self.depth()), Rel::Rel, &ty);
        let mut es = (*self.ctx.entries).clone();
        es.push(CtxEntry { name: Rc::from(name), rel: Rel::Rel, ty, def: None });
        self.ctx = Ctx { entries: Rc::new(es) };
        let mut ve = (*self.venv.0).clone();
        ve.push(entry);
        self.venv = VEnv(Rc::new(ve));
    }

    /// A snapshot of the facts for a scan (charged per fact).
    fn scan_facts(&self) -> Vec<Fact> {
        meter::spend(1 + self.facts.len() as u64);
        self.facts.clone()
    }

    fn at(&self, t: &Tm, depth: u32) -> Tm {
        shift(t, (self.depth() - depth) as i64)
    }

    fn fact_tm(&self, f: &Fact) -> Tm {
        self.at(&f.tm, f.depth)
    }

    /// The stated type of a fact as a term (its recorded term, else quoted).
    fn fact_ty_tm(&self, f: &Fact) -> Tm {
        match &f.ty_tm {
            // the second component of a conjunction is recorded as
            // `let h = fst(p); Q`: contract the lets (ζ) so the statement's
            // shape (an equation) is visible
            Some(t) => zeta_top(&self.at(t, f.depth)),
            None => self.quote(&f.ty),
        }
    }

    /// Adds a fact, splitting conjunctions; irrelevant equational facts
    /// are promoted.
    fn add_fact(&mut self, tm: Tm, irr: bool, ty: V, ty_tm: Option<Tm>, b: &mut Budget, nest: u32) {
        if nest > 8 {
            return;
        }
        let ty_tm = ty_tm.map(|t| zeta_top(&t));
        match &*ty {
            Value::Sigma { fst, snd, snd_rel, name } => {
                // the conjunction itself (an assumption for an identical
                // goal, e.g. an `exists` proven by a lemma), then its parts
                if nest == 0 {
                    self.facts.push(Fact { tm: tm.clone(), depth: self.depth(), ty: ty.clone(), ty_tm: ty_tm.clone() });
                }
                let f = mk::fst(tm.clone());
                // the conjunction's term: recorded, or behind spec
                // functions (`exists` in a spec function's body); without
                // it the parts would be quoted from their values
                let sigma_tm = ty_tm.as_ref().and_then(|t| super::tm::head_unfold(self.env, &self.at(t, self.depth()), &|x| matches!(x, Term::Sigma { .. })));
                let (fst_tm, snd_tm) = match sigma_tm.as_deref() {
                    Some(Term::Sigma { fst, snd, .. }) => (Some(fst.clone()), Some(snd.clone())),
                    _ => (None, None),
                };
                self.add_fact(f.clone(), irr, fst.clone(), fst_tm.clone(), b, nest + 1);
                // the second component; an irrelevant one (the dependent
                // conjunction `p && q` of propositions) is an irrelevant
                // fact (equations are promoted)
                // (only with its statement term: an irrelevant equation is
                // promoted from its sides, which are otherwise quoted)
                if *snd_rel == Rel::Irr && snd_tm.is_none() {
                    return;
                }
                let mut es = (*snd.env.0).clone();
                if is_prop_type(fst) {
                    // a proof component: bound as its term (see `prove`)
                    es.push(EnvEntry::Irr(sandblaster_kernel::value::Closure { env: self.venv.clone(), body: f.clone() }));
                } else {
                    let Some(fv) = self.eval(&f, b) else { return };
                    es.push(EnvEntry::Rel(fv));
                }
                if let Ok(sty) = self.env.eval(&VEnv(Rc::new(es)), Lvl(self.depth()), &snd.body, b) {
                    let st = match (snd_tm, fst_tm) {
                        (Some(s), Some(ft)) => Some(mk::let_(name, Rel::Rel, ft, f.clone(), s)),
                        _ => None,
                    };
                    self.add_fact(mk::snd(tm), irr || *snd_rel == Rel::Irr, sty, st, b, nest + 1);
                }
            }
            Value::Eq { ty: ety, lhs, rhs } if irr => {
                let (et, lt, rt) = match ty_tm.as_deref() {
                    Some(Term::Eq { ty, lhs, rhs }) => (ty.clone(), lhs.clone(), rhs.clone()),
                    _ => (self.quote(ety), self.quote(lhs), self.quote(rhs)),
                };
                let promoted = match self.promote {
                    Some(p) => mk::apps(mk::global(p), [(Rel::Rel, et), (Rel::Rel, lt), (Rel::Rel, rt), (Rel::Irr, tm)]),
                    None => tm,
                };
                self.facts.push(Fact { tm: promoted, depth: self.depth(), ty, ty_tm });
            }
            _ => self.facts.push(Fact { tm, depth: self.depth(), ty, ty_tm }),
        }
    }

    /// The main loop. `tgt` is the target as a term (at the current depth),
    /// when known.
    fn prove(&mut self, target: &V, tgt: Option<&Tm>, splits: u32, b: &mut Budget) -> Option<Tm> {
        if !meter::settle(b) {
            return None;
        }
        // 1. refl / trivial
        match &**target {
            Value::Eq { ty, lhs, rhs } => {
                if self.conv(lhs, rhs, b) {
                    return Some(match tgt.map(|t| &**t) {
                        Some(Term::Eq { ty, lhs, .. }) => mk::refl(ty.clone(), lhs.clone()),
                        _ => mk::refl(self.quote(ty), self.quote(lhs)),
                    });
                }
            }
            Value::Ind { ind, .. } if self.env.inductive_decl(*ind).is_some_and(|d| d.ctors.len() == 1 && d.ctors[0].fields.is_empty()) => {
                return Some(mk::ctor(*ind, 0, vec![], vec![]));
            }
            _ => {}
        }
        // 2. assumption: first a fact whose recorded statement is the
        // target term up to proofs (no evaluation: conversion of two
        // separately evaluated copies of a large statement walks both),
        // then by conversion
        if let Some(t) = tgt {
            let t = zeta_top(t);
            for f in self.scan_facts() {
                if let Some(ft) = &f.ty_tm
                    && self.env.alpha_eq_relevant(&zeta_top(&self.at(ft, f.depth)), &t, &|a, b| a == b)
                {
                    return Some(self.fact_tm(&f));
                }
            }
        }
        for f in self.scan_facts() {
            if self.conv(&f.ty, target, b) {
                return Some(self.fact_tm(&f));
            }
        }
        // 3. connectives
        match &**target {
            Value::Sigma { fst, snd, name, .. } => {
                // contradictory facts close the whole target: a witness
                // `absurd(T, p)` would reach the second component's type
                // with its proof erased (`absurd(T, _)`, not re-checkable)
                if let Some(p) = self.contradiction(b) {
                    let ty = match tgt {
                        Some(t) => t.clone(),
                        None => self.quote(target),
                    };
                    return Some(Rc::new(Term::Absurd { ty, proof: p }));
                }
                let (fst_tm, snd_tm) = match tgt.map(|t| &**t) {
                    Some(Term::Sigma { fst, snd, .. }) => (Some(fst.clone()), Some(snd.clone())),
                    _ => (None, None),
                };
                let p1 = self.prove(fst, fst_tm.as_ref(), splits, b)?;
                // the second component sees the first only through proofs:
                // bind the proof *term* (an irrelevant closure), never its
                // value — a proof evaluates to `refl(c)`, which reads back
                // as `refl(Bool, c)` where `Eq(Bool, c, true)` is needed
                let mut es = (*snd.env.0).clone();
                es.push(EnvEntry::Irr(sandblaster_kernel::value::Closure { env: self.venv.clone(), body: p1.clone() }));
                let sty = self.env.eval(&VEnv(Rc::new(es)), Lvl(self.depth()), &snd.body, b).ok()?;
                let st = match (&snd_tm, &fst_tm) {
                    (Some(s), Some(ft)) => Some(mk::let_(name, Rel::Rel, ft.clone(), p1.clone(), s.clone())),
                    _ => None,
                };
                let p2 = self.prove(&sty, st.as_ref(), splits, b)?;
                let ty = match tgt {
                    Some(t) => t.clone(),
                    None => self.quote(target),
                };
                return Some(mk::pair(ty, p1, p2));
            }
            Value::Pi { name, rel, dom, cod } => {
                let (dom_t, cod_t) = match tgt.map(|t| &**t) {
                    Some(Term::Pi { dom, cod, .. }) => (dom.clone(), Some(cod.clone())),
                    _ => (self.quote(dom), None),
                };
                let saved = (self.ctx.clone(), self.venv.clone(), self.facts.len());
                self.push(name, dom.clone());
                let x = self.venv.0.last().cloned()?;
                if is_prop_type(dom) || matches!(&**dom, Value::Ind { ind, .. } if *ind == self.env.empty_ind()) {
                    self.add_fact(mk::var(0), false, dom.clone(), Some(shift(&dom_t, 1)), b, 0);
                }
                let mut es = (*cod.env.0).clone();
                es.push(x);
                let body_ty = self.env.eval(&VEnv(Rc::new(es)), Lvl(self.depth()), &cod.body, b).ok();
                let r = body_ty.and_then(|t| self.prove(&t, cod_t.as_ref(), splits, b));
                self.ctx = saved.0;
                self.venv = saved.1;
                self.facts.truncate(saved.2);
                return Some(mk::lam(name, *rel, dom_t, r?));
            }
            _ => {}
        }
        let tgt_t = match tgt {
            Some(t) => t.clone(),
            None => self.quote(target),
        };
        // 4a. linear arithmetic over the facts that share a variable with
        // the goal (transitively): the other facts' atoms can be large (a
        // residual's slices, `list_take`/`list_drop` unfolded), and their
        // linearization dominated trivial goals; the complete search below
        // runs when this finds nothing
        if let Some(p) = self.linarith_relevant(target, &tgt_t, b) {
            return Some(p);
        }
        // 4. contradictions
        if let Some(p) = self.contradiction(b) {
            return Some(Rc::new(Term::Absurd { ty: tgt_t, proof: p }));
        }
        // 5. linarith (after equational saturation)
        let (res, atoms) = self.linarith(target, &tgt_t, b);
        if let Some(p) = res {
            return Some(p);
        }
        if !atoms.is_empty() {
            let n = self.facts.len();
            self.saturate_equations(&atoms, b);
            if self.facts.len() > n {
                let (res, _) = self.linarith(target, &tgt_t, b);
                if let Some(p) = res {
                    return Some(p);
                }
            }
        }
        // 6. bounds of piecewise atoms, each proven by a local split
        if !atoms.is_empty() && self.atom_bounds(&atoms, b) {
            let (res, _) = self.linarith(target, &tgt_t, b);
            if let Some(p) = res {
                return Some(p);
            }
        }
        // 7. case splits
        if splits > 0
            && let Some(p) = self.split(target, &tgt_t, &atoms, splits, b)
        {
            return Some(p);
        }
        None
    }

    /// A proof of `Empty` from the facts, if one is immediate.
    fn contradiction(&mut self, b: &mut Budget) -> Option<Tm> {
        let empty = self.env.empty_ind();
        let facts = self.facts.clone();
        for f in &facts {
            match &*f.ty {
                Value::Ind { ind, .. } if *ind == empty => return Some(self.fact_tm(f)),
                Value::Eq { lhs, rhs, .. } => {
                    if let (Value::Ctor { ind: i1, ctor: c1, .. }, Value::Ctor { ind: i2, ctor: c2, .. }) = (&**lhs, &**rhs)
                        && i1 == i2
                        && c1 != c2
                    {
                        let (ft, fty) = (self.fact_tm(f), self.fact_ty_tm(f));
                        return self.no_confusion(ft, &fty, *i1, *c1);
                    }
                }
                _ => {}
            }
        }
        // two facts equating one term to different constructors
        for (i, f) in facts.iter().enumerate() {
            let Value::Eq { lhs: l1, rhs: r1, .. } = &*f.ty else { continue };
            let Value::Ctor { ind: i1, ctor: c1, .. } = &**r1 else { continue };
            for g in &facts[i + 1..] {
                if !meter::spend(1) {
                    return None;
                }
                let Value::Eq { lhs: l2, rhs: r2, .. } = &*g.ty else { continue };
                let Value::Ctor { ind: i2, ctor: c2, .. } = &**r2 else { continue };
                if i1 != i2 || c1 == c2 || !self.conv(l1, l2, b) {
                    continue;
                }
                let (Some(sym), Some(trans)) = (self.sym, self.trans) else { continue };
                let (fty, gty) = (self.fact_ty_tm(f), self.fact_ty_tm(g));
                let (Term::Eq { ty, lhs, rhs: rf }, Term::Eq { rhs: rg, .. }) = (&*fty, &*gty) else { continue };
                // trans(C1, t, C2, sym f, g) : Eq(A, C1, C2)
                let symf = mk::apps(mk::global(sym), [(Rel::Rel, ty.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, rf.clone()), (Rel::Rel, self.fact_tm(f))]);
                let chain = mk::apps(mk::global(trans), [(Rel::Rel, ty.clone()), (Rel::Rel, rf.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, rg.clone()), (Rel::Rel, symf), (Rel::Rel, self.fact_tm(g))]);
                let cty = mk::eq(ty.clone(), rf.clone(), rg.clone());
                return self.no_confusion(chain, &cty, *i1, *c1);
            }
        }
        // a disequality fact whose negation linarith proves
        for f in &facts {
            if !meter::spend(1) {
                return None;
            }
            let Some((cmp_t, neg_val)) = self.diseq(f) else { continue };
            let bool_t = mk::bool_ty(self.bool_);
            let goal = mk::eq(bool_t.clone(), cmp_t.clone(), mk::bool_lit(self.bool_, neg_val));
            let hyps = self.lin_hyps();
            let Ok(p) = linarith_term_b(self.env, &self.ctx, hyps, goal, b) else { continue };
            let (Some(sym), Some(trans), Some(fnt)) = (self.sym, self.trans, self.false_ne_true) else { continue };
            let (t_, f_) = (mk::bool_lit(self.bool_, true), mk::bool_lit(self.bool_, false));
            let ft = self.fact_tm(f);
            // eq case: f : X = false, p : X = true ⟹ trans(false, X, true, sym f, p)
            // ne case: f : X = true,  p : X = false ⟹ trans(false, X, true, sym p, f)
            let (e1, e2) = if neg_val { (ft, p) } else { (p, ft) };
            let sym_e1 = mk::apps(mk::global(sym), [(Rel::Rel, bool_t.clone()), (Rel::Rel, cmp_t.clone()), (Rel::Rel, f_.clone()), (Rel::Rel, e1)]);
            let chain = mk::apps(mk::global(trans), [(Rel::Rel, bool_t.clone()), (Rel::Rel, f_.clone()), (Rel::Rel, cmp_t.clone()), (Rel::Rel, t_.clone()), (Rel::Rel, sym_e1), (Rel::Rel, e2)]);
            return Some(mk::app(mk::global(fnt), chain));
        }
        // linarith contradiction among the facts
        let goal = mk::ind(empty, vec![]);
        let hyps = self.lin_hyps();
        if !hyps.is_empty()
            && let Ok(t) = linarith_term_b(self.env, &self.ctx, hyps, goal, b)
        {
            return Some(t);
        }
        None
    }

    /// `pf : Eq(D, C₁.., C₂..)` ⟹ `Empty`, by `bool::false_ne_true` or a
    /// transport with a constructor-discriminating motive.
    fn no_confusion(&mut self, pf: Tm, pf_ty: &Tm, ind: IndId, c1: u32) -> Option<Tm> {
        let Term::Eq { ty: ty_t, lhs, rhs } = &**pf_ty else { return None };
        if ind == self.bool_
            && c1 == 0
            && let Some(g) = self.false_ne_true
        {
            return Some(mk::app(mk::global(g), pf));
        }
        let decl = self.env.inductive_decl(ind)?;
        let unit = self.env.lookup_ind("Unit")?;
        let empty = self.env.empty_ind();
        let params = match &**ty_t {
            Term::Ind { params, .. } => params.clone(),
            _ => return None,
        };
        let arms = decl
            .ctors
            .iter()
            .enumerate()
            .map(|(k, c)| sandblaster_kernel::term::Arm {
                names: c.fields.iter().map(|x| x.0.clone()).collect(),
                body: if k as u32 == c1 { mk::ind(unit, vec![]) } else { mk::ind(empty, vec![]) },
            })
            .collect();
        let motive = Rc::new(Term::Match { ind, params: params.iter().map(|p| shift(p, 1)).collect(), scrut: mk::var(0), motive: mk::ty(), arms });
        Some(Rc::new(Term::Transport { ty: ty_t.clone(), lhs: lhs.clone(), rhs: rhs.clone(), eq: pf, motive, val: mk::ctor(unit, 0, vec![], vec![]) }))
    }

    /// A disequality fact `eq_w(a, b) = false` / `ne_w(a, b) = true`: the
    /// comparison term and the boolean value its negation has.
    fn diseq(&self, f: &Fact) -> Option<(Tm, bool)> {
        let Value::Eq { ty, lhs, rhs } = &*f.ty else { return None };
        if !matches!(&**ty, Value::Ind { ind, .. } if *ind == self.bool_) {
            return None;
        }
        // decide on the value first: the statement is only read back (an
        // unmetered quote of a possibly large fact) for a disequality
        let neg = match (prim_head(lhs), as_bool_lit(rhs, self.bool_)) {
            (Some(PrimOp::Eq(_)), Some(false)) => true,
            (Some(PrimOp::Ne(_)), Some(true)) => false,
            _ => return None,
        };
        let lt = match self.fact_ty_tm(f).as_ref() {
            Term::Eq { lhs, .. } => lhs.clone(),
            _ => self.quote(lhs),
        };
        Some((lt, neg))
    }

    /// The facts in a §5.8 hypothesis form, as `(proof, stated)`.
    fn lin_hyps(&self) -> Vec<(Tm, Tm)> {
        let mut out = Vec::new();
        for f in &self.facts {
            if let Value::Eq { ty, lhs, rhs } = &*f.ty {
                let ok = match &**ty {
                    Value::IntTy(_) => true,
                    Value::Ind { ind, .. } if *ind == self.bool_ => match (prim_head(lhs), as_bool_lit(rhs, self.bool_)) {
                        (Some(op), Some(v)) if is_cmp(op) => !(matches!(op, PrimOp::Ne(_)) && v) && !(matches!(op, PrimOp::Eq(_)) && !v),
                        _ => false,
                    },
                    _ => false,
                };
                if ok {
                    out.push((self.fact_tm(f), self.fact_ty_tm(f)));
                }
            }
        }
        out
    }

    /// Linear arithmetic over the facts connected to the goal by shared
    /// variables (see step 4a of [`PCx::prove`]); `None` when that is every
    /// fact (the complete steps follow) or no certificate is found.
    fn linarith_relevant(&mut self, target: &V, goal: &Tm, b: &mut Budget) -> Option<Tm> {
        if !self.lin_goal(target) || matches!(&**target, Value::Ind { .. }) {
            return None;
        }
        let depth = self.depth();
        let levels = |t: &Tm| -> Vec<u32> {
            let mut out = Vec::new();
            super::tm::any_node_depth(t, &mut |n, d| {
                if let Term::Var(i) = n
                    && i.0 >= d
                    && i.0 - d < depth
                {
                    out.push(depth - 1 - (i.0 - d));
                }
                false
            });
            out
        };
        let hyps = self.lin_hyps();
        let hvars: Vec<Vec<u32>> = hyps.iter().map(|(_, st)| levels(st)).collect();
        let mut vars: std::collections::BTreeSet<u32> = levels(goal).into_iter().collect();
        if vars.is_empty() {
            return None;
        }
        let mut chosen = vec![false; hyps.len()];
        loop {
            let mut grew = false;
            for (i, hv) in hvars.iter().enumerate() {
                if !chosen[i] && hv.iter().any(|v| vars.contains(v)) {
                    chosen[i] = true;
                    vars.extend(hv.iter().copied());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        if chosen.iter().all(|c| *c) || !chosen.iter().any(|c| *c) {
            return None;
        }
        let mut sel: Vec<(Tm, Tm)> = hyps.into_iter().zip(&chosen).filter(|(_, c)| **c).map(|(h, _)| h).collect();
        let mut extra = Vec::new();
        super::recert::harvest(self.env, goal, &mut extra);
        for (_, st) in &sel {
            super::recert::harvest(self.env, st, &mut extra);
        }
        sel.extend(extra);
        let sys = self.env.linearize(&self.ctx, &sel, goal, b).ok()?;
        let cert = super::fm::certificate(&sys)?;
        Some(self.lin_term(sel, goal, &sys, cert, b))
    }

    /// Whether the target is a §5.8 goal form.
    fn lin_goal(&self, target: &V) -> bool {
        match &**target {
            Value::Eq { ty, lhs, rhs } => match &**ty {
                Value::IntTy(_) => true,
                Value::Ind { ind, .. } if *ind == self.bool_ => prim_head(lhs).is_some_and(is_cmp) && as_bool_lit(rhs, self.bool_).is_some(),
                _ => false,
            },
            Value::Ind { ind, .. } => *ind == self.env.empty_ind(),
            _ => false,
        }
    }

    /// Linear arithmetic; returns the proof or the atoms of the system.
    fn linarith(&mut self, target: &V, goal: &Tm, b: &mut Budget) -> (Option<Tm>, Vec<Tm>) {
        if !self.lin_goal(target) {
            return (None, vec![]);
        }
        let mut hyps = self.lin_hyps();
        let mut extra = Vec::new();
        super::recert::harvest(self.env, goal, &mut extra);
        for (_, st) in &hyps {
            super::recert::harvest(self.env, st, &mut extra);
        }
        hyps.extend(extra);
        let sys = match self.env.linearize(&self.ctx, &hyps, goal, b) {
            Ok(s) => s,
            Err(e) => {
                self.tried.push(format!("linarith: {}", e.message.lines().next().unwrap_or("")));
                return (None, vec![]);
            }
        };
        match super::fm::certificate(&sys) {
            Some(cert) => (Some(self.lin_term(hyps, goal, &sys, cert, b)), vec![]),
            None => {
                self.tried.push(format!("linarith over {} hypothesis(es): no certificate", hyps.len()));
                // atoms are quoted values: re-certify their embedded proofs
                // (once, here); huge atoms (e.g. whole arrays) are dropped,
                // they only make the rewriting steps expensive
                let atoms = sys.atoms.iter().filter(|a| super::tm::size(a) <= MAX_ATOM_SIZE).map(|a| super::recert::recertify_quoted(self.env, &self.ctx, a)).collect();
                (None, atoms)
            }
        }
    }

    /// The `Linarith` term without the hypotheses the certificate does not
    /// use (as `auto`'s `lin_term`): every later check of the proof — the
    /// re-certification, the kernel's `add_def`, and every motive or clone
    /// lemma that re-checks it — linearizes only what the proof needs (the
    /// unused facts of a context can be large atoms, e.g. the unfolded
    /// slices of `list_take`/`list_drop`). The certificate is recomputed on
    /// the smaller system; the original term stays if none is found.
    fn lin_term(&self, hyps: Vec<(Tm, Tm)>, goal: &Tm, sys: &sandblaster_kernel::linarith::LinSystem, cert: Vec<sandblaster_kernel::term::Rat>, b: &mut Budget) -> Tm {
        let mut used = vec![false; hyps.len()];
        let mut off = 0;
        for p in &sys.problems {
            for (c, m) in p.iter().zip(cert.get(off..off + p.len()).unwrap_or(&[])) {
                if let sandblaster_kernel::linarith::ConstraintOrigin::Hyp(i) = c.origin
                    && i < used.len()
                    && m.num != num_bigint::BigInt::from(0)
                {
                    used[i] = true;
                }
            }
            off += p.len();
        }
        if !used.iter().all(|u| *u) {
            let small: Vec<(Tm, Tm)> = hyps.iter().zip(&used).filter(|(_, u)| **u).map(|(h, _)| h.clone()).collect();
            if let Ok(sys2) = self.env.linearize(&self.ctx, &small, goal, b)
                && let Some(cert2) = super::fm::certificate(&sys2)
            {
                return Rc::new(Term::Linarith { hyps: small, goal: goal.clone(), cert: cert2 });
            }
        }
        Rc::new(Term::Linarith { hyps, goal: goal.clone(), cert })
    }

    /// For every equational fact `t = v` (`v` a constructor or literal, `t`
    /// not), adds `A = A[t := v]` for the atoms `A` containing `t`.
    fn saturate_equations(&mut self, atoms: &[Tm], b: &mut Budget) {
        for f in self.scan_facts() {
            let Value::Eq { lhs, rhs, .. } = &*f.ty else { continue };
            if !closed_val(rhs) || closed_val(lhs) {
                continue;
            }
            let Term::Eq { ty, lhs: lt, rhs: rt } = &*self.fact_ty_tm(&f) else { continue };
            let pf = self.fact_tm(&f);
            self.subst_atom_facts(atoms, ty, lt, rt, &pf, b);
        }
    }

    /// Adds `A = A[t := v]` for the atoms `A` containing `t`, given `pf :
    /// Eq(T, t, v)`.
    fn subst_atom_facts(&mut self, atoms: &[Tm], tty: &Tm, t: &Tm, v: &Tm, pf: &Tm, b: &mut Budget) {
        let t1 = shift(t, 1);
        for a in atoms {
            let a1 = shift(a, 1);
            let m = replace_occ(self.env, &a1, &t1);
            if !occurs(&m, 0) {
                continue;
            }
            let aty = match self.env.infer(&self.ctx, a, &mut *b) {
                Ok(t) => t,
                Err(e) => {
                    if std::env::var("SANDBLASTER_DEBUG_BASIC").is_ok() {
                        eprintln!("subst_atom_facts: cannot type atom {}: {e}", self.env.print_term(&self.names(), a).chars().take(400).collect::<String>());
                    }
                    continue;
                }
            };
            let wt = self.quote(&aty);
            // transport(T, t, v, pf, y. Eq(W, A, A[t := y]), refl(W, A)) : Eq(W, A, A[t := v])
            let motive = mk::eq(shift(&wt, 1), a1.clone(), m.clone());
            let proof = Rc::new(Term::Transport { ty: tty.clone(), lhs: t.clone(), rhs: v.clone(), eq: pf.clone(), motive, val: mk::refl(wt.clone(), a.clone()) });
            // the motive must be well-typed for every value of `t` (it is
            // not when `t` is the scrutinee of a dependent-match idiom in
            // `A` whose arms use their path equation)
            if self.env.infer(&self.ctx, &proof, &mut *b).is_err() {
                continue;
            }
            let fty = mk::eq(wt, a.clone(), super::tm::subst0(&m, v));
            let Some(fv) = self.eval(&fty, b) else { continue };
            self.facts.push(Fact { tm: proof, depth: self.depth(), ty: fv, ty_tm: Some(fty) });
        }
    }

    /// Adds bound facts for the piecewise atoms (and their piecewise
    /// subterms) of a linear system: `min(a, c) ≤ a, c`, `a, c ≤ max(a, c)`,
    /// `sat_sub(a, c) ≤ a`, and `lo ≤ m ≤ hi` for a stuck `Bool` match `m`
    /// whose arms are literals (e.g. `b as u64`). Each is proven by a
    /// one-level split with only its own atom ([`Self::split_on`] with the
    /// §5.10 axiom instances). Returns whether a fact was added.
    fn atom_bounds(&mut self, atoms: &[Tm], b: &mut Budget) -> bool {
        if self.in_bounds {
            return false;
        }
        self.in_bounds = true;
        let r = self.atom_bounds_inner(atoms, b);
        self.in_bounds = false;
        r
    }

    fn atom_bounds_inner(&mut self, atoms: &[Tm], b: &mut Budget) -> bool {
        let mut subs = Vec::new();
        for a in atoms {
            piecewise_subterms(a, self.bool_, &mut subs);
        }
        let mut added = false;
        for piece in subs {
            let (atom, w, bounds, scrut, ax) = match piece {
                Piece::Split { atom, w, bounds, scrut, ax } => (atom, w, bounds, scrut, ax),
                Piece::Axiom { atom, schema, w, args } => {
                    let key = format!("{:016x}{schema:?}", super::tm::fingerprint(&atom));
                    if self.bounded.contains(&key) {
                        continue;
                    }
                    self.bounded.push(key);
                    let Some(id) = axiom_id(schema, w) else { continue };
                    let t = Rc::new(Term::Axiom { ax: id, args });
                    if let Ok(ty) = self.env.infer(&self.ctx, &t, &mut *b) {
                        let tyt = self.quote(&ty);
                        self.facts.push(Fact { tm: t, depth: self.depth(), ty, ty_tm: Some(tyt) });
                        added = true;
                    }
                    continue;
                }
                Piece::Mul { atom, x, y, xb, yb } => {
                    let key = format!("{:016x}", super::tm::fingerprint(&atom));
                    if self.bounded.contains(&key) {
                        continue;
                    }
                    self.bounded.push(key);
                    if let Some((p, stmt, v)) = self.mul_bound(&x, &y, &xb, &yb, b) {
                        self.facts.push(Fact { tm: p, depth: self.depth(), ty: v, ty_tm: Some(stmt) });
                        added = true;
                    }
                    continue;
                }
                Piece::Match { atom, w, ub } => {
                    // a bound by cases on the match's scrutinee
                    if self.restricted {
                        continue;
                    }
                    let key = format!("{:016x}", super::tm::fingerprint(&atom));
                    if self.bounded.contains(&key) {
                        continue;
                    }
                    self.bounded.push(key);
                    if let Some((p, stmt, v)) = self.match_bound(&atom, w, &ub, b) {
                        self.facts.push(Fact { tm: p, depth: self.depth(), ty: v, ty_tm: Some(stmt) });
                        added = true;
                    }
                    continue;
                }
            };
            let key = format!("{:016x}", super::tm::fingerprint(&atom));
            if self.bounded.contains(&key) {
                continue;
            }
            self.bounded.push(key);
            for (lo, hi) in bounds {
                let bool_t = mk::bool_ty(self.bool_);
                let tgt = mk::eq(bool_t, mk::prim(PrimOp::Le(w), vec![lo, hi], vec![]), mk::bool_lit(self.bool_, true));
                let Some(tv) = self.eval(&tgt, b) else { continue };
                let saved = (self.facts.clone(), self.tried.len());
                self.facts.clear();
                let budget = std::mem::replace(&mut self.split_budget, 1);
                let r = self.split_on(&tv, &tgt, std::slice::from_ref(&atom), &scrut, ax.clone(), 1, b);
                self.split_budget = budget;
                self.facts = saved.0;
                self.tried.truncate(saved.1);
                if let Some(p) = r {
                    self.facts.push(Fact { tm: p, depth: self.depth(), ty: tv, ty_tm: Some(tgt) });
                    added = true;
                }
            }
        }
        added
    }

    /// The facts mentioning the `Bool` scrutinee `c` (at the current
    /// depth `d`), generalized for a split's motive: `(fact proof, G)` with
    /// `G` in the context `d, y : Bool, e : Eq(Bool, c, y)` such that
    /// `G[y := c, e := refl(Bool, c)] ≡` the fact's statement (see
    /// [`generalize`]). Each `G` is type-checked; facts whose recorded
    /// statement does not mention `c` are tried with their quoted
    /// statement, in which let-bound locals are unfolded.
    fn generalizable_facts(&mut self, c: &Tm, atoms: &[Tm], b: &mut Budget) -> Vec<(Tm, Tm)> {
        let bool_t = mk::bool_ty(self.bool_);
        let mut out = Vec::new();
        let saved = (self.ctx.clone(), self.venv.clone());
        let facts = self.facts.clone();
        let Some(bv) = self.eval(&bool_t, b) else { return out };
        self.push("y", bv);
        let ety = mk::eq(shift(&bool_t, 1), shift(c, 1), mk::var(0));
        let Some(ev) = self.eval(&ety, b) else {
            (self.ctx, self.venv) = saved;
            return out;
        };
        self.push("e", ev);
        let c2 = shift(c, 2);
        for f in &facts {
            if !matches!(&*f.ty, Value::Eq { .. }) {
                continue;
            }
            if out.len() >= MAX_GEN_FACTS || !meter::spend(1) {
                break;
            }
            // the recorded statement (at `f.depth`; the current depth is
            // `d + 2`), then the quoted one — built only when needed, and
            // re-certified only when small enough to be used
            for i in 0..2 {
                let t = match (i, &f.ty_tm) {
                    (0, Some(t)) => self.at(t, f.depth),
                    (0, None) => continue,
                    _ => {
                        let q = self.quote_in(&saved.0, &f.ty);
                        if super::tm::size_capped(&q, MAX_ATOM_SIZE + 1) > MAX_ATOM_SIZE {
                            continue;
                        }
                        shift(&super::recert::recertify_quoted(self.env, &saved.0, &q), 2)
                    }
                };
                if super::tm::size_capped(&t, MAX_ATOM_SIZE + 1) > MAX_ATOM_SIZE {
                    continue;
                }
                let g = generalize(self.env, self.bool_, &t, &c2, &mk::var(1), &mk::var(0), 0);
                if !occurs(&g, 1) && !occurs(&g, 0) {
                    continue;
                }
                match self.env.infer(&self.ctx, &g, &mut *b) {
                    Ok(_) => {
                        let pf = shift(&self.fact_tm(f), -2);
                        out.push((pf, g));
                        break;
                    }
                    Err(e) => {
                        if std::env::var("SANDBLASTER_DEBUG_BASIC").is_ok() {
                            eprintln!("generalize: ill-typed: {e}");
                        }
                    }
                }
            }
        }
        // the atoms that mention `c`: `A = A[c := y]` (generalized like a
        // fact; its proof at `y := c`, `e := refl` is `refl(W, A)`), so each
        // branch sees the atom computed with the scrutinee's value
        let mut natoms = 0;
        for a in atoms {
            if natoms >= MAX_GEN_FACTS || super::tm::size_capped(a, MAX_ATOM_SIZE + 1) > MAX_ATOM_SIZE {
                continue;
            }
            let a2 = shift(a, 2);
            let g_rhs = generalize(self.env, self.bool_, &a2, &c2, &mk::var(1), &mk::var(0), 0);
            if !occurs(&g_rhs, 1) && !occurs(&g_rhs, 0) {
                continue;
            }
            let Ok(wv) = self.env.infer(&saved.0, a, &mut *b) else { continue };
            let wt = self.quote_in(&saved.0, &wv);
            let g = mk::eq(shift(&wt, 2), a2, g_rhs);
            match self.env.infer(&self.ctx, &g, &mut *b) {
                Ok(_) => {
                    out.push((mk::refl(wt, a.clone()), g));
                    natoms += 1;
                }
                Err(e) => {
                    if std::env::var("SANDBLASTER_DEBUG_BASIC").is_ok() {
                        eprintln!("generalize atom: ill-typed: {e}");
                    }
                }
            }
        }
        (self.ctx, self.venv) = saved;
        out
    }

    /// `x · y ≤ X · Y` (see [`Piece::Mul`]).
    fn mul_bound(&mut self, x: &Tm, y: &Tm, xb: &num_bigint::BigInt, yb: &num_bigint::BigInt, b: &mut Budget) -> Option<(Tm, Tm, V)> {
        let int = Width::Int;
        let bool_t = mk::bool_ty(self.bool_);
        let tru = mk::bool_lit(self.bool_, true);
        let holds = |t: Tm| mk::eq(bool_t.clone(), t, tru.clone());
        let le = |a: Tm, c: Tm| holds(mk::prim(PrimOp::Le(int), vec![a, c], vec![]));
        let (xl, yl) = (mk::lit(int, xb.clone()), mk::lit(int, yb.clone()));
        let zero = mk::lit(int, 0u8);
        let mut proofs = Vec::new();
        for g in [le(zero.clone(), x.clone()), le(x.clone(), xl.clone()), le(zero.clone(), y.clone()), le(y.clone(), yl.clone())] {
            proofs.push(linarith_term_b(self.env, &self.ctx, vec![], g, b).ok()?);
        }
        let id = axiom_id(Schema::MulMono, int)?;
        let mut args = vec![x.clone(), xl.clone(), y.clone(), yl.clone()];
        args.extend(proofs);
        let t = Rc::new(Term::Axiom { ax: id, args });
        let stmt = le(mk::prim(PrimOp::IMul, vec![x.clone(), y.clone()], vec![]), mk::prim(PrimOp::IMul, vec![xl, yl], vec![]));
        let v = self.eval(&stmt, b)?;
        self.env.check(&self.ctx, &t, &v, &mut *b).ok()?;
        Some((t, stmt, v))
    }

    /// `atom ≤ ub` for a stuck match `atom` (plain or dependent-match
    /// idiom) of width `w`: a match on its scrutinee `s` whose motive
    /// generalizes `s` in the atom (for the idiom, the path equation of
    /// the atom's own match becomes the new motive's binder, so the motive
    /// stays well-typed); in each arm the atom computes to that arm's body,
    /// bounded by refl or linear arithmetic. Returns (proof, statement,
    /// statement value) at the current depth.
    fn match_bound(&mut self, atom: &Tm, w: Width, ub: &num_bigint::BigInt, b: &mut Budget) -> Option<(Tm, Tm, V)> {
        let bool_t = mk::bool_ty(self.bool_);
        let tru = mk::bool_lit(self.bool_, true);
        let stmt_of = |a: Tm, ub_t: Tm| mk::eq(bool_t.clone(), mk::prim(PrimOp::Le(w), vec![a, ub_t], vec![]), tru.clone());
        let ub_lit = mk::lit(w, ub.clone());
        let stmt = stmt_of(atom.clone(), ub_lit.clone());
        let stmt_v = self.eval(&stmt, b)?;
        let (idiom, m) = match &**atom {
            Term::App { rel: Rel::Irr, fun, .. } => (true, fun.clone()),
            _ => (false, atom.clone()),
        };
        let Term::Match { ind, params, scrut, motive, arms } = &*m else { return None };
        let decl = self.env.inductive_decl(*ind)?;
        let d_ty = mk::ind(*ind, params.clone());
        // motive over y (and, for the idiom, e' : Eq(D, s, y))
        let k = if idiom { 2 } else { 1 };
        // shift the whole match (arm bodies are under their field binders)
        let Term::Match { params: sp, motive: sm, arms: sa, .. } = &*shift(&m, k) else { return None };
        let inner = Rc::new(Term::Match {
            ind: *ind,
            params: sp.clone(),
            scrut: mk::var((k - 1) as u32),
            motive: sm.clone(),
            arms: sa.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect(),
        });
        let _ = (motive, arms);
        let inner = if idiom { Rc::new(Term::App { rel: Rel::Irr, fun: inner, arg: mk::var(0) }) } else { inner };
        let body = stmt_of(inner, shift(&ub_lit, k));
        let our_motive = if idiom { mk::pi("e", Rel::Irr, mk::eq(shift(&d_ty, 1), shift(scrut, 1), mk::var(0)), body.clone()) } else { body.clone() };
        // parameter values for the field types
        let pvals: Vec<V> = params.iter().map(|p| self.eval(p, b)).collect::<Option<_>>()?;
        let mut our_arms = Vec::new();
        for (ci, c) in decl.ctors.iter().enumerate() {
            let saved = (self.ctx.clone(), self.venv.clone(), self.facts.clone(), self.tried.len());
            let nf = c.fields.len() as u32;
            let mut fenv: Vec<EnvEntry> = pvals.iter().cloned().map(EnvEntry::Rel).collect();
            let mut ok = true;
            for (name, _, fty) in &c.fields {
                let Ok(tv) = self.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(self.depth()), fty, b) else {
                    ok = false;
                    break;
                };
                self.push(name, tv);
                fenv.push(self.venv.0.last().cloned()?);
            }
            let result = if !ok {
                None
            } else {
                let ctor_t = mk::ctor(*ind, ci as u32, params.iter().map(|p| shift(p, nf as i64)).collect(), (0..nf).rev().map(mk::var).collect());
                // the arm's goal: the motive body with y := ctor (and e' := Var(0))
                if idiom {
                    let e_ty = mk::eq(shift(&d_ty, nf as i64), shift(scrut, nf as i64), ctor_t.clone());
                    let e_v = self.eval(&e_ty, b)?;
                    self.push("e", e_v);
                    // body lives in [d, y, e']; here: [d, fields, e']
                    let g = super::tm::subst_idx(&shift_above(&body, 2, nf), 1, &shift(&ctor_t, 1));
                    let gv = self.eval(&g, b);
                    let p = gv.and_then(|gv| self.prove(&gv, Some(&g), 0, b));
                    p.map(|p| mk::lam("e", Rel::Irr, e_ty, p))
                } else {
                    let g = super::tm::subst0(&shift_above(&body, 1, nf), &ctor_t);
                    let gv = self.eval(&g, b);
                    gv.and_then(|gv| self.prove(&gv, Some(&g), 0, b))
                }
            };
            self.ctx = saved.0;
            self.venv = saved.1;
            self.facts = saved.2;
            self.tried.truncate(saved.3);
            our_arms.push(sandblaster_kernel::term::Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: result? });
        }
        let mt = Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut.clone(), motive: our_motive, arms: our_arms });
        let proof = if idiom { Rc::new(Term::App { rel: Rel::Irr, fun: mt, arg: mk::refl(d_ty, scrut.clone()) }) } else { mt };
        // certificates in the exact context of the final term
        let proof = super::recert::recertify(self.env, &self.ctx, &proof);
        if let Err(e) = self.env.check(&self.ctx, &proof, &stmt_v, &mut *b) {
            if std::env::var("SANDBLASTER_DEBUG_BASIC").is_ok() {
                eprintln!("match_bound: ill-typed: {e}");
            }
            return None;
        }
        Some((proof, stmt, stmt_v))
    }

    /// Case splits on the atoms that blocked linarith.
    fn split(&mut self, target: &V, tgt: &Tm, atoms: &[Tm], splits: u32, b: &mut Budget) -> Option<Tm> {
        let mut cands: Vec<SplitCand> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        let mut pool: Vec<Tm> = atoms.to_vec();
        pool.push(tgt.clone());
        for f in &self.facts {
            if let Value::Eq { lhs, rhs, .. } = &*f.ty
                && as_bool_lit(rhs, self.bool_).is_some()
                && matches!(&**lhs, Value::Neu(n) if n.spine.iter().any(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. })))
            {
                pool.push(self.quote(lhs));
            }
        }
        for a in &pool {
            collect_splits(a, self.bool_, &mut cands, &mut seen);
        }
        // a ≠ b splits into a < b ∨ b < a
        for f in self.scan_facts() {
            let Some((cmp_t, _)) = self.diseq(&f) else { continue };
            if let Term::Prim { op: PrimOp::Eq(w) | PrimOp::Ne(w), args, .. } = &*cmp_t
                && args.len() == 2
            {
                for (x, y) in [(&args[1], &args[0]), (&args[0], &args[1])] {
                    let c = mk::prim(PrimOp::Lt(*w), vec![x.clone(), y.clone()], vec![]);
                    let fc = super::tm::fingerprint(&c);
                    if !seen.contains(&fc) {
                        seen.push(fc);
                        cands.push((c, None));
                    }
                }
            }
        }
        for (scrut, ax) in cands.into_iter().take(12) {
            if meter::exhausted().is_some() {
                return None;
            }
            if let Some(p) = self.split_on(target, tgt, atoms, &scrut, ax, splits, b) {
                return Some(p);
            }
        }
        None
    }

    /// Dependent match on the boolean `scrut`; the goal is unchanged; each
    /// branch adds its path equation, `A = A[scrut := b]` for the atoms, and
    /// the axiom instance for a comparison.
    #[allow(clippy::too_many_arguments)]
    fn split_on(&mut self, target: &V, tgt: &Tm, atoms: &[Tm], scrut: &Tm, ax: Option<(Schema, Schema, Width, Tm, Tm)>, splits: u32, b: &mut Budget) -> Option<Tm> {
        // case-split bookkeeping (fact scans, generalization, the arms'
        // contexts) is charged per fact
        if !meter::spend(1 + self.facts.len() as u64) || !meter::settle(b) {
            return None;
        }
        let sv = self.eval(scrut, b)?;
        if as_bool_lit(&sv, self.bool_).is_some() {
            return None;
        }
        if self.split_budget == 0 {
            return None;
        }
        // an enclosing split (or a fact) already decides the scrutinee
        let bool_t0 = mk::bool_ty(self.bool_);
        for lit in [false, true] {
            let t = mk::eq(bool_t0.clone(), scrut.clone(), mk::bool_lit(self.bool_, lit));
            if let Some(tv) = self.eval(&t, b)
                && self.facts.clone().iter().any(|f| self.conv(&f.ty, &tv, b))
            {
                return None;
            }
        }
        self.split_budget -= 1;
        self.tried.push(format!("case split on `{}`", sandblaster_kernel::syntax::printer::print_term_bounded(self.env, &self.names(), scrut, 300)));
        let bool_t = mk::bool_ty(self.bool_);
        // facts mentioning the scrutinee are generalized in the motive, so
        // that each branch sees them with the scrutinee replaced
        let gfacts = self.generalizable_facts(scrut, atoms, b);
        let n = gfacts.len() as u32;
        let mut arms = Vec::new();
        for val in [false, true] {
            let saved = (self.ctx.clone(), self.venv.clone(), self.facts.clone());
            let bl = mk::bool_lit(self.bool_, val);
            let eq_ty_t = mk::eq(bool_t.clone(), scrut.clone(), bl.clone());
            let eq_ty = self.eval(&eq_ty_t, b)?;
            self.push("e", eq_ty.clone());
            self.add_fact(mk::var(0), false, eq_ty, Some(shift(&eq_ty_t, 1)), b, 0);
            // the generalized facts at `y := val`, `e := Var(0)`
            let mut doms = Vec::new();
            for (i, (_, g)) in gfacts.iter().enumerate() {
                // g lives in [d, y, e]; instantiate y with the literal
                let gi = super::tm::subst_idx(g, 1, &shift(&bl, 1));
                let gi = shift(&gi, i as i64);
                let Some(gv) = self.eval(&gi, b) else {
                    self.ctx = saved.0;
                    self.venv = saved.1;
                    self.facts = saved.2;
                    return None;
                };
                self.push("f", gv.clone());
                self.add_fact(mk::var(0), false, gv, Some(shift(&gi, 1)), b, 0);
                doms.push(gi);
            }
            let k = 1 + n;
            if let Some((le_s, gt_s, w, a, c)) = &ax {
                let schema = if val { *le_s } else { *gt_s };
                if let Some(id) = axiom_id(schema, *w) {
                    let args = vec![shift(a, k as i64), shift(c, k as i64), mk::var(n)];
                    let t = Rc::new(Term::Axiom { ax: id, args: args.clone() });
                    if let Ok(ty) = self.env.infer(&self.ctx, &t, &mut *b) {
                        let tyt = self.quote(&ty);
                        self.add_fact(t, false, ty, Some(tyt), b, 0);
                    }
                }
            }
            let r = self.prove(target, Some(&shift(tgt, k as i64)), splits - 1, b);
            self.ctx = saved.0;
            self.venv = saved.1;
            self.facts = saved.2;
            let mut body = r?;
            for d in doms.into_iter().rev() {
                body = mk::lam("f", Rel::Rel, d, body);
            }
            arms.push(sandblaster_kernel::term::Arm { names: vec![], body: mk::lam("e", Rel::Rel, eq_ty_t, body) });
        }
        let mut mbody = shift(tgt, 2 + n as i64);
        for (i, (_, g)) in gfacts.iter().enumerate().rev() {
            mbody = mk::pi("f", Rel::Rel, shift(g, i as i64), mbody);
        }
        let motive = mk::pi("e", Rel::Rel, mk::eq(bool_t.clone(), shift(scrut, 1), mk::var(0)), mbody);
        let mt = Rc::new(Term::Match { ind: self.bool_, params: vec![], scrut: scrut.clone(), motive, arms });
        let mut app = mk::app(mt, mk::refl(bool_t, scrut.clone()));
        for (pf, _) in gfacts {
            app = mk::app(app, pf);
        }
        Some(app)
    }
}

/// Shifts the free variables of `t` at or above index `k` by `n` (inserts
/// `n` binders below the `k` innermost free variables).
fn shift_above(t: &Tm, k: u32, n: u32) -> Tm {
    super::tm::map_post(t, 0, &mut |node, b| match &*node {
        Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b + k => Some(mk::var(*i + n)),
        _ => Some(node),
    })
    .expect("shift_above")
}

/// Quotes a value in `ctx` (charged to the goal; an unaffordable
/// read-back yields `Erased` and exhausts the goal, [`meter::charge_quote`]).
fn quote_at(env: &Env, ctx: &Ctx, v: &V) -> Tm {
    if !meter::charge_quote(env, ctx, v, None, true) {
        return Rc::new(Term::Erased);
    }
    meter::spend(ctx.entries.len() as u64);
    crate::auto::util::kernel_friendly(env, &env.quote_typed(ctx, v, None, false))
}

/// Generalizes the `Bool` scrutinee `c` in `t` (both under `b` extra
/// binders relative to `y`, `e`): relevant occurrences of `c` become `y`,
/// and the dependent-match idiom `(match c as y' return Π(.e1 : Eq(Bool,
/// c, y')). T with arms) .refl(Bool, c)` becomes `(match y as y' return
/// Π(.e1 : Eq(Bool, c, y')). T with arms) .e` — its motive and arms are
/// kept, so it stays well-typed given `e : Eq(Bool, c, y)`. Proof terms
/// and other irrelevant positions are left untouched.
fn generalize(env: &Env, bool_: IndId, t: &Tm, c: &Tm, y: &Tm, e: &Tm, b: u32) -> Tm {
    use Term::*;
    // a tree walk (charged per node; stops, leaving the rest unchanged, when
    // the goal is exhausted)
    if !meter::spend(1) {
        return t.clone();
    }
    let is_c = |x: &Tm, k: u32| {
        let ck = shift(c, (b + k) as i64);
        std::mem::discriminant(&**x) == std::mem::discriminant(&*ck) && env.alpha_eq_relevant(x, &ck, &|p, q| p == q)
    };
    if is_c(t, 0) {
        return shift(y, b as i64);
    }
    // (the original argument is irrelevant: usually `refl`, but quoting
    // may have instantiated it)
    if let App { rel: Rel::Irr, fun, arg: _ } = &**t
        && let Match { ind, params, scrut, motive, arms } = &**fun
        && *ind == bool_
        && is_c(scrut, 0)
        && matches!(&**motive, Pi { dom, .. } if matches!(&**dom, Eq { lhs, rhs, .. } if is_c(lhs, 1) && matches!(&**rhs, Var(sandblaster_kernel::term::Idx(0)))))
    {
        let m = Rc::new(Match { ind: *ind, params: params.clone(), scrut: shift(y, b as i64), motive: motive.clone(), arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect() });
        return Rc::new(App { rel: Rel::Irr, fun: m, arg: shift(e, b as i64) });
    }
    let r = |x: &Tm, k: u32| generalize(env, bool_, x, c, y, e, b + k);
    match &**t {
        // proofs and irrelevant positions: untouched
        Refl { .. } | Linarith { .. } | BvRefl { .. } | Absurd { .. } | Axiom { .. } | Delta { .. } | Unfold { .. } | Transport { .. } | Erased | Rec { .. } => t.clone(),
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } => t.clone(),
        App { rel: Rel::Irr, fun, arg } => Rc::new(App { rel: Rel::Irr, fun: r(fun, 0), arg: arg.clone() }),
        App { rel, fun, arg } => Rc::new(App { rel: *rel, fun: r(fun, 0), arg: r(arg, 0) }),
        Prim { op, args, proofs } => Rc::new(Prim { op: *op, args: args.iter().map(|a| r(a, 0)).collect(), proofs: proofs.clone() }),
        Eq { ty, lhs, rhs } => Rc::new(Eq { ty: r(ty, 0), lhs: r(lhs, 0), rhs: r(rhs, 0) }),
        Fst(x) => Rc::new(Fst(r(x, 0))),
        Snd(x) => Rc::new(Snd(r(x, 0))),
        Pi { name, rel, dom, cod } => Rc::new(Pi { name: name.clone(), rel: *rel, dom: r(dom, 0), cod: r(cod, 1) }),
        Lam { name, rel, dom, body } => Rc::new(Lam { name: name.clone(), rel: *rel, dom: r(dom, 0), body: r(body, 1) }),
        Let { name, rel, ty, val, body } => Rc::new(Let { name: name.clone(), rel: *rel, ty: r(ty, 0), val: if *rel == Rel::Irr { val.clone() } else { r(val, 0) }, body: r(body, 1) }),
        Sigma { name, snd_rel, fst, snd } => Rc::new(Sigma { name: name.clone(), snd_rel: *snd_rel, fst: r(fst, 0), snd: r(snd, 1) }),
        Pair { ty, fst, snd } => {
            let irr_snd = matches!(&**ty, Sigma { snd_rel: Rel::Irr, .. });
            Rc::new(Pair { ty: r(ty, 0), fst: r(fst, 0), snd: if irr_snd { snd.clone() } else { r(snd, 0) } })
        }
        Ind { ind, params } => Rc::new(Ind { ind: *ind, params: params.iter().map(|p| r(p, 0)).collect() }),
        Ctor { ind, ctor, params, args } => {
            let rels: Vec<Rel> = env.inductive_decl(*ind).and_then(|d| d.ctors.get(*ctor as usize).map(|c| c.fields.iter().map(|f| f.1).collect())).unwrap_or_default();
            Rc::new(Ctor {
                ind: *ind,
                ctor: *ctor,
                params: params.iter().map(|p| r(p, 0)).collect(),
                args: args.iter().enumerate().map(|(i, a)| if rels.get(i) == Some(&Rel::Irr) { a.clone() } else { r(a, 0) }).collect(),
            })
        }
        // the head of an idiom whose application was not recognized: left
        // alone (replacing inside it would retype its arms' path equations)
        Match { scrut, motive, .. } if is_c(scrut, 0) && matches!(&**motive, Pi { .. }) => t.clone(),
        Match { ind, params, scrut, motive, arms } => Rc::new(Match {
            ind: *ind,
            params: params.iter().map(|p| r(p, 0)).collect(),
            scrut: r(scrut, 0),
            motive: r(motive, 1),
            arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: r(&a.body, a.names.len() as u32) }).collect(),
        }),
    }
}

/// A piecewise subterm of a linear atom, with how its bound facts are
/// proven (see [`PCx::atom_bounds`]).
enum Piece {
    /// `lo ≤ hi` pairs about the subterm, proven by a split on `scrut`
    /// (with the §5.10 axiom instances `ax` in each branch).
    Split { atom: Tm, w: Width, bounds: Vec<(Tm, Tm)>, scrut: Tm, ax: Option<(Schema, Schema, Width, Tm, Tm)> },
    /// A stuck match (plain or the dependent-match idiom) of width `w`
    /// whose arms are all at most `ub`: `atom ≤ ub`, proven by a match on
    /// its scrutinee with the atom generalized in the motive.
    Match { atom: Tm, w: Width, ub: num_bigint::BigInt },
    /// An unconditional §5.10 axiom instance about the subterm (e.g.
    /// `count_ones(a) ≤ w`, `a & b ≤ a`, `a >> s ≤ a`).
    Axiom { atom: Tm, schema: Schema, w: Width, args: Vec<Tm> },
    /// A product `x · y` over `Int` of factors with evident bounds
    /// `0 ≤ x ≤ X`, `0 ≤ y ≤ Y`: `x · y ≤ X · Y` by the `mul_mono` axiom
    /// (§5.10), its hypotheses by linear arithmetic.
    Mul { atom: Tm, x: Tm, y: Tm, xb: num_bigint::BigInt, yb: num_bigint::BigInt },
}

/// A syntactic upper bound of a non-negative `Int` term (a machine value
/// cast to `Int`, a literal).
fn int_upper_bound(t: &Tm) -> Option<num_bigint::BigInt> {
    match &**t {
        Term::Lit { w: Width::Int, n } if n.sign() != num_bigint::Sign::Minus => Some(n.clone()),
        Term::Prim { op: PrimOp::Cast { from, to: Width::Int }, args, .. } if *from != Width::Int && args.len() == 1 => {
            Some(upper_bound(&args[0]).map(|x| x.1).unwrap_or_else(|| sandblaster_kernel::prim::max_of(*from)))
        }
        _ => None,
    }
}

/// A syntactic upper bound of a machine-integer term (an arm body), when
/// one below the type's maximum is evident.
fn upper_bound(t: &Tm) -> Option<(Width, num_bigint::BigInt)> {
    use num_bigint::BigInt;
    let ones = |bits: u32| (BigInt::from(1u8) << bits) - 1u8;
    match &**t {
        Term::Lit { w, n } if *w != Width::Int => Some((*w, n.clone())),
        Term::Prim { op: PrimOp::Cast { from, to }, .. } if *to != Width::Int => {
            let (fb, tb) = (from.bits()?, to.bits()?);
            Some((*to, ones(fb.min(tb))))
        }
        Term::Prim { op: PrimOp::CountOnes(w) | PrimOp::LeadingZeros(w) | PrimOp::TrailingZeros(w), .. } => Some((Width::U32, BigInt::from(w.bits()?))),
        Term::Prim { op: PrimOp::Min(w), args, .. } if args.len() == 2 => {
            let a = upper_bound(&args[0]).map(|x| x.1);
            let c = upper_bound(&args[1]).map(|x| x.1);
            match (a, c) {
                (Some(a), Some(c)) => Some((*w, a.min(c))),
                (Some(x), None) | (None, Some(x)) => Some((*w, x)),
                _ => None,
            }
        }
        Term::Prim { op: PrimOp::And(w), args, .. } if args.len() == 2 => {
            let a = upper_bound(&args[0]).map(|x| x.1);
            let c = upper_bound(&args[1]).map(|x| x.1);
            match (a, c) {
                (Some(a), Some(c)) => Some((*w, a.min(c))),
                (Some(x), None) | (None, Some(x)) => Some((*w, x)),
                _ => None,
            }
        }
        Term::Lam { body, .. } => upper_bound(body),
        _ => {
            let (_, arms) = match_parts(t)?;
            let mut best: Option<(Width, BigInt)> = None;
            for a in arms {
                let (w, n) = upper_bound(&a.body)?;
                best = Some(match best {
                    None => (w, n),
                    Some((w0, n0)) if w0 == w => (w, n0.max(n)),
                    Some(_) => return None,
                });
            }
            best
        }
    }
}

/// The scrutinee and arms of a stuck match: a plain `match`, or the
/// dependent-match idiom `(match s … λe. …) .refl(D, s)`.
fn match_parts(t: &Tm) -> Option<(&Tm, &[sandblaster_kernel::term::Arm])> {
    match &**t {
        // a match whose motive is a Π is the head of a dependent-match
        // idiom (its value is a function of the path equation)
        Term::Match { scrut, arms, motive, .. } if !matches!(&**scrut, Term::Ctor { .. }) && !matches!(&**motive, Term::Pi { .. }) => Some((scrut, arms)),
        Term::App { rel: Rel::Irr, fun, .. } => match &**fun {
            Term::Match { scrut, arms, motive, .. } if !matches!(&**scrut, Term::Ctor { .. }) && matches!(&**motive, Term::Pi { .. }) => Some((scrut, arms)),
            _ => None,
        },
        _ => None,
    }
}

/// The piecewise subterms of a term (see [`PCx::atom_bounds`]), visiting
/// relevant positions only.
fn piecewise_subterms(t: &Tm, bool_: IndId, out: &mut Vec<Piece>) {
    // a tree walk: charged per node, stops when the goal is exhausted
    if !meter::spend(1) {
        return;
    }
    // stuck matches with bounded arms (join values like `match o { Some(x)
    // => x as u32, None => 0 }`)
    if match_parts(t).is_some()
        && let Some((w, ub)) = upper_bound(t)
        && w != Width::Int
        && ub < sandblaster_kernel::prim::max_of(w)
    {
        out.push(Piece::Match { atom: t.clone(), w, ub });
    }
    if let Term::Prim { op: PrimOp::IMul, args, .. } = &**t
        && args.len() == 2
        && let (Some(xb), Some(yb)) = (int_upper_bound(&args[0]), int_upper_bound(&args[1]))
    {
        out.push(Piece::Mul { atom: t.clone(), x: args[0].clone(), y: args[1].clone(), xb, yb });
    }
    if let Term::Prim { op, args, .. } = &**t {
        let ax = |schema: Schema, w: Width| Piece::Axiom { atom: t.clone(), schema, w, args: args.clone() };
        match op {
            PrimOp::CountOnes(w) if args.len() == 1 => out.push(ax(Schema::CountOnesLe, *w)),
            PrimOp::And(w) if args.len() == 2 => {
                out.push(ax(Schema::AndLeLeft, *w));
                out.push(ax(Schema::AndLeRight, *w));
            }
            PrimOp::Or(w) if args.len() == 2 => {
                out.push(ax(Schema::OrGeLeft, *w));
                out.push(ax(Schema::OrGeRight, *w));
                out.push(ax(Schema::OrLeAdd, *w));
            }
            PrimOp::Xor(w) if args.len() == 2 => out.push(ax(Schema::XorLeOr, *w)),
            PrimOp::WShr(w) if args.len() == 2 => out.push(ax(Schema::ShrLe, *w)),
            _ => {}
        }
    }
    match &**t {
        Term::Prim { op, args, .. } => {
            let le = |w: Width, a: &Tm, c: &Tm| mk::prim(PrimOp::Le(w), vec![a.clone(), c.clone()], vec![]);
            if args.len() == 2 {
                let (a, c) = (&args[0], &args[1]);
                let split = |bounds: Vec<(Tm, Tm)>, w: Width, scrut: Tm, ax| Piece::Split { atom: t.clone(), w, bounds, scrut, ax };
                match op {
                    PrimOp::Min(w) => out.push(split(vec![(t.clone(), a.clone()), (t.clone(), c.clone())], *w, le(*w, a, c), Some((Schema::MinDefLe, Schema::MinDefGt, *w, a.clone(), c.clone())))),
                    PrimOp::Max(w) => out.push(split(vec![(a.clone(), t.clone()), (c.clone(), t.clone())], *w, le(*w, a, c), Some((Schema::MaxDefLe, Schema::MaxDefGt, *w, a.clone(), c.clone())))),
                    PrimOp::SatSub(w) => out.push(split(vec![(t.clone(), a.clone())], *w, le(*w, c, a), Some((Schema::SatSubDefLe, Schema::SatSubDefGt, *w, a.clone(), c.clone())))),
                    _ => {}
                }
            }
            for a in args {
                piecewise_subterms(a, bool_, out);
            }
        }
        Term::Match { ind, scrut, arms, .. } if *ind == bool_ && !matches!(&**scrut, Term::Ctor { .. }) => {
            let lits: Vec<(Width, &num_bigint::BigInt)> = arms
                .iter()
                .filter_map(|a| match &*a.body {
                    Term::Lit { w, n } => Some((*w, n)),
                    _ => None,
                })
                .collect();
            if lits.len() == 2 && lits[0].0 == lits[1].0 {
                let w = lits[0].0;
                let (x, y) = (mk::lit(w, lits[0].1.clone()), mk::lit(w, lits[1].1.clone()));
                let (lo, hi) = if lits[0].1 <= lits[1].1 { (x, y) } else { (y, x) };
                out.push(Piece::Split { atom: t.clone(), w, bounds: vec![(lo, t.clone()), (t.clone(), hi)], scrut: scrut.clone(), ax: None });
            }
            piecewise_subterms(scrut, bool_, out);
        }
        Term::App { fun, arg, rel } => {
            piecewise_subterms(fun, bool_, out);
            if *rel == Rel::Rel {
                piecewise_subterms(arg, bool_, out);
            }
        }
        Term::Fst(x) | Term::Snd(x) => piecewise_subterms(x, bool_, out),
        _ => {}
    }
}

/// Split candidates in a term: `(bool scrutinee, axiom info)`.
fn collect_splits(t: &Tm, bool_: IndId, out: &mut Vec<SplitCand>, seen: &mut Vec<u64>) {
    // a tree walk: charged per node, stops when the goal is exhausted
    if !meter::spend(1) {
        return;
    }
    let push = |scrut: Tm, ax: Option<(Schema, Schema, Width, Tm, Tm)>, out: &mut Vec<SplitCand>, seen: &mut Vec<u64>| {
        let key = super::tm::fingerprint(&scrut);
        if seen.contains(&key) {
            return;
        }
        seen.push(key);
        out.push((scrut, ax));
    };
    match &**t {
        Term::Prim { op, args, .. } => {
            let cmp = |w: Width, a: &Tm, c: &Tm| mk::prim(PrimOp::Le(w), vec![a.clone(), c.clone()], vec![]);
            match op {
                PrimOp::Min(w) if args.len() == 2 => push(cmp(*w, &args[0], &args[1]), Some((Schema::MinDefLe, Schema::MinDefGt, *w, args[0].clone(), args[1].clone())), out, seen),
                PrimOp::Max(w) if args.len() == 2 => push(cmp(*w, &args[0], &args[1]), Some((Schema::MaxDefLe, Schema::MaxDefGt, *w, args[0].clone(), args[1].clone())), out, seen),
                PrimOp::SatSub(w) if args.len() == 2 => push(cmp(*w, &args[1], &args[0]), Some((Schema::SatSubDefLe, Schema::SatSubDefGt, *w, args[0].clone(), args[1].clone())), out, seen),
                PrimOp::SatAdd(w) if args.len() == 2 => {
                    let to_int = |x: &Tm| mk::prim(PrimOp::Cast { from: *w, to: Width::Int }, vec![x.clone()], vec![]);
                    let c = mk::prim(PrimOp::Le(Width::Int), vec![mk::prim(PrimOp::IAdd, vec![to_int(&args[0]), to_int(&args[1])], vec![]), mk::lit(Width::Int, sandblaster_kernel::prim::max_of(*w))], vec![]);
                    push(c, Some((Schema::SatAddDefLe, Schema::SatAddDefGt, *w, args[0].clone(), args[1].clone())), out, seen)
                }
                _ => {}
            }
            for a in args {
                collect_splits(a, bool_, out, seen);
            }
        }
        Term::Match { ind, scrut, .. } => {
            if *ind == bool_ && !matches!(&**scrut, Term::Ctor { .. }) {
                push(scrut.clone(), None, out, seen);
            }
            collect_splits(scrut, bool_, out, seen);
        }
        Term::App { fun, arg, rel } => {
            collect_splits(fun, bool_, out, seen);
            if *rel == Rel::Rel {
                collect_splits(arg, bool_, out, seen);
            }
        }
        Term::Eq { lhs, rhs, .. } => {
            collect_splits(lhs, bool_, out, seen);
            collect_splits(rhs, bool_, out, seen);
        }
        Term::Fst(x) | Term::Snd(x) => collect_splits(x, bool_, out, seen),
        Term::Ctor { args, .. } => args.iter().for_each(|a| collect_splits(a, bool_, out, seen)),
        _ => {}
    }
}

/// `Env::abstract_occurrences`, completed by a syntactic pass (modulo
/// irrelevant positions) that also abstracts occurrences at neutral heads —
/// e.g. the variable scrutinee of a stuck `match` — which the kernel's
/// quoter does not visit. The result is a motive body in `ctx` extended
/// with `y` (`Var(0)` at its root) such that `motive[y := t] ≡ goal`.
pub fn abstract_all(env: &Env, ctx: &Ctx, goal: &V, t: &V, b: &mut Budget) -> Result<Tm, String> {
    let m1 = env.abstract_occurrences(ctx, goal, t, b).map_err(|e| e.to_string())?;
    let m1 = crate::auto::util::kernel_friendly(env, &m1);
    let tt = env.quote_typed(ctx, t, None, false);
    let target = shift(&tt, 1);
    Ok(replace_occ(env, &m1, &target))
}

/// Syntactic abstraction of `t` in the term `goal` (both in `ctx`): a
/// motive body in `ctx` extended with `y`.
pub fn abstract_tm(env: &Env, goal: &Tm, t: &Tm) -> Tm {
    replace_occ(env, &shift(goal, 1), &shift(t, 1))
}

/// Replaces the subterms of `m` that equal `target` (modulo irrelevant
/// positions; both in the motive context) by the motive variable. Proof
/// terms and irrelevant positions are left untouched (their types would
/// no longer match).
fn replace_occ(env: &Env, m: &Tm, target: &Tm) -> Tm {
    replace_rel(env, m, target, 0)
}

fn replace_rel(env: &Env, t: &Tm, target: &Tm, b: u32) -> Tm {
    replace_gen(env, t, target, b)
}

fn replace_gen(env: &Env, t: &Tm, target: &Tm, b: u32) -> Tm {
    use Term::*;
    // a tree walk (charged per node; stops, leaving the rest unchanged, when
    // the goal is exhausted)
    if !meter::spend(1) {
        return t.clone();
    }
    let tb = shift(target, b as i64);
    if std::mem::discriminant(&**t) == std::mem::discriminant(&*tb) && env.alpha_eq_relevant(t, &tb, &|x, y| x == y) {
        return mk::var(b);
    }
    let r = |x: &Tm, k: u32| replace_gen(env, x, target, b + k);
    match &**t {
        // proofs and irrelevant positions: untouched
        Refl { .. } | Linarith { .. } | BvRefl { .. } | Absurd { .. } | Axiom { .. } | Delta { .. } | Unfold { .. } | Transport { .. } | Erased | Rec { .. } => t.clone(),
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } => t.clone(),
        App { rel: Rel::Irr, fun, arg } => Rc::new(App { rel: Rel::Irr, fun: r(fun, 0), arg: arg.clone() }),
        App { rel, fun, arg } => Rc::new(App { rel: *rel, fun: r(fun, 0), arg: r(arg, 0) }),
        Prim { op, args, proofs } => Rc::new(Prim { op: *op, args: args.iter().map(|a| r(a, 0)).collect(), proofs: proofs.clone() }),
        Pi { name, rel, dom, cod } => Rc::new(Pi { name: name.clone(), rel: *rel, dom: r(dom, 0), cod: r(cod, 1) }),
        Lam { name, rel, dom, body } => Rc::new(Lam { name: name.clone(), rel: *rel, dom: r(dom, 0), body: r(body, 1) }),
        Let { name, rel, ty, val, body } => Rc::new(Let { name: name.clone(), rel: *rel, ty: r(ty, 0), val: if *rel == Rel::Irr { val.clone() } else { r(val, 0) }, body: r(body, 1) }),
        Sigma { name, snd_rel, fst, snd } => Rc::new(Sigma { name: name.clone(), snd_rel: *snd_rel, fst: r(fst, 0), snd: r(snd, 1) }),
        Pair { ty, fst, snd } => {
            let irr_snd = matches!(&**ty, Sigma { snd_rel: Rel::Irr, .. });
            Rc::new(Pair { ty: r(ty, 0), fst: r(fst, 0), snd: if irr_snd { snd.clone() } else { r(snd, 0) } })
        }
        Fst(x) => Rc::new(Fst(r(x, 0))),
        Snd(x) => Rc::new(Snd(r(x, 0))),
        Eq { ty, lhs, rhs } => Rc::new(Eq { ty: r(ty, 0), lhs: r(lhs, 0), rhs: r(rhs, 0) }),
        Ind { ind, params } => Rc::new(Ind { ind: *ind, params: params.iter().map(|p| r(p, 0)).collect() }),
        Ctor { ind, ctor, params, args } => {
            let rels: Vec<Rel> = env.inductive_decl(*ind).and_then(|d| d.ctors.get(*ctor as usize).map(|c| c.fields.iter().map(|f| f.1).collect())).unwrap_or_default();
            Rc::new(Ctor {
                ind: *ind,
                ctor: *ctor,
                params: params.iter().map(|p| r(p, 0)).collect(),
                args: args.iter().enumerate().map(|(i, a)| if rels.get(i) == Some(&Rel::Irr) { a.clone() } else { r(a, 0) }).collect(),
            })
        }
        Match { ind, params, scrut, motive, arms } => Rc::new(Match {
            ind: *ind,
            params: params.iter().map(|p| r(p, 0)).collect(),
            scrut: r(scrut, 0),
            motive: r(motive, 1),
            arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: r(&a.body, a.names.len() as u32) }).collect(),
        }),
    }
}

/// Contracts the top-level `let`s of a statement (ζ): the second component
/// of a conjunction is recorded as `let h = fst(p); Q`.
fn zeta_top(t: &Tm) -> Tm {
    let mut t = t.clone();
    while let Term::Let { val, body, .. } = &*t {
        t = super::tm::subst0(body, val);
    }
    t
}
