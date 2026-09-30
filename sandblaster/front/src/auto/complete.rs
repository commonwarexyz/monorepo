//! Discharges of the completeness statements `complete_p(R)` (DESIGN.md
//! §15.5, "Discharges (by `auto`)"; stage S3).
//!
//! A statement comes from the kernel (`Env::abstract_section`) and has the
//! shape
//!
//! ```text
//! Π(F₁' : T₁)…(Fₖ' : Tₖ). Π(h₁ : H₁[F'])…(hₘ : Hₘ[F']). Π(x̄ : Ā)(r̄ :Irr Req[F'](x̄))(r̄' :Irr Req(x̄)).
//!     obs_eq(F_p' x̄ r̄, p x̄ r̄')
//! ```
//!
//! where every `hᵢ : Hᵢ[F']` is the abstraction of a checked lemma `Lᵢ :
//! Hᵢ[R]` (a law, `ensures`, refinement lemma or type invariant), so the
//! same statement about the real functions is available as a fact.
//! [`prove`] opens the telescope (the hypotheses and requires become facts)
//! and tries, in a fixed order (deterministic; every prover call on the
//! goal's step budget):
//!
//! 1. **direct** — every hypothesis and its real counterpart are
//!    *instantiated at the goal's arguments* `x̄` (when their leading binders
//!    have the parameters' types), and at the two results `F_p' x̄` and
//!    `p x̄` (when their leading binder has the result type: a round trip
//!    `∀x. d(e(x)) == x` gives `d` only through its instance at `x := d(b)`),
//!    and chained forward (a premise met by a
//!    fact is discharged); then the prover chain closes the goal. This is
//!    the refinement discharge: `α(F_p' x̄) = s(α x̄)` and `α(p x̄) = s(α x̄)`
//!    give `α(F_p' x̄) = α(p x̄)`, hence `F_p' x̄ = p x̄` through an identity
//!    or injective view (casts are decided by arithmetic, `view_inj`
//!    lemmas are facts); the ∀-facts of the context rewrite the other
//!    members to their specifications first;
//! 2. **bool split** — for `obs_eq` at `bool` (`Eq(Bool, F_p' x̄, p x̄)`):
//!    both results are split (`match … as u return (Eq(Bool, a, u) → …)`),
//!    the equal cases are `refl` and the two crossed cases are refuted from
//!    the chained instances (an exact characterization `f(x) == true ↔
//!    P(x)` refutes both: `F' x = true ⇒ P x ⇒ f x = true`, and back);
//! 3. **induction** — for a recursive `p` whose section states its
//!    recursive equation (`F_p' x̄ = E[F', x̄]`): the statement is proven as
//!    a definition by measure recursion on `p`'s measure; after rewriting
//!    both sides with the equation instances, the boolean scrutinees of `E`
//!    are split and every application `F_p' ȳ` of a case gets its induction
//!    hypothesis `rec(…, ȳ; m(ȳ) < m(x̄)) : obs_eq(F_p' ȳ, p ȳ)` (the
//!    decrease proven by the prover from the path conditions).
//!
//! Untrusted: every prover result is re-certified and checked by the kernel
//! here, and the caller adds the lemma with exactly the kernel's statement
//! as its type (checked once more). Nothing here can make a false statement
//! pass.

use std::collections::BTreeSet;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Arm, GlobalId, Lvl, Name, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{Budget, V, Value};

use crate::elab::ProverChain;
use crate::prover::{AutoFailure, FactOrigin, FactRef, Goal, Hint, ObligationId, ObligationKind};
use crate::span::Span;

/// How a statement is laid out (the caller knows the section).
#[derive(Clone, Debug)]
pub struct Layout {
    /// `k`: the members' `F'` binders.
    pub members: usize,
    /// Index (among the members) of the published function `p`.
    pub member_p: usize,
    /// For each of the `m` hypothesis binders, the checked lemma whose
    /// abstraction it is (its statement about the real functions).
    pub real: Vec<GlobalId>,
}

/// Measure recursion for the induction discharge: `measure` is a term at
/// the statement's full depth (over its binders), of width `width` (`Int`
/// or a machine width).
#[derive(Clone, Debug)]
pub struct Induction {
    pub measure: Tm,
    pub width: Width,
}

/// A proof of a statement: the closed proof term (a λ over the whole
/// telescope), its recursion and arity (for `add_def`), and the discharge
/// that found it.
#[derive(Clone, Debug)]
pub struct Proven {
    pub body: Tm,
    pub recursion: Recursion,
    pub arity: u32,
    pub by: &'static str,
}

/// The binders of a closed Π telescope and its conclusion.
pub fn telescope(t: &Tm) -> (Vec<(Name, Rel, Tm)>, Tm) {
    let mut out = Vec::new();
    let mut t = t.clone();
    while let Term::Pi { name, rel, dom, cod } = &*t.clone() {
        out.push((name.clone(), *rel, dom.clone()));
        t = cod.clone();
    }
    (out, t)
}

/// `λ` over `bs` around `body`.
pub fn lams(bs: &[(Name, Rel, Tm)], body: Tm) -> Tm {
    bs.iter().rev().fold(body, |acc, (n, r, d)| Rc::new(Term::Lam { name: n.clone(), rel: *r, dom: d.clone(), body: acc }))
}

type Fail = AutoFailure;

fn fail(msg: impl Into<String>) -> Fail {
    AutoFailure { tried: vec![msg.into()], ..Default::default() }
}

/// An opened proof context: the statement's binders, then `let`s of
/// derived facts.
#[derive(Clone)]
struct PCx<'e> {
    env: &'e Env,
    ctx: Ctx,
    facts: Vec<FactRef>,
    /// Each fact's type as a term at its own depth (for the basic prover).
    fact_tys: Vec<(u32, Tm)>,
    /// `let .h : ty = val` binders pushed after the statement's binders.
    lets: Vec<(Name, Tm, Tm)>,
    budget: u64,
    span: Span,
    /// Premise applications already made (`(fact, argument)`) and Σ facts
    /// already split, by level.
    used: BTreeSet<(u32, u32)>,
    split: BTreeSet<u32>,
}

impl<'e> PCx<'e> {
    fn new(env: &'e Env, budget: u64, span: Span) -> PCx<'e> {
        PCx { env, ctx: Ctx::default(), facts: vec![], fact_tys: vec![], lets: vec![], budget, span, used: BTreeSet::new(), split: BTreeSet::new() }
    }

    fn depth(&self) -> u32 {
        self.ctx.depth().0
    }

    fn b(&self) -> Budget {
        Budget { steps: self.budget }
    }

    fn eval(&self, t: &Tm) -> Result<V, Fail> {
        let mut b = self.b();
        self.env.eval(&self.env.ctx_venv(&self.ctx), self.ctx.depth(), t, &mut b).map_err(|e| fail(format!("evaluation failed: {e:?}")))
    }

    fn quote(&self, v: &V) -> Tm {
        self.env.quote_typed(&self.ctx, v, None, false)
    }

    fn var(&self, lvl: u32) -> Tm {
        mk::var(self.depth() - 1 - lvl)
    }

    /// Pushes a binder of the statement (a λ binder of the proof); a fact
    /// when `origin` is given.
    fn push(&mut self, name: &str, rel: Rel, ty: &Tm, origin: Option<FactOrigin>) -> Result<u32, Fail> {
        let tv = self.eval(ty)?;
        let lvl = self.depth();
        self.ctx = self.ctx.push(CtxEntry { name: Rc::from(name), rel, ty: tv, def: None });
        if let Some(o) = origin {
            self.facts.push(FactRef { lvl: Lvl(lvl), origin: o, span: self.span });
            self.fact_tys.push((lvl, ty.clone()));
        }
        Ok(lvl)
    }

    /// Pushes `let .name : ty = val` (an irrelevant fact; `ty` a term at
    /// the current depth — built by substitution, never read back from a
    /// value, which could unfold a whole specification).
    fn push_let(&mut self, name: &str, ty: Tm, val: Tm) -> Result<u32, Fail> {
        let tv = self.eval(&ty)?;
        self.lets.push((Rc::from(name), ty.clone(), val));
        let lvl = self.depth();
        self.ctx = self.ctx.push(CtxEntry { name: Rc::from(name), rel: Rel::Irr, ty: tv, def: None });
        self.facts.push(FactRef { lvl: Lvl(lvl), origin: FactOrigin::LemmaHyp, span: self.span });
        self.fact_tys.push((lvl, ty));
        Ok(lvl)
    }

    /// The type term of the fact at `lvl`, at the current depth.
    fn fact_ty(&self, lvl: u32) -> Option<Tm> {
        self.fact_tys.iter().find(|(l, _)| *l == lvl).map(|(l, t)| shift(t, (self.depth() - l) as i64))
    }

    /// `body` (at the current depth) inside the `let`s pushed since the
    /// `mark`-th one.
    fn wrap(&self, mark: usize, mut body: Tm) -> Tm {
        for (name, ty, val) in self.lets[mark..].iter().rev() {
            body = Rc::new(Term::Let { name: name.clone(), rel: Rel::Irr, ty: ty.clone(), val: val.clone(), body });
        }
        body
    }

    fn ty_of(&self, lvl: u32) -> V {
        self.ctx.entries[lvl as usize].ty.clone()
    }

    fn conv(&self, a: &V, b: &V) -> bool {
        let mut bud = self.b();
        self.env.conv(self.ctx.depth(), a, b, &mut bud).unwrap_or(false)
    }

    /// Instantiates `head : ty` (a Π type term at the current depth),
    /// binder by binder, at the first of `args` (context levels) not used
    /// yet whose type its leading relevant binder accepts (type-directed, so
    /// a hypothesis over `k: u8` meets the parameter `k` of `(t: [u8; 4], k:
    /// u8)`). The application and its type term, when at least one argument
    /// was taken.
    fn instantiate(&self, head: Tm, ty: &Tm, args: &[u32]) -> Option<(Tm, Tm)> {
        let mut t = head;
        let mut cur = ty.clone();
        let mut used: Vec<u32> = Vec::new();
        while let Term::Pi { rel: Rel::Rel, dom, cod, .. } = &*cur.clone() {
            let Ok(dv) = self.eval(dom) else { break };
            let Some(a) = args.iter().copied().find(|a| !used.contains(a) && self.conv(&dv, &self.ty_of(*a))) else { break };
            used.push(a);
            t = mk::app(t, self.var(a));
            cur = crate::elab::tm::subst0(cod, &self.var(a));
        }
        (!used.is_empty()).then_some((t, cur))
    }

    /// [`PCx::instantiate`] at terms: `args` are terms at the current depth
    /// with their types (values).
    fn instantiate_terms(&self, head: Tm, ty: &Tm, args: &[(Tm, V)]) -> Option<(Tm, Tm)> {
        let mut t = head;
        let mut cur = ty.clone();
        let mut n = 0;
        for (a, av) in args {
            let Term::Pi { rel: Rel::Rel, dom, cod, .. } = &*cur.clone() else { break };
            let Ok(dv) = self.eval(dom) else { break };
            if !self.conv(&dv, av) {
                break;
            }
            t = mk::app(t, a.clone());
            cur = crate::elab::tm::subst0(cod, a);
            n += 1;
        }
        (n > 0).then_some((t, cur))
    }

    /// Forward chaining: a fact `Π(y : P). Q` whose premise `P` is another
    /// fact gives `Q`; a non-dependent Σ fact gives its components.
    /// Bounded rounds; each combination once. Works on the facts' type
    /// terms (substitution), comparing premises by conversion.
    fn saturate(&mut self, rounds: u32) {
        for _ in 0..rounds {
            let mut added = false;
            let levels: Vec<u32> = self.facts.iter().map(|f| f.lvl.0).collect();
            for &lf in &levels {
                let Some(t) = self.fact_ty(lf) else { continue };
                match &*t {
                    Term::Pi { rel, dom, cod, .. } => {
                        // a premise that is a type of data (a ∀ over values) is
                        // instantiated by the prover, not here
                        let Ok(dv) = self.eval(dom) else { continue };
                        if matches!(&*dv, Value::IntTy(_) | Value::Sort(_)) {
                            continue;
                        }
                        for &lg in &levels {
                            if lg == lf || self.used.contains(&(lf, lg)) || !self.conv(&dv, &self.ty_of(lg)) {
                                continue;
                            }
                            self.used.insert((lf, lg));
                            let q = crate::elab::tm::subst0(cod, &self.var(lg));
                            let app = Rc::new(Term::App { rel: *rel, fun: self.var(lf), arg: self.var(lg) });
                            if self.push_let("mp", q, app).is_ok() {
                                added = true;
                            }
                            break;
                        }
                    }
                    Term::Sigma { snd_rel: Rel::Rel, fst, snd, .. } if !self.split.contains(&lf) && !occurs0(snd) => {
                        self.split.insert(lf);
                        let v = self.var(lf);
                        if self.push_let("l", fst.clone(), mk::fst(v.clone())).is_err() {
                            continue;
                        }
                        let _ = self.push_let("r", shift(snd, 0), mk::snd(shift(&v, 1)));
                        added = true;
                    }
                    _ => {}
                }
            }
            if !added {
                break;
            }
        }
    }

    /// Asks the prover chain for `target` (a term at the current depth),
    /// after forward chaining; the result is re-certified and checked.
    fn close(&mut self, prover: &mut ProverChain, target: &Tm, hints: &[Hint]) -> Result<Tm, Fail> {
        let saved = self.clone();
        let mark = self.lets.len();
        let d0 = self.depth();
        self.saturate(3);
        let by = (self.depth() - d0) as i64;
        let tt = shift(target, by);
        let res = self.eval(&tt).and_then(|tv| {
            let id = u32::MAX - 7;
            let goal = Goal {
                id: ObligationId(id),
                kind: ObligationKind::Completeness,
                span: self.span,
                ctx: self.ctx.clone(),
                facts: self.facts.clone(),
                target: tv.clone(),
                hints: hints.iter().map(|h| shift_hint(h, by)).collect(),
            };
            // every prover of the chain in turn: a proof the kernel
            // rejects falls through to the next prover
            let mut failure = AutoFailure::default();
            let trace = std::env::var_os("SANDBLASTER_TRACE_SECTIONS").is_some();
            // the chain's provers, `auto` configured for these goals (no
            // automatic `BvRefl`: see `AutoConfig::auto_bvrefl`)
            for (name, p) in prover.provers.iter_mut() {
                let mut own: Option<crate::auto::Auto> = (name.as_str() == "auto").then(|| crate::auto::Auto::with_config(crate::auto::AutoConfig { auto_bvrefl: false, ..Default::default() }));
                let p: &mut dyn crate::prover::Prover = match own.as_mut() {
                    Some(a) => a,
                    None => p.as_mut(),
                };
                let t0 = std::time::Instant::now();
                crate::elab::basic::set_goal_terms(Some(crate::elab::basic::GoalTerms { id, target: tt.clone(), facts: self.fact_tys.clone() }));
                let mut b = self.b();
                let r = p.prove(self.env, &goal, &mut b);
                crate::elab::basic::set_goal_terms(None);
                if trace {
                    eprintln!("      {name}: {} in {:?} ({} facts, {} steps left)", if r.is_ok() { "proof" } else { "no proof" }, t0.elapsed(), self.facts.len(), b.steps);
                }
                match r {
                    Ok(pf) => {
                        let pf = crate::elab::recert::recertify(self.env, &self.ctx, &pf);
                        let mut cb = Budget { steps: self.budget.saturating_mul(20) };
                        match self.env.check(&self.ctx, &pf, &tv, &mut cb) {
                            Ok(()) => return Ok(self.wrap(mark, pf)),
                            Err(e) => failure.tried.push(format!("{name}: its proof was rejected by the kernel: {}", e.message.lines().next().unwrap_or(""))),
                        }
                    }
                    Err(f) => {
                        if failure.goal.is_empty() {
                            failure.goal = f.goal.clone();
                        }
                        failure.stuck.extend(f.stuck);
                        failure.tried.extend(f.tried.into_iter().map(|t| format!("{name}: {t}")));
                    }
                }
            }
            Err(failure)
        });
        *self = saved;
        res
    }
}

fn shift_hint(h: &Hint, by: i64) -> Hint {
    match h {
        Hint::Lemma(t) => Hint::Lemma(shift(t, by)),
        other => other.clone(),
    }
}

/// Whether variable 0 occurs in `t`.
fn occurs0(t: &Tm) -> bool {
    crate::elab::tm::any_node_depth(t, &mut |n, k| matches!(n, Term::Var(i) if i.0 == k))
}

/// `Eq(Bool, a, b)`: its sides.
fn bool_eq(env: &Env, t: &Tm) -> Option<(Tm, Tm)> {
    match &**t {
        Term::Eq { ty, lhs, rhs } if matches!(&**ty, Term::Ind { ind, params } if *ind == env.bool_ind() && params.is_empty()) => Some((lhs.clone(), rhs.clone())),
        _ => None,
    }
}

/// Proves the closed statement `stmt` (see the module docs).
#[allow(clippy::too_many_arguments)]
pub fn prove(env: &Env, prover: &mut ProverChain, stmt: &Tm, lay: &Layout, ind: Option<&Induction>, budget: u64, span: Span) -> Result<Proven, Fail> {
    let (bs, concl) = telescope(stmt);
    let k = lay.members;
    let m = lay.real.len();
    if bs.len() < k + m {
        return Err(fail("the statement does not have the section's binders"));
    }
    let mut pcx = PCx::new(env, budget, span);
    let mut params = Vec::new();
    for (i, (name, rel, dom)) in bs.iter().enumerate() {
        let origin = if i < k {
            None
        } else if i < k + m {
            Some(FactOrigin::LemmaHyp)
        } else if *rel == Rel::Irr {
            Some(FactOrigin::Requires)
        } else {
            None
        };
        let lvl = pcx.push(name, *rel, dom, origin)?;
        if i >= k + m && *rel == Rel::Rel {
            params.push(lvl);
        }
    }
    let n = pcx.depth();
    let hints: Vec<Hint> = lay.real.iter().map(|g| Hint::Lemma(mk::global(*g))).collect();
    let mut tried: Vec<String> = Vec::new();
    let mut last: Option<Fail>;

    // the instances of every hypothesis and of its real counterpart at x̄
    let mut inst = pcx.clone();
    for (i, real) in lay.real.iter().enumerate() {
        let lh = (k + i) as u32;
        let hty = shift(&bs[k + i].2, (inst.depth() - lh) as i64);
        if let Some((t, ty)) = inst.instantiate(inst.var(lh), &hty, &params) {
            inst.push_let(&format!("h{i}x"), ty, t)?;
        }
        if let Some(rt) = env.global_type(*real)
            && let Some((t, ty)) = inst.instantiate(mk::global(*real), &rt, &params)
        {
            inst.push_let(&format!("l{i}x"), ty, t)?;
        }
    }
    // … and at the two results `F_p' x̄` and `p x̄` (the sides of the
    // conclusion), for a hypothesis quantified over the result type first:
    // a round trip `∀x. d(e(x)) == x` with canonicity `∀b. e(d(b)) == b`
    // determines `d` only through its instance at `x := d(b)`
    if let Term::Eq { ty, lhs, rhs } = &*concl {
        let at = |inst: &PCx<'_>, t: &Tm| shift(t, (inst.depth() - n) as i64);
        for (i, real) in lay.real.iter().enumerate() {
            for (side, name) in [(lhs, "f"), (rhs, "r")] {
                let Ok(tyv) = inst.eval(&at(&inst, ty)) else { continue };
                let arg = at(&inst, side);
                let lh = (k + i) as u32;
                let hty = shift(&bs[k + i].2, (inst.depth() - lh) as i64);
                if let Some((t, hty)) = inst.instantiate_terms(inst.var(lh), &hty, &[(arg.clone(), tyv.clone())]) {
                    inst.push_let(&format!("h{i}{name}"), hty, t)?;
                }
                let arg = at(&inst, side);
                if let Some(rt) = env.global_type(*real)
                    && let Some((t, rty)) = inst.instantiate_terms(mk::global(*real), &rt, &[(arg, tyv)])
                {
                    inst.push_let(&format!("l{i}{name}"), rty, t)?;
                }
            }
        }
    }
    let target = shift(&concl, (inst.depth() - n) as i64);
    let done = |inst: &PCx<'_>, p: Tm, by: &'static str, recursion: Recursion, arity: u32| Proven { body: lams(&bs, inst.wrap(0, p)), recursion, arity, by };

    // 1. direct
    match inst.clone().close(prover, &target, &hints) {
        Ok(p) => return Ok(done(&inst, p, "auto: rewriting with the hypotheses (refinement)", Recursion::None, 0)),
        Err(f) => {
            tried.push("direct: not closed from the hypotheses instantiated at the arguments".into());
            last = Some(f);
        }
    }
    // 2. bool split
    if let Some((a, b)) = bool_eq(env, &target) {
        match bool_split(&mut inst.clone(), prover, &a, &b, &hints) {
            Ok(p) => return Ok(done(&inst, p, "auto: both results split (exact characterization)", Recursion::None, 0)),
            Err(f) => {
                tried.push("bool split: a crossed case (the two results differ) was not refuted".into());
                last = Some(f);
            }
        }
    }
    // 3. induction on p's measure
    if let Some(ind) = ind {
        match induction(&mut inst.clone(), prover, lay, &bs, &concl, n, &params, ind, &target, &hints) {
            Ok(p) => return Ok(done(&inst, p, "auto: induction with the recursive equation", Recursion::Measure { measure: ind.measure.clone() }, n)),
            Err(f) => {
                tried.push("induction: a case was not closed".into());
                last = Some(f);
            }
        }
    }
    let mut f = last.unwrap_or_default();
    f.tried.splice(0..0, tried);
    Err(f)
}

/// Discharge 2: `Eq(Bool, a, b)` by splitting both sides.
fn bool_split(pcx: &mut PCx<'_>, prover: &mut ProverChain, a: &Tm, b: &Tm, hints: &[Hint]) -> Result<Tm, Fail> {
    let bi = pcx.env.bool_ind();
    let boolt = mk::ind(bi, vec![]);
    let lit = |v: bool| mk::ctor(bi, v as u32, vec![], vec![]);
    // over u: Π(.e : Eq(Bool, a, u)). Eq(Bool, u, b)
    let motive = mk::pi("e", Rel::Irr, mk::eq(boolt.clone(), shift(a, 1), mk::var(0)), mk::eq(boolt.clone(), mk::var(1), shift(b, 2)));
    let mut arms = Vec::new();
    for u in [false, true] {
        let saved = pcx.clone();
        pcx.push("e1", Rel::Irr, &mk::eq(boolt.clone(), a.clone(), lit(u)), Some(FactOrigin::PathCond))?;
        let b1 = shift(b, 1);
        // over v: Π(.e : Eq(Bool, b, v)). Eq(Bool, u, v)
        let imotive = mk::pi("e", Rel::Irr, mk::eq(boolt.clone(), shift(&b1, 1), mk::var(0)), mk::eq(boolt.clone(), lit(u), mk::var(1)));
        let mut iarms = Vec::new();
        for v in [false, true] {
            let saved2 = pcx.clone();
            pcx.push("e2", Rel::Irr, &mk::eq(boolt.clone(), b1.clone(), lit(v)), Some(FactOrigin::PathCond))?;
            let leaf = if u == v { Ok(mk::refl(boolt.clone(), lit(u))) } else { pcx.close(prover, &mk::eq(boolt.clone(), lit(u), lit(v)), hints) };
            *pcx = saved2;
            let body = mk::lam("e2", Rel::Irr, mk::eq(boolt.clone(), b1.clone(), lit(v)), leaf?);
            iarms.push(Arm { names: vec![], body });
        }
        *pcx = saved;
        let inner = Rc::new(Term::Match { ind: bi, params: vec![], scrut: b1.clone(), motive: imotive, arms: iarms });
        let inner = mk::app_irr(inner, mk::refl(boolt.clone(), b1.clone()));
        let body = mk::lam("e1", Rel::Irr, mk::eq(boolt.clone(), a.clone(), lit(u)), inner);
        arms.push(Arm { names: vec![], body });
    }
    let mt = Rc::new(Term::Match { ind: bi, params: vec![], scrut: a.clone(), motive, arms });
    Ok(mk::app_irr(mt, mk::refl(boolt, a.clone())))
}

/// An irrelevant equation fact `t : Eq(ty, a, b)` used relevantly.
fn promote(env: &Env, ty: &Tm, a: &Tm, b: &Tm, t: Tm) -> Result<Tm, Fail> {
    let g = env.lookup_global("eq::promote").ok_or_else(|| fail("eq::promote is not loaded"))?;
    Ok(mk::apps(mk::global(g), [(Rel::Rel, ty.clone()), (Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Irr, t)]))
}

/// Forward chaining as prover hints (for the scripts of `#[proof(complete
/// = p)]` items, whose goals the elaborator proves): every application
/// `F G` of a fact `F : Π(y : P). Q` to a fact `G : P'` with `P ≡ P'`, and
/// again on the results (bounded rounds). `facts`: the context levels of
/// the facts with their type terms at their own depth. Returns the
/// derived facts (proof, type) at the context's depth.
pub fn forward_hints(env: &Env, ctx: &Ctx, facts: &[(u32, Tm)], budget: u64) -> Vec<(Tm, Tm)> {
    let d = ctx.depth().0;
    let eval = |t: &Tm| -> Option<V> {
        let mut b = Budget { steps: budget };
        env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut b).ok()
    };
    // (proof term, type term) at depth d
    let mut known: Vec<(Tm, Tm)> = facts.iter().filter(|(l, _)| *l < d).map(|(l, t)| (mk::var(d - 1 - l), shift(t, (d - l) as i64))).collect();
    let mut vals: Vec<Option<V>> = known.iter().map(|(_, t)| eval(t)).collect();
    let mut used: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut out = Vec::new();
    for _ in 0..3 {
        let mut added = Vec::new();
        for (i, (pf, t)) in known.iter().enumerate() {
            let Term::Pi { rel, dom, cod, .. } = &**t else { continue };
            let Some(dv) = eval(dom) else { continue };
            if matches!(&*dv, Value::IntTy(_) | Value::Sort(_)) {
                continue;
            }
            for (j, gv) in vals.iter().enumerate() {
                let Some(gv) = gv else { continue };
                if i == j || used.contains(&(i, j)) {
                    continue;
                }
                let mut b = Budget { steps: budget };
                if !env.conv(ctx.depth(), &dv, gv, &mut b).unwrap_or(false) {
                    continue;
                }
                used.insert((i, j));
                let app = Rc::new(Term::App { rel: *rel, fun: pf.clone(), arg: known[j].0.clone() });
                let q = crate::elab::tm::subst0(cod, &known[j].0);
                added.push((app, q));
                break;
            }
        }
        if added.is_empty() {
            break;
        }
        for (app, q) in added {
            out.push((app.clone(), q.clone()));
            vals.push(eval(&q));
            known.push((app, q));
        }
    }
    out
}

/// Largest recursive equation (term nodes) the induction discharge splits.
const MAX_EQUATION: usize = 4000;

/// Discharge 3: induction on `p`'s measure with its recursive equation.
#[allow(clippy::too_many_arguments)]
fn induction(pcx: &mut PCx<'_>, prover: &mut ProverChain, lay: &Layout, bs: &[(Name, Rel, Tm)], concl: &Tm, n: u32, params: &[u32], ind: &Induction, target: &Tm, hints: &[Hint]) -> Result<Tm, Fail> {
    // `p`'s telescope must have only relevant parameters after the
    // hypotheses: the induction hypothesis cannot supply requires proofs
    if bs.len() - params.len() != lay.members + lay.real.len() {
        return Err(fail("induction: a function with requires is not handled by the induction discharge (use `#[proof(complete = ..)]`)"));
    }
    let Term::Eq { ty, lhs, rhs } = &**target else { return Err(fail("induction: the conclusion is not an equation")) };
    let lhs_v = pcx.eval(lhs)?;
    let rhs_v = pcx.eval(rhs)?;
    // the equation instances `F' x̄ = E_F` and `p x̄ = E_p` among the facts
    let (mut e_f, mut e_p): (Option<u32>, Option<u32>) = (None, None);
    for f in pcx.facts.clone() {
        let tv = pcx.ty_of(f.lvl.0);
        let Value::Eq { lhs: l, rhs: r, .. } = &*tv else { continue };
        if e_f.is_none() && pcx.conv(l, &lhs_v) && !pcx.conv(r, &lhs_v) {
            e_f = Some(f.lvl.0);
        } else if e_p.is_none() && pcx.conv(l, &rhs_v) && !pcx.conv(r, &rhs_v) {
            e_p = Some(f.lvl.0);
        }
    }
    let (Some(lf), Some(lp)) = (e_f, e_p) else { return Err(fail("induction: the section states no recursive equation of the function (for both sides)")) };
    // the right-hand sides, as the facts' own type terms (well-typed)
    let rhs_of = |pcx: &PCx<'_>, l: u32| -> Option<Tm> {
        let (_, t) = pcx.fact_tys.iter().find(|(x, _)| *x == l)?;
        match &**t {
            Term::Eq { rhs, .. } => Some(shift(rhs, (pcx.depth() - l) as i64)),
            _ => None,
        }
    };
    let (Some(ef), Some(ep)) = (rhs_of(pcx, lf), rhs_of(pcx, lp)) else { return Err(fail("induction: the recursive equation is not stated as an equation")) };
    let goal = mk::eq(ty.clone(), ef.clone(), ep.clone());
    // the cases are read back from values: only for equations of a
    // readable size (a recursive equation, not an unfolded specification)
    if crate::elab::tm::size_capped(&goal, MAX_EQUATION + 1) > MAX_EQUATION {
        return Err(fail("induction: the recursive equation is too large to split into cases"));
    }
    let search = pcx.eval(&goal).map(|v| pcx.quote(&v))?;
    let core = split_cases(pcx, prover, lay, concl, n, ind, &goal, &search, hints, &[], 0)?;
    // trans(F' x̄, E_F, p x̄, e_f, trans(E_F, E_p, p x̄, core, sym(e_p)))
    let g = |name: &str| pcx.env.lookup_global(name).map(mk::global).ok_or_else(|| fail(format!("{name} is not loaded")));
    let (trans, sym) = (g("eq::trans")?, g("eq::sym")?);
    let e_f_pf = promote(pcx.env, ty, lhs, &ef, pcx.var(lf))?;
    let e_p_pf = promote(pcx.env, ty, rhs, &ep, pcx.var(lp))?;
    let sym_p = mk::apps(sym, [(Rel::Rel, ty.clone()), (Rel::Rel, rhs.clone()), (Rel::Rel, ep.clone()), (Rel::Rel, e_p_pf)]);
    let inner = mk::apps(trans.clone(), [(Rel::Rel, ty.clone()), (Rel::Rel, ef.clone()), (Rel::Rel, ep.clone()), (Rel::Rel, rhs.clone()), (Rel::Rel, core), (Rel::Rel, sym_p)]);
    Ok(mk::apps(trans, [(Rel::Rel, ty.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, ef), (Rel::Rel, rhs.clone()), (Rel::Rel, e_f_pf), (Rel::Rel, inner)]))
}

/// Visits the nodes of `t` in relevant positions (not proof slots,
/// irrelevant arguments, `let` values or constructor fields), with the
/// number of binders crossed, until `f` returns `true`.
fn any_relevant(t: &Tm, k: u32, f: &mut dyn FnMut(&Term, u32) -> bool) -> bool {
    if f(t, k) {
        return true;
    }
    match &**t {
        Term::Prim { args, .. } => args.iter().any(|a| any_relevant(a, k, f)),
        Term::App { rel: Rel::Irr, fun, .. } => any_relevant(fun, k, f),
        Term::App { fun, arg, .. } => any_relevant(fun, k, f) || any_relevant(arg, k, f),
        Term::Let { rel: Rel::Irr, body, .. } => any_relevant(body, k + 1, f),
        Term::Let { val, body, .. } => any_relevant(val, k, f) || any_relevant(body, k + 1, f),
        Term::Lam { body, .. } => any_relevant(body, k + 1, f),
        Term::Match { scrut, arms, .. } => any_relevant(scrut, k, f) || arms.iter().any(|a| any_relevant(&a.body, k + a.names.len() as u32, f)),
        Term::Pair { fst, snd, .. } => any_relevant(fst, k, f) || any_relevant(snd, k, f),
        Term::Fst(x) | Term::Snd(x) => any_relevant(x, k, f),
        Term::Ctor { args, .. } => args.iter().any(|a| any_relevant(a, k, f)),
        Term::Eq { lhs, rhs, .. } => any_relevant(lhs, k, f) || any_relevant(rhs, k, f),
        Term::Transport { val, .. } => any_relevant(val, k, f),
        _ => false,
    }
}

/// The first boolean `match` scrutinee of `t` in a relevant position,
/// outside binders of `t` (not a constructor).
fn bool_scrutinee(env: &Env, t: &Tm) -> Option<Tm> {
    let mut found: Option<Tm> = None;
    any_relevant(t, 0, &mut |node, k| {
        if let Term::Match { ind, scrut, .. } = node
            && *ind == env.bool_ind()
            && k == 0
            && !matches!(&**scrut, Term::Ctor { .. })
        {
            found = Some(scrut.clone());
            return true;
        }
        false
    });
    found
}

/// `s` (a term at the current depth) with the occurrences of `c` replaced
/// by the boolean `v` and evaluated: the form of a case, for searching it
/// (its proofs may not type-check; it never becomes part of a proof).
fn reduce_with(pcx: &PCx<'_>, s: &Tm, c: &Tm, v: bool) -> Result<Tm, Fail> {
    let sv = pcx.eval(s)?;
    let cv = pcx.eval(c)?;
    let mut b = pcx.b();
    let m = pcx.env.abstract_occurrences(&pcx.ctx, &sv, &cv, &mut b).map_err(|e| fail(format!("induction: abstraction failed: {}", e.message)))?;
    let bi = pcx.env.bool_ind();
    let inst = crate::elab::tm::subst0(&m, &mk::ctor(bi, v as u32, vec![], vec![]));
    pcx.eval(&inst).map(|x| pcx.quote(&x))
}

/// In a term read back from a case's search form, the path equation of a
/// dependent match on a split scrutinee `c` was instantiated with the
/// `refl(Bool, c)` it was applied to (`refl(Bool, c) : Eq(Bool, c, c)` where
/// `Eq(Bool, c, v)` is expected); the case's own path fact has exactly the
/// expected type. Replaces those `refl`s by the path facts (`paths`: the
/// scrutinee at the depth of its fact, and the fact's level; `t` at depth
/// `d`). A wrong replacement only makes the kernel reject the proof.
fn repair_path_refls(env: &Env, t: &Tm, paths: &[(Tm, u32)], d: u32) -> Tm {
    if paths.is_empty() {
        return t.clone();
    }
    let bi = env.bool_ind();
    crate::elab::tm::map_post(t, 0, &mut |node, b| {
        if let Term::Refl { ty, val } = &*node
            && matches!(&**ty, Term::Ind { ind, params } if *ind == bi && params.is_empty())
        {
            for (c, lvl) in paths {
                let c_here = shift(c, (d + b - lvl) as i64);
                if env.alpha_eq_relevant(val, &c_here, &|x, y| x == y) {
                    return Some(mk::var(d + b - 1 - lvl));
                }
            }
        }
        Some(node)
    })
    .unwrap_or_else(|| t.clone())
}

/// `goal` (an equation of the two unfolded sides; `search` its reduced
/// form): the boolean scrutinees of the search form are split (at most 3
/// deep; each case gets its path condition as a fact, the goal itself is
/// unchanged), induction hypotheses at the cases.
#[allow(clippy::too_many_arguments)]
fn split_cases(pcx: &mut PCx<'_>, prover: &mut ProverChain, lay: &Layout, concl: &Tm, n: u32, ind: &Induction, goal: &Tm, search: &Tm, hints: &[Hint], paths: &[(Tm, u32)], depth: u32) -> Result<Tm, Fail> {
    let scrut = if depth < 3 { bool_scrutinee(pcx.env, search) } else { None };
    let Some(c) = scrut else {
        return ih_case(pcx, prover, lay, concl, n, ind, goal, search, hints, paths);
    };
    let c = crate::elab::recert::recertify_quoted(pcx.env, &pcx.ctx, &c);
    let bi = pcx.env.bool_ind();
    let boolt = mk::ind(bi, vec![]);
    let lit = |v: bool| mk::ctor(bi, v as u32, vec![], vec![]);
    // over y: Π(.e : Eq(Bool, c, y)). goal — the goal does not mention y
    let motive = mk::pi("e", Rel::Irr, mk::eq(boolt.clone(), shift(&c, 1), mk::var(0)), shift(goal, 2));
    let mut arms = Vec::new();
    for v in [false, true] {
        let saved = pcx.clone();
        let path = mk::eq(boolt.clone(), c.clone(), lit(v));
        let lvl = pcx.push("c", Rel::Irr, &path, Some(FactOrigin::PathCond))?;
        let mut paths2 = paths.to_vec();
        paths2.push((c.clone(), lvl));
        let r = reduce_with(pcx, &shift(search, 1), &shift(&c, 1), v).and_then(|s1| split_cases(pcx, prover, lay, concl, n, ind, &shift(goal, 1), &s1, hints, &paths2, depth + 1));
        *pcx = saved;
        arms.push(Arm { names: vec![], body: mk::lam("c", Rel::Irr, path, r?) });
    }
    let mt = Rc::new(Term::Match { ind: bi, params: vec![], scrut: c.clone(), motive, arms });
    Ok(mk::app_irr(mt, mk::refl(boolt, c)))
}

/// A case of the induction: the induction hypothesis of every application
/// `F_p' ȳ` of the case's search form (its arguments re-certified against
/// the path conditions), then the prover on the goal.
#[allow(clippy::too_many_arguments)]
fn ih_case(pcx: &mut PCx<'_>, prover: &mut ProverChain, lay: &Layout, concl: &Tm, n: u32, ind: &Induction, goal: &Tm, search: &Tm, hints: &[Hint], paths: &[(Tm, u32)]) -> Result<Tm, Fail> {
    let d = pcx.depth();
    let fvar = lay.member_p as u32;
    let fixed = (lay.members + lay.real.len()) as u32;
    let np = (n - fixed) as usize;
    let mut calls: Vec<Vec<Tm>> = Vec::new();
    any_relevant(search, 0, &mut |node, k| {
        let mut args = Vec::new();
        let mut head = node;
        while let Term::App { fun, arg, .. } = head {
            args.push(arg.clone());
            head = &**fun;
        }
        // the variable of F_p' (level fvar) under k binders of the search form
        let is_f = matches!(head, Term::Var(i) if i.0 >= k && d + k - 1 - i.0 == fvar);
        if k == 0 && is_f && args.len() == np {
            args.reverse();
            if !calls.iter().any(|c| c.len() == args.len() && c.iter().zip(&args).all(|(x, y)| pcx.env.alpha_eq_relevant(x, y, &|a, b| a == b))) {
                calls.push(args);
            }
        }
        false
    });
    let saved = pcx.clone();
    let mark = pcx.lets.len();
    let d0 = d;
    let r = (|| {
        for ys in calls {
            let d = pcx.depth();
            // every binder of the statement: F'…, h…, then ȳ
            let mut args: Vec<Tm> = (0..fixed).map(|l| mk::var(d - 1 - l)).collect();
            for y in &ys {
                let y = repair_path_refls(pcx.env, &shift(y, (d - d0) as i64), paths, d);
                args.push(crate::elab::recert::recertify_quoted(pcx.env, &pcx.ctx, &y));
            }
            let m_x = shift(&ind.measure, (d - n) as i64);
            let m_y = crate::elab::tm::subst_closed(&ind.measure, &args);
            let bi = pcx.env.bool_ind();
            let holds = |op: PrimOp, x: Tm, y: Tm| mk::eq_bool(bi, mk::prim(op, vec![x, y], vec![]), true);
            let proof = if ind.width == Width::Int {
                let g0 = holds(PrimOp::Le(Width::Int), mk::lit(Width::Int, 0u8), m_y.clone());
                let g1 = holds(PrimOp::Lt(Width::Int), m_y.clone(), m_x.clone());
                let p0 = pcx.close(prover, &g0, hints)?;
                let p1 = pcx.close(prover, &g1, hints)?;
                mk::pair(mk::sigma("_", Rel::Rel, g0, shift(&g1, 1)), p0, p1)
            } else {
                pcx.close(prover, &holds(PrimOp::Lt(ind.width), m_y, m_x), hints)?
            };
            let rec = Rc::new(Term::Rec { args: args.clone(), proof: Some(proof) });
            let ih_ty = crate::elab::tm::subst_closed(concl, &args);
            pcx.push_let("ih", ih_ty, rec)?;
        }
        let g = shift(goal, (pcx.depth() - d0) as i64);
        let p = pcx.close(prover, &g, hints)?;
        Ok(pcx.wrap(mark, p))
    })();
    *pcx = saved;
    r
}
