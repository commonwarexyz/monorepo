//! Fallback rungs of Σ2 (optimizer design §7.6): when no closed form is
//! found or proven (or synthesis is switched off), a structural rewrite of
//! the loop that is still certified by the kernel.
//!
//! **Early exit.** A loop with a `FirstMatch` payload `p` that it returns as
//! is at every exit gets a **stop test** `S` at the top of its body: once
//! `S` holds, no later iteration changes `p`, so the rest of the run returns
//! `p`. `S` is one of the payload's own in-place select tests (or its
//! negation) that keeps `p`, validated on the traces (it stays true and `p`
//! stays unchanged after it first holds). The emitted helper is
//!
//! ```text
//! fn loop__early(s̄) -> R { if S(s̄) { p } else { <the loop's body, recursing into loop__early> } }
//! ```
//!
//! with the loop's `requires` and measure, and an entry wrapper at the
//! call's static arguments (`loop__early_entry(d̄) = loop__early(statics, d̄)`,
//! always inlined), which is what the call site uses. Two measure-recursive
//! lemmas link it to the loop, both built here and checked by the kernel:
//!
//! ```text
//! <loop>::early::final : Π s̄ h̄ (.hs : Eq(Bool, S(s̄), true)). Eq(R, loop(s̄) h̄, p)
//! <loop>::early::equiv : Π s̄ h̄. Eq(R, loop__early(s̄) h̄, loop(s̄) h̄)
//! ```
//!
//! `final` unfolds one step and splits on the body's tests: an exit returns
//! `p` (conversion), a recursive call is the induction hypothesis at the
//! next state, whose `.hs` — `S` preserved — and payload — unchanged under
//! `S` — are the obligations (**invariant preservation**; a wrong stop test,
//! e.g. the design's must-reject R6, an early exit on a find-*last* loop,
//! fails here). `equiv` splits on `S`: its true arm is `final`, its false
//! arm unfolds the loop and splits both bodies in lockstep down to the
//! recursive calls, which are the induction hypothesis.
//!
//! **Entry idle-run skip** ([`EntrySkip`]): when the loop's first
//! iterations are idle (only its static parameters change) while a dynamic
//! value is below a static halving power of two, the entry wrapper jumps
//! to the first non-idle iteration with one bit scan and runs the helper
//! from there (lemmas `<loop>::early::idle<j>`, `<entry>::idle_at`, and the
//! entry's link by a case split on the value's magnitude).
//!
//! Idle runs after the entry are still iterated one at a time, and the
//! set-bit iteration rung is not built; selection among rungs needs the
//! cost model (plan O8).

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Lvl, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, Neutral, V, Value};

use super::classify::{self, CVal, Class, Loop, SVal};
use super::expr::{CE, E};
use super::traces::Traces;
use super::{LoopFailure, LoopHelper, LoopKey};
use crate::auto::search::{Engine, R};
use crate::auto::state::St;
use crate::auto::util::{apps, as_eq, irr_entry, prefix};
use crate::hir::*;

/// Whether the early-exit rung applies (a `FirstMatch` loop): the parameter
/// of the payload.
pub fn early_exit_param(lp: &Loop) -> Option<u32> {
    let fm: Vec<u32> = (0..lp.params.len() as u32).filter(|i| lp.classes[*i as usize] == Class::FirstMatch).collect();
    (fm.len() == 1).then(|| fm[0])
}

/// The stop test of an early exit.
#[derive(Clone, Debug)]
pub enum Stop {
    /// A comparison of the state (already oriented: the stop holds when it
    /// is true).
    Cond(E),
    /// "The payload is set" (not the unset constructor): only as a
    /// simulated fault (must-reject R6), never proposed.
    PayloadSet { unset: u32 },
}

/// The early-exit rung's plan.
#[derive(Clone, Debug)]
pub struct EarlyExit {
    /// The payload parameter (relevant index = telescope index).
    pub payload: u32,
    pub stop: Stop,
    /// The measure parameter (telescope index).
    pub measure: u32,
}

/// The negation of a comparison as a comparison (`¬(a < b)` is `b ≤ a`).
fn negate(c: &E) -> Option<E> {
    let CE::Op(op, a) = &**c else { return None };
    let (x, y) = (a.first()?.clone(), a.get(1)?.clone());
    Some(match op {
        PrimOp::Lt(w) => super::expr::op2(PrimOp::Le(*w), y, x),
        PrimOp::Le(w) => super::expr::op2(PrimOp::Lt(*w), y, x),
        PrimOp::Gt(w) => super::expr::op2(PrimOp::Le(*w), x, y),
        PrimOp::Ge(w) => super::expr::op2(PrimOp::Lt(*w), x, y),
        PrimOp::Eq(w) => super::expr::op2(PrimOp::Ne(*w), x, y),
        PrimOp::Ne(w) => super::expr::op2(PrimOp::Eq(*w), x, y),
        _ => return None,
    })
}

fn is_cmp(c: &E) -> bool {
    matches!(&**c, CE::Op(PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_) | PrimOp::Eq(_) | PrimOp::Ne(_), a) if a.iter().all(|x| matches!(&**x, CE::Var(..) | CE::Lit(..))))
}

/// The select tests of the payload's update that keep it (a test whose
/// `true` side is the old payload, or the negation of one whose `false`
/// side is).
fn keep_tests(s: &SVal, p: u32, out: &mut Vec<E>) {
    if let SVal::Ite(c, a, b) = s {
        let keeps = |x: &SVal| matches!(x, SVal::Param(i) if *i == p);
        if keeps(a) && is_cmp(c) && !out.contains(c) {
            out.push(c.clone());
        }
        if keeps(b)
            && let Some(n) = negate(c)
            && is_cmp(&n)
            && !out.contains(&n)
        {
            out.push(n);
        }
        keep_tests(a, p, out);
        keep_tests(b, p, out);
    }
}

/// Plans the early exit (see the module docs); `fault`: the must-reject
/// R6 stop test ("the payload is set").
pub fn plan_early_exit(lp: &Loop, tr: &Traces, measure: u32, fault: bool) -> Result<EarlyExit, String> {
    let p = early_exit_param(lp).ok_or("no FirstMatch payload")?;
    if !lp.exits.iter().all(|x| matches!(x.value, SVal::Param(i) if i == p)) {
        return Err("an exit that does not return the payload as it is".into());
    }
    if fault {
        let unset = match lp.statics[p as usize].as_ref().and_then(|t| match &**t {
            Term::Ctor { ctor, .. } => Some(*ctor),
            _ => None,
        }) {
            Some(c) => c,
            None => return Err("the payload is not a constructor at the call".into()),
        };
        return Ok(EarlyExit { payload: p, stop: Stop::PayloadSet { unset }, measure });
    }
    let mut cands = Vec::new();
    for c in &lp.cont {
        keep_tests(&c.next[p as usize], p, &mut cands);
    }
    let nums = |st: &[CVal]| -> Vec<u128> { st.iter().map(|c| c.num().unwrap_or(0)).collect() };
    for c in cands {
        let holds = |st: &[CVal]| c.eval(&nums(st), None).and_then(|v| v.as_bool()) == Some(true);
        let mut useful = false;
        let mut ok = true;
        'traces: for t in &tr.traces {
            for i in 0..t.states.len() {
                if !holds(&t.states[i]) {
                    continue;
                }
                if i + 1 < t.states.len() {
                    useful = true;
                    if !holds(&t.states[i + 1]) || t.states[i + 1][p as usize] != t.states[i][p as usize] {
                        ok = false;
                        break 'traces;
                    }
                }
            }
        }
        if ok && useful {
            return Ok(EarlyExit { payload: p, stop: Stop::Cond(c), measure });
        }
    }
    Err("no select test of the payload is final on the traces".into())
}

// ---------------------------------------------------------------------------
// The helper (HIR).
// ---------------------------------------------------------------------------

fn uint_of(w: Width) -> Option<UintTy> {
    Some(match w {
        Width::U8 => UintTy::U8,
        Width::U16 => UintTy::U16,
        Width::U32 => UintTy::U32,
        Width::U64 => UintTy::U64,
        Width::Usize => UintTy::Usize,
        _ => return None,
    })
}

/// A comparison of parameters and literals as a HIR `bool` expression.
fn cmp_hir(c: &E, params: &[(LocalId, Ty)], span: crate::span::Span) -> Option<Expr> {
    let leaf = |x: &E| -> Option<Expr> {
        match &**x {
            CE::Var(i, _) => {
                let (l, t) = params.get(*i as usize)?;
                Some(Expr::new(ExprKind::Local(*l), t.clone(), span))
            }
            CE::Lit(w, n) => Some(Expr::new(ExprKind::Lit(Lit::Int(*n)), Ty::Uint(uint_of(*w)?), span)),
            _ => None,
        }
    };
    let CE::Op(op, a) = &**c else { return None };
    let bop = match op {
        PrimOp::Lt(_) => BinOp::Lt,
        PrimOp::Le(_) => BinOp::Le,
        PrimOp::Gt(_) => BinOp::Gt,
        PrimOp::Ge(_) => BinOp::Ge,
        PrimOp::Eq(_) => BinOp::Eq,
        PrimOp::Ne(_) => BinOp::Ne,
        _ => return None,
    };
    Some(Expr::new(ExprKind::Binary(bop, Box::new(leaf(&a[0])?), Box::new(leaf(&a[1])?)), Ty::Bool, span))
}

/// The HIR stop test.
fn stop_hir(ee: &EarlyExit, params: &[(LocalId, Ty)], span: crate::span::Span) -> Option<Expr> {
    match &ee.stop {
        Stop::Cond(c) => cmp_hir(c, params, span),
        Stop::PayloadSet { .. } => {
            let (l, t) = params.get(ee.payload as usize)?;
            let Ty::Option(inner) = t else { return None };
            let recv = Expr::new(ExprKind::Ref(Box::new(Expr::new(ExprKind::Local(*l), t.clone(), span))), Ty::reference(t.clone()), span);
            Some(Expr::new(ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Option(crate::builtins::OptionMethod::IsSome), vec![(**inner).clone()]), args: vec![recv] }, Ty::Bool, span))
        }
    }
}

/// The stop test as a kernel term over the telescope's parameters (the
/// first `n` binders; `names` their parse names).
fn stop_term(env: &Env, ee: &EarlyExit, lp: &Loop, names: &[String]) -> Result<Tm, String> {
    match &ee.stop {
        Stop::Cond(c) => {
            let ns: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            env.parse_term(&ns, &c.text(names, None)).map_err(|e| format!("the stop test: {e}"))
        }
        Stop::PayloadSet { unset } => {
            let Term::Ind { ind, params } = &*lp.params[ee.payload as usize].ty.clone() else { return Err("the payload's type".into()) };
            let decl = env.inductive_decl(*ind).ok_or("the payload's type")?;
            let n = names.len() as u32;
            let bi = env.bool_ind();
            let arms: Vec<sandblaster_kernel::term::Arm> = decl
                .ctors
                .iter()
                .enumerate()
                .map(|(k, c)| sandblaster_kernel::term::Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::bool_lit(bi, k as u32 != *unset) })
                .collect();
            Ok(Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: mk::var(n - 1 - ee.payload), motive: mk::bool_ty(bi), arms }))
        }
    }
}

// ---------------------------------------------------------------------------
// The lemmas.
// ---------------------------------------------------------------------------

/// Proof search for the two lemmas (see the module docs).
struct Pf<'s> {
    /// The loop.
    f: GlobalId,
    /// The function whose calls are the induction hypothesis's (the loop
    /// for `final`, the helper for `equiv`).
    this: GlobalId,
    ee: &'s EarlyExit,
    /// The lemma's statement (for the induction hypothesis' telescope).
    stmt: Tm,
    /// Its measure binder's level and width.
    m_lvl: u32,
    m_w: Width,
    /// The lemma `final` (for `equiv`'s early arm).
    final_lemma: Option<GlobalId>,
    /// The stop test over the parameters, in the telescope's context (the
    /// loop's `arity` binders).
    stop_full: Tm,
    arity: u32,
    trust: bool,
    failure: Option<String>,
}

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> Result<V, String> {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut Budget { steps: 50_000_000 }).map_err(|e| format!("eval: {e:?}"))
}

/// The scrutinee (and its match) of the first stuck match inside a value's
/// relevant parts (a call's arguments, a constructor's fields).
fn stuck_inside(v: &V) -> Option<(V, sandblaster_kernel::term::IndId, Vec<V>)> {
    let mut found = None;
    crate::auto::util::walk(v, &mut |x| {
        if found.is_some() {
            return false;
        }
        if let Value::Neu(n) = &**x
            && let Some(i) = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))
            && let Elim::Match { ind, params, .. } = &n.spine[i]
        {
            found = Some((prefix(n, i), *ind, params.clone()));
            return false;
        }
        true
    });
    found
}

/// The first stuck match of a value at its head.
fn head_match(v: &V) -> Option<(V, sandblaster_kernel::term::IndId, Vec<V>)> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))?;
    let Elim::Match { ind, params, .. } = &n.spine[i] else { return None };
    Some((prefix(n, i), *ind, params.clone()))
}

fn call_args(v: &V, func: GlobalId) -> Option<Vec<Arg>> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if *def == func && spine.is_empty() => Some(args.clone()),
        _ => None,
    }
}

impl Pf<'_> {
    fn note_failure(&mut self, env: &Env, st: &St, what: &str, v: &V) {
        if self.failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.failure = Some(format!("{what}: {}", crate::elab::show::value(env, &names, v, 600)));
        }
    }

    /// An obligation: conversion or an assumption, linear arithmetic over
    /// the facts, then `auto`.
    fn obligation(&mut self, e: &mut Engine<'_>, st: &St, target: &V, what: &str) -> Option<Tm> {
        let env = e.env;
        if let Some(p) = super::lemmas::trivial(env, &st.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Some(p);
        }
        if let Ok(Some(p)) = e.lin_prove(st, target, true) {
            return Some(e.promote(st, target, p));
        }
        if let Ok(Some(p)) = e.solve(st, target.clone(), true) {
            return Some(p);
        }
        self.note_failure(env, st, what, target);
        if self.trust {
            // a simulated fault's claim: the kernel's check judges it
            return Some(Rc::new(Term::Linarith { hyps: vec![], goal: env.quote_typed(&st.ctx, target, None, false), cert: vec![] }));
        }
        None
    }

    /// The contradiction of an arm's facts, if linear arithmetic finds one.
    fn absurd(&mut self, e: &mut Engine<'_>, st: &St, goal: &V) -> Option<Tm> {
        let mut c = st.child();
        match e.contradiction(&mut c) {
            Ok(Some(p)) => Some(e.absurd(st, goal, c.finish(p))),
            _ => None,
        }
    }

    /// The induction hypothesis at the call `this(args)`: its relevant
    /// arguments from the call, the `requires` and `.hs` as obligations,
    /// the measure's decrease proven.
    fn ih(&mut self, e: &mut Engine<'_>, st: &mut St, args: &[Arg]) -> R<Option<Tm>> {
        let env = e.env;
        let rel_vals: Vec<V> = args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        let Ok(mut cur) = eval_in(env, &Ctx::default(), &self.stmt) else { return Ok(None) };
        let mut out: Vec<(Rel, Tm)> = Vec::new();
        let mut ri = 0usize;
        let mut bi = 0u32;
        while let Value::Pi { rel, dom, cod, .. } = &*cur.clone() {
            if bi == self.arity + if self.final_lemma.is_none() { 1 } else { 0 } {
                break;
            }
            let entry = match rel {
                Rel::Rel => {
                    let Some(v) = rel_vals.get(ri).cloned() else { return Ok(None) };
                    ri += 1;
                    out.push((Rel::Rel, st.quote(env, &v)));
                    EnvEntry::Rel(v)
                }
                Rel::Irr => {
                    let what = if bi == self.arity { "invariant preservation (the stop test at the next state)" } else { "a requires at the next state" };
                    let Some(p) = self.obligation(e, st, dom, what) else { return Ok(None) };
                    out.push((Rel::Irr, p.clone()));
                    irr_entry(&st.venv, &p)
                }
            };
            let Some(next) = e.inst(cod, vec![entry], st.depth())? else { return Ok(None) };
            cur = next;
            bi += 1;
        }
        // the measure decreases
        let Some(m_next) = rel_vals.get(self.m_lvl as usize) else { return Ok(None) };
        let goal_tm = mk::eq(mk::bool_ty(env.bool_ind()), Rc::new(Term::Prim { op: PrimOp::Lt(self.m_w), args: vec![st.quote(env, m_next), st.var(self.m_lvl)], proofs: vec![] }), mk::bool_lit(env.bool_ind(), true));
        let Ok(goal) = eval_in(env, &st.ctx, &goal_tm) else { return Ok(None) };
        let Some(dec) = self.obligation(e, st, &goal, "the measure's decrease") else { return Ok(None) };
        Ok(Some(Rc::new(Term::Rec { args: out.into_iter().map(|(_, t)| t).collect(), proof: Some(dec) })))
    }

    /// `final`: the goal `Eq(R, L, p)` split down to exits and recursive calls.
    fn fin(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        let Some((_, lhs, _)) = as_eq(goal) else { return Ok(None) };
        let lhs = lhs.clone();
        if let Some(args) = call_args(&lhs, self.this) {
            // the payload argument must be the payload: decide its selects
            let pay = args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).nth(self.ee.payload as usize);
            if let Some(pv) = pay
                && depth > 0
                && let Some((c, ind, params)) = stuck_inside(&pv)
            {
                let d = st.depth_left;
                let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.fin(e2, a2, &tk, depth - 1) };
                return e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn);
            }
            if let Some(p) = self.absurd(e, st, goal) {
                return Ok(Some(p));
            }
            return self.ih(e, st, &args);
        }
        if let Some((c, ind, params)) = head_match(&lhs)
            && depth > 0
        {
            let d = st.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.fin(e2, a2, &tk, depth - 1) };
            return e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn);
        }
        // an exit: the payload by conversion, or an infeasible arm
        if let Some(p) = super::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        if let Some(p) = self.absurd(e, st, goal) {
            return Ok(Some(p));
        }
        self.note_failure(env, st, "an exit that does not return the payload", goal);
        Ok(None)
    }

    /// `equiv`, below the stop test's false arm: both bodies split in
    /// lockstep down to the recursive calls.
    fn step(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        let Some((_, lhs, _)) = as_eq(goal) else { return Ok(None) };
        let lhs = lhs.clone();
        if let Some(args) = call_args(&lhs, self.this) {
            if let Some(p) = super::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 5_000_000 }) {
                return Ok(Some(p));
            }
            // the two calls differ where one side's select is decided by an
            // enclosing split and the other's is not: split it too
            let rhs = as_eq(goal).map(|(_, _, r)| r.clone());
            let differ = match rhs.as_ref().and_then(|r| call_args(r, self.f)) {
                Some(rargs) => args.iter().zip(&rargs).any(|(a, b)| match (a, b) {
                    (Arg::Rel(x), Arg::Rel(y)) => !env.conv(st.ctx.depth(), x, y, &mut Budget { steps: 1_000_000 }).unwrap_or(false),
                    _ => false,
                }),
                None => true,
            };
            if differ
                && depth > 0
                && let Some((c, ind, params)) = rhs.as_ref().and_then(stuck_inside).or_else(|| stuck_inside(&lhs))
            {
                let d = st.depth_left;
                let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.step(e2, a2, &tk, depth - 1) };
                return e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn);
            }
            if differ && let Some(p) = self.absurd(e, st, goal) {
                return Ok(Some(p));
            }
            return self.ih(e, st, &args);
        }
        if let Some((c, ind, params)) = head_match(&lhs)
            && depth > 0
        {
            let d = st.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.step(e2, a2, &tk, depth - 1) };
            return e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn);
        }
        if let Some(p) = super::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        if let Some(p) = self.absurd(e, st, goal) {
            return Ok(Some(p));
        }
        self.note_failure(env, st, "a leaf where the two bodies differ", goal);
        Ok(None)
    }

    /// `equiv`'s body: the helper's stop test split; its true arm by
    /// `final`, its false arm by unfolding the loop then [`Self::step`].
    fn equiv(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, params: &[Tm]) -> R<Option<Tm>> {
        let env = e.env;
        let Some((rty, lhs, rhs)) = as_eq(goal) else { return Ok(None) };
        let (rty, lhs, rhs) = (rty.clone(), lhs.clone(), rhs.clone());
        let Some((c, ind, ps)) = head_match(&lhs) else {
            self.note_failure(env, st, "the helper does not start with its stop test", goal);
            return Ok(None);
        };
        let f = self.f;
        let fin = self.final_lemma;
        let np = params.len();
        let d = st.depth_left;
        let base = st.depth();
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            let env = e2.env;
            let Some((rty2, l2, r2)) = as_eq(&tk) else { return Ok(None) };
            let (rty2, l2, r2) = (rty2.clone(), l2.clone(), r2.clone());
            let sh = (a2.depth() - base) as i64;
            let ps: Vec<Tm> = params.iter().map(|p| crate::auto::util::shift(p, sh)).collect();
            let ty_tm = a2.quote(env, &rty2);
            let (l_tm, r_tm) = (a2.quote(env, &l2), a2.quote(env, &r2));
            if k == 1 {
                // the stop test holds: `final` (reversed)
                let Some(fl) = fin else { return Ok(None) };
                let stop_now = crate::auto::util::shift(&self.stop_full, (a2.depth() - self.arity) as i64);
                let hs_ty = eval_in(env, &a2.ctx, &mk::eq(mk::bool_ty(env.bool_ind()), stop_now, mk::bool_lit(env.bool_ind(), true))).ok();
                let Some(hs_ty) = hs_ty else { return Ok(None) };
                let Some(hs) = self.obligation(e2, a2, &hs_ty, "the stop test in its arm") else { return Ok(None) };
                let mut fargs: Vec<(Rel, Tm)> = Vec::new();
                let Some(tele) = crate::opt::symex::telescope(env, f) else { return Ok(None) };
                for (i, (_, rel, _)) in tele.binders.iter().enumerate() {
                    fargs.push((*rel, ps[i].clone()));
                }
                fargs.push((Rel::Irr, hs));
                let fin_app = apps(mk::global(fl), fargs);
                let Some(sym) = env.lookup_global("eq::sym") else { return Ok(None) };
                return Ok(Some(apps(mk::global(sym), [(Rel::Rel, ty_tm), (Rel::Rel, r_tm), (Rel::Rel, l_tm), (Rel::Rel, fin_app)])));
            }
            // the stop test fails: unfold the loop, then both bodies in lockstep
            let Some(fbody) = env.global_body(f) else { return Ok(None) };
            let body = apps(fbody, ps.iter().enumerate().map(|(i, p)| (if i < np { rel_of(env, f, i) } else { Rel::Irr }, p.clone())));
            let delta = Rc::new(Term::Delta { def: f, args: ps.clone() });
            let Ok(g2) = eval_in(env, &a2.ctx, &mk::eq(ty_tm.clone(), l_tm.clone(), body.clone())) else { return Ok(None) };
            let Some(p2) = self.step(e2, a2, &g2, 12)? else { return Ok(None) };
            let (Some(sym), Some(trans)) = (env.lookup_global("eq::sym"), env.lookup_global("eq::trans")) else { return Ok(None) };
            let back = apps(mk::global(sym), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, r_tm.clone()), (Rel::Rel, body.clone()), (Rel::Rel, delta)]);
            Ok(Some(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, l_tm), (Rel::Rel, body), (Rel::Rel, r_tm), (Rel::Rel, p2), (Rel::Rel, back)])))
        };
        let _ = (rty, rhs);
        e.case_split_with(st, &c, ind, &ps, goal, true, d, &mut arm_fn)
    }
}

fn rel_of(env: &Env, f: GlobalId, i: usize) -> Rel {
    env.global_param_rels(f).and_then(|r| r.get(i).copied()).unwrap_or(Rel::Rel)
}

/// Commits a measure-recursive lemma.
fn add_rec_lemma(env: &mut Env, name: &str, ty: Tm, body: Tm, arity: u32, m_binder: u32, budget: u64) -> Result<(GlobalId, u64), String> {
    let body = super::lemmas::hashcons(&body);
    let measure = mk::var(arity - 1 - m_binder);
    let budget = super::meter::cap(budget);
    let mut b = Budget { steps: budget };
    let r = env.add_def(DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body, recursion: Recursion::Measure { measure }, arity, opaque: true }, &mut b);
    super::meter::charge(budget - b.steps);
    let g = r
        .map_err(|e| {
            if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                eprintln!("[loopsum] the kernel rejected `{name}`: {e}");
            }
            format!("the kernel rejected `{name}`: {}", e.to_string().chars().take(600).collect::<String>())
        })?;
    Ok((g, budget - b.steps))
}

/// Builds `final` and `equiv` (see the module docs) for the loop `f` and
/// its early helper `h`; returns `equiv` and the kernel steps.
#[allow(clippy::too_many_arguments)]
pub fn prove(env: &mut Env, f: GlobalId, h: GlobalId, lp: &Loop, ee: &EarlyExit, prefix: &str, trust: bool, budget: u64) -> Result<(GlobalId, GlobalId, u64), String> {
    let tele = crate::opt::symex::telescope(env, f).ok_or("the loop has no telescope")?;
    let n = tele.binders.len() as u32;
    let np = tele.binders.iter().take_while(|(_, r, _)| *r == Rel::Rel).count() as u32;
    let names: Vec<String> = (0..np).map(|i| format!("p{i}")).collect();
    let stop_tm = stop_term(env, ee, lp, &names)?;
    // the stop test in the full telescope's context (over the parameters)
    let stop_full = crate::auto::util::shift(&stop_tm, (n - np) as i64);
    let bi = env.bool_ind();
    let m_w = match &*tele.binders[ee.measure as usize].2 {
        Term::IntTy(w) => *w,
        _ => return Err("a measure that is not a machine integer".into()),
    };
    let vars = |extra: u32| -> Vec<(Rel, Tm)> { tele.binders.iter().enumerate().map(|(i, (_, r, _))| (*r, mk::var(n + extra - 1 - i as u32))).collect() };
    let close = |mut t: Tm, extra: Option<(&str, Tm)>| -> Tm {
        if let Some((nm, dom)) = extra {
            t = mk::pi(nm, Rel::Irr, dom, t);
        }
        for (nm, rel, dom) in tele.binders.iter().rev() {
            t = mk::pi(nm, *rel, dom.clone(), t);
        }
        t
    };
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let mut steps = 0u64;
    // final : Π s̄ h̄ (.hs). Eq(R, f s̄ h̄, p)
    let hs_dom = mk::eq(mk::bool_ty(bi), stop_full.clone(), mk::bool_lit(bi, true));
    let fin_ty = close(mk::eq(crate::auto::util::shift(&tele.ret, 1), apps(mk::global(f), vars(1)), mk::var(n + 1 - 1 - ee.payload)), Some(("hs", hs_dom)));
    let fin_name = format!("{prefix}::final");
    let lim = super::meter::cap(200_000_000);
    let mut sb = Budget { steps: lim };
    let (fin_body, failure) = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 64);
        let goal = super::lemmas::open(&mut e, &mut st, &fin_ty)?;
        let (rty, lhs, rhs) = as_eq(&goal).ok_or("final's statement")?;
        let (ty_tm, lhs_tm, rhs_tm) = (st.quote(envr, rty), st.quote(envr, lhs), st.quote(envr, rhs));
        let args: Vec<Tm> = (0..n).map(|i| st.var(i)).collect();
        let body = apps(envr.global_body(f).ok_or("the loop has no body")?, args.iter().enumerate().map(|(i, a)| (rel_of(envr, f, i), a.clone())));
        let g1 = eval_in(envr, &st.ctx, &mk::eq(ty_tm.clone(), body.clone(), rhs_tm.clone()))?;
        let mut pf = Pf { f, this: f, ee, stmt: fin_ty.clone(), m_lvl: ee.measure, m_w, final_lemma: None, stop_full: stop_full.clone(), arity: n, trust, failure: None };
        let p = pf.fin(&mut e, &mut st, &g1, 16).map_err(|s| format!("{s:?}"))?;
        let p = p.map(|p| {
            let delta = Rc::new(Term::Delta { def: f, args: args.clone() });
            let trans = envr.lookup_global("eq::trans").unwrap();
            st.finish(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, lhs_tm), (Rel::Rel, body), (Rel::Rel, rhs_tm), (Rel::Rel, delta), (Rel::Rel, p)]))
        });
        (p, pf.failure)
    };
    super::meter::charge(lim - sb.steps);
    let fin_body = fin_body.ok_or_else(|| format!("the stability lemma is not proven: {}", failure.unwrap_or_default()))?;
    let (fin_g, s1) = add_rec_lemma(env, &fin_name, fin_ty, fin_body, n + 1, ee.measure, budget)?;
    steps += s1;
    // equiv : Π s̄ h̄. Eq(R, h s̄ h̄, f s̄ h̄)
    let eq_ty = close(mk::eq(tele.ret.clone(), apps(mk::global(h), vars(0)), apps(mk::global(f), vars(0))), None);
    let eq_name = format!("{prefix}::equiv");
    let lim = super::meter::cap(200_000_000);
    let mut sb = Budget { steps: lim };
    let (eq_body, failure) = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 64);
        let goal = super::lemmas::open(&mut e, &mut st, &eq_ty)?;
        let (rty, lhs, rhs) = as_eq(&goal).ok_or("equiv's statement")?;
        let (ty_tm, lhs_tm, rhs_tm) = (st.quote(envr, rty), st.quote(envr, lhs), st.quote(envr, rhs));
        let args: Vec<Tm> = (0..n).map(|i| st.var(i)).collect();
        let hbody = apps(envr.global_body(h).ok_or("the helper has no body")?, args.iter().enumerate().map(|(i, a)| (rel_of(envr, h, i), a.clone())));
        let g1 = eval_in(envr, &st.ctx, &mk::eq(ty_tm.clone(), hbody.clone(), rhs_tm.clone()))?;
        let mut pf = Pf { f, this: h, ee, stmt: eq_ty.clone(), m_lvl: ee.measure, m_w, final_lemma: Some(fin_g), stop_full: stop_full.clone(), arity: n, trust, failure: None };
        let p = pf.equiv(&mut e, &mut st, &g1, &args).map_err(|s| format!("{s:?}"))?;
        let p = p.map(|p| {
            let delta = Rc::new(Term::Delta { def: h, args: args.clone() });
            let trans = envr.lookup_global("eq::trans").unwrap();
            st.finish(apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, lhs_tm), (Rel::Rel, hbody), (Rel::Rel, rhs_tm), (Rel::Rel, delta), (Rel::Rel, p)]))
        });
        (p, pf.failure)
    };
    super::meter::charge(lim - sb.steps);
    let eq_body = eq_body.ok_or_else(|| format!("the helper's lemma is not proven: {}", failure.unwrap_or_default()))?;
    let (eq_g, s2) = add_rec_lemma(env, &eq_name, eq_ty, eq_body, n, ee.measure, budget)?;
    steps += s2;
    Ok((fin_g, eq_g, steps))
}

// ---------------------------------------------------------------------------
// The rung, end to end.
// ---------------------------------------------------------------------------

/// Builds the early-exit rung for `key` (see the module docs): the plan,
/// the recursive helper, its lemmas, and the entry wrapper the call site
/// uses (registered like a closed-form helper).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_early(
    cx: &mut crate::opt::Ctx<'_>,
    ext: &mut Crate,
    chain: &mut crate::elab::ProverChain,
    eopts: &crate::elab::Options,
    key: &LoopKey,
    user_globals: &HashMap<GlobalId, ItemId>,
    fault: bool,
    why_not_closed: &str,
) -> Result<LoopHelper, LoopFailure> {
    let fail = |reason: String, steps: u64| LoopFailure { reason: format!("no closed form ({why_not_closed}); no early exit: {reason}"), steps };
    let fid = *user_globals.get(&key.def).ok_or_else(|| fail("the loop is not a user function".into(), 0))?;
    let fd = ext.fn_def(fid).cloned().ok_or_else(|| fail("the loop is not a function".into(), 0))?;
    if !fd.generics.is_empty() {
        return Err(fail("a generic loop".into(), 0));
    }
    let measure = match crate::opt::drive::measure_of(fid, &fd) {
        Some(crate::opt::drive::Measure::Param(i)) => i as u32,
        _ => return Err(fail("the loop's measure is not a parameter".into(), 0)),
    };
    // analysis: one step, classes, traces (cheap; synthesis is not needed)
    let env = &cx.out.env;
    let one = super::onestep::one_step(env, key.def, 20_000_000).map_err(|e| fail(e, 0))?;
    let mut steps = one.steps;
    let statics = super::statics_of(env, key, one.nparams as usize).map_err(|e| fail(e, steps))?;
    let lp = classify::classify(env, one, statics).map_err(|e| fail(e, steps))?;
    let name = env.global_name(key.def).map(|s| s.to_string()).unwrap_or_default();
    let profile = with_profile(&name);
    let samples = super::traces::samples(env, &lp, &super::project_profile(&lp, &profile)).map_err(|e| fail(e, steps))?;
    let tr = super::traces::run(env, &lp, &samples, super::KERNEL_CHECKED_TRACES, 10_000_000).map_err(|e| fail(e, steps))?;
    steps += tr.steps;
    super::meter::charge(steps);
    let ee = plan_early_exit(&lp, &tr, measure, fault).map_err(|e| fail(e, steps))?;
    // the helper: the loop with the stop test at the top, recursing into itself
    let orig = ext.item(fid).clone();
    let n = super::with_registry(|r| {
        let c = r.count.entry(key.def).or_insert(0);
        let n = *c;
        *c += 1;
        n
    });
    let suffix = if n > 0 { format!("{n}") } else { String::new() };
    let hname = format!("{}__early{suffix}", orig.name);
    let span = orig.span;
    let params: Vec<(LocalId, Ty)> = fd
        .params
        .iter()
        .filter(|p| !p.ghost)
        .map(|p| match &p.pat.kind {
            PatKind::Binding { local, .. } => Some((*local, p.ty.clone())),
            _ => None,
        })
        .collect::<Option<_>>()
        .ok_or_else(|| fail("a parameter pattern".into(), steps))?;
    let stop = stop_hir(&ee, &params, span).ok_or_else(|| fail("the stop test is not printable".into(), steps))?;
    let FnBody::Exec(body) = &fd.body else { return Err(fail("the loop has no exec body".into(), steps)) };
    let hid_next = ItemId(ext.items.len() as u32);
    let mut els = body.clone();
    crate::opt::multiversion::rename_calls(&mut els, &|i| (i == fid).then_some(hid_next));
    let (pl, pt) = params[ee.payload as usize].clone();
    let ret = els.ty.clone();
    let then = Expr::new(ExprKind::Block(Block { stmts: vec![], tail: Some(Box::new(Expr::new(ExprKind::Local(pl), pt, span))), span }), ret.clone(), span);
    let mut hf = fd.clone();
    hf.body = FnBody::Exec(Expr::new(ExprKind::If { cond: Box::new(stop), then: Box::new(then), els: Some(Box::new(els)) }, ret.clone(), span));
    hf.ensures = None;
    hf.specialize = false;
    hf.implements = None;
    hf.inline = None;
    let hid = crate::opt::push_elaborate(cx, ext, chain, eopts, &orig, hname.clone(), hf, false).map_err(|(why, _)| fail(format!("the helper `{hname}` did not elaborate: {why}"), steps))?;
    if hid != hid_next {
        crate::opt::pop_driven(cx, ext, hid);
        return Err(fail("the helper's item id moved".into(), steps));
    }
    let Some(hg) = cx.out.fn_globals.get(&hid).copied() else {
        crate::opt::pop_driven(cx, ext, hid);
        return Err(fail("the helper has no global".into(), steps));
    };
    let prefix = format!("{name}::early{suffix}");
    let lemmas = prove(&mut cx.out.env, key.def, hg, &lp, &ee, &prefix, fault, cx.opts.check_budget.max(400_000_000));
    let (fin_g, eq_g, s) = match lemmas {
        Ok(x) => x,
        Err(e) => {
            ext.items[hid.0 as usize].ghost = true;
            crate::opt::pop_driven(cx, ext, hid);
            return Err(fail(e, steps));
        }
    };
    steps += s;
    cx.set_aside_obligations(hid);
    // the entry idle-run skip, when the first iterations are idle runs of a
    // halving static (its lemmas first; without them, the plain entry)
    let skip = if fault { None } else { plan_entry_skip(&lp) };
    let chain_lemmas = match &skip {
        Some(sk) => {
            let w = sk.width;
            let lim = super::meter::cap(200_000_000);
            let mut b = Budget { steps: lim };
            let fams = (0..super::expr::bits(w)).try_for_each(|k| crate::auto::bitlib::ensure(&mut cx.out.env, crate::auto::bitlib::Family::LzRange, w, k, &mut b).map(|_| ()));
            super::meter::charge(lim - b.steps);
            match fams.map_err(|e| e.to_string()).and_then(|_| idle_chain(&mut cx.out.env, key, &lp, sk, &prefix, 100_000_000)) {
                Ok((c, s)) => {
                    steps += s;
                    Some(c)
                }
                Err(e) => {
                    if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                        eprintln!("[loopsum] no entry skip: {e}");
                    }
                    None
                }
            }
        }
        None => None,
    };
    let skip_ref = match (&skip, &chain_lemmas) {
        (Some(sk), Some(c)) => Some((sk, &c[..])),
        _ => None,
    };
    // the entry wrapper at the call's static arguments (with the skip, else plain)
    let (wid, wg, link, skipped) = match entry_wrapper(cx, ext, chain, eopts, key, &lp, &fd, &orig, hid, hg, eq_g, &suffix, skip_ref) {
        Ok((a, b, c)) => (a, b, c, skip_ref.is_some()),
        Err(e) if skip_ref.is_some() => {
            if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                eprintln!("[loopsum] the entry skip failed ({e}); the plain entry");
            }
            let (a, b, c) = entry_wrapper(cx, ext, chain, eopts, key, &lp, &fd, &orig, hid, hg, eq_g, &suffix, None).map_err(|e| fail(e, steps))?;
            (a, b, c, false)
        }
        Err(e) => return Err(fail(e, steps)),
    };
    let _ = wid;
    let describe = match &ee.stop {
        Stop::Cond(c) => format!("early exit{}: stop test `{}` (payload `{}`); helper {hname}; lemmas `{}` (stability), `{}`", if skipped { " with the entry idle-run skip" } else { "" }, c.text(&lp.params.iter().map(|p| super::invariant::sanitize(&p.name)).collect::<Vec<_>>(), None), lp.params[ee.payload as usize].name, cx.out.env.global_name(fin_g).map(|s| s.to_string()).unwrap_or_default(), cx.out.env.global_name(eq_g).map(|s| s.to_string()).unwrap_or_default()),
        Stop::PayloadSet { .. } => format!("early exit: stop test `payload set` (simulated fault); helper {hname}"),
    };
    Ok(LoopHelper { item: wid, global: wg, lemma: link, rung: crate::opt::Rung::EarlyExit, facts: Vec::new(), loop_facts: None, summary_lemma: cx.out.env.global_name(eq_g).map(|s| s.to_string()).unwrap_or_default(), describe, steps })
}

fn with_profile(name: &str) -> Vec<Vec<Option<u128>>> {
    super::with_registry(|r| r.config.profile.get(name).cloned().unwrap_or_default())
}

/// The entry wrapper `loop__early_entry(d̄) = loop__early(statics, d̄)`
/// (always inlined) and its link `Π d̄ h̄. Eq(R, entry d̄ h̄, loop(statics, d̄) h̄)`.
#[allow(clippy::too_many_arguments)]
fn entry_wrapper(
    cx: &mut crate::opt::Ctx<'_>,
    ext: &mut Crate,
    chain: &mut crate::elab::ProverChain,
    eopts: &crate::elab::Options,
    key: &LoopKey,
    lp: &Loop,
    fd: &FnDef,
    orig: &Item,
    hid: ItemId,
    hg: GlobalId,
    equiv: GlobalId,
    suffix: &str,
    skip: Option<(&EntrySkip, &[Option<GlobalId>])>,
) -> Result<(ItemId, GlobalId, GlobalId), String> {
    let dy = lp.dynamic();
    let mut smap: HashMap<LocalId, Expr> = HashMap::new();
    for (i, p) in fd.params.iter().enumerate() {
        if let Some(t) = &lp.statics[i]
            && let PatKind::Binding { local, .. } = &p.pat.kind
            && let Term::Lit { n: v, .. } = &**t
            && let Some(v) = num_traits::ToPrimitive::to_u128(v)
        {
            smap.insert(*local, Expr::new(ExprKind::Lit(Lit::Int(v)), p.ty.clone(), p.span));
        }
    }
    let mut wf = fd.clone();
    wf.params = dy.iter().map(|i| fd.params[*i as usize].clone()).collect();
    wf.requires = fd.requires.iter().map(|r| super::subst_requires(r, &smap)).collect::<Option<Vec<_>>>().ok_or("a requires over a non-integer static argument")?;
    wf.ensures = None;
    wf.decreases = None;
    wf.recursion = crate::hir::Recursion::None;
    wf.specialize = false;
    wf.implements = None;
    wf.inline = Some(Inline::Always);
    // the body: the helper applied to the statics and the dynamic parameters
    let (body, locals) = {
        let env = &cx.out.env;
        let tele = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
        let statics = super::statics_of(env, key, lp.params.len())?;
        let mut st = St::new(env, &Ctx::default(), 0);
        for i in &dy {
            let ty = lp.one.root.ctx.entries[*i as usize].ty.clone();
            st.push_raw(env, Rc::from(super::invariant::sanitize(&lp.params[*i as usize].name).as_str()), Rel::Rel, ty);
        }
        let names: Vec<String> = st.ctx.entries.iter().map(|x| x.name.to_string()).collect();
        let ns: Vec<&str> = names.iter().map(|x| x.as_str()).collect();
        let mut args = Vec::new();
        for (i, (_, rel, _)) in tele.binders.iter().enumerate() {
            args.push(match rel {
                Rel::Rel => (Rel::Rel, match (&statics[i], skip) {
                    // the entry skip: a static parameter at the first non-idle iteration
                    (Some(t), Some((sk, _))) => match sk.forms.iter().find(|(p, _)| *p as usize == i) {
                        Some((_, form)) => {
                            let vname = &names[dy.iter().position(|d| *d == sk.v).ok_or("the skip's variable")?];
                            env.parse_term(&ns, &EntrySkip::form_text(form, &sk.j_text(vname))).map_err(|e| format!("the entry's jump: {e}"))?
                        }
                        // static at the call, unchanged on the idle run
                        None => t.clone(),
                    },
                    (Some(t), None) => t.clone(),
                    (None, _) => st.var(dy.iter().position(|d| *d as usize == i).ok_or("a dynamic parameter")? as u32),
                }),
                Rel::Irr => (Rel::Irr, Rc::new(Term::Erased)),
            });
        }
        let t = apps(mk::global(hg), args);
        let op = |g: GlobalId| g == hg;
        let v = env.eval_opaque(&env.ctx_venv(&st.ctx), Lvl(st.depth()), &t, &op, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("the entry's value: {e:?}"))?;
        let node = crate::opt::drive::tree::Node { depth: st.depth() + wf.requires.len() as u32, steps: vec![], kind: crate::opt::drive::tree::NodeKind::Leaf(v) };
        let maps = crate::opt::residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts)?;
        let ev = crate::opt::drive::step::Eval { env, opaque: &op };
        let r = crate::opt::residual::tree::build_tree(env, &maps, ext, &wf, &node, &ev, &std::collections::BTreeMap::new(), &std::collections::BTreeMap::new(), 1_000, orig.span, None).map_err(|e| format!("the entry is not printable: {e}"))?;
        (r.body, r.locals)
    };
    wf.body = FnBody::Exec(body);
    wf.locals = locals;
    let wname = format!("{}__early_entry{suffix}", orig.name);
    let wid = crate::opt::push_elaborate(cx, ext, chain, eopts, orig, wname.clone(), wf, false).map_err(|(why, _)| format!("the entry `{wname}` did not elaborate: {why}"))?;
    let Some(wg) = cx.out.fn_globals.get(&wid).copied() else {
        crate::opt::pop_driven(cx, ext, wid);
        return Err("the entry has no global".into());
    };
    let link = match skip {
        Some((sk, chain)) => entry_link_skip(&mut cx.out.env, key, lp, wg, hg, equiv, sk, chain),
        None => entry_link(&mut cx.out.env, key, lp, wg, hg, equiv),
    };
    match link {
        Ok(l) => {
            cx.set_aside_obligations(wid);
            let _ = hid;
            Ok((wid, wg, l))
        }
        Err(e) => {
            ext.items[wid.0 as usize].ghost = true;
            crate::opt::pop_driven(cx, ext, wid);
            Err(format!("the entry's link: {e}"))
        }
    }
}

/// `Π d̄ h̄. Eq(R, entry d̄ h̄, loop(statics, d̄) h̄) := trans(Delta(entry), equiv(statics, d̄, h̄))`.
fn entry_link(env: &mut Env, key: &LoopKey, lp: &Loop, wg: GlobalId, hg: GlobalId, equiv: GlobalId) -> Result<GlobalId, String> {
    let tele_w = crate::opt::symex::telescope(env, wg).ok_or("the entry has no telescope")?;
    let tele_l = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let n = tele_w.binders.len();
    let np = tele_w.binders.iter().filter(|(_, r, _)| *r == Rel::Rel).count();
    let var = |b: usize| mk::var((n - 1 - b) as u32);
    let dy = lp.dynamic();
    let statics = super::statics_of(env, key, lp.params.len())?;
    let mut largs = Vec::new();
    let mut ri = 0usize;
    for (i, (_, rel, _)) in tele_l.binders.iter().enumerate() {
        match rel {
            Rel::Rel => largs.push((Rel::Rel, match &statics[i] {
                Some(t) => t.clone(),
                None => var(dy.iter().position(|d| *d as usize == i).ok_or("a dynamic parameter")?),
            })),
            Rel::Irr => {
                largs.push((Rel::Irr, var(np + ri)));
                ri += 1;
            }
        }
    }
    if np + ri != n {
        return Err("the entry's requires are not the loop's".into());
    }
    let w_args: Vec<(Rel, Tm)> = tele_w.binders.iter().enumerate().map(|(b, (_, r, _))| (*r, var(b))).collect();
    let w_app = apps(mk::global(wg), w_args.clone());
    let h_app = apps(mk::global(hg), largs.clone());
    let l_app = apps(mk::global(key.def), largs.clone());
    let ret = tele_w.ret.clone();
    let delta = Rc::new(Term::Delta { def: wg, args: w_args.iter().map(|(_, t)| t.clone()).collect() });
    let inst = apps(mk::global(equiv), largs.clone());
    let trans = env.lookup_global("eq::trans").ok_or("eq::trans")?;
    let mut body = apps(mk::global(trans), [(Rel::Rel, ret.clone()), (Rel::Rel, w_app.clone()), (Rel::Rel, h_app), (Rel::Rel, l_app.clone()), (Rel::Rel, delta), (Rel::Rel, inst)]);
    let mut ty = mk::eq(ret, w_app, l_app);
    for (nm, rel, dom) in tele_w.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
        body = mk::lam(nm, *rel, dom.clone(), body);
    }
    let name = format!("{}::equiv", env.global_name(wg).map(|s| s.to_string()).unwrap_or_default());
    let (g, _) = super::lemmas::add_lemma(env, &name, ty, body, 400_000_000)?;
    Ok(g)
}

// ---------------------------------------------------------------------------
// The entry idle-run skip.
// ---------------------------------------------------------------------------

/// A static parameter's trajectory `x_j` over the iterations.
#[derive(Clone, Debug)]
pub enum Form {
    Const(Width, u128),
    /// `x_0 − j`.
    Down(Width, u128),
    /// `x_0 >> j`.
    Shr(Width, u128),
}

/// The entry idle-run skip (design §7.6 rung 2, at the call's entry): the
/// loop's first iterations are idle — only its static parameters change —
/// while `v < w_j`, with `v` a dynamic parameter and `w_j = 2^(e − j)` a
/// static halving power of two. The entry jumps to the first non-idle
/// iteration `J(v) = sat_sub(lz(v), B − 1 − e)` (`B` the width) and runs
/// the early-exit helper from there. Proven by the chain of idle-run lemmas
/// `<loop>::idle_j : … loop(s_0) = loop(s_j)` (one unfolding each) and a
/// case split of the entry lemma on `v`'s magnitude, where each arm pins
/// `lz(v)` with the bit library's `lz_range` and closes by `idle_{J}`.
#[derive(Clone, Debug)]
pub struct EntrySkip {
    pub v: u32,
    pub w: u32,
    pub width: Width,
    pub e: u32,
    pub k: u32,
    /// Every static parameter's trajectory.
    pub forms: Vec<(u32, Form)>,
}

fn keeps_param(s: &SVal, i: u32) -> bool {
    match s {
        SVal::Param(p) => *p == i,
        SVal::Ce(e) => matches!(&**e, CE::Var(p, _) if *p == i),
        _ => false,
    }
}

/// Plans the entry skip (see [`EntrySkip`]).
pub fn plan_entry_skip(lp: &Loop) -> Option<EntrySkip> {
    let n = lp.params.len() as u32;
    let k = lp.k;
    let seq = &lp.static_seq;
    let is_static = |i: u32| seq.first().and_then(|s| s.get(i as usize)).is_some_and(|x| x.is_some());
    let lit_at = |j: usize, i: u32| -> Option<u128> { seq.get(j)?.get(i as usize)?.as_ref()?.num() };
    for c in &lp.cont {
        let mut vw: Option<(u32, u32, Width)> = None;
        let mut ok = true;
        for (g, b) in &c.guards {
            let mut vs = Vec::new();
            g.vars(&mut vs);
            if vs.iter().all(|x| is_static(*x)) {
                continue;
            }
            match (&**g, b) {
                (CE::Op(PrimOp::Lt(wd), a), true) if vw.is_none() => match (&*a[0], &*a[1]) {
                    (CE::Var(x, _), CE::Var(y, _)) if !is_static(*x) && is_static(*y) => vw = Some((*x, *y, *wd)),
                    _ => ok = false,
                },
                _ => ok = false,
            }
        }
        let Some((v, w, width)) = vw else { continue };
        if !ok || !(0..n).all(|i| is_static(i) || keeps_param(&c.next[i as usize], i)) {
            continue;
        }
        // the path's static guards hold at every iteration before the exhaustion
        let static_ok = (0..k as usize).all(|j| {
            let nums: Vec<u128> = (0..n).map(|i| lit_at(j, i).unwrap_or(0)).collect();
            c.guards.iter().all(|(g, b)| {
                let mut vs = Vec::new();
                g.vars(&mut vs);
                !vs.iter().all(|x| is_static(*x)) || g.eval(&nums, None).and_then(|x| x.as_bool()) == Some(*b)
            })
        });
        if !static_ok {
            continue;
        }
        // w_j = 2^(e − j) = w_0 >> j at every iteration
        let Some(w0) = lit_at(0, w) else { continue };
        if w0 == 0 || !w0.is_power_of_two() {
            continue;
        }
        let e = w0.trailing_zeros();
        let bits = super::expr::bits(width);
        if !(0..=k as usize).all(|j| lit_at(j, w) == Some(if (j as u32) < 128 { w0 >> j } else { 0 })) || e + 1 > k || e + 1 >= bits {
            continue;
        }
        // every static parameter's trajectory
        let mut forms = Vec::new();
        let mut fit = true;
        for i in 0..n {
            if !is_static(i) {
                continue;
            }
            let Some(pw) = lp.params[i as usize].width else {
                fit = false;
                break;
            };
            let xs: Vec<u128> = match (0..=k as usize).map(|j| lit_at(j, i)).collect::<Option<Vec<_>>>() {
                Some(x) => x,
                None => {
                    fit = false;
                    break;
                }
            };
            let x0 = xs[0];
            let f = if xs.iter().all(|x| *x == x0) {
                Form::Const(pw, x0)
            } else if x0 >= k as u128 && xs.iter().enumerate().all(|(j, x)| *x == x0 - j as u128) {
                Form::Down(pw, x0)
            } else if xs.iter().enumerate().all(|(j, x)| *x == if j < 128 { x0 >> j } else { 0 }) {
                Form::Shr(pw, x0)
            } else {
                fit = false;
                break;
            };
            forms.push((i, f));
        }
        if fit {
            return Some(EntrySkip { v, w, width, e, k, forms });
        }
    }
    None
}

impl EntrySkip {
    /// `J(v)` as core text over the dynamic names.
    fn j_text(&self, v: &str) -> String {
        let ws = sandblaster_kernel::prim::width_suffix(self.width);
        format!("#sat_sub_u32(#leading_zeros_{ws}({v}), {}u32)", super::expr::bits(self.width) - 1 - self.e)
    }

    /// `J` at a given `lz(v)`.
    fn j_at(&self, lz: u32) -> u32 {
        lz.saturating_sub(super::expr::bits(self.width) - 1 - self.e)
    }

    /// A static parameter's value at iteration `j` (core text; `j` a u32 term).
    fn form_text(f: &Form, j: &str) -> String {
        match f {
            Form::Const(w, x) => super::expr::lit_text(*w, *x),
            Form::Down(w, x0) => {
                let ws = sandblaster_kernel::prim::width_suffix(*w);
                let jw = if *w == Width::U32 { j.to_string() } else { format!("#cast_u32_{ws}({j})") };
                format!("#wsub_{ws}({}, {jw})", super::expr::lit_text(*w, *x0))
            }
            Form::Shr(w, x0) => format!("#wshr_{}({}, {j})", sandblaster_kernel::prim::width_suffix(*w), super::expr::lit_text(*w, *x0)),
        }
    }
}

/// `subst_n` of the proof builder (a telescope binder's type at arguments).
fn inst(body: &Tm, args: &[Tm]) -> Tm {
    crate::opt::proof::steps::subst_n(body, args)
}

/// Builds the idle-run lemmas `idle_1 … idle_K` (see [`EntrySkip`]) over the
/// entry's telescope (the dynamic parameters and the loop's requires at
/// the statics): `idle_j : Π d̄ h̄ h̄_j (.hv : Eq(Bool, lt(v, w_{j−1}), true)).
/// Eq(R, loop(s_0) h̄, loop(s_j) h̄_j)`. Returns them by `j` (index 0 unused).
fn idle_chain(env: &mut Env, key: &LoopKey, lp: &Loop, sk: &EntrySkip, prefix: &str, budget: u64) -> Result<(Vec<Option<GlobalId>>, u64), String> {
    let tele = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let np = lp.params.len();
    let nr = tele.binders.len() - np;
    let dy = lp.dynamic();
    let nd = dy.len();
    let statics = super::statics_of(env, key, np)?;
    let bi = env.bool_ind();
    let lit_at = |j: usize, i: usize| -> Option<Tm> {
        let c = lp.static_seq.get(j)?.get(i)?.as_ref()?;
        let w = lp.params[i].width?;
        Some(mk::lit(w, c.num()?))
    };
    // the loop's arguments at iteration j, at depth `d`, with the requires
    // binders starting at level `req_lvl`
    let args_at = |j: usize, d: u32, req_lvl: u32| -> Option<Vec<Tm>> {
        // (a prefix only when `d` does not reach every binder: the caller
        // takes the arguments before the binder it types)
        let mut out = Vec::new();
        for i in 0..np {
            let t = match &statics[i] {
                Some(_) => lit_at(j, i).or_else(|| statics[i].clone())?,
                None => match d.checked_sub(1 + dy.iter().position(|x| *x as usize == i)? as u32) {
                    Some(ix) => mk::var(ix),
                    None => return Some(out),
                },
            };
            out.push(t);
        }
        for r in 0..nr {
            match d.checked_sub(1 + req_lvl + r as u32) {
                Some(ix) => out.push(mk::var(ix)),
                None => return Some(out),
            }
        }
        Some(out)
    };
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let mut out: Vec<Option<GlobalId>> = vec![None];
    let mut steps = 0u64;
    let rels: Vec<Rel> = tele.binders.iter().map(|b| b.1).collect();
    for j in 1..=sk.k as usize {
        // the statement: d̄ (nd), h̄ (nr, at s_0), h̄_j (nr, at s_j), hv
        let mut binders: Vec<(String, Rel, Tm)> = Vec::new();
        for (b, i) in dy.iter().enumerate() {
            let dom = inst(&tele.binders[*i as usize].2, &args_at(0, b as u32, nd as u32).ok_or("arguments")?[..*i as usize]);
            binders.push((super::invariant::sanitize(&lp.params[*i as usize].name), Rel::Rel, dom));
        }
        for (jj, base) in [(0usize, nd as u32), (j, (nd + nr) as u32)] {
            for r in 0..nr {
                let d = base + r as u32;
                let a = args_at(jj, d, base).ok_or("arguments")?;
                binders.push((format!("r{jj}_{r}"), Rel::Irr, inst(&tele.binders[np + r].2, &a[..np + r])));
            }
        }
        let d_hv = (nd + 2 * nr) as u32;
        let vpos = dy.iter().position(|x| *x == sk.v).ok_or("the skip's variable")? as u32;
        let w_prev = lit_at(j - 1, sk.w as usize).ok_or("the width")?;
        let hv_dom = mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(sk.width), args: vec![mk::var(d_hv - 1 - vpos), w_prev], proofs: vec![] }), mk::bool_lit(bi, true));
        binders.push(("hv".into(), Rel::Irr, hv_dom));
        let d_goal = d_hv + 1;
        let a0 = args_at(0, d_goal, nd as u32).ok_or("arguments")?;
        let aj = args_at(j, d_goal, (nd + nr) as u32).ok_or("arguments")?;
        let ret = inst(&tele.ret, &a0);
        let l0 = apps(mk::global(key.def), rels.iter().copied().zip(a0.iter().cloned()));
        let lj = apps(mk::global(key.def), rels.iter().copied().zip(aj.iter().cloned()));
        let mut ty = mk::eq(ret, l0, lj);
        for (nm, rel, dom) in binders.iter().rev() {
            ty = mk::pi(nm, *rel, dom.clone(), ty);
        }
        let name = format!("{prefix}::idle{j}");
        // the proof: idle_{j−1} (or refl) then one unfolding at s_{j−1}
        let lim = super::meter::cap(50_000_000);
        let mut sb = Budget { steps: lim };
        let body = {
            let envr: &Env = env;
            let mut db = crate::auto::lemmas::LemmaDb::default();
            db.refresh(envr);
            let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
            let mut st = St::new(envr, &Ctx::default(), 32);
            let goal = super::lemmas::open(&mut e, &mut st, &ty)?;
            let (rty, _, _) = as_eq(&goal).ok_or("idle statement")?;
            let r_tm = st.quote(envr, rty);
            let d = st.depth();
            let a0 = args_at(0, d, nd as u32).ok_or("arguments")?;
            let aj = args_at(j, d, (nd + nr) as u32).ok_or("arguments")?;
            let l0 = apps(mk::global(key.def), rels.iter().copied().zip(a0.iter().cloned()));
            let lj = apps(mk::global(key.def), rels.iter().copied().zip(aj.iter().cloned()));
            // the requires at s_{j−1} (obligations)
            let mut prev_args: Vec<Tm> = Vec::new();
            for i in 0..np {
                prev_args.push(match &statics[i] {
                    Some(_) => lit_at(j - 1, i).or_else(|| statics[i].clone()).ok_or("a static")?,
                    None => mk::var(d - 1 - dy.iter().position(|x| *x as usize == i).ok_or("dyn")? as u32),
                });
            }
            let mut pf = Pf { f: key.def, this: key.def, ee: &EarlyExit { payload: 0, stop: Stop::Cond(super::expr::lit(Width::U32, 0)), measure: 0 }, stmt: ty.clone(), m_lvl: 0, m_w: Width::U32, final_lemma: None, stop_full: mk::bool_lit(bi, true), arity: 0, trust: false, failure: None };
            let mut req_prev: Vec<Tm> = Vec::new();
            for r in 0..nr {
                let mut a = prev_args.clone();
                a.extend(req_prev.iter().cloned());
                let dom = inst(&tele.binders[np + r].2, &a);
                let dv = eval_in(envr, &st.ctx, &dom)?;
                let p = pf.obligation(&mut e, &st, &dv, "a requires on the idle run").ok_or_else(|| format!("idle_{j}: {}", pf.failure.clone().unwrap_or_default()))?;
                req_prev.push(p);
            }
            let mut full_prev = prev_args.clone();
            full_prev.extend(req_prev.iter().cloned());
            let l_prev = apps(mk::global(key.def), rels.iter().copied().zip(full_prev.iter().cloned()));
            // step: loop(s_{j−1}) = loop(s_j) by one unfolding (the idle arm)
            let fbody = apps(envr.global_body(key.def).ok_or("the loop has no body")?, rels.iter().copied().zip(full_prev.iter().cloned()));
            let g_step = eval_in(envr, &st.ctx, &mk::eq(r_tm.clone(), fbody.clone(), lj.clone()))?;
            // (the idle guard at j − 1 is .hv)
            let p_step = pf.step_idle(&mut e, &mut st, &g_step, 8).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("idle_{j}: the idle step: {}", pf.failure.clone().unwrap_or_default()))?;
            let trans = envr.lookup_global("eq::trans").ok_or("eq::trans")?;
            let step = apps(mk::global(trans), [(Rel::Rel, r_tm.clone()), (Rel::Rel, l_prev.clone()), (Rel::Rel, fbody.clone()), (Rel::Rel, lj.clone()), (Rel::Rel, Rc::new(Term::Delta { def: key.def, args: full_prev.clone() })), (Rel::Rel, p_step)]);
            let p = if j == 1 {
                step
            } else {
                // idle_{j−1} d̄ h̄ (requires at s_{j−1}) (.hv at j − 2)
                let prev = out[j - 1].ok_or("the previous idle lemma")?;
                let w_pp = lit_at(j - 2, sk.w as usize).ok_or("the width")?;
                let hv_goal = mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(sk.width), args: vec![mk::var(d - 1 - vpos), w_pp], proofs: vec![] }), mk::bool_lit(bi, true));
                let hvv = eval_in(envr, &st.ctx, &hv_goal)?;
                let hv = pf.obligation(&mut e, &st, &hvv, "the idle guard").ok_or("the idle guard at the previous iteration")?;
                let mut pargs: Vec<(Rel, Tm)> = (0..nd).map(|b| (Rel::Rel, mk::var(d - 1 - b as u32))).collect();
                for r in 0..nr {
                    pargs.push((Rel::Irr, mk::var(d - 1 - (nd + r) as u32)));
                }
                for p in &req_prev {
                    pargs.push((Rel::Irr, p.clone()));
                }
                pargs.push((Rel::Irr, hv));
                let ih = apps(mk::global(prev), pargs);
                apps(mk::global(trans), [(Rel::Rel, r_tm), (Rel::Rel, l0), (Rel::Rel, l_prev), (Rel::Rel, lj), (Rel::Rel, ih), (Rel::Rel, step)])
            };
            st.finish(p)
        };
        super::meter::charge(lim - sb.steps);
        let (g, s) = super::lemmas::add_lemma(env, &name, ty, body, budget)?;
        steps += s;
        out.push(Some(g));
    }
    Ok((out, steps))
}

impl Pf<'_> {
    /// One idle step: the unfolded body split on its tests down to the
    /// recursive call (conversion with the next state), the other arms
    /// infeasible.
    fn step_idle(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if let Some(p) = super::lemmas::trivial(env, &st.ctx, goal, &mut Budget { steps: 5_000_000 }) {
            return Ok(Some(p));
        }
        let Some((_, lhs, _)) = as_eq(goal) else { return Ok(None) };
        let lhs = lhs.clone();
        if let Some((c, ind, params)) = head_match(&lhs)
            && depth > 0
        {
            let d = st.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.step_idle(e2, a2, &tk, depth - 1) };
            return e.case_split_with(st, &c, ind, &params, goal, true, d, &mut arm_fn);
        }
        if let Some(p) = self.absurd(e, st, goal) {
            return Ok(Some(p));
        }
        self.note_failure(env, st, "an idle step that is not the next iteration", goal);
        Ok(None)
    }
}

/// The skip entry's link `Π d̄ h̄. Eq(R, entry d̄ h̄, loop(s_0) h̄)`:
/// `Delta(entry)`, `equiv` at `s_J`, and the idle run `loop(s_0) = loop(s_J)`
/// by a case split on the magnitude of `v` (each arm pins `lz(v)`, making
/// `J` a literal, and closes by `idle_J`).
#[allow(clippy::too_many_arguments)]
fn entry_link_skip(env: &mut Env, key: &LoopKey, lp: &Loop, wg: GlobalId, hg: GlobalId, equiv: GlobalId, sk: &EntrySkip, chain: &[Option<GlobalId>]) -> Result<GlobalId, String> {
    let tele_w = crate::opt::symex::telescope(env, wg).ok_or("the entry has no telescope")?;
    let tele_l = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let np = lp.params.len();
    let nr = tele_l.binders.len() - np;
    let dy = lp.dynamic();
    let nd = dy.len();
    if tele_w.binders.len() != nd + nr {
        return Err("the entry's requires are not the loop's".into());
    }
    let statics = super::statics_of(env, key, np)?;
    let rels: Vec<Rel> = tele_l.binders.iter().map(|b| b.1).collect();
    let bits = super::expr::bits(sk.width);
    let aux_name = format!("{}::idle_at", env.global_name(wg).map(|s| s.to_string()).unwrap_or_default());
    let aux = idle_at(env, key, lp, sk, &tele_w, &tele_l, &aux_name)?;
    let mut ty = mk::eq(tele_w.ret.clone(), apps(mk::global(wg), tele_w.binders.iter().enumerate().map(|(b, (_, r, _))| (*r, mk::var((nd + nr - 1 - b) as u32)))), {
        let d = (nd + nr) as u32;
        let mut a: Vec<Tm> = Vec::new();
        for i in 0..np {
            a.push(match &statics[i] {
                Some(t) => t.clone(),
                None => mk::var(d - 1 - dy.iter().position(|x| *x as usize == i).ok_or("dyn")? as u32),
            });
        }
        for r in 0..nr {
            a.push(mk::var(d - 1 - (nd + r) as u32));
        }
        apps(mk::global(key.def), rels.iter().copied().zip(a))
    });
    for (nm, rel, dom) in tele_w.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let lim = super::meter::cap(200_000_000);
    let mut sb = Budget { steps: lim };
    let body = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 80);
        let goal = super::lemmas::open(&mut e, &mut st, &ty)?;
        let (rty, lhs, rhs) = as_eq(&goal).ok_or("the entry's statement")?;
        let (rty, lhs, rhs) = (rty.clone(), lhs.clone(), rhs.clone());
        let vpos = dy.iter().position(|x| *x == sk.v).ok_or("the skip's variable")?;
        // the bit library's `lz(v) ≤ w` (the jump `J` stays within the trajectory)
        if let Some(lg) = envr.lookup_global(&format!("bits::leading_zeros_le_{}", sandblaster_kernel::prim::width_suffix(sk.width))) {
            let h = apps(mk::global(lg), [(Rel::Rel, st.var(vpos as u32))]);
            if let Ok(hty) = envr.infer(&st.ctx, &h, &mut Budget { steps: 1_000_000 }) {
                st.push_fact(envr, hty, h, crate::auto::state::Origin::Hint);
            }
        }
        let (r_tm, w_tm, l0_tm) = (st.quote(envr, &rty), st.quote(envr, &lhs), st.quote(envr, &rhs));
        let d = st.depth();
        let names: Vec<String> = st.ctx.entries.iter().map(|x| x.name.to_string()).collect();
        let ns: Vec<&str> = names.iter().map(|x| x.as_str()).collect();
        let vname = names[vpos].clone();
        let jt = sk.j_text(&vname);
        // s_J and the requires there (obligations)
        let mut pf = Pf { f: key.def, this: key.def, ee: &EarlyExit { payload: 0, stop: Stop::Cond(super::expr::lit(Width::U32, 0)), measure: 0 }, stmt: ty.clone(), m_lvl: 0, m_w: Width::U32, final_lemma: None, stop_full: mk::bool_lit(envr.bool_ind(), true), arity: 0, trust: false, failure: None };
        let mut sj: Vec<Tm> = Vec::new();
        for i in 0..np {
            sj.push(match &statics[i] {
                Some(t) => match sk.forms.iter().find(|(p, _)| *p as usize == i) {
                    Some((_, form)) => envr.parse_term(&ns, &EntrySkip::form_text(form, &jt)).map_err(|e| format!("s_J: {e}"))?,
                    None => t.clone(),
                },
                None => mk::var(d - 1 - dy.iter().position(|x| *x as usize == i).ok_or("dyn")? as u32),
            });
        }
        let req_at = |pf: &mut Pf<'_>, e: &mut Engine<'_>, st: &St, a: &[Tm]| -> Result<Vec<Tm>, String> {
            let mut out: Vec<Tm> = Vec::new();
            for r in 0..nr {
                let mut full = a.to_vec();
                full.extend(out.iter().cloned());
                let dom = inst(&tele_l.binders[np + r].2, &full);
                let dv = eval_in(envr, &st.ctx, &dom)?;
                out.push(pf.obligation(e, st, &dv, "a requires at the jump").ok_or_else(|| format!("the requires at the jump: {}", pf.failure.clone().unwrap_or_default()))?);
            }
            Ok(out)
        };
        let hj = req_at(&mut pf, &mut e, &st, &sj)?;
        let mut sj_full = sj.clone();
        sj_full.extend(hj.iter().cloned());
        let h_sj = apps(mk::global(hg), rels.iter().copied().zip(sj_full.iter().cloned()));
        let l_sj = apps(mk::global(key.def), rels.iter().copied().zip(sj_full.iter().cloned()));
        let equiv_inst = apps(mk::global(equiv), rels.iter().copied().zip(sj_full.iter().cloned()));
        // the idle run, by v's magnitude
        // aux(d̄, h̄, J): the loop at s_J with proofs inside its definition, so
        // the magnitude split can rewrite `J` in the goal
        let j_tm = envr.parse_term(&ns, &jt).map_err(|e| format!("J: {e}"))?;
        let mut aux_args: Vec<(Rel, Tm)> = (0..(nd + nr) as u32).map(|b| (if (b as usize) < nd { Rel::Rel } else { Rel::Irr }, st.var(b))).collect();
        aux_args.push((Rel::Rel, j_tm.clone()));
        let aux_j = apps(mk::global(aux), aux_args.clone());
        // loop(s_J) hJ = aux(d̄, h̄, J): unfold aux, split on `J ≤ K` (its false
        // arm is infeasible)
        let aux_body = apps(envr.global_body(aux).ok_or("idle_at's body")?, aux_args.clone());
        let g_aux = eval_in(envr, &st.ctx, &mk::eq(r_tm.clone(), l_sj.clone(), aux_body.clone()))?;
        let p_aux = {
            let bi = envr.bool_ind();
            let test = Rc::new(Term::Prim { op: PrimOp::Le(Width::U32), args: vec![j_tm.clone(), mk::lit(Width::U32, sk.k)], proofs: vec![] });
            // `J ≤ K` (an obligation: `lz(v) ≤ w` and a case split on the
            // saturation), rewritten in the unfolded aux, which then reduces
            let g_le = eval_in(envr, &st.ctx, &mk::eq(mk::bool_ty(bi), test.clone(), mk::bool_lit(bi, true)))?;
            let p_le = pf.obligation(&mut e, &st, &g_le, "J ≤ K").ok_or_else(|| format!("J ≤ K: {}", pf.failure.clone().unwrap_or_default()))?;
            // split on `J ≤ K` (the engine's motive transports the proofs
            // that mention it): the true arm reduces, the false arm clashes
            // with `J ≤ K`
            let tv = eval_in(envr, &st.ctx, &test)?;
            let (d_st, dl) = (st.depth(), st.depth_left);
            let p_body = {
                let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
                    if k == 1 {
                        return Ok(super::lemmas::trivial(e2.env, &a2.ctx, &tk, &mut Budget { steps: 50_000_000 }));
                    }
                    let sh = (a2.depth() - d_st) as i64;
                    let c_tm = crate::auto::util::shift(&test, sh);
                    let e_var = a2.var(a2.depth() - 1);
                    let clash = e2.bool_clash(&c_tm, &crate::auto::util::shift(&p_le, sh), &e_var);
                    Ok(Some(e2.absurd(a2, &tk, clash)))
                };
                e.case_split_with(&st, &tv, bi, &[], &g_aux, true, dl, &mut arm_fn).map_err(|s| format!("{s:?}"))?.ok_or("loop(s_J) = aux(J)")?
            };
            let sym = envr.lookup_global("eq::sym").ok_or("eq::sym")?;
            let trans = envr.lookup_global("eq::trans").ok_or("eq::trans")?;
            let delta = Rc::new(Term::Delta { def: aux, args: aux_args.iter().map(|(_, t)| t.clone()).collect() });
            let back = apps(mk::global(sym), [(Rel::Rel, r_tm.clone()), (Rel::Rel, aux_j.clone()), (Rel::Rel, aux_body.clone()), (Rel::Rel, delta)]);
            apps(mk::global(trans), [(Rel::Rel, r_tm.clone()), (Rel::Rel, l_sj.clone()), (Rel::Rel, aux_body.clone()), (Rel::Rel, aux_j.clone()), (Rel::Rel, p_body), (Rel::Rel, back)])
        };
        let g_ir = eval_in(envr, &st.ctx, &mk::eq(r_tm.clone(), l0_tm.clone(), aux_j.clone()))?;
        let v_tm = st.var(vpos as u32);
        let ws = sandblaster_kernel::prim::width_suffix(sk.width);
        let lz_tm = envr.parse_term(&ns, &format!("#leading_zeros_{ws}({vname})")).map_err(|e| format!("{e}"))?;
        let mut mc = MagCtx { key, lp, sk, chain, statics: &statics, nd, nr, np, rels: &rels, vpos, lz_tm, aux, lz_depth: d, bits };
        let p_ir = mc.mag(&mut pf, &mut e, &mut st, &g_ir, 0, &v_tm).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("the idle run: {}", pf.failure.clone().unwrap_or_default()))?;
        let trans = envr.lookup_global("eq::trans").ok_or("eq::trans")?;
        let sym = envr.lookup_global("eq::sym").ok_or("eq::sym")?;
        let w_args: Vec<Tm> = (0..(nd + nr) as u32).map(|b| st.var(b)).collect();
        let delta = Rc::new(Term::Delta { def: wg, args: w_args });
        let back = apps(mk::global(sym), [(Rel::Rel, r_tm.clone()), (Rel::Rel, l0_tm.clone()), (Rel::Rel, aux_j.clone()), (Rel::Rel, p_ir)]);
        let via_aux = apps(mk::global(trans), [(Rel::Rel, r_tm.clone()), (Rel::Rel, l_sj.clone()), (Rel::Rel, aux_j), (Rel::Rel, l0_tm.clone()), (Rel::Rel, p_aux), (Rel::Rel, back)]);
        let tail = apps(mk::global(trans), [(Rel::Rel, r_tm.clone()), (Rel::Rel, h_sj.clone()), (Rel::Rel, l_sj), (Rel::Rel, l0_tm.clone()), (Rel::Rel, equiv_inst), (Rel::Rel, via_aux)]);
        let p = apps(mk::global(trans), [(Rel::Rel, r_tm), (Rel::Rel, w_tm), (Rel::Rel, h_sj), (Rel::Rel, l0_tm), (Rel::Rel, delta), (Rel::Rel, tail)]);
        st.finish(p)
    };
    super::meter::charge(lim - sb.steps);
    let name = format!("{}::equiv", env.global_name(wg).map(|s| s.to_string()).unwrap_or_default());
    let (g, _) = super::lemmas::add_lemma(env, &name, ty, body, 400_000_000)?;
    Ok(g)
}

/// The magnitude case split of [`entry_link_skip`].
struct MagCtx<'a> {
    key: &'a LoopKey,
    lp: &'a Loop,
    sk: &'a EntrySkip,
    chain: &'a [Option<GlobalId>],
    statics: &'a [Option<Tm>],
    nd: usize,
    nr: usize,
    np: usize,
    rels: &'a [Rel],
    vpos: usize,
    /// `lz(v)` at depth `lz_depth`.
    lz_tm: Tm,
    /// `idle_at` (opaque: unfolded by `Delta` at a literal iteration).
    aux: GlobalId,
    lz_depth: u32,
    bits: u32,
}

impl MagCtx<'_> {
    /// `lz(v)` at the depth of `st`.
    fn lz_at(&self, st: &St) -> Tm {
        crate::auto::util::shift(&self.lz_tm, (st.depth() - self.lz_depth) as i64)
    }
}

impl MagCtx<'_> {
    /// Arm `c`: `v < 2^c` is split (`c = 0`: `v = 0`); its true arm pins
    /// `lz(v)` and closes, its false arm is arm `c + 1`.
    fn mag(&mut self, pf: &mut Pf<'_>, e: &mut Engine<'_>, st: &mut St, goal: &V, c: u32, v_tm: &Tm) -> R<Option<Tm>> {
        let env = e.env;
        let bi = env.bool_ind();
        let w = self.sk.width;
        let d0 = st.depth();
        let sh = |t: &Tm, st: &St| crate::auto::util::shift(t, (st.depth() - d0) as i64);
        if c == self.bits {
            // v ≥ 2^(B−1): lz(v) = 0
            return Ok(self.pin(pf, e, st, goal, self.bits - 1, v_tm));
        }
        let test = if c == 0 {
            Rc::new(Term::Prim { op: PrimOp::Eq(w), args: vec![v_tm.clone(), mk::lit(w, 0u32)], proofs: vec![] })
        } else {
            Rc::new(Term::Prim { op: PrimOp::Lt(w), args: vec![v_tm.clone(), mk::lit(w, 1u128 << c)], proofs: vec![] })
        };
        let Ok(tv) = eval_in(env, &st.ctx, &test) else { return Ok(None) };
        let d = st.depth_left;
        let v0 = v_tm.clone();
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            let v2 = sh(&v0, a2);
            if k == 0 {
                return self.mag(pf, e2, a2, &tk, c + 1, &v2);
            }
            if c == 0 {
                // v = 0: lz(v) = lz(0) by congruence
                let env = e2.env;
                let wt = mk::int_ty(w);
                let Ok(g) = eval_in(env, &a2.ctx, &mk::eq(wt.clone(), v2.clone(), mk::lit(w, 0u32))) else { return Ok(None) };
                let Some(p0) = pf.obligation(e2, a2, &g, "v = 0") else { return Ok(None) };
                let (Some(cong), Some(sym)) = (env.lookup_global("eq::cong"), env.lookup_global("eq::sym")) else { return Ok(None) };
                let f = mk::lam("y", Rel::Rel, wt.clone(), Rc::new(Term::Prim { op: PrimOp::LeadingZeros(w), args: vec![mk::var(0)], proofs: vec![] }));
                let lz_v = self.lz_at(a2);
                let p_lz = apps(mk::global(cong), [(Rel::Rel, wt.clone()), (Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, f), (Rel::Rel, v2.clone()), (Rel::Rel, mk::lit(w, 0u32)), (Rel::Rel, p0)]);
                let lit = mk::lit(Width::U32, self.bits);
                let eq = apps(mk::global(sym), [(Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, lz_v.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p_lz)]);
                let Some((t2, wrap)) = super::lemmas::rewrite(env, a2, &tk, &lz_v, &lit, mk::int_ty(Width::U32), eq) else { return Ok(None) };
                return Ok(self.close(pf, e2, a2, &t2, self.sk.j_at(self.bits)).map(wrap));
            }
            // 2^(c−1) ≤ v < 2^c: lz(v) = B − c
            Ok(self.pin(pf, e2, a2, &tk, c - 1, &v2))
        };
        let _ = bi;
        e.case_split_with(st, &tv, bi, &[], goal, true, d, &mut arm_fn)
    }

    /// `lz_range_k` pins `lz(v) = B − 1 − k`; the goal then closes by `idle_J`.
    fn pin(&mut self, pf: &mut Pf<'_>, e: &mut Engine<'_>, st: &mut St, goal: &V, k: u32, v_tm: &Tm) -> Option<Tm> {
        let env = e.env;
        let w = self.sk.width;
        let bi = env.bool_ind();
        let lem = env.lookup_global(&crate::auto::bitlib::lemma_name(crate::auto::bitlib::Family::LzRange, w, k))?;
        let lo = eval_in(env, &st.ctx, &mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Le(w), args: vec![mk::lit(w, 1u128 << k), v_tm.clone()], proofs: vec![] }), mk::bool_lit(bi, true))).ok()?;
        let p_lo = pf.obligation(e, st, &lo, "the magnitude's lower bound")?;
        let mut args = vec![(Rel::Rel, v_tm.clone()), (Rel::Irr, p_lo)];
        if k + 1 < self.bits {
            let hi = eval_in(env, &st.ctx, &mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(w), args: vec![v_tm.clone(), mk::lit(w, 1u128 << (k + 1))], proofs: vec![] }), mk::bool_lit(bi, true))).ok()?;
            args.push((Rel::Irr, pf.obligation(e, st, &hi, "the magnitude's upper bound")?));
        }
        let p = apps(mk::global(lem), args);
        let lz_v = self.lz_at(st);
        let lz_val = self.bits - 1 - k;
        let lit = mk::lit(Width::U32, lz_val);
        let sym = env.lookup_global("eq::sym")?;
        let eq = apps(mk::global(sym), [(Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, lz_v.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p)]);
        let (t2, wrap) = super::lemmas::rewrite(env, st, goal, &lz_v, &lit, mk::int_ty(Width::U32), eq)?;
        self.close(pf, e, st, &t2, self.sk.j_at(lz_val)).map(wrap)
    }

    /// The goal `Eq(R, loop(s_0) h̄, loop(s_J) hJ)` at a literal `J`: `refl`
    /// at 0, else `idle_J d̄ h̄ (requires at s_J) (.hv)`.
    fn close(&mut self, pf: &mut Pf<'_>, e: &mut Engine<'_>, st: &mut St, goal: &V, j: u32) -> Option<Tm> {
        let env = e.env;
        let d = st.depth();
        // `aux(d̄, h̄, j) = loop(s_j)` by `Delta` (the match on `j ≤ K` computes)
        let (rty, l0, _) = as_eq(goal)?;
        let (r_tm, l0_tm) = (st.quote(env, rty), st.quote(env, l0));
        let mut aux_args: Vec<Tm> = (0..(self.nd + self.nr) as u32).map(|b| mk::var(d - 1 - b)).collect();
        aux_args.push(mk::lit(Width::U32, j));
        let aux_app = apps(mk::global(self.aux), aux_args.iter().enumerate().map(|(i, t)| (if i < self.nd || i == self.nd + self.nr { Rel::Rel } else { Rel::Irr }, t.clone())));
        let aux_body = apps(env.global_body(self.aux)?, aux_args.iter().enumerate().map(|(i, t)| (if i < self.nd || i == self.nd + self.nr { Rel::Rel } else { Rel::Irr }, t.clone())));
        let (sym, trans) = (env.lookup_global("eq::sym")?, env.lookup_global("eq::trans")?);
        let back = apps(mk::global(sym), [(Rel::Rel, r_tm.clone()), (Rel::Rel, aux_app.clone()), (Rel::Rel, aux_body.clone()), (Rel::Rel, Rc::new(Term::Delta { def: self.aux, args: aux_args.clone() }))]);
        if j == 0 {
            // loop(s_0) h̄ = aux(0) (its body computes to loop(s_0))
            return Some(back);
        }
        let g = (*self.chain.get(j as usize)?)?;
        let bi = env.bool_ind();
        let lit_at = |jj: usize, i: usize| -> Option<Tm> {
            let c = self.lp.static_seq.get(jj)?.get(i)?.as_ref()?;
            Some(mk::lit(self.lp.params[i].width?, c.num()?))
        };
        // the loop's arguments at s_j and the requires there
        let mut a: Vec<Tm> = Vec::new();
        for i in 0..self.np {
            a.push(match &self.statics[i] {
                Some(t) => lit_at(j as usize, i).unwrap_or_else(|| t.clone()),
                None => mk::var(d - 1 - self.lp.dynamic().iter().position(|x| *x as usize == i)? as u32),
            });
        }
        let tele = crate::opt::symex::telescope(env, self.key.def)?;
        let mut reqs: Vec<Tm> = Vec::new();
        for r in 0..self.nr {
            let mut full = a.clone();
            full.extend(reqs.iter().cloned());
            let dom = inst(&tele.binders[self.np + r].2, &full);
            let dv = eval_in(env, &st.ctx, &dom).ok()?;
            reqs.push(pf.obligation(e, st, &dv, "a requires at s_J")?);
        }
        let w_prev = lit_at(j as usize - 1, self.sk.w as usize)?;
        let v_tm = mk::var(d - 1 - self.vpos as u32);
        let hv_g = eval_in(env, &st.ctx, &mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(self.sk.width), args: vec![v_tm, w_prev], proofs: vec![] }), mk::bool_lit(bi, true))).ok()?;
        let hv = pf.obligation(e, st, &hv_g, "the idle guard before the jump")?;
        let mut args: Vec<(Rel, Tm)> = (0..self.nd as u32).map(|b| (Rel::Rel, mk::var(d - 1 - b))).collect();
        for r in 0..self.nr {
            args.push((Rel::Irr, mk::var(d - 1 - (self.nd + r) as u32)));
        }
        args.extend(reqs.into_iter().map(|p| (Rel::Irr, p)));
        args.push((Rel::Irr, hv));
        let _ = self.rels;
        let idle = apps(mk::global(g), args);
        // idle_j : loop(s_0) = loop(s_j) ≡ aux(j)'s body; then back to aux(j)
        Some(apps(mk::global(trans), [(Rel::Rel, r_tm), (Rel::Rel, l0_tm), (Rel::Rel, aux_body), (Rel::Rel, aux_app), (Rel::Rel, idle), (Rel::Rel, back)]))
    }
}

/// `<loop>::idle_at : Π d̄ h̄ (j : u32). R`, the loop at iteration `j` of the
/// static trajectory: `match j ≤ K { true => loop(s_j) <its requires, proven
/// from j ≤ K and h̄>, false => loop(s_0) h̄ }` (transparent). The entry
/// lemma rewrites `J` in `aux(d̄, h̄, J)` freely: no proof in the goal
/// mentions it.
fn idle_at(env: &mut Env, key: &LoopKey, lp: &Loop, sk: &EntrySkip, tele_w: &crate::opt::symex::Telescope, tele_l: &crate::opt::symex::Telescope, name: &str) -> Result<GlobalId, String> {
    let np = lp.params.len();
    let nr = tele_l.binders.len() - np;
    let dy = lp.dynamic();
    let nd = dy.len();
    let statics = super::statics_of(env, key, np)?;
    let rels: Vec<Rel> = tele_l.binders.iter().map(|b| b.1).collect();
    let bi = env.bool_ind();
    // telescope: the entry's binders, then j
    let mut ty = crate::auto::util::shift(&tele_w.ret, 1);
    ty = mk::pi("j", Rel::Rel, mk::int_ty(Width::U32), ty);
    for (nm, rel, dom) in tele_w.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let lim = super::meter::cap(50_000_000);
    let mut sb = Budget { steps: lim };
    let body = {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = St::new(envr, &Ctx::default(), 8);
        let rty = super::lemmas::open(&mut e, &mut st, &ty)?;
        let d = st.depth();
        let names: Vec<String> = st.ctx.entries.iter().map(|x| x.name.to_string()).collect();
        let ns: Vec<&str> = names.iter().map(|x| x.as_str()).collect();
        let test = Rc::new(Term::Prim { op: PrimOp::Le(Width::U32), args: vec![st.var(d - 1), mk::lit(Width::U32, sk.k)], proofs: vec![] });
        let tv = eval_in(envr, &st.ctx, &test)?;
        let mut pf = Pf { f: key.def, this: key.def, ee: &EarlyExit { payload: 0, stop: Stop::Cond(super::expr::lit(Width::U32, 0)), measure: 0 }, stmt: ty.clone(), m_lvl: 0, m_w: Width::U32, final_lemma: None, stop_full: mk::bool_lit(bi, true), arity: 0, trust: false, failure: None };
        let dd = st.depth_left;
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, _tk: V, k: u32| -> R<Option<Tm>> {
            let da = a2.depth();
            let dyn_var = |i: usize| -> Option<Tm> { Some(mk::var(da - 1 - dy.iter().position(|x| *x as usize == i)? as u32)) };
            let jv = mk::var(da - 1 - (nd + nr) as u32);
            let jname = &names[nd + nr];
            let mut a: Vec<Tm> = Vec::new();
            for i in 0..np {
                let t = match (&statics[i], k) {
                    (None, _) => dyn_var(i),
                    (Some(t), 0) => Some(t.clone()),
                    (Some(t), _) => match sk.forms.iter().find(|(p, _)| *p as usize == i) {
                        Some((_, form)) => {
                            let txt = EntrySkip::form_text(form, jname);
                            e2.env.parse_term(&ns, &txt).ok().map(|x| crate::auto::util::shift(&x, (da - d) as i64))
                        }
                        None => Some(t.clone()),
                    },
                };
                let Some(t) = t else { return Ok(None) };
                a.push(t);
            }
            let _ = jv;
            if k == 0 {
                for r in 0..nr {
                    a.push(mk::var(da - 1 - (nd + r) as u32));
                }
            } else {
                let mut reqs: Vec<Tm> = Vec::new();
                for r in 0..nr {
                    let mut full = a.clone();
                    full.extend(reqs.iter().cloned());
                    let dom = inst(&tele_l.binders[np + r].2, &full);
                    let Ok(dv) = eval_in(e2.env, &a2.ctx, &dom) else { return Ok(None) };
                    let Some(p) = pf.obligation(e2, a2, &dv, "a requires at iteration j") else { return Ok(None) };
                    reqs.push(p);
                }
                a.extend(reqs);
            }
            Ok(Some(apps(mk::global(key.def), rels.iter().copied().zip(a))))
        };
        let m = e.case_split_with(&st, &tv, bi, &[], &rty, true, dd, &mut arm_fn).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("idle_at: {}", pf.failure.clone().unwrap_or_default()))?;
        st.finish(m)
    };
    super::meter::charge(lim - sb.steps);
    let mut arity = 0;
    let mut t = &ty;
    while let Term::Pi { cod, .. } = &**t {
        arity += 1;
        t = cod;
    }
    let lim = super::meter::cap(100_000_000);
    let mut b = Budget { steps: lim };
    let r = env.add_def(DefDecl { name: Rc::from(name), kind: DefKind::Spec, ty, body, recursion: Recursion::None, arity, opaque: true }, &mut b);
    super::meter::charge(lim - b.steps);
    r.map_err(|e| format!("the kernel rejected `{name}`: {}", e.to_string().chars().take(400).collect::<String>()))
}
